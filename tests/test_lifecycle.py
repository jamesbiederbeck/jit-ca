from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
import socket
import ssl
import threading

import pytest

from jitca.config import load_config
from jitca.events import EventLog
import jitca.service as service_module
from jitca.service import JITCAService
from test_e2e import config_file, lookup, tls_request


def events(service):
    return [json.loads(line) for line in service.log.path.read_text().splitlines()]


def assert_stopped(service):
    assert not service.log.thread.is_alive()
    assert not service.prewarmer.thread.is_alive()
    assert all(not thread.is_alive() for thread in service.threads)
    assert service.dns_server.fileno() == service.tls_server.fileno() == -1


def test_slow_log_does_not_delay_dns_or_tls_and_shutdown_flushes(tmp_path, monkeypatch):
    service = JITCAService(load_config(config_file(tmp_path)))
    writing = threading.Event()
    release = threading.Event()
    write = service.log._write

    def slow_write(record):
        if record["event"] == "dns_query":
            writing.set()
            assert release.wait(5)
        write(record)

    monkeypatch.setattr(service.log, "_write", slow_write)
    service.start()
    try:
        lookup(service.dns_address[1], "robot.example.test")
        assert writing.wait(2)
        # The writer is still blocked when these complete.
        lookup(service.dns_address[1], "robot.example.test", qtype=28)
        response, _ = tls_request(service.tls_address[1], service.store.root_ca_path)
        assert b"200 OK" in response
    finally:
        release.set()
        service.stop()
    records = events(service)
    assert sum(record["event"] == "dns_query" for record in records) == 2
    assert any(record["event"] == "http_flow" for record in records)
    assert records[-1]["event"] == "service_stopped"
    assert_stopped(service)


def test_shutdown_drains_inflight_signing(tmp_path, monkeypatch):
    service = JITCAService(load_config(config_file(tmp_path)))
    signing, draining, release = (threading.Event() for _ in range(3))
    issue = service.store.get_or_issue
    stop = service.prewarmer.stop

    def slow_issue(hostname):
        signing.set()
        assert release.wait(5)
        return issue(hostname)

    def drain_worker():
        draining.set()
        stop()

    monkeypatch.setattr(service.store, "get_or_issue", slow_issue)
    monkeypatch.setattr(service.prewarmer, "stop", drain_worker)
    service.start()
    try:
        lookup(service.dns_address[1], "robot.example.test")
        assert signing.wait(2)
        with ThreadPoolExecutor(max_workers=1) as pool:
            stopping = pool.submit(service.stop)
            try:
                assert draining.wait(2)
                assert not stopping.done()
                assert service.log.thread.is_alive()
            finally:
                release.set()
            stopping.result(timeout=5)
    finally:
        release.set()
        service.stop()
    names = [record["event"] for record in events(service)]
    assert names.index("cert_prewarmed") < names.index("service_stopped")
    assert_stopped(service)
    with pytest.raises(RuntimeError, match="not running"):
        service.prewarmer.request("robot.example.test")


def test_shutdown_drains_active_http_handler(tmp_path, monkeypatch):
    service = JITCAService(load_config(config_file(tmp_path)))
    reading, draining, release = (threading.Event() for _ in range(3))
    read = service_module._read_http
    close = service.tls_server.server_close

    def slow_read(*args):
        reading.set()
        assert release.wait(5)
        return read(*args)

    def drain_handlers():
        draining.set()
        close()

    monkeypatch.setattr(service_module, "_read_http", slow_read)
    monkeypatch.setattr(service.tls_server, "server_close", drain_handlers)
    service.start()
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            request = pool.submit(tls_request, service.tls_address[1], service.store.root_ca_path)
            try:
                assert reading.wait(2)
                stopping = pool.submit(service.stop)
                assert draining.wait(2)
                assert not stopping.done()
                assert service.log.thread.is_alive()
            finally:
                release.set()
            assert b"200 OK" in request.result(timeout=5)[0]
            stopping.result(timeout=5)
    finally:
        release.set()
        service.stop()
    names = [record["event"] for record in events(service)]
    assert names.index("http_flow") < names.index("service_stopped")
    assert_stopped(service)


def test_stop_before_start_and_repeat_stop(tmp_path):
    service = JITCAService(load_config(config_file(tmp_path)))
    service.stop()
    service.stop()
    assert_stopped(service)
    with pytest.raises(RuntimeError, match="only be started once"):
        service.start()


def test_failed_handshake_and_successful_request_close_tls_sockets(tmp_path, monkeypatch):
    service = JITCAService(load_config(config_file(tmp_path)))
    sockets = []
    wrap = service.base_ssl.wrap_socket

    def capture_socket(*args, **kwargs):
        wrapped = wrap(*args, **kwargs)
        sockets.append(wrapped)
        return wrapped

    monkeypatch.setattr(service.base_ssl, "wrap_socket", capture_socket)
    service.start()
    try:
        untrusted = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        with socket.create_connection(service.tls_address, timeout=3) as raw:
            with pytest.raises(ssl.SSLError):
                untrusted.wrap_socket(raw, server_hostname="robot.example.test")
        response, _ = tls_request(service.tls_address[1], service.store.root_ca_path)
        assert b"200 OK" in response
    finally:
        service.stop()
    assert len(sockets) == 2
    assert all(wrapped.fileno() == -1 for wrapped in sockets)
    assert any(record["event"] == "tls_or_http_error" for record in events(service))
    assert_stopped(service)


def test_constructor_failure_releases_dns_listener_and_log(tmp_path, monkeypatch):
    logs, listeners = [], []
    dns_server = service_module._DNSServer

    def capture_log(path):
        log = EventLog(path)
        logs.append(log)
        return log

    def capture_dns(*args):
        listener = dns_server(*args)
        listeners.append(listener)
        return listener

    monkeypatch.setattr(service_module, "EventLog", capture_log)
    monkeypatch.setattr(service_module, "_DNSServer", capture_dns)
    cfg = load_config(config_file(tmp_path))
    with socket.socket() as occupied:
        occupied.bind(("127.0.0.1", 0))
        occupied.listen()
        with pytest.raises(OSError):
            JITCAService(replace(cfg, tls_port=occupied.getsockname()[1]))
    assert len(listeners) == len(logs) == 1
    assert listeners[0].fileno() == -1
    assert not logs[0].thread.is_alive()


def test_partial_start_failure_is_cleaned_up(tmp_path, monkeypatch):
    service = JITCAService(load_config(config_file(tmp_path)))
    start_thread = threading.Thread.start

    def fail_tls_start(thread):
        if thread.name == "jitca-tls":
            raise RuntimeError("simulated thread startup failure")
        start_thread(thread)

    monkeypatch.setattr(threading.Thread, "start", fail_tls_start)
    with pytest.raises(RuntimeError, match="simulated thread startup failure"):
        service.start()
    service.stop()
    assert_stopped(service)


def test_log_write_failure_reported_without_stranding_shutdown(tmp_path, monkeypatch):
    log = EventLog(tmp_path / "events.jsonl")

    def fail_write(record):
        raise OSError("simulated disk failure")

    monkeypatch.setattr(log, "_write", fail_write)
    log.emit("first")
    log.emit("second")
    with pytest.raises(OSError, match="event log writer failed") as error:
        log.close()
    assert "simulated disk failure" in str(error.value.__cause__)
    assert not log.thread.is_alive()
    assert log._queue.unfinished_tasks == 0
    with pytest.raises(RuntimeError, match="closed"):
        log.emit("too_late")
