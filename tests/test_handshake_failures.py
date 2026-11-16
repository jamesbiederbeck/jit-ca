import json
import socket
import ssl

import pytest

from jitca.config import load_config
from jitca.observed import summarize
from jitca.service import JITCAService, classify_handshake_error
from test_e2e import config_file, tls_request


def run(tmp_path, action, extra=""):
    path = config_file(tmp_path)
    if extra:
        path.write_text(path.read_text() + extra)
    service = JITCAService(load_config(path))
    service.start()
    try:
        action(service)
    finally:
        service.stop()
    return service, [json.loads(line) for line in (service.config.state_dir / "events.jsonl").read_text().splitlines()]


def failures(events):
    return [e for e in events if e["event"] == "tls_handshake_failed"]


def test_client_rejecting_the_certificate_is_logged_with_sni_and_alert(tmp_path):
    def action(service):
        untrusted = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # does not trust the demo CA
        with socket.create_connection(service.tls_address, timeout=3) as raw:
            with pytest.raises(ssl.SSLError):
                untrusted.wrap_socket(raw, server_hostname="robot.example.test")
    _, events = run(tmp_path, action)
    (failure,) = failures(events)
    assert failure["category"] == "client_alert" and failure["reason"] == "TLSV1_ALERT_UNKNOWN_CA"
    assert failure["sni"] == "robot.example.test" and failure["source"] == "127.0.0.1"
    assert failure["error_type"] == "SSLError" and failure["elapsed_ms"] >= 0
    assert not any(e["event"] == "http_request" for e in events)


def test_plain_http_to_the_tls_port_is_a_protocol_mismatch_without_sni(tmp_path):
    def action(service):
        with socket.create_connection(service.tls_address, timeout=3) as raw:
            raw.sendall(b"GET / HTTP/1.1\r\nHost: robot.example.test\r\n\r\n")
            raw.settimeout(3)
            try:
                raw.recv(1024)
            except OSError:
                pass
    _, events = run(tmp_path, action)
    (failure,) = failures(events)
    assert failure["category"] == "protocol_mismatch" and failure["sni"] is None
    assert failure["reason"] in ("HTTP_REQUEST", "WRONG_VERSION_NUMBER", "UNKNOWN_PROTOCOL")


def test_rejected_sni_is_logged_as_failure_and_keeps_the_sni_denied_event(tmp_path):
    def action(service):
        with pytest.raises(ssl.SSLError):
            tls_request(service.tls_address[1], service.store.root_ca_path, hostname="other.example")
    _, events = run(tmp_path, action)
    (failure,) = failures(events)
    assert failure["category"] == "sni_rejected" and failure["sni"] == "other.example"
    assert any(e["event"] == "tls_sni_denied" and e["hostname"] == "other.example" for e in events)


def test_connection_closed_before_handshake_is_logged(tmp_path):
    def action(service):
        socket.create_connection(service.tls_address, timeout=3).close()
        # A later good request proves the listener is unaffected.
        assert b"200 OK" in tls_request(service.tls_address[1], service.store.root_ca_path)[0]
    _, events = run(tmp_path, action)
    assert [f["category"] for f in failures(events)] == ["connection_closed"]
    assert failures(events)[0]["sni"] is None


def test_successful_handshake_logs_no_failure(tmp_path):
    _, events = run(tmp_path, lambda s: tls_request(s.tls_address[1], s.store.root_ca_path))
    assert failures(events) == []


@pytest.mark.parametrize("exc,category", [
    (TimeoutError("_ssl.c:1015: The handshake operation timed out"), "timeout"),
    (ssl.SSLEOFError(8, "EOF occurred in violation of protocol"), "connection_closed"),
    (ConnectionResetError(), "connection_closed"),
    (OSError("something else"), "other"),
])
def test_classification_of_non_ssl_errors(exc, category):
    assert classify_handshake_error(exc)[0] == category


def test_observed_summary_counts_handshake_failures_by_sni(tmp_path):
    def action(service):
        for _ in range(2):
            with socket.create_connection(service.tls_address, timeout=3) as raw:
                with pytest.raises(ssl.SSLError):
                    ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).wrap_socket(raw, server_hostname="robot.example.test")
    service, _ = run(tmp_path, action)
    entry = next(e for e in summarize(service.config.state_dir / "events.jsonl") if e["hostname"] == "robot.example.test")
    assert entry["handshake_failures"] == 2
