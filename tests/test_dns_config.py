from dataclasses import replace
import socket

import pytest

from jitca.config import load_config
from jitca.service import JITCAService
from test_e2e import config_file, lookup


@pytest.mark.parametrize("tls_host,override,expected", [
    ("127.0.0.2", None, "127.0.0.2"),
    ("0.0.0.0", None, "127.0.0.1"),
    ("127.0.0.1", "192.0.2.42", "192.0.2.42"),
])
def test_dns_advertises_service_address_unless_overridden(tmp_path, tls_host, override, expected):
    path = config_file(tmp_path)
    path.write_text(path.read_text().replace('redirect_ipv4 = "127.0.0.1"\n', ""))
    cfg = replace(load_config(path), tls_host=tls_host, redirect_ipv4=override)
    service = JITCAService(cfg)
    service.start()
    try:
        reply = lookup(service.dns_address[1], "robot.example.test")
        assert reply[-4:] == socket.inet_aton(expected)
        ipv6 = lookup(service.dns_address[1], "robot.example.test", qtype=28)
        assert ipv6[6:8] == b"\x00\x00"
    finally:
        service.stop()


def test_dns_override_rejects_wildcard_address(tmp_path):
    path = config_file(tmp_path)
    path.write_text(path.read_text().replace('redirect_ipv4 = "127.0.0.1"', 'redirect_ipv4 = "0.0.0.0"'))
    with pytest.raises(ValueError, match="concrete IPv4"):
        load_config(path)


def _answer_all_config(tmp_path, enabled=True):
    path = config_file(tmp_path)
    if enabled:
        path.write_text(path.read_text().replace(
            'redirect_ipv4 = "127.0.0.1"', 'redirect_ipv4 = "192.0.2.45"\ndns_answer_all = true'))
    return load_config(path)


def test_dns_answer_all_answers_unknown_names_without_issuing_certs(tmp_path):
    service = JITCAService(_answer_all_config(tmp_path))
    service.start()
    try:
        port = service.dns_address[1]
        reply = lookup(port, "anything.vendor-cloud.example")
        assert reply[3] & 0x0F == 0 and reply[6:8] == b"\x00\x01"
        assert reply[-4:] == socket.inet_aton("192.0.2.45")
        # Non-A types for unknown names get NODATA, not REFUSED.
        aaaa = lookup(port, "anything.vendor-cloud.example", qtype=28)
        assert aaaa[3] & 0x0F == 0 and aaaa[6:8] == b"\x00\x00"
        service.prewarmer.queue.join()
        # Catch-all answers must never create certificates for arbitrary names.
        assert service.store.all_metadata() == []
        # Configured endpoints are still signed before the reply.
        lookup(port, "robot.example.test")
        assert len(service.store.all_metadata()) == 1
    finally:
        service.stop()


def test_dns_refuses_unknown_names_by_default(tmp_path):
    service = JITCAService(_answer_all_config(tmp_path, enabled=False))
    service.start()
    try:
        reply = lookup(service.dns_address[1], "anything.vendor-cloud.example")
        assert reply[3] & 0x0F == 5 and reply[6:8] == b"\x00\x00"
    finally:
        service.stop()


def test_dns_answer_all_requires_concrete_redirect(tmp_path):
    path = config_file(tmp_path)
    path.write_text(path.read_text().replace(
        'redirect_ipv4 = "127.0.0.1"', 'dns_answer_all = true'))
    with pytest.raises(ValueError, match="requires network.redirect_ipv4"):
        load_config(path)
    path.write_text(path.read_text().replace(
        'dns_answer_all = true', 'redirect_ipv4 = "127.0.0.1"\ndns_answer_all = "yes"'))
    with pytest.raises(ValueError, match="true or false"):
        load_config(path)
