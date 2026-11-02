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
