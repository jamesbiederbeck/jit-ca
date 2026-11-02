import json
import socket
import ssl
import struct
import time
from pathlib import Path

import pytest
from cryptography import x509

from jitca.config import load_config
from jitca.service import JITCAService


def config_file(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text('''
[network]
dns_host = "127.0.0.1"
dns_port = 0
tls_host = "127.0.0.1"
tls_port = 0
redirect_ipv4 = "127.0.0.1"
allowed_clients = ["127.0.0.1/32"]
[certificates]
mode = "local"
state_dir = "state"
leaf_days = 30
leaf_key = "rsa2048"
[[endpoints]]
hostname = "robot.example.test"
[[endpoints.routes]]
method = "GET"
path = "/status"
body = '{"connected":true}'
[[endpoints.routes]]
method = "POST"
path = "/command"
status = 202
body = '{"accepted":true}'
''')
    return path


def dns_query(hostname: str, qtype=1):
    labels = b"".join(bytes([len(x)]) + x.encode("ascii") for x in hostname.split("."))
    return struct.pack("!HHHHHH", 0x4321, 0x0100, 1, 0, 0, 0) + labels + b"\x00" + struct.pack("!HH", qtype, 1)


def lookup(port, hostname, qtype=1):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    try:
        sock.sendto(dns_query(hostname, qtype), ("127.0.0.1", port))
        return sock.recvfrom(4096)[0]
    finally:
        sock.close()


def tls_request(port, ca, hostname="robot.example.test", path="/status", body=b"", host_header=None):
    context = ssl.create_default_context(cafile=str(ca))
    with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as tls:
            negotiated_version = tls.version()
            request = (f"{'POST' if body else 'GET'} {path} HTTP/1.1\r\n"
                       f"Host: {host_header or hostname}\r\n"
                       f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body
            tls.sendall(request)
            response = b""
            while data := tls.recv(8192):
                response += data
            return response, negotiated_version


def test_dns_prewarm_tls_flow(tmp_path):
    config = load_config(config_file(tmp_path))
    server = JITCAService(config)
    server.start()
    try:
        assert server.store.all_metadata() == []  # no eager leaf issuance
        reply = lookup(server.dns_address[1], "robot.example.test")
        assert struct.unpack("!H", reply[6:8])[0] == 1
        assert reply[-4:] == socket.inet_aton("127.0.0.1")
        server.prewarmer.queue.join()
        certs = server.store.all_metadata()
        assert len(certs) == 1
        assert certs[0]["hostname"] == "robot.example.test"
        result, tlsver = tls_request(server.tls_address[1], server.store.root_ca_path)
        assert b"HTTP/1.1 200 OK" in result
        assert b'"connected":true' in result
        assert tlsver in ("TLSv1.2", "TLSv1.3")
        # Unknown path still terminates TLS and gets explicit unimplemented answer.
        res2, _ = tls_request(server.tls_address[1], server.store.root_ca_path, path="/missing")
        assert b"404 Not Found" in res2
        res3, _ = tls_request(server.tls_address[1], server.store.root_ca_path,
                              body=b'{"password":"abc","thing":1}', path="/command")
        assert b"202 Accepted" in res3
        # Repeated A/AAAA queries do not duplicate a certificate.
        for _ in range(4):
            lookup(server.dns_address[1], "robot.example.test", qtype=28)
        server.prewarmer.queue.join()
        assert len(server.store.all_metadata()) == 1
        # Refuse unknown hostnames instead of issuing for arbitrary SNI.
        bad = lookup(server.dns_address[1], "unlisted.example.test")
        assert struct.unpack("!H", bad[2:4])[0] & 0x000f == 5
        with pytest.raises(ssl.SSLError):
            tls_request(server.tls_address[1], server.store.root_ca_path,
                        hostname="unlisted.example.test")
    finally:
        server.stop()
    events = [json.loads(line) for line in (config.state_dir / "events.jsonl").read_text().splitlines()]
    assert any(x["event"] == "cert_prewarmed" and x["new"] for x in events)
    assert any(x["event"] == "tls_certificate_selected" and not x["new"] for x in events)
    flows = [x for x in events if x["event"] == "http_flow"]
    assert [x["status"] for x in flows] == [200,404,202]
    assert '"password": "[REDACTED]"' in flows[-1]["request_preview"]
    assert "abc" not in (config.state_dir / "events.jsonl").read_text()
    assert (config.state_dir / "events.jsonl").stat().st_mode & 0o077 == 0
    assert list((config.state_dir / "certificates").glob("*/fullchain.pem"))


def test_certificate_validity_and_persistence(tmp_path):
    from jitca.certs import CertificateStore
    cfg = load_config(config_file(tmp_path))
    first = CertificateStore(cfg)
    cert_path, key_path, created = first.get_or_issue("robot.example.test")
    assert created
    second = CertificateStore(cfg)
    cert_path2, key_path2, created2 = second.get_or_issue("robot.example.test")
    assert not created2 and cert_path == cert_path2 and key_path == key_path2
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    assert cert.not_valid_after_utc <= first.not_after
    assert cert.subject == x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "robot.example.test")])
    assert key_path.stat().st_mode & 0o077 == 0
    with pytest.raises(PermissionError):
        second.get_or_issue("outside.example.test")


def test_sni_fallback_without_dns(tmp_path):
    cfg = load_config(config_file(tmp_path))
    service = JITCAService(cfg)
    service.start()
    try:
        assert service.store.all_metadata() == []
        response, _ = tls_request(service.tls_address[1], service.store.root_ca_path)
        assert b"200 OK" in response
        assert len(service.store.all_metadata()) == 1
    finally:
        service.stop()


def test_http_host_mismatch_rejected(tmp_path):
    cfg = load_config(config_file(tmp_path))
    service = JITCAService(cfg)
    service.start()
    try:
        response, _ = tls_request(service.tls_address[1], service.store.root_ca_path,
                                  host_header="other.example.test")
        assert b"403 Forbidden" in response
    finally:
        service.stop()


def test_external_intermediate_chain(tmp_path):
    """Exercise the optional signer with a synthetic cross-signed-style CA chain."""
    from datetime import datetime, timedelta, timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    from jitca.certs import CertificateStore

    now = datetime.now(timezone.utc)
    key_root = ec.generate_private_key(ec.SECP384R1())
    key_intermediate = ec.generate_private_key(ec.SECP384R1())
    root_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Demo Crosssign Root")])
    intermediate_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Demo External Intermediate")])

    def key_usage():
        return x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                             data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                             encipher_only=False, decipher_only=False)

    root = (x509.CertificateBuilder().subject_name(root_subject).issuer_name(root_subject)
            .public_key(key_root.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=2)).not_valid_after(now + timedelta(days=10))
            .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key_root.public_key()), False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key_root.public_key()), False)
            .add_extension(key_usage(), critical=True)
            .sign(key_root, hashes.SHA384()))
    intermediate = (x509.CertificateBuilder().subject_name(intermediate_subject).issuer_name(root_subject)
            .public_key(key_intermediate.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=3))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key_intermediate.public_key()), False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key_root.public_key()), False)
            .add_extension(key_usage(), critical=True)
            .sign(key_root, hashes.SHA384()))
    (tmp_path / "demo-root.pem").write_bytes(root.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "demo-intermediate.pem").write_bytes(intermediate.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "demo-intermediate.key").write_bytes(key_intermediate.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

    path = config_file(tmp_path)
    src = path.read_text().replace('mode = "local"',
            'mode = "external"\nissuer_cert = "demo-intermediate.pem"\nissuer_key = "demo-intermediate.key"\nchain_files = ["demo-root.pem"]')
    path.write_text(src)
    cfg = load_config(path)
    service = JITCAService(cfg)
    service.start()
    try:
        lookup(service.dns_address[1], "robot.example.test")
        service.prewarmer.queue.join()
        response, _ = tls_request(service.tls_address[1], tmp_path / "demo-root.pem")
        assert b"200 OK" in response
        cert_path, _, made = service.store.get_or_issue("robot.example.test")
        assert not made
        issued = x509.load_pem_x509_certificate(cert_path.read_bytes())
        assert issued.issuer == intermediate_subject
        assert issued.not_valid_after_utc < now + timedelta(days=4)
        assert issued.not_valid_after_utc <= intermediate.not_valid_after_utc
    finally:
        service.stop()
