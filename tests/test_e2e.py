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
        # Unknown paths are observed and receive an empty 204 response.
        res2, _ = tls_request(server.tls_address[1], server.store.root_ca_path, path="/missing")
        assert b"204 No Content" in res2
        res3, _ = tls_request(server.tls_address[1], server.store.root_ca_path,
                                  body=b'{"password":"secret-that-must-never-appear-in-capture","thing":1}', path="/command")
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
    assert [x["status"] for x in flows] == [200,204,202]
    assert '"password": "[REDACTED]"' in flows[-1]["request_preview"]
    assert "secret-that-must-never-appear-in-capture" not in (config.state_dir / "events.jsonl").read_text()
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


def _write_ca_pair(ca_dir, stem, subject_cn, days=30):
    """Write a self-signed CA cert/key pair mimicking an operator-supplied
    issuer directory entry, with no manifest beyond the matching filenames."""
    from datetime import datetime, timedelta, timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    now = datetime.now(timezone.utc)
    key = ec.generate_private_key(ec.SECP384R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn),
                         x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Corp"),
                         x509.NameAttribute(NameOID.COUNTRY_NAME, "US")])
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                         crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .sign(key, hashes.SHA384()))
    (ca_dir / f"{stem}.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (ca_dir / f"{stem}.key").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return subject_cn


def _directory_config(tmp_path, ca_dir, extra_certificates="", extra_endpoint=""):
    path = tmp_path / "config.toml"
    path.write_text(f'''
[network]
dns_host = "127.0.0.1"
dns_port = 0
tls_host = "127.0.0.1"
tls_port = 0
redirect_ipv4 = "127.0.0.1"
allowed_clients = ["127.0.0.1/32"]
[certificates]
mode = "directory"
ca_dir = "{ca_dir}"
state_dir = "state"
leaf_days = 30
leaf_key = "rsa2048"
{extra_certificates}
[[endpoints]]
hostname = "robot.example.test"
issuer = "OV TLS"
[[endpoints.routes]]
method = "GET"
path = "/status"
body = '{{"connected":true}}'
{extra_endpoint}
''')
    return path


def test_directory_issuer_selected_per_endpoint(tmp_path):
    from jitca.certs import CertificateStore

    ca_dir = tmp_path / "cas"
    ca_dir.mkdir()
    _write_ca_pair(ca_dir, "ov-tls-g3c-us", "Example OV TLS Issuing CA G3C")
    _write_ca_pair(ca_dir, "ev-tls-g3b-nl", "Example EV TLS Issuing CA G3B")
    cfg = load_config(_directory_config(tmp_path, ca_dir))
    store = CertificateStore(cfg)
    assert sorted(store.issuers) == ["ev-tls-g3b-nl", "ov-tls-g3c-us"]
    assert store.endpoint_issuer["robot.example.test"] == "ov-tls-g3c-us"
    cert_path, _, created = store.get_or_issue("robot.example.test")
    assert created
    issued = x509.load_pem_x509_certificate(cert_path.read_bytes())
    assert "Example OV TLS Issuing CA G3C" in issued.issuer.rfc4514_string()


def test_directory_issuer_default_and_tls_handshake(tmp_path):
    ca_dir = tmp_path / "cas"
    ca_dir.mkdir()
    _write_ca_pair(ca_dir, "ov-tls-g3c-us", "Example OV TLS Issuing CA G3C")
    _write_ca_pair(ca_dir, "dv-tls-g3b-nl", "Example DV TLS Issuing CA G3B")
    cfg = load_config(_directory_config(
        tmp_path, ca_dir,
        extra_certificates='default_issuer = "DV TLS"',
        extra_endpoint='[[endpoints]]\nhostname = "other.example.test"\n'))
    service = JITCAService(cfg)
    service.start()
    try:
        response, _ = tls_request(service.tls_address[1], ca_dir / "ov-tls-g3c-us.pem")
        assert b"200 OK" in response
        other_cert_path, _, _ = service.store.get_or_issue("other.example.test")
        other_cert = x509.load_pem_x509_certificate(other_cert_path.read_bytes())
        assert "Example DV TLS Issuing CA G3B" in other_cert.issuer.rfc4514_string()
    finally:
        service.stop()


def test_directory_issuer_ambiguous_selector_rejected(tmp_path):
    from jitca.certs import CertificateStore

    ca_dir = tmp_path / "cas"
    ca_dir.mkdir()
    _write_ca_pair(ca_dir, "ov-tls-g3c-us", "Example OV TLS Issuing CA G3C")
    _write_ca_pair(ca_dir, "ov-tls-g3b-nl", "Example OV TLS Issuing CA G3B")
    cfg = load_config(_directory_config(tmp_path, ca_dir))  # selector "OV TLS" matches both
    with pytest.raises(ValueError, match="matched 2 CA"):
        CertificateStore(cfg)


def test_directory_issuer_orphan_key_rejected(tmp_path):
    from jitca.certs import CertificateStore

    ca_dir = tmp_path / "cas"
    ca_dir.mkdir()
    _write_ca_pair(ca_dir, "ov-tls-g3c-us", "Example OV TLS Issuing CA G3C")
    (ca_dir / "stray.key").write_bytes((ca_dir / "ov-tls-g3c-us.key").read_bytes())
    cfg = load_config(_directory_config(tmp_path, ca_dir))
    with pytest.raises(ValueError, match="without matching certificate"):
        CertificateStore(cfg)


def test_config_rejects_issuer_selector_outside_directory_mode(tmp_path):
    path = config_file(tmp_path)
    path.write_text(path.read_text().replace(
        '[[endpoints]]\nhostname = "robot.example.test"',
        '[[endpoints]]\nhostname = "robot.example.test"\nissuer = "anything"'))
    with pytest.raises(ValueError, match="certificates.mode"):
        load_config(path)


def test_config_directory_mode_requires_a_selector(tmp_path):
    ca_dir = tmp_path / "cas"
    ca_dir.mkdir()
    path = tmp_path / "config.toml"
    path.write_text(f'''
[network]
dns_host = "127.0.0.1"
dns_port = 0
tls_host = "127.0.0.1"
tls_port = 0
redirect_ipv4 = "127.0.0.1"
allowed_clients = ["127.0.0.1/32"]
[certificates]
mode = "directory"
ca_dir = "{ca_dir}"
state_dir = "state"
leaf_days = 30
leaf_key = "rsa2048"
[[endpoints]]
hostname = "robot.example.test"
[[endpoints.routes]]
method = "GET"
path = "/status"
body = '{{"connected":true}}'
''')
    with pytest.raises(ValueError, match="no issuer selector"):
        load_config(path)


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


class _FakeUpstream:
    """Loopback UDP resolver that answers every A query with 203.0.113.7 (or stays silent)."""

    def __init__(self, silent=False):
        import threading
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.silent, self.queries, self.running = silent, 0, True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        while self.running:
            try:
                data, peer = self.sock.recvfrom(4096)
            except OSError:
                continue
            self.queries += 1
            if self.silent:
                continue
            question = data[12:]
            reply = (data[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + question
                     + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("203.0.113.7"))
            self.sock.sendto(reply, peer)

    def close(self):
        self.running = False
        self.thread.join()
        self.sock.close()


def _forward_config(tmp_path, upstream_port, hostnames='["cloud.vendor.test"]', extra=""):
    path = config_file(tmp_path)
    path.write_text(path.read_text() + f'''
[dns_forward]
upstream = "127.0.0.1"
port = {upstream_port}
timeout_seconds = 0.5
hostnames = {hostnames}
{extra}''')
    return path


def test_dns_forward_whitelisted_hostname_gets_real_answer(tmp_path):
    upstream = _FakeUpstream()
    server = JITCAService(load_config(_forward_config(tmp_path, upstream.port)))
    server.start()
    try:
        reply = lookup(server.dns_address[1], "Cloud.Vendor.Test")
        assert reply[:2] == struct.pack("!H", 0x4321)
        assert reply[-4:] == socket.inet_aton("203.0.113.7")
        assert upstream.queries == 1
        # Not whitelisted: still REFUSED, never relayed, and no certificate issued.
        assert struct.unpack("!H", lookup(server.dns_address[1], "other.vendor.test")[2:4])[0] & 0xF == 5
        assert upstream.queries == 1
        # Explicit endpoints are unchanged.
        assert lookup(server.dns_address[1], "robot.example.test")[-4:] == socket.inet_aton("127.0.0.1")
        server.prewarmer.queue.join()
        assert [c["hostname"] for c in server.store.all_metadata()] == ["robot.example.test"]
    finally:
        server.stop()
        upstream.close()
    events = [json.loads(line) for line in (server.config.state_dir / "events.jsonl").read_text().splitlines()]
    forwarded = [x for x in events if x["event"] == "dns_query" and x["action"] == "forward"]
    assert len(forwarded) == 1 and forwarded[0]["hostname"] == "cloud.vendor.test"
    assert forwarded[0]["upstream"] == f"127.0.0.1:{upstream.port}"
    assert [(r["name"].lower(), r["type"], r["ttl"], r["data"]) for r in forwarded[0]["answers"]] == [
        ("cloud.vendor.test", "A", 60, "203.0.113.7")]
    assert forwarded[0]["rcode"] == "NOERROR" and forwarded[0]["reply_bytes"] > 12
    assert forwarded[0]["truncated"] is False and forwarded[0]["answers_error"] is None


def test_dns_forward_upstream_timeout_returns_servfail(tmp_path):
    upstream = _FakeUpstream(silent=True)
    server = JITCAService(load_config(_forward_config(tmp_path, upstream.port)))
    server.start()
    try:
        reply = lookup(server.dns_address[1], "cloud.vendor.test")
        assert struct.unpack("!H", reply[2:4])[0] & 0xF == 2
        assert reply[:2] == struct.pack("!H", 0x4321)
    finally:
        server.stop()
        upstream.close()
    events = [json.loads(line) for line in (server.config.state_dir / "events.jsonl").read_text().splitlines()]
    assert any(x.get("action") == "forward_failed" for x in events)


def test_dns_forward_config_validation(tmp_path):
    with pytest.raises(ValueError, match="overlap"):
        load_config(_forward_config(tmp_path, 53, hostnames='["robot.example.test"]'))
    other = tmp_path / "empty"
    other.mkdir()
    with pytest.raises(ValueError, match="non-empty"):
        load_config(_forward_config(other, 53, hostnames="[]"))


def _ntp_config(tmp_path, extra=""):
    path = config_file(tmp_path)
    path.write_text(path.read_text() + f'\n[ntp]\nport = 0\n{extra}')
    return path


def _ntp_request(port, mode=3, version=4, size=48):
    packet = bytearray(size)
    packet[0] = (version << 3) | mode
    packet[40:48] = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1)
    try:
        sock.sendto(bytes(packet), ("127.0.0.1", port))
        return sock.recvfrom(1024)[0]
    finally:
        sock.close()


def test_ntp_answers_client_request_with_current_time(tmp_path):
    config = load_config(_ntp_config(tmp_path, "stratum = 3\n"))
    server = JITCAService(config)
    server.start()
    try:
        before = time.time()
        reply = _ntp_request(server.ntp_address[1])
        after = time.time()
        assert len(reply) == 48
        assert reply[0] & 7 == 4 and (reply[0] >> 3) & 7 == 4
        assert reply[1] == 3
        assert reply[24:32] == b"\x01\x02\x03\x04\x05\x06\x07\x08"
        seconds, _ = struct.unpack("!II", reply[40:48])
        assert before - 1 <= seconds - 2208988800 <= after + 1
        # Server-mode packets, short packets and bad versions get no reply.
        for bad in ({"mode": 4}, {"version": 0}, {"size": 20}):
            with pytest.raises(socket.timeout):
                _ntp_request(server.ntp_address[1], **bad)
    finally:
        server.stop()
    events = [json.loads(line) for line in (config.state_dir / "events.jsonl").read_text().splitlines()]
    assert sum(x["event"] == "ntp_query" for x in events) == 1
    assert sum(x["event"] == "ntp_invalid" for x in events) == 3


def test_ntp_disabled_by_default_and_validated(tmp_path):
    server = JITCAService(load_config(config_file(tmp_path)))
    try:
        assert server.ntp_address is None
    finally:
        server.stop()
    other = tmp_path / "bad"
    other.mkdir()
    with pytest.raises(ValueError, match="stratum"):
        load_config(_ntp_config(other, "stratum = 16\n"))


def _plain_config(tmp_path, extra=""):
    path = config_file(tmp_path)
    path.write_text(path.read_text() + f'\n[plain_http]\nport = 0\n[capture]\nenabled = true\n{extra}')
    return path


def _plain_request(port, method, path, host, body=b""):
    with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
        request = (f"{method} {path} HTTP/1.1\r\n" + (f"Host: {host}\r\n" if host else "")
                   + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body
        sock.sendall(request)
        response = b""
        while data := sock.recv(8192):
            response += data
        return response


def test_plain_http_routes_logs_and_captures_bodies(tmp_path):
    config = load_config(_plain_config(tmp_path))
    server = JITCAService(config)
    server.start()
    try:
        port = server.http_address[1]
        ok = _plain_request(port, "GET", "/status", "robot.example.test:80")
        assert b"200 OK" in ok and b'"connected":true' in ok
        secret = b"raw-device-payload"
        # Unlisted host and IP-literal Host are observed (captured) but get an empty 204.
        assert b"204 No Content" in _plain_request(port, "POST", "/up", "unlisted.example.test", secret)
        assert b"204 No Content" in _plain_request(port, "POST", "/up", "10.1.2.3", secret)
        assert b"204 No Content" in _plain_request(port, "POST", "/up", None, secret)
    finally:
        server.stop()
    events = [json.loads(line) for line in (config.state_dir / "events.jsonl").read_text().splitlines()]
    flows = [x for x in events if x["event"] == "http_flow"]
    assert [x["status"] for x in flows] == [200, 204, 204, 204]
    assert all(x["scheme"] == "http" for x in flows)
    assert [x["hostname"] for x in flows] == ["robot.example.test", "unlisted.example.test", None, None]
    assert flows[2]["host_header"] == "10.1.2.3"
    captured = [x["request_capture"]["file"] for x in flows if "request_capture" in x]
    assert len(captured) == 3
    assert any("unknown-host" in name for name in captured)
    for name in captured:
        assert (config.state_dir / "captures" / name).read_bytes() == secret


def test_plain_http_disabled_by_default_and_denies_other_clients(tmp_path):
    server = JITCAService(load_config(config_file(tmp_path)))
    try:
        assert server.http_address is None
    finally:
        server.stop()
    other = tmp_path / "deny"
    other.mkdir()
    path = _plain_config(other)
    path.write_text(path.read_text().replace('allowed_clients = ["127.0.0.1/32"]',
                                             'allowed_clients = ["192.0.2.0/24"]'))
    config = load_config(path)
    server = JITCAService(config)
    server.start()
    try:
        with socket.create_connection(("127.0.0.1", server.http_address[1]), timeout=2) as sock:
            sock.sendall(b"GET / HTTP/1.1\r\nHost: robot.example.test\r\n\r\n")
            assert sock.recv(100) == b""
    finally:
        server.stop()
    events = (config.state_dir / "events.jsonl").read_text()
    assert "http_plain_denied" in events and "http_flow" not in events


def test_parse_dns_answers_handles_cname_aaaa_and_malformed():
    from jitca.service import _parse_dns_answers
    header = struct.pack("!HHHHHH", 1, 0x8180, 1, 3, 0, 0)
    question = b"\x05cloud\x06vendor\x04test\x00" + struct.pack("!HH", 1, 1)
    cname = b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 30, 7) + b"\x04edge\xc0\x12"
    a = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("198.51.100.9")
    aaaa = b"\xc0\x0c" + struct.pack("!HHIH", 28, 1, 60, 16) + socket.inet_pton(socket.AF_INET6, "2001:db8::1")
    records = _parse_dns_answers(header + question + cname + a + aaaa)
    assert [(r["type"], r["data"]) for r in records] == [
        ("CNAME", "edge.vendor.test"), ("A", "198.51.100.9"), ("AAAA", "2001:db8::1")]
    with pytest.raises(ValueError):
        _parse_dns_answers((header + question + cname)[:-3])
