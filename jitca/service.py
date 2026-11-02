from __future__ import annotations

import hashlib
import ipaddress
import json
from pathlib import Path
import queue
import socketserver
import ssl
import struct
import threading
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from .certs import CertificateStore, _save_private, _private_pem
from .config import Config, canonical_hostname
from .events import EventLog


class CertificatePrewarmer:
    def __init__(self, store: CertificateStore, log: EventLog):
        self.store = store
        self.log = log
        self.queue: queue.Queue[str | None] = queue.Queue()
        self.pending: set[str] = set()
        self.lock = threading.Lock()
        self._started = False
        self._stopped = False
        self.thread = threading.Thread(target=self._work, name="jitca-cert-prewarm", daemon=True)

    def start(self):
        with self.lock:
            if self._started or self._stopped:
                raise RuntimeError("certificate worker cannot be restarted")
            self.thread.start()
            self._started = True

    def request(self, hostname: str):
        hostname = canonical_hostname(hostname)
        if hostname not in self.store.config.endpoints:
            raise PermissionError(f"hostname not approved: {hostname}")
        with self.lock:
            if not self._started or self._stopped:
                raise RuntimeError("certificate worker is not running")
            if hostname not in self.pending:
                self.pending.add(hostname)
                self.queue.put(hostname)

    def _work(self):
        while True:
            hostname = self.queue.get()
            if hostname is None:
                self.queue.task_done()
                return
            try:
                cert_path, _, issued = self.store.get_or_issue(hostname)
                self.log.emit("cert_prewarmed", hostname=hostname, new=issued,
                              certificate=str(cert_path.relative_to(self.store.config.state_dir)))
            except Exception as exc:
                self.log.emit("cert_prewarm_error", hostname=hostname, error=str(exc))
            finally:
                with self.lock:
                    self.pending.discard(hostname)
                self.queue.task_done()

    def stop(self):
        with self.lock:
            if not self._stopped:
                self._stopped = True
                if self._started:
                    self.queue.put(None)
        if self._started:
            self.thread.join()


def _parse_dns_question(payload: bytes):
    if len(payload) < 17:
        raise ValueError("short DNS query")
    ident, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", payload[:12])
    if qdcount != 1 or flags & 0x8000 or flags & 0x7800:
        raise ValueError("only one standard DNS query supported")
    labels, position, jumped, next_position, visited = [], 12, False, None, set()
    for _ in range(128):
        if position >= len(payload) or position in visited:
            raise ValueError("malformed DNS labels")
        visited.add(position)
        size = payload[position]
        if size & 0xC0 == 0xC0:
            if position + 1 >= len(payload):
                raise ValueError("truncated DNS compression")
            offset = ((size & 0x3F) << 8) | payload[position+1]
            if offset >= len(payload):
                raise ValueError("invalid compression offset")
            if not jumped:
                next_position = position + 2
            jumped = True
            position = offset
            continue
        if size & 0xC0:
            raise ValueError("bad DNS label")
        position += 1
        if size == 0:
            question_end = next_position if jumped else position
            break
        if position + size > len(payload):
            raise ValueError("truncated label")
        labels.append(payload[position:position+size].decode("ascii"))
        position += size
    else:
        raise ValueError("DNS compression loop")
    if question_end + 4 > len(payload):
        raise ValueError("truncated question")
    qtype, qclass = struct.unpack("!HH", payload[question_end:question_end+4])
    hostname = canonical_hostname(".".join(labels))
    return ident, flags, hostname, qtype, qclass, payload[12:question_end+4]


def _dns_response(payload: bytes, config: Config):
    ident, flags, hostname, qtype, qclass, question = _parse_dns_question(payload)
    approved = hostname in config.endpoints
    rcode = 0 if approved else 5  # REFUSED for unknown hostnames (no forwarding in POC).
    answer = b""
    if approved and qtype == 1 and qclass == 1:
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4)
        answer += ipaddress.IPv4Address(config.redirect_ipv4).packed
    reply_flags = 0x8000 | 0x0400 | (flags & 0x0100) | rcode
    header = struct.pack("!HHHHHH", ident, reply_flags, 1, int(bool(answer)), 0, 0)
    return header + question + answer, hostname, approved, qtype


class _DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        controller = self.server.controller
        if not controller.config.allows_client(self.client_address[0]):
            controller.log.emit("dns_denied", source=self.client_address[0])
            return
        try:
            response, hostname, approved, qtype = _dns_response(data, controller.config)
        except (ValueError, UnicodeDecodeError) as exc:
            controller.log.emit("dns_invalid", source=self.client_address[0], error=str(exc))
            return
        controller.log.emit("dns_query", source=self.client_address[0], hostname=hostname,
                            qtype=qtype, intercepted=approved)
        if approved:
            controller.prewarmer.request(hostname)
        sock.sendto(response, self.client_address)


class _DNSServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = False  # server_close waits for handlers before their dependencies close.

    def __init__(self, address, controller):
        super().__init__(address, _DNSHandler)
        self.controller = controller


def _bootstrap_context(path: Path) -> ssl.SSLContext:
    cert_path, key_path = path / "bootstrap.crt", path / "bootstrap.key"
    if not cert_path.exists() or not key_path.exists():
        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(timezone.utc)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "jitca-bootstrap.invalid")])
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("jitca-bootstrap.invalid")]), False)
                .sign(key, hashes.SHA256()))
        _save_private(key_path, _private_pem(key))
        _save_private(cert_path, cert.public_bytes(serialization.Encoding.PEM))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(["http/1.1"])
    context.load_cert_chain(str(cert_path), str(key_path))
    return context


def _safe_preview(body: bytes):
    if not body:
        return ""
    try:
        payload = json.loads(body)
        def redact(value):
            if isinstance(value, dict):
                return {k: "[REDACTED]" if any(p in k.lower() for p in (
                    "pass", "secret", "token", "auth", "cookie", "credential", "apikey", "api_key"))
                    else redact(v) for k, v in value.items()}
            if isinstance(value, list):
                return [redact(v) for v in value[:50]]
            return value
        return json.dumps(redact(payload), ensure_ascii=False)[:4096]
    except (ValueError, UnicodeDecodeError):
        return "[non-JSON body omitted]"


def _read_http(stream, max_body):
    request_line = stream.readline(8193)
    if not request_line or len(request_line) > 8192:
        raise ValueError("invalid request line")
    parts = request_line.decode("latin-1").strip().split(" ")
    if len(parts) != 3 or not parts[2].startswith("HTTP/1."):
        raise ValueError("unsupported HTTP request")
    method, target, version = parts
    headers, total = {}, 0
    for _ in range(100):
        line = stream.readline(8193)
        total += len(line)
        if not line or len(line) > 8192 or total > 16384:
            raise ValueError("invalid headers")
        if line in (b"\r\n", b"\n"):
            break
        if b":" not in line:
            raise ValueError("bad header")
        k, v = line.split(b":", 1)
        name = k.decode("ascii").lower()
        if name in headers:
            raise ValueError("duplicate headers not supported")
        headers[name] = v.decode("latin-1").strip()
    else:
        raise ValueError("too many headers")
    if "transfer-encoding" in headers:
        raise ValueError("chunked requests not supported in POC")
    length = int(headers.get("content-length", "0"))
    if length < 0 or length > max_body:
        raise ValueError("oversize request body")
    body = stream.read(length)
    if len(body) != length:
        raise ValueError("incomplete request body")
    return method, target, version, headers, body


def _http_response(status: int, body: bytes, content_type: str) -> bytes:
    reasons = {200:"OK", 201:"Created", 202:"Accepted", 204:"No Content",
               400:"Bad Request", 403:"Forbidden", 404:"Not Found", 413:"Content Too Large",
               500:"Internal Server Error", 501:"Not Implemented", 503:"Service Unavailable"}
    header = (f"HTTP/1.1 {status} {reasons.get(status, 'Response')}\r\n"
              f"Content-Type: {content_type}\r\nContent-Length: {len(body)}\r\n"
              "Connection: close\r\nCache-Control: no-store\r\n\r\n").encode("ascii")
    return header + body


class _TLSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        ctrl = self.server.controller
        client_ip = self.client_address[0]
        if not ctrl.config.allows_client(client_ip):
            ctrl.log.emit("tls_denied", source=client_ip)
            return
        self.request.settimeout(8)
        wrapped = None
        stream = None
        try:
            wrapped = ctrl.base_ssl.wrap_socket(self.request, server_side=True, do_handshake_on_connect=False)
            wrapped.do_handshake()
            hostname = getattr(wrapped, "_jitca_hostname", None)
            if hostname is None:
                raise ValueError("no selected hostname")
            stream = wrapped.makefile("rb")
            method, target, version, headers, request_body = _read_http(stream, ctrl.config.max_body_bytes)
            host_header = headers.get("host", "")
            # Host and SNI must match; no cross-vhost routing.
            if host_header.split(":")[0].lower() != hostname:
                status, body, typ = 403, b'{"error":"Host/SNI mismatch"}', "application/json"
            else:
                route_path = urlsplit(target).path
                route = next((x for x in ctrl.config.endpoints[hostname].routes
                              if x.method == method and x.path == route_path), None)
                if route is None:
                    status, body, typ = 404, b'{"error":"unimplemented endpoint"}', "application/json"
                else:
                    status, body, typ = route.status, route.body.encode("utf-8"), route.content_type
            response = _http_response(status, body, typ)
            wrapped.sendall(response)
            public_headers = {k: ("[REDACTED]" if k in (
                "authorization", "cookie", "proxy-authorization", "x-api-key", "x-auth-token") else v)
                for k, v in headers.items()}
            ctrl.log.emit("http_flow", source=client_ip, hostname=hostname,
                          method=method, path=urlsplit(target).path, status=status,
                          tls_version=wrapped.version(), cipher=wrapped.cipher()[0],
                          request_headers=public_headers, request_bytes=len(request_body),
                          request_sha256=hashlib.sha256(request_body).hexdigest(),
                          request_preview=_safe_preview(request_body),
                          response_preview=_safe_preview(body))
        except (ssl.SSLError, OSError, ValueError, UnicodeError) as exc:
            ctrl.log.emit("tls_or_http_error", source=client_ip, error=str(exc))
            if wrapped is not None:
                try:
                    wrapped.sendall(_http_response(400, b'{"error":"invalid request"}', "application/json"))
                except OSError:
                    pass
        finally:
            if stream is not None:
                stream.close()
            if wrapped is not None:
                wrapped.close()


class _TLSServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = False

    def __init__(self, address, controller):
        super().__init__(address, _TLSHandler)
        self.controller = controller


class JITCAService:
    def __init__(self, config: Config):
        self.config = config
        config.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.log = EventLog(config.state_dir / "events.jsonl")
        self._lifecycle_lock = threading.RLock()
        self._state = "new"
        self._servers = []
        self._running_servers = []
        self.threads: list[threading.Thread] = []
        try:
            self.store = CertificateStore(config)
            self.prewarmer = CertificatePrewarmer(self.store, self.log)
            self.base_ssl = _bootstrap_context(config.state_dir / "certificates")
            self.base_ssl.sni_callback = self._sni_callback
            self.dns_server = _DNSServer((config.dns_host, config.dns_port), self)
            self._servers.append(self.dns_server)
            self.tls_server = _TLSServer((config.tls_host, config.tls_port), self)
            self._servers.append(self.tls_server)
        except BaseException:
            for server in reversed(self._servers):
                server.server_close()
            self.log.close()
            raise

    @property
    def dns_address(self):
        return self.dns_server.server_address

    @property
    def tls_address(self):
        return self.tls_server.server_address

    def _sni_callback(self, ssl_obj: ssl.SSLSocket, servername: str | None, initial: ssl.SSLContext):
        if servername is None:
            self.log.emit("tls_sni_denied", reason="missing SNI")
            return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
        try:
            hostname = canonical_hostname(servername)
        except ValueError:
            return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
        if hostname not in self.config.endpoints:
            self.log.emit("tls_sni_denied", hostname=hostname, reason="not allowlisted")
            return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
        try:
            context, issued = self.store.ssl_context(hostname)
            ssl_obj.context = context
            ssl_obj._jitca_hostname = hostname
            self.log.emit("tls_certificate_selected", hostname=hostname, new=issued)
        except Exception as exc:
            self.log.emit("tls_cert_error", hostname=hostname, error=str(exc))
            return ssl.ALERT_DESCRIPTION_INTERNAL_ERROR

    def start(self):
        with self._lifecycle_lock:
            if self._state != "new":
                raise RuntimeError("service can only be started once")
            self._state = "running"
            try:
                self.prewarmer.start()
                for name, server in (("jitca-dns", self.dns_server), ("jitca-tls", self.tls_server)):
                    thread = threading.Thread(target=server.serve_forever,
                                              kwargs={"poll_interval": 0.1}, name=name, daemon=True)
                    thread.start()
                    self.threads.append(thread)
                    self._running_servers.append(server)
                self.log.emit("service_started", dns_address=self.dns_address, tls_address=self.tls_address)
            except BaseException:
                self.stop()
                raise

    def stop(self):
        with self._lifecycle_lock:
            if self._state == "stopped":
                return
            # Stop accepting first, then drain every producer before closing the log.
            for server in self._running_servers:
                server.shutdown()
            for server in self._servers:
                server.server_close()
            self.prewarmer.stop()
            for thread in self.threads:
                thread.join()
            self.log.emit("service_stopped")
            self._state = "stopped"
            self.log.close()
