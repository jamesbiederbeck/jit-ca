from __future__ import annotations

import hashlib
import ipaddress
import json
from pathlib import Path
import queue
import socket
import socketserver
import ssl
import struct
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlsplit
from http.client import HTTPException

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from .capture import BodyCapture
from .certs import CertificateStore, _save_private, _private_pem
from .config import Config, canonical_hostname
from .events import EventLog
from .http import Response, encode_response, respond, select_route


def _issue_and_log(store: CertificateStore, log: EventLog, hostname: str, trigger: str = "prewarm") -> str:
    """Issue (or confirm) a leaf and log the outcome; returns "issued", "cached" or "error"."""
    started = time.monotonic()
    try:
        cert_path, _, issued = store.get_or_issue(hostname)
    except Exception as exc:
        log.emit("cert_prewarm_error", hostname=hostname, trigger=trigger,
                 error_type=type(exc).__name__, error=str(exc),
                 elapsed_ms=round((time.monotonic() - started) * 1000, 1))
        return "error"
    log.emit("cert_prewarmed", hostname=hostname, new=issued, trigger=trigger,
             certificate=str(cert_path.relative_to(store.config.state_dir)),
             elapsed_ms=round((time.monotonic() - started) * 1000, 1))
    return "issued" if issued else "cached"


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
                _issue_and_log(self.store, self.log, hostname)
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


class DNSNameError(ValueError):
    """A well-formed query whose name is not a valid hostname; keeps the raw name for logging."""

    def __init__(self, message: str, qname: str):
        super().__init__(message)
        self.qname = qname


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
    raw_name = ".".join(labels)
    try:
        hostname = canonical_hostname(raw_name)
    except ValueError as exc:
        raise DNSNameError(str(exc), raw_name[:253]) from exc
    return ident, flags, hostname, qtype, qclass, payload[12:question_end+4]


def _dns_response(payload: bytes, config: Config, client_ip: str = "127.0.0.1"):
    ident, flags, hostname, qtype, qclass, question = _parse_dns_question(payload)
    approved = hostname in config.endpoints
    # Unknown hostnames are REFUSED (no forwarding in POC) unless the operator opted
    # in to answering every query with the configured redirect address. Catch-all
    # answers never trigger certificate issuance: only explicit endpoints are signed.
    answerable = approved or config.dns_answer_all
    rcode = 0 if answerable else 5
    answer = b""
    if answerable and qtype == 1 and qclass == 1:
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4)
        redirect = config.redirect_ipv4
        if redirect is None:
            redirect = socket.gethostbyname(config.tls_host)
            if ipaddress.IPv4Address(redirect).is_unspecified:
                # Route lookup only: UDP connect sends no packet.
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                    probe.connect((client_ip, 9))
                    redirect = probe.getsockname()[0]
        answer += ipaddress.IPv4Address(redirect).packed
    reply_flags = 0x8000 | 0x0400 | (flags & 0x0100) | rcode
    header = struct.pack("!HHHHHH", ident, reply_flags, 1, int(bool(answer)), 0, 0)
    return header + question + answer, hostname, approved, qtype, bool(answer)


def _forward_dns(payload: bytes, forward) -> bytes:
    """Relay one query to the configured upstream resolver; raises OSError/ValueError on failure."""
    family = socket.AF_INET6 if ":" in forward.upstream else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as upstream:
        upstream.settimeout(forward.timeout_seconds)
        upstream.connect((forward.upstream, forward.port))  # connected UDP drops other sources
        upstream.send(payload)
        reply = upstream.recv(65535)
    if len(reply) < 12 or reply[:2] != payload[:2] or not reply[2] & 0x80:
        raise ValueError("invalid upstream DNS reply")
    return reply


DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS"}


def _dns_name_at(message: bytes, position: int) -> tuple[str, int]:
    """Decode a (possibly compressed) name; return (name, offset just past it in the record)."""
    labels, end, jumps = [], None, 0
    while True:
        if position >= len(message):
            raise ValueError("truncated DNS name")
        size = message[position]
        if size & 0xC0 == 0xC0:
            if position + 1 >= len(message):
                raise ValueError("truncated DNS compression")
            if end is None:
                end = position + 2
            position = ((size & 0x3F) << 8) | message[position + 1]
            jumps += 1
            if jumps > 32:
                raise ValueError("DNS compression loop")
            continue
        if size & 0xC0:
            raise ValueError("bad DNS label")
        position += 1
        if size == 0:
            return ".".join(labels), position if end is None else end
        labels.append(message[position:position + size].decode("ascii", "replace"))
        position += size


def _parse_dns_answers(message: bytes, limit: int = 50) -> list[dict]:
    """Answer-section records of a DNS reply as JSON-friendly dicts; ValueError if malformed."""
    if len(message) < 12:
        raise ValueError("short DNS reply")
    qdcount, ancount = struct.unpack("!HH", message[4:8])
    position = 12
    for _ in range(qdcount):
        _, position = _dns_name_at(message, position)
        position += 4
    records = []
    for _ in range(min(ancount, limit)):
        name, position = _dns_name_at(message, position)
        if position + 10 > len(message):
            raise ValueError("truncated DNS record")
        rtype, _rclass, ttl, length = struct.unpack("!HHIH", message[position:position + 10])
        position += 10
        rdata = message[position:position + length]
        if len(rdata) != length:
            raise ValueError("truncated DNS rdata")
        if rtype == 1 and length == 4:
            data = str(ipaddress.IPv4Address(rdata))
        elif rtype == 28 and length == 16:
            data = str(ipaddress.IPv6Address(rdata))
        elif rtype in (2, 5, 12):
            data = _dns_name_at(message, position)[0]
        elif rtype == 15 and length >= 3:
            data = f"{struct.unpack('!H', rdata[:2])[0]} {_dns_name_at(message, position + 2)[0]}"
        else:
            data = rdata[:64].hex()
        records.append({"name": name, "type": DNS_TYPES.get(rtype, rtype), "ttl": ttl, "data": data})
        position += length
    return records


def _servfail(payload: bytes) -> bytes:
    ident, flags, _hostname, _qtype, _qclass, question = _parse_dns_question(payload)
    return struct.pack("!HHHHHH", ident, 0x8000 | 0x0080 | (flags & 0x0100) | 2, 1, 0, 0, 0) + question


DNS_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


class _DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        controller = self.server.controller
        source = self.client_address[0]
        started = time.monotonic()
        if not controller.config.allows_client(source):
            controller.log.emit("dns_denied", source=source, bytes=len(data))
            return
        forward = controller.config.dns_forward
        if forward is not None:
            try:
                _, _, fwd_name, fwd_qtype, _, _ = _parse_dns_question(data)
            except (ValueError, UnicodeDecodeError):
                fwd_name = None
            if fwd_name in forward.hostnames:
                self._forward(data, sock, forward, source, fwd_name, fwd_qtype, started)
                return
        try:
            response, hostname, approved, qtype, answered = _dns_response(
                data, controller.config, source)
        except (ValueError, UnicodeDecodeError, OSError) as exc:
            controller.log.emit("dns_invalid", source=source, bytes=len(data),
                                qname=getattr(exc, "qname", None), error=str(exc))
            return
        cert = None
        if approved and answered:
            # Hold the reply until the leaf certificate is actually ready, so the
            # client's TLS handshake never hits a signing cache-miss.
            cert = _issue_and_log(controller.store, controller.log, hostname, trigger="dns")
        rcode = response[3] & 0x0F
        # What jit-ca did with the query. `intercepted` only means "explicit endpoint" and is kept
        # for compatibility; `action` is the field to read.
        if answered:
            action = "endpoint" if approved else "catch_all"
        else:
            action = "nodata" if rcode == 0 else "refused"
        controller.log.emit("dns_query", source=source, hostname=hostname, qtype=qtype,
                            action=action, intercepted=approved, catch_all=answered and not approved,
                            rcode=DNS_RCODES.get(rcode, rcode),
                            answer=socket.inet_ntoa(response[-4:]) if answered else None,
                            cert=cert, elapsed_ms=round((time.monotonic() - started) * 1000, 1))
        if approved and not answered:
            controller.prewarmer.request(hostname)
        try:
            sock.sendto(response, self.client_address)
        except OSError as exc:
            controller.log.emit("dns_reply_error", source=source, hostname=hostname, error=str(exc))


    def _forward(self, data, sock, forward, source, hostname, qtype, started):
        controller = self.server.controller
        try:
            response, action, error = _forward_dns(data, forward), "forward", None
        except (OSError, ValueError) as exc:
            response, action, error = _servfail(data), "forward_failed", str(exc) or type(exc).__name__
        rcode = response[3] & 0x0F
        answers = answers_error = None
        if action == "forward":
            try:
                answers = _parse_dns_answers(response)
            except (ValueError, UnicodeError, struct.error) as exc:
                answers_error = str(exc)  # the reply is still relayed untouched
        controller.log.emit("dns_query", source=source, hostname=hostname, qtype=qtype,
                            action=action, intercepted=False, catch_all=False,
                            rcode=DNS_RCODES.get(rcode, rcode), answers=answers,
                            answers_error=answers_error, reply_bytes=len(response),
                            truncated=bool(response[2] & 0x02),
                            upstream=f"{forward.upstream}:{forward.port}", error=error,
                            elapsed_ms=round((time.monotonic() - started) * 1000, 1))
        try:
            sock.sendto(response, self.client_address)
        except OSError as exc:
            controller.log.emit("dns_reply_error", source=source, hostname=hostname, error=str(exc))


NTP_UNIX_OFFSET = 2208988800  # seconds between 1900-01-01 and 1970-01-01


def _ntp_timestamp(unix_time: float) -> bytes:
    seconds = int(unix_time)
    fraction = int((unix_time - seconds) * (1 << 32))
    return struct.pack("!II", (seconds + NTP_UNIX_OFFSET) & 0xFFFFFFFF, fraction)


def _ntp_response(request: bytes, stratum: int, received: float, transmitted: float) -> bytes:
    """Build an SNTP server reply for a client (mode 3) request; ValueError if not one."""
    if len(request) < 48:
        raise ValueError("short NTP packet")
    version, mode = (request[0] >> 3) & 7, request[0] & 7
    if mode != 3 or not 1 <= version <= 4:
        raise ValueError(f"unsupported NTP mode {mode} version {version}")
    refid = b"LOCL" if stratum == 1 else b"\0\0\0\0"
    return (struct.pack("!BBBb", (version << 3) | 4, stratum, request[2], -20)
            + struct.pack("!II", 0, 0x00010000) + refid
            + _ntp_timestamp(received)       # reference: this host's clock, treated as in sync
            + request[40:48]                 # originate: the client's transmit timestamp
            + _ntp_timestamp(received) + _ntp_timestamp(transmitted))


class _NTPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        received = time.time()
        data, sock = self.request
        controller = self.server.controller
        source = self.client_address[0]
        if not controller.config.allows_client(source):
            controller.log.emit("ntp_denied", source=source, bytes=len(data))
            return
        try:
            reply = _ntp_response(data, controller.config.ntp.stratum, received, time.time())
        except ValueError as exc:
            controller.log.emit("ntp_invalid", source=source, bytes=len(data), error=str(exc))
            return
        controller.log.emit("ntp_query", source=source, version=(data[0] >> 3) & 7,
                            stratum=controller.config.ntp.stratum,
                            time=datetime.fromtimestamp(received, timezone.utc).isoformat())
        try:
            sock.sendto(reply, self.client_address)
        except OSError as exc:
            controller.log.emit("ntp_reply_error", source=source, error=str(exc))


class _NTPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = False

    def __init__(self, address, controller):
        super().__init__(address, _NTPHandler)
        self.controller = controller

    def server_close(self):
        self._threads.join()
        super().server_close()


class _DNSServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = False  # server_close waits for handlers before their dependencies close.

    def __init__(self, address, controller):
        super().__init__(address, _DNSHandler)
        self.controller = controller

    def server_close(self):
        # A handler may still be blocked signing a certificate and will send its
        # reply on this same shared UDP socket; join it before the socket closes
        # instead of ThreadingMixIn's default close-then-join order, which would
        # otherwise race an in-flight reply against socket teardown.
        self._threads.join()
        super().server_close()


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


def _redact(value):
    if isinstance(value, dict):
        return {k: "[REDACTED]" if any(p in k.lower() for p in (
            "pass", "secret", "token", "auth", "cookie", "credential", "apikey", "api_key"))
            else _redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(v) for v in value[:50]]
    return value


def _log_value(value, redact: bool):
    return _redact(value) if redact else value


def _safe_preview(body: bytes, redact: bool = True):
    if not body:
        return ""
    try:
        payload = json.loads(body)
        return json.dumps(_log_value(payload, redact), ensure_ascii=False)[:4096]
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
    if not target.startswith("/") or target.startswith("//") or "#" in target:
        raise ValueError("request target must be an origin-form path")
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


def classify_handshake_error(exc: BaseException) -> tuple[str, str | None]:
    """Return (category, OpenSSL reason) for a failed server-side TLS handshake."""
    reason = getattr(exc, "reason", None)
    text = str(exc).lower()
    if isinstance(exc, TimeoutError) or "timed out" in text:
        return "timeout", reason
    if isinstance(exc, (ssl.SSLEOFError, ConnectionError)) or "eof occurred" in text:
        return "connection_closed", reason
    if reason == "CALLBACK_FAILED":
        return "sni_rejected", reason  # our SNI callback refused the name (see tls_sni_denied)
    if reason and "ALERT" in reason:
        return "client_alert", reason  # the client aborted, e.g. TLSV1_ALERT_UNKNOWN_CA
    if reason and any(word in reason for word in ("PROTOCOL", "VERSION", "CIPHER", "HTTP", "CURVE", "SIGNATURE")):
        return "protocol_mismatch", reason
    return "other", reason


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
            started = time.monotonic()
            try:
                wrapped.do_handshake()
            except OSError as exc:  # includes ssl.SSLError and timeouts
                category, reason = classify_handshake_error(exc)
                ctrl.log.emit("tls_handshake_failed", source=client_ip,
                              sni=getattr(wrapped, "_jitca_sni", None), category=category,
                              reason=reason, error_type=type(exc).__name__, error=str(exc),
                              elapsed_ms=round((time.monotonic() - started) * 1000, 1))
                return
            hostname = getattr(wrapped, "_jitca_hostname", None)
            if hostname is None:
                raise ValueError("no selected hostname")
            stream = wrapped.makefile("rb")
            method, target, version, headers, request_body = _read_http(stream, ctrl.config.max_body_bytes)
            parsed = urlsplit(target)
            parameters = _log_value(parse_qs(parsed.query, keep_blank_values=True, max_num_fields=1000), ctrl.config.log_redact)
            public_headers = _log_value(headers, ctrl.config.log_redact)
            request_details = dict(source=client_ip, hostname=hostname, method=method,
                                   default_endpoint=hostname not in ctrl.config.endpoints,
                                   path=parsed.path, query_parameters=parameters,
                                   request_headers=public_headers, request_bytes=len(request_body),
                                   request_sha256=hashlib.sha256(request_body).hexdigest(),
                                   request_preview=_safe_preview(request_body, ctrl.config.log_redact))
            if ctrl.capture is not None:
                saved = ctrl.capture.save(ctrl.log, "request", hostname, request_body)
                if saved:
                    request_details["request_capture"] = saved
            ctrl.log.emit("http_request", **request_details)
            host_header = headers.get("host", "")
            # Host and SNI must match; no cross-vhost routing.
            if canonical_hostname(host_header.split(":")[0]) != hostname:
                result = Response(403, b'{"error":"Host/SNI mismatch"}', {"content-type": "application/json"})
            else:
                route = select_route(ctrl.config.endpoint_for(hostname), method, parsed.path)
                try:
                    result = respond(ctrl.config, route, method, target, headers, request_body)
                except (HTTPException, OSError, ValueError) as exc:
                    ctrl.log.emit("backend_error", hostname=hostname, path=parsed.path, error=str(exc))
                    result = Response(502, b'{"error":"backend unavailable"}', {"content-type": "application/json"})
            wrapped.sendall(encode_response(result, method))
            response_details = {}
            if ctrl.capture is not None:
                saved = ctrl.capture.save(ctrl.log, "response", hostname, result.body)
                if saved:
                    response_details["response_capture"] = saved
            ctrl.log.emit("http_flow", **request_details, **response_details, status=result.status,
                          tls_version=wrapped.version(), cipher=wrapped.cipher()[0],
                          response_preview=_safe_preview(result.body, ctrl.config.log_redact))
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


class _PlainHTTPHandler(socketserver.BaseRequestHandler):
    """Cleartext HTTP/1.1 capture point: same routes, logging and body capture as TLS, no SNI.

    The virtual host comes from the Host header. Names without an endpoint (and no default
    endpoint) are still logged and captured but only get an empty 204.
    """

    def handle(self):
        ctrl = self.server.controller
        client_ip = self.client_address[0]
        if not ctrl.config.allows_client(client_ip):
            ctrl.log.emit("http_plain_denied", source=client_ip)
            return
        self.request.settimeout(8)
        stream = None
        try:
            stream = self.request.makefile("rb")
            method, target, version, headers, request_body = _read_http(stream, ctrl.config.max_body_bytes)
            host_header = headers.get("host", "")
            try:
                hostname = canonical_hostname(host_header.rsplit(":", 1)[0] if not host_header.startswith("[")
                                              else host_header)
            except ValueError:
                hostname = None  # missing Host, IP literal or invalid name: observe only
            endpoint = ctrl.config.endpoint_for(hostname) if hostname else None
            parsed = urlsplit(target)
            request_details = dict(scheme="http", source=client_ip, hostname=hostname,
                                   host_header=host_header[:255], method=method,
                                   default_endpoint=bool(hostname) and hostname not in ctrl.config.endpoints,
                                   path=parsed.path,
                                   query_parameters=_log_value(parse_qs(parsed.query, keep_blank_values=True,
                                                                      max_num_fields=1000), ctrl.config.log_redact),
                                   request_headers=_log_value(headers, ctrl.config.log_redact), request_bytes=len(request_body),
                                   request_sha256=hashlib.sha256(request_body).hexdigest(),
                                   request_preview=_safe_preview(request_body, ctrl.config.log_redact))
            label = hostname or "unknown-host"
            if ctrl.capture is not None:
                saved = ctrl.capture.save(ctrl.log, "request", label, request_body)
                if saved:
                    request_details["request_capture"] = saved
            ctrl.log.emit("http_request", **request_details)
            route = select_route(endpoint, method, parsed.path) if endpoint else None
            try:
                result = respond(ctrl.config, route, method, target, headers, request_body)
            except (HTTPException, OSError, ValueError) as exc:
                ctrl.log.emit("backend_error", hostname=hostname, path=parsed.path, error=str(exc))
                result = Response(502, b'{"error":"backend unavailable"}', {"content-type": "application/json"})
            self.request.sendall(encode_response(result, method))
            response_details = {}
            if ctrl.capture is not None:
                saved = ctrl.capture.save(ctrl.log, "response", label, result.body)
                if saved:
                    response_details["response_capture"] = saved
            ctrl.log.emit("http_flow", **request_details, **response_details, status=result.status,
                          response_preview=_safe_preview(result.body, ctrl.config.log_redact))
        except (OSError, ValueError, UnicodeError) as exc:
            ctrl.log.emit("http_plain_error", source=client_ip, error=str(exc))
            try:
                self.request.sendall(_http_response(400, b'{"error":"invalid request"}', "application/json"))
            except OSError:
                pass
        finally:
            if stream is not None:
                stream.close()


class _PlainHTTPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = False

    def __init__(self, address, controller):
        super().__init__(address, _PlainHTTPHandler)
        self.controller = controller


class JITCAService:
    def __init__(self, config: Config):
        self.config = config
        config.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.log = EventLog(config.state_dir / "events.jsonl", **({"echo": sys.stdout} if config.log_stdout else {}))
        self._lifecycle_lock = threading.RLock()
        self._default_lock = threading.Lock()
        self._default_hosts: set[str] = set()
        self._state = "new"
        self._servers = []
        self._running_servers = []
        self.threads: list[threading.Thread] = []
        try:
            self.store = CertificateStore(config)
            self.capture = (BodyCapture(config.state_dir / "captures", config.capture, _redact)
                            if config.capture else None)
            self.prewarmer = CertificatePrewarmer(self.store, self.log)
            self.base_ssl = _bootstrap_context(config.state_dir / "certificates")
            self.base_ssl.sni_callback = self._sni_callback
            self.dns_server = _DNSServer((config.dns_host, config.dns_port), self)
            self._servers.append(self.dns_server)
            self.tls_server = _TLSServer((config.tls_host, config.tls_port), self)
            self._servers.append(self.tls_server)
            self.http_server = None
            if config.plain_http is not None:
                self.http_server = _PlainHTTPServer(
                    (config.plain_http.host or config.tls_host, config.plain_http.port), self)
                self._servers.append(self.http_server)
            self.ntp_server = None
            if config.ntp is not None:
                self.ntp_server = _NTPServer((config.ntp.host or config.dns_host, config.ntp.port), self)
                self._servers.append(self.ntp_server)
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

    @property
    def http_address(self):
        return self.http_server.server_address if self.http_server else None

    @property
    def ntp_address(self):
        return self.ntp_server.server_address if self.ntp_server else None

    def _sni_callback(self, ssl_obj: ssl.SSLSocket, servername: str | None, initial: ssl.SSLContext):
        if servername:
            ssl_obj._jitca_sni = servername[:253]  # for tls_handshake_failed, even if the name is rejected
        if servername is None:
            self.log.emit("tls_sni_denied", reason="missing SNI")
            return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
        try:
            hostname = canonical_hostname(servername)
        except ValueError:
            return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
        if hostname not in self.config.endpoints:
            if self.config.default_endpoint is None:
                self.log.emit("tls_sni_denied", hostname=hostname, reason="not allowlisted")
                return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
            if not self._claim_default_hostname(hostname):
                self.log.emit("tls_sni_denied", hostname=hostname,
                              reason="default_endpoint max_hostnames reached")
                return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
        started = time.monotonic()
        try:
            context, issued = self.store.ssl_context(hostname)
            ssl_obj.context = context
            ssl_obj._jitca_hostname = hostname
            self.log.emit("tls_certificate_selected", hostname=hostname, new=issued,
                          elapsed_ms=round((time.monotonic() - started) * 1000, 1))
        except Exception as exc:
            self.log.emit("tls_cert_error", hostname=hostname, error_type=type(exc).__name__,
                          error=str(exc), elapsed_ms=round((time.monotonic() - started) * 1000, 1))
            return ssl.ALERT_DESCRIPTION_INTERNAL_ERROR

    def _log_issuers(self) -> None:
        """Record which CAs are loaded and warn about any that expire soon."""
        now = datetime.now(timezone.utc)
        issuers = {label: {"subject": issuer.subject, "not_after": issuer.not_after.isoformat()}
                   for label, issuer in self.store.issuers.items()}
        self.log.emit("cert_issuers", mode=self.config.issuer_mode,
                      default_issuer=self.config.default_issuer, issuers=issuers)
        for label, issuer in self.store.issuers.items():
            days_left = (issuer.not_after - now).days
            if days_left < 30:
                self.log.emit("cert_issuer_expiring", issuer=label, subject=issuer.subject,
                              not_after=issuer.not_after.isoformat(), days_left=days_left)

    def _claim_default_hostname(self, hostname: str) -> bool:
        """Bound how many distinct non-endpoint names may get on-demand certificates."""
        with self._default_lock:
            if hostname in self._default_hosts:
                return True
            if len(self._default_hosts) >= self.config.default_max_hostnames:
                return False
            self._default_hosts.add(hostname)
            return True

    def start(self):
        with self._lifecycle_lock:
            if self._state != "new":
                raise RuntimeError("service can only be started once")
            self._state = "running"
            try:
                self.prewarmer.start()
                named = [("jitca-dns", self.dns_server), ("jitca-tls", self.tls_server)]
                if self.http_server is not None:
                    named.append(("jitca-http", self.http_server))
                if self.ntp_server is not None:
                    named.append(("jitca-ntp", self.ntp_server))
                for name, server in named:
                    thread = threading.Thread(target=server.serve_forever,
                                              kwargs={"poll_interval": 0.1}, name=name, daemon=True)
                    thread.start()
                    self.threads.append(thread)
                    self._running_servers.append(server)
                self._log_issuers()
                self.log.emit("service_started", dns_address=self.dns_address,
                              tls_address=self.tls_address, ntp_address=self.ntp_address,
                              http_address=self.http_address)
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
