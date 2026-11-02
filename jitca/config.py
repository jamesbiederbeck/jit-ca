from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import ipaddress
import re
import tomllib
from urllib.parse import urlsplit


def canonical_hostname(raw: str) -> str:
    name = raw.lower()
    if name.endswith("."):
        name = name[:-1]
    try:
        name = name.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("invalid hostname") from exc
    if not name or len(name) > 253:
        raise ValueError("invalid hostname")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
           for label in name.split(".")):
        raise ValueError("invalid hostname")
    try:
        ipaddress.ip_address(name)
    except ValueError:
        pass
    else:
        raise ValueError("endpoint must be a DNS hostname, not an IP address")
    return name


@dataclass(frozen=True)
class Route:
    method: str
    path: str
    status: int
    body: str
    content_type: str
    prefix: bool = False
    proxy_pass: str | None = None
    headers: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Endpoint:
    hostname: str
    routes: tuple[Route, ...]
    issuer: str | None = None


@dataclass(frozen=True)
class Config:
    path: Path
    state_dir: Path
    dns_host: str
    dns_port: int
    tls_host: str
    tls_port: int
    redirect_ipv4: str | None
    allowed_client_networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    endpoints: dict[str, Endpoint]
    issuer_mode: str
    issuer_cert: Path | None
    issuer_key: Path | None
    chain_files: tuple[Path, ...]
    ca_dir: Path | None
    default_issuer: str | None
    leaf_days: int
    leaf_key: str
    max_body_bytes: int
    backend_timeout_seconds: float = 5
    max_response_bytes: int = 1048576

    def allows_client(self, ip: str) -> bool:
        address = ipaddress.ip_address(ip)
        return any(address in network for network in self.allowed_client_networks)


def load_config(filename: str | Path) -> Config:
    path = Path(filename).resolve()
    with path.open("rb") as handle:
        raw = tomllib.load(handle)
    net = raw.get("network", {})
    cert = raw.get("certificates", {})
    tls = raw.get("http", {})
    endpoints = {}
    for item in raw.get("endpoints", []):
        hostname = canonical_hostname(item["hostname"])
        if hostname in endpoints:
            raise ValueError(f"duplicate endpoint: {hostname}")
        routes = []
        for record in item.get("routes", []):
            method = record.get("method", "*").upper()
            if method != "*" and not re.fullmatch(r"[A-Z]+", method):
                raise ValueError("invalid route method")
            if ("path" in record) == ("path_prefix" in record):
                raise ValueError("route needs exactly one of path or path_prefix")
            prefix = "path_prefix" in record
            route_path = record["path_prefix" if prefix else "path"]
            if not route_path.startswith("/"):
                raise ValueError("route path must start with /")
            status = int(record.get("status", 200))
            if not 200 <= status <= 599:
                raise ValueError("route status must be a final HTTP status (200..599)")
            backend = record.get("proxy_pass")
            if backend:
                parsed = urlsplit(backend)
                if (parsed.scheme not in ("http", "https") or not parsed.hostname
                        or parsed.username is not None or parsed.password is not None
                        or parsed.path not in ("", "/") or parsed.query or parsed.fragment):
                    raise ValueError("proxy_pass must be an http(s) origin without credentials or path")
                if parsed.port == 0:
                    raise ValueError("invalid backend port")
                if any(key in record for key in ("body", "status", "content_type")):
                    raise ValueError("proxy_pass cannot be combined with a static response")
            headers = record.get("headers", {})
            for name, value in headers.items():
                if (not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name)
                        or not isinstance(value, str) or any(ord(c) < 32 or ord(c) > 126 for c in value)
                        or name.lower() in ("connection", "content-length", "transfer-encoding", "trailer", "upgrade")):
                    raise ValueError("invalid response header")
            content_type = record.get("content_type", "application/json")
            if any(ord(c) < 32 or ord(c) > 126 for c in content_type):
                raise ValueError("invalid content_type")
            if any(r.path == route_path and r.prefix == prefix and r.method == method for r in routes):
                raise ValueError("duplicate route")
            routes.append(Route(method, route_path, status, str(record.get("body", "")),
                                content_type, prefix, backend, headers))
        issuer_selector = item.get("issuer")
        endpoints[hostname] = Endpoint(hostname, tuple(routes), issuer_selector)
    if not endpoints:
        raise ValueError("configure at least one explicit endpoint")

    mode = cert.get("mode", "local")
    if mode not in ("local", "external", "directory"):
        raise ValueError("certificates.mode must be local, external, or directory")

    def file_ref(key: str) -> Path | None:
        val = cert.get(key)
        return (path.parent / val).resolve() if val else None

    def chain_ref(item: str) -> Path:
        return (path.parent / item).resolve()

    allowed = tuple(ipaddress.ip_network(x, strict=False)
                    for x in net.get("allowed_clients", ["127.0.0.1/32", "::1/128"]))
    redirect = net.get("redirect_ipv4")
    if redirect is not None:
        if ipaddress.IPv4Address(redirect).is_unspecified:
            raise ValueError("redirect_ipv4 must be a concrete IPv4 address")
    state = (path.parent / cert.get("state_dir", "./state")).resolve()
    leaf_days = int(cert.get("leaf_days", 30))
    if not 1 <= leaf_days <= 197:
        raise ValueError("leaf_days must be between 1 and 197")
    leaf_key = cert.get("leaf_key", "rsa2048")
    if leaf_key not in ("rsa2048", "p256"):
        raise ValueError("leaf_key must be rsa2048 or p256")
    if mode == "external" and not (file_ref("issuer_cert") and file_ref("issuer_key")):
        raise ValueError("external issuer needs issuer_cert and issuer_key")
    ca_dir_value = cert.get("ca_dir")
    ca_dir = (path.parent / ca_dir_value).resolve() if ca_dir_value else None
    default_issuer = cert.get("default_issuer")
    if mode == "directory":
        if not ca_dir:
            raise ValueError("directory issuer mode needs certificates.ca_dir")
        for hostname, endpoint in endpoints.items():
            if not endpoint.issuer and not default_issuer:
                raise ValueError(f"endpoint {hostname} has no issuer selector and "
                                 "certificates.default_issuer is not set")
    elif any(endpoint.issuer for endpoint in endpoints.values()):
        raise ValueError("per-endpoint issuer selectors require certificates.mode = \"directory\"")
    max_body = int(tls.get("max_body_bytes", 65536))
    if not 0 <= max_body <= 1048576:
        raise ValueError("max_body_bytes out of range")
    backend_timeout = float(tls.get("backend_timeout_seconds", 5))
    response_limit = int(tls.get("max_response_bytes", 1048576))
    if not 0 < backend_timeout <= 60 or not 0 <= response_limit <= 16777216:
        raise ValueError("invalid backend timeout or response size limit")
    return Config(path, state, net.get("dns_host", "127.0.0.1"),
                  int(net.get("dns_port", 15353)), net.get("tls_host", "127.0.0.1"),
                  int(net.get("tls_port", 18443)), redirect, allowed, endpoints,
                  mode, file_ref("issuer_cert"), file_ref("issuer_key"),
                  tuple(chain_ref(x) for x in cert.get("chain_files", [])),
                  ca_dir, default_issuer,
                  leaf_days, leaf_key, max_body, backend_timeout, response_limit)
