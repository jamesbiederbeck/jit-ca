from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import ipaddress
import re
import tomllib


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


@dataclass(frozen=True)
class Endpoint:
    hostname: str
    routes: tuple[Route, ...]


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
    leaf_days: int
    leaf_key: str
    max_body_bytes: int

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
            method = record.get("method", "GET").upper()
            route_path = record["path"]
            if not route_path.startswith("/"):
                raise ValueError("route path must start with /")
            status = int(record.get("status", 200))
            if not 100 <= status <= 599:
                raise ValueError("invalid status")
            routes.append(Route(method, route_path, status, str(record.get("body", "")),
                                record.get("content_type", "application/json")))
        endpoints[hostname] = Endpoint(hostname, tuple(routes))
    if not endpoints:
        raise ValueError("configure at least one explicit endpoint")

    mode = cert.get("mode", "local")
    if mode not in ("local", "external"):
        raise ValueError("certificates.mode must be local or external")

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
    max_body = int(tls.get("max_body_bytes", 65536))
    if not 0 <= max_body <= 1048576:
        raise ValueError("max_body_bytes out of range")
    return Config(path, state, net.get("dns_host", "127.0.0.1"),
                  int(net.get("dns_port", 15353)), net.get("tls_host", "127.0.0.1"),
                  int(net.get("tls_port", 18443)), redirect, allowed, endpoints,
                  mode, file_ref("issuer_cert"), file_ref("issuer_key"),
                  tuple(chain_ref(x) for x in cert.get("chain_files", [])),
                  leaf_days, leaf_key, max_body)
