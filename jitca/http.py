"""Hostname-scoped HTTP rules and optional, explicitly configured backends."""
from __future__ import annotations

from dataclasses import dataclass
import http.client
from urllib.parse import urlsplit

from .config import Config, Endpoint, Route


HOP_HEADERS = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
               "te", "trailer", "transfer-encoding", "upgrade", "proxy-connection"}


@dataclass(frozen=True)
class Response:
    status: int
    body: bytes
    headers: dict[str, str]
    extra_headers: tuple[tuple[str, str], ...] = ()


def select_route(endpoint: Endpoint, method: str, path: str) -> Route | None:
    candidates = [route for route in endpoint.routes
                  if route.method in ("*", method)
                  and (path.startswith(route.path) if route.prefix else path == route.path)]
    return max(candidates, key=lambda route: (not route.prefix, len(route.path),
                                             route.method == method), default=None)


def _end_to_end(headers: dict[str, str]) -> dict[str, str]:
    connection_tokens = {token.strip().lower()
                         for token in headers.get("connection", "").split(",")}
    return {name.lower(): value for name, value in headers.items()
            if name.lower() not in HOP_HEADERS | connection_tokens | {"content-length"}}


def respond(config: Config, route: Route | None, method: str, target: str,
            headers: dict[str, str], body: bytes) -> Response:
    if route is None:
        return Response(204, b"", {})
    if route.proxy_pass is None:
        return Response(route.status, route.body.encode("utf-8"),
                        {"content-type": route.content_type,
                         **{key.lower(): value for key, value in route.headers.items()}})
    origin = urlsplit(route.proxy_pass)
    connection_type = http.client.HTTPSConnection if origin.scheme == "https" else http.client.HTTPConnection
    connection = connection_type(origin.hostname, origin.port, timeout=config.backend_timeout_seconds)
    try:
        outgoing = _end_to_end(headers)
        outgoing["host"] = origin.netloc
        outgoing["connection"] = "close"
        # Always forward an origin-form target to the configured origin only.
        parsed = urlsplit(target)
        upstream_target = (parsed.path or "/") + ("?" + parsed.query if parsed.query else "")
        connection.request(method, upstream_target, body=body, headers=outgoing)
        response = connection.getresponse()
        payload = response.read(config.max_response_bytes + 1)
        if len(payload) > config.max_response_bytes:
            raise ValueError("backend response exceeds max_response_bytes")
        result_headers = _end_to_end({name.lower(): value for name, value in response.getheaders()})
        cookies = tuple(("set-cookie", value) for name, value in response.getheaders()
                        if name.lower() == "set-cookie")
        result_headers.pop("set-cookie", None)
        if method == "HEAD":
            length = response.getheader("content-length", "")
            if length.isdecimal():
                result_headers["content-length"] = length
        result_headers.update({key.lower(): value for key, value in route.headers.items()})
        if "set-cookie" in result_headers:
            cookies = ()
        return Response(response.status, payload, result_headers, cookies)
    finally:
        connection.close()


def encode_response(response: Response, method: str) -> bytes:
    # This server handles one response per connection, including backend responses.
    headers = _end_to_end(response.headers)
    no_body = response.status in (204, 304) or 100 <= response.status < 200
    if not no_body:
        headers["content-length"] = (response.headers.get("content-length", str(len(response.body)))
                                     if method == "HEAD" else str(len(response.body)))
    headers["connection"] = "close"
    headers.setdefault("cache-control", "no-store")
    reason = http.client.responses.get(response.status, "Response")
    head = f"HTTP/1.1 {response.status} {reason}\r\n"
    head += "".join(f"{name}: {value}\r\n" for name, value in (*headers.items(), *response.extra_headers))
    head += "\r\n"
    return head.encode("latin-1") + (b"" if method == "HEAD" or no_body else response.body)
