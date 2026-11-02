from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import socket
import ssl
import threading

import pytest

from jitca.config import load_config
from jitca.service import JITCAService
from test_e2e import config_file, tls_request


@contextmanager
def running(tmp_path, extra="", http_options=""):
    path = config_file(tmp_path)
    path.write_text(path.read_text() + extra + ("\n[http]\n" + http_options if http_options else ""))
    service = JITCAService(load_config(path))
    service.start()
    try:
        yield service
    finally:
        service.stop()


def request(service, method="GET", path="/unknown", extra_headers=""):
    context = ssl.create_default_context(cafile=str(service.store.root_ca_path))
    with socket.create_connection(service.tls_address, timeout=3) as raw:
        with context.wrap_socket(raw, server_hostname="robot.example.test") as tls:
            tls.sendall((f"{method} {path} HTTP/1.1\r\nHost: robot.example.test\r\n"
                         f"Connection: keep-alive, x-hop\r\nX-Hop: private\r\n{extra_headers}\r\n").encode())
            chunks = []
            while chunk := tls.recv(8192):
                chunks.append(chunk)
            return b"".join(chunks)


@pytest.fixture
def backend():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            payload = json.dumps({"path": self.path, "method": self.command,
                                  "headers": dict(self.headers),
                                  "body": self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Set-Cookie", "first=1")
            self.send_header("Set-Cookie", "second=2")
            self.send_header("Connection", "x-private")
            self.send_header("X-Private", "must not pass")
            self.end_headers()
            self.wfile.write(payload)

        do_POST = do_GET

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_default_logs_redacted_parameters_returns_204_and_closes(tmp_path):
    with running(tmp_path) as service:
        response = request(service, path="/unknown?mode=idle&mode=quiet&token=do-not-log-this-query-secret",
                           extra_headers="Authorization: Bearer do-not-log-this-header-secret\r\n")
        assert response.startswith(b"HTTP/1.1 204 No Content\r\n")
        assert b"connection: close\r\n" in response.lower()
        assert response.split(b"\r\n\r\n", 1)[1] == b""
    records = [json.loads(line) for line in service.log.path.read_text().splitlines()]
    observation = next(record for record in records if record["event"] == "http_request")
    assert observation["query_parameters"] == {"mode": ["idle", "quiet"], "token": "[REDACTED]"}
    assert observation["request_headers"]["authorization"] == "[REDACTED]"
    assert "do-not-log-this" not in service.log.path.read_text()


def test_exact_prefix_method_and_hostname_rules(tmp_path):
    rules = '''
[[endpoints.routes]]
path_prefix = "/"
body = 'root'
[[endpoints.routes]]
path_prefix = "/api/"
body = 'api'
[[endpoints.routes]]
path = "/api/item"
body = 'item'
headers = { X-Fixture = "yes" }
[[endpoints.routes]]
path = "/api/item"
method = "POST"
status = 201
body = 'created'
[[endpoints]]
hostname = "other.example.test"
[[endpoints.routes]]
path = "/api/item"
body = 'other host'
'''
    with running(tmp_path, rules) as service:
        assert request(service, path="/elsewhere").endswith(b"root")
        assert request(service, path="/api/elsewhere").endswith(b"api")
        exact = request(service, path="/api/item?q=1")
        assert exact.endswith(b"item") and b"x-fixture: yes" in exact.lower()
        created = request(service, method="POST", path="/api/item")
        assert b"201 Created" in created and created.endswith(b"created")
        head = request(service, method="HEAD", path="/api/item")
        assert head.endswith(b"\r\n\r\n") and b"content-length: 4" in head.lower()
        other, _ = tls_request(service.tls_address[1], service.store.root_ca_path,
                               hostname="other.example.test", path="/api/item")
        assert other.endswith(b"other host")


def test_proxy_pass_forwards_original_path_body_and_end_to_end_headers(tmp_path, backend):
    rules = f'''\n[[endpoints.routes]]\npath_prefix = "/api/"\nproxy_pass = "{backend}"\nheaders = {{ X-Gateway = "jitca" }}\n'''
    with running(tmp_path, rules) as service:
        response = request(service, method="POST", path="/api/echo?x=1&x=2",
                           extra_headers="Content-Length: 7\r\nContent-Type: text/plain\r\n\r\npayload")
        head, body = response.split(b"\r\n\r\n", 1)
        payload = json.loads(body)
        assert payload["path"] == "/api/echo?x=1&x=2"
        assert payload["method"] == "POST" and payload["body"] == "payload"
        assert payload["headers"]["host"] == backend.removeprefix("http://")
        assert "x-hop" not in payload["headers"]
        assert head.lower().count(b"set-cookie:") == 2
        assert b"x-private:" not in head.lower()
        assert b"x-gateway: jitca" in head.lower()
        assert b"connection: close" in head.lower()


def test_backend_response_size_limit_returns_502(tmp_path, backend):
    rules = f'''\n[[endpoints.routes]]\npath_prefix = "/api/"\nproxy_pass = "{backend}"\n'''
    with running(tmp_path, rules, "max_response_bytes = 4") as service:
        assert b"502 Bad Gateway" in request(service, path="/api/too-large")


def test_backend_connection_failure_returns_502(tmp_path):
    with socket.socket() as unavailable:
        unavailable.bind(("127.0.0.1", 0))
        origin = f"http://127.0.0.1:{unavailable.getsockname()[1]}"
        rules = f'''\n[[endpoints.routes]]\npath_prefix = "/api/"\nproxy_pass = "{origin}"\n'''
        with running(tmp_path, rules) as service:
            assert b"502 Bad Gateway" in request(service, path="/api/fail")


@pytest.mark.parametrize("rule", [
    'path = "/"\npath_prefix = "/"',
    'path = "/"\nproxy_pass = "http://user:password@localhost"',
    'path = "/"\nproxy_pass = "http://localhost/api"',
    'path = "/"\nproxy_pass = "http://localhost"\nbody = "ambiguous"',
    'path = "/"\nheaders = { Connection = "keep-alive" }',
    'path = "/"\ncontent_type = "text/plain\\r\\nInjected: yes"',
])
def test_invalid_route_directives_rejected(tmp_path, rule):
    path = config_file(tmp_path)
    path.write_text(path.read_text() + "\n[[endpoints.routes]]\n" + rule + "\n")
    with pytest.raises(ValueError):
        load_config(path)
