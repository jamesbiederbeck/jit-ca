import json

import pytest

from jitca.cli import main
from jitca.config import load_config
from jitca.observed import endpoint_stanzas, summarize
from jitca.service import JITCAService
from test_e2e import config_file, lookup, tls_request


def default_config(tmp_path, extra="", pre=""):
    path = config_file(tmp_path)
    path.write_text(path.read_text().replace(
        'redirect_ipv4 = "127.0.0.1"', 'redirect_ipv4 = "127.0.0.1"\ndns_answer_all = true') + extra)
    return path


def events(service):
    service.log.close()
    return [json.loads(line) for line in (service.config.state_dir / "events.jsonl").read_text().splitlines()]


def test_default_endpoint_serves_and_logs_unknown_hostname(tmp_path):
    path = default_config(tmp_path, '''
[default_endpoint]
max_hostnames = 5
[[default_endpoint.routes]]
method = "GET"
path_prefix = "/"
status = 200
body = '{"observed":true}'
''')
    service = JITCAService(load_config(path))
    service.start()
    try:
        ca = service.store.root_ca_path
        lookup(service.dns_address[1], "telemetry.vendor-cloud.example")
        response, _ = tls_request(service.tls_address[1], ca, hostname="telemetry.vendor-cloud.example",
                                  path="/v1/ping?id=7")
        assert b"200 OK" in response and b'{"observed":true}' in response
        # Explicit endpoints keep their own routes and are not marked as default.
        explicit, _ = tls_request(service.tls_address[1], ca)
        assert b'"connected":true' in explicit
    finally:
        service.stop()
    flows = [e for e in events(service) if e["event"] == "http_request"]
    by_host = {e["hostname"]: e for e in flows}
    assert by_host["telemetry.vendor-cloud.example"]["default_endpoint"] is True
    assert by_host["telemetry.vendor-cloud.example"]["path"] == "/v1/ping"
    assert by_host["robot.example.test"]["default_endpoint"] is False


def test_default_endpoint_without_routes_returns_204(tmp_path):
    service = JITCAService(load_config(default_config(tmp_path, "\n[default_endpoint]\n")))
    service.start()
    try:
        response, _ = tls_request(service.tls_address[1], service.store.root_ca_path,
                                  hostname="anything.example")
        assert b"204 No Content" in response
    finally:
        service.stop()


def test_default_endpoint_hostname_cap(tmp_path):
    service = JITCAService(load_config(default_config(tmp_path, "\n[default_endpoint]\nmax_hostnames = 2\n")))
    service.start()
    try:
        ca, port = service.store.root_ca_path, service.tls_address[1]
        for name in ("a.example", "b.example", "a.example"):
            assert b"204" in tls_request(port, ca, hostname=name)[0]
        with pytest.raises(Exception):
            tls_request(port, ca, hostname="c.example")
        # Explicit endpoints are never limited by the default-endpoint cap.
        assert b"200 OK" in tls_request(port, ca)[0]
        issued = {m["hostname"] for m in service.store.all_metadata()}
        assert issued == {"a.example", "b.example", "robot.example.test"}
    finally:
        service.stop()
    assert any(e.get("reason") == "default_endpoint max_hostnames reached" for e in events(service))


def test_unknown_hostname_still_denied_without_default_endpoint(tmp_path):
    service = JITCAService(load_config(config_file(tmp_path)))
    service.start()
    try:
        with pytest.raises(Exception):
            tls_request(service.tls_address[1], service.store.root_ca_path, hostname="other.example")
        assert service.store.all_metadata() == []
    finally:
        service.stop()


@pytest.mark.parametrize("extra,message", [
    ("\n[default_endpoint]\nmax_hostnames = 0\n", "max_hostnames"),
    ("\n[default_endpoint]\nhostname = \"x.example\"\n", "cannot set hostname"),
    ("\n[default_endpoint]\nissuer = \"x\"\n", "cannot set hostname or issuer"),
])
def test_default_endpoint_validation(tmp_path, extra, message):
    path = config_file(tmp_path)
    path.write_text(path.read_text() + extra)
    with pytest.raises(ValueError, match=message):
        load_config(path)


def test_default_endpoint_alone_satisfies_endpoint_requirement(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text('[network]\nredirect_ipv4 = "127.0.0.1"\n[default_endpoint]\n')
    cfg = load_config(path)
    assert cfg.endpoints == {} and cfg.endpoint_for("x.example").hostname == "x.example"


def test_observed_summary_and_promotion_stanzas(tmp_path):
    path = default_config(tmp_path, "\n[default_endpoint]\n")
    service = JITCAService(load_config(path))
    service.start()
    try:
        port, ca = service.tls_address[1], service.store.root_ca_path
        lookup(service.dns_address[1], "telemetry.vendor-cloud.example")
        for _ in range(2):
            tls_request(port, ca, hostname="telemetry.vendor-cloud.example", path="/v1/ping")
        tls_request(port, ca)
    finally:
        service.stop()
    summary = summarize(service.config.state_dir / "events.jsonl", frozenset(["robot.example.test"]))
    entry = next(e for e in summary if e["hostname"] == "telemetry.vendor-cloud.example")
    assert entry["requests"] == 2 and entry["dns_queries"] == 1 and not entry["configured"]
    assert entry["top_requests"] == ["2x GET /v1/ping"]
    stanzas = endpoint_stanzas(summary)
    assert 'hostname = "telemetry.vendor-cloud.example"' in stanzas
    assert "robot.example.test" not in stanzas


def test_observed_cli(tmp_path, capsys):
    path = default_config(tmp_path, "\n[default_endpoint]\n")
    service = JITCAService(load_config(path))
    service.start()
    try:
        tls_request(service.tls_address[1], service.store.root_ca_path, hostname="x.example")
    finally:
        service.stop()
    main(["--config", str(path), "observed", "--toml"])
    assert 'hostname = "x.example"' in capsys.readouterr().out
    main(["--config", str(path), "observed"])
    assert json.loads(capsys.readouterr().out)
