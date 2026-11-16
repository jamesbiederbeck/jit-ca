from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import socket
import ssl
import time

import pytest

from jitca.config import load_config
from jitca.service import JITCAService
from test_e2e import config_file, dns_query, lookup, tls_request


def run_service(tmp_path, action, edit=lambda text: text, prepare=lambda service: None):
    path = config_file(tmp_path)
    path.write_text(edit(path.read_text()))
    service = JITCAService(load_config(path))
    prepare(service)
    service.start()
    try:
        action(service)
    finally:
        service.stop()
    return [json.loads(line) for line in (service.config.state_dir / "events.jsonl").read_text().splitlines()]


def of(events, kind, **match):
    return [e for e in events if e["event"] == kind and all(e.get(k) == v for k, v in match.items())]


def test_dns_query_event_records_answer_rcode_cert_outcome_and_latency(tmp_path):
    def action(service):
        port = service.dns_address[1]
        lookup(port, "robot.example.test")
        lookup(port, "robot.example.test")
        lookup(port, "unknown.example")
    events = run_service(tmp_path, action)
    first, second = of(events, "dns_query", hostname="robot.example.test")
    assert (first["rcode"], first["answer"], first["cert"], first["intercepted"]) == ("NOERROR", "127.0.0.1", "issued", True)
    assert second["cert"] == "cached" and isinstance(second["elapsed_ms"], float)
    assert first["elapsed_ms"] >= 0
    assert first["action"] == second["action"] == "endpoint"
    (refused,) = of(events, "dns_query", hostname="unknown.example")
    assert (refused["rcode"], refused["answer"], refused["cert"]) == ("REFUSED", None, None)
    assert refused["action"] == "refused"
    # The issuance triggered by DNS is attributed to it and timed.
    issued = of(events, "cert_prewarmed", trigger="dns", new=True)
    assert len(issued) == 1 and issued[0]["elapsed_ms"] >= 0


def test_aaaa_query_has_no_answer_and_prewarms_in_the_background(tmp_path):
    def action(service):
        lookup(service.dns_address[1], "robot.example.test", qtype=28)
        service.prewarmer.queue.join()
    events = run_service(tmp_path, action)
    (query,) = of(events, "dns_query", qtype=28)
    assert (query["rcode"], query["answer"], query["cert"]) == ("NOERROR", None, None)
    assert query["action"] == "nodata" and query["intercepted"] is True
    assert len(of(events, "cert_prewarmed", trigger="prewarm")) == 1


def test_answer_all_catch_all_queries_are_flagged_and_issue_no_certificate(tmp_path):
    def action(service):
        lookup(service.dns_address[1], "anything.vendor.example")
    events = run_service(tmp_path, action, edit=lambda text: text.replace(
        'redirect_ipv4 = "127.0.0.1"', 'redirect_ipv4 = "127.0.0.1"\ndns_answer_all = true'))
    (query,) = of(events, "dns_query", hostname="anything.vendor.example")
    assert query["catch_all"] is True and query["answer"] == "127.0.0.1" and query["cert"] is None
    assert query["action"] == "catch_all" and query["intercepted"] is False
    assert not of(events, "cert_prewarmed", hostname="anything.vendor.example")


def test_certificate_failure_during_dns_is_logged_and_the_reply_still_goes_out(tmp_path):
    def prepare(service):
        def boom(hostname):
            raise ValueError("issuer expires too soon to issue a certificate")
        service.store.get_or_issue = boom

    def action(service):
        reply = lookup(service.dns_address[1], "robot.example.test")
        assert reply[3] & 0x0F == 0 and reply[-4:] == socket.inet_aton("127.0.0.1")
    events = run_service(tmp_path, action, prepare=prepare)
    (failure,) = of(events, "cert_prewarm_error", trigger="dns")
    assert failure["error_type"] == "ValueError" and "expires too soon" in failure["error"]
    (query,) = of(events, "dns_query")
    assert query["cert"] == "error" and query["answer"] == "127.0.0.1"


def test_tls_certificate_failure_is_logged_with_type_and_timing(tmp_path):
    def prepare(service):
        def boom(hostname):
            raise RuntimeError("signer unavailable")
        service.store.ssl_context = boom

    def action(service):
        with pytest.raises(ssl.SSLError):
            tls_request(service.tls_address[1], service.store.root_ca_path)
    events = run_service(tmp_path, action, prepare=prepare)
    (failure,) = of(events, "tls_cert_error", hostname="robot.example.test")
    assert failure["error_type"] == "RuntimeError" and failure["error"] == "signer unavailable"
    assert failure["elapsed_ms"] >= 0
    assert of(events, "tls_handshake_failed")


def test_tls_certificate_selection_records_whether_it_was_issued_and_how_long(tmp_path):
    events = run_service(tmp_path, lambda s: tls_request(s.tls_address[1], s.store.root_ca_path))
    (selected,) = of(events, "tls_certificate_selected")
    assert selected["new"] is True and selected["elapsed_ms"] >= 0


def test_invalid_dns_name_is_logged_with_the_raw_name(tmp_path):
    def action(service):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(dns_query("_dmarc.example.test"), ("127.0.0.1", service.dns_address[1]))
        lookup(service.dns_address[1], "robot.example.test")  # reply => the datagram above was handled
    events = run_service(tmp_path, action)
    (invalid,) = of(events, "dns_invalid")
    assert invalid["qname"] == "_dmarc.example.test" and invalid["bytes"] > 12 and invalid["source"] == "127.0.0.1"


def test_dns_from_a_disallowed_client_is_logged_with_size(tmp_path):
    def action(service):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(dns_query("robot.example.test"), ("127.0.0.1", service.dns_address[1]))
        time.sleep(0.3)
    events = run_service(tmp_path, action, edit=lambda text: text.replace("127.0.0.1/32", "10.0.0.0/8"))
    (denied,) = of(events, "dns_denied")
    assert denied["source"] == "127.0.0.1" and denied["bytes"] > 12
    assert not of(events, "dns_query")


def test_loaded_issuers_are_logged_at_start(tmp_path):
    events = run_service(tmp_path, lambda service: None)
    (loaded,) = of(events, "cert_issuers")
    assert loaded["mode"] == "local" and set(loaded["issuers"]) == {"local"}
    assert loaded["issuers"]["local"]["subject"] and loaded["issuers"]["local"]["not_after"]
    assert not of(events, "cert_issuer_expiring")
    assert [e["event"] for e in events].index("cert_issuers") < [e["event"] for e in events].index("service_started")


def test_issuer_close_to_expiry_is_warned_about(tmp_path):
    def prepare(service):
        issuer = service.store.issuers["local"]
        service.store.issuers["local"] = replace(issuer, not_after=datetime.now(timezone.utc) + timedelta(days=5, hours=1))
    events = run_service(tmp_path, lambda service: None, prepare=prepare)
    (warning,) = of(events, "cert_issuer_expiring")
    assert warning["issuer"] == "local" and warning["days_left"] == 5


def test_dns_action_distinguishes_catch_all_nodata_and_refused(tmp_path):
    def action(service):
        port = service.dns_address[1]
        lookup(port, "device.vendor.example")             # A for an unlisted name: catch_all
        lookup(port, "device.vendor.example", qtype=28)   # AAAA for the same name: nodata
        lookup(port, "device.vendor.example", qtype=16)   # TXT: nodata
        lookup(port, "robot.example.test")                # explicit endpoint: endpoint
    events = run_service(tmp_path, action, edit=lambda text: text.replace(
        'redirect_ipv4 = "127.0.0.1"', 'redirect_ipv4 = "127.0.0.1"\ndns_answer_all = true'))
    seen = [(e["hostname"], e["qtype"], e["action"]) for e in of(events, "dns_query")]
    assert seen == [("device.vendor.example", 1, "catch_all"), ("device.vendor.example", 28, "nodata"),
                    ("device.vendor.example", 16, "nodata"), ("robot.example.test", 1, "endpoint")]
