from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import threading

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import jitca.certs as certs
from jitca.config import canonical_hostname, load_config
from jitca.service import JITCAService
from test_e2e import config_file, lookup, tls_request


@pytest.mark.parametrize("hostname", [
    "*.example.test", "foo_bar.test", "-foo.test", "foo-.test",
    "foo..test", "foo.test..", " foo.test", "foo.test ",
    "127.0.0.1", "::1", "foo/test", "a" * 64 + ".test",
])
def test_invalid_endpoint_names(hostname):
    with pytest.raises(ValueError):
        canonical_hostname(hostname)


def test_hostname_normalization():
    assert canonical_hostname("ROBOT.Example.Test.") == "robot.example.test"
    assert canonical_hostname("BÜCHER.test") == "xn--bcher-kva.test"


def test_one_day_leaf_singleflight_and_context_reuse(tmp_path):
    cfg = replace(load_config(config_file(tmp_path)), leaf_days=1)
    store = certs.CertificateStore(cfg)
    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(store.get_or_issue, ["robot.example.test"] * 24))
    assert sum(created for _, _, created in results) == 1
    first, issued = store.ssl_context("ROBOT.EXAMPLE.TEST.")
    second, issued_again = store.ssl_context("robot.example.test")
    assert first is second
    assert not issued and not issued_again
    assert not certs.CertificateStore(cfg).get_or_issue("robot.example.test")[2]


@pytest.mark.parametrize("damage", ["corrupt_cert", "corrupt_key", "mismatched_key"])
def test_damaged_cache_is_repaired(tmp_path, damage):
    cfg = load_config(config_file(tmp_path))
    store = certs.CertificateStore(cfg)
    old_context, _ = store.ssl_context("robot.example.test")
    cert_path, key_path, _ = store.get_or_issue("robot.example.test")
    if damage == "corrupt_cert":
        cert_path.write_bytes(b"invalid PEM")
    elif damage == "corrupt_key":
        key_path.write_bytes(b"invalid PEM")
    else:
        key_path.write_bytes(ec.generate_private_key(ec.SECP256R1()).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
    context, issued = store.ssl_context("robot.example.test")
    assert issued and context is not old_context
    assert not store.get_or_issue("robot.example.test")[2]


def test_expired_issuer_rejected_even_with_cached_context(tmp_path, monkeypatch):
    cfg = load_config(config_file(tmp_path))
    store = certs.CertificateStore(cfg)
    store.ssl_context("robot.example.test")

    class FutureClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return store.not_after + timedelta(seconds=1)

    monkeypatch.setattr(certs, "datetime", FutureClock)
    with pytest.raises(ValueError, match="issuer chain"):
        store.ssl_context("robot.example.test")


def test_issuer_limited_leaf_reused(tmp_path):
    cfg = load_config(config_file(tmp_path))
    store = certs.CertificateStore(cfg)
    store.not_after = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(hours=2)
    store.issuers["local"] = replace(store.issuers["local"], not_after=store.not_after)
    assert store.get_or_issue("robot.example.test")[2]
    assert not store.get_or_issue("robot.example.test")[2]


def test_dns_response_during_signing_and_concurrent_tls(tmp_path, monkeypatch):
    service = JITCAService(load_config(config_file(tmp_path)))
    signing = threading.Event()
    release = threading.Event()
    generate = certs.rsa.generate_private_key
    calls = []

    def delayed_key(*args, **kwargs):
        calls.append(1)
        signing.set()
        assert release.wait(5), "test did not release certificate signer"
        return generate(*args, **kwargs)

    monkeypatch.setattr(certs.rsa, "generate_private_key", delayed_key)
    service.start()
    try:
        # DNS must return while the certificate signer is blocked.
        lookup(service.dns_address[1], "robot.example.test")
        assert signing.wait(2)
        lookup(service.dns_address[1], "robot.example.test", qtype=28)
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(tls_request, service.tls_address[1], service.store.root_ca_path)
            release.set()
            response, _ = future.result(timeout=5)
        assert b"200 OK" in response
        service.prewarmer.queue.join()
        assert len(calls) == 1
        assert len(service.store.all_metadata()) == 1
    finally:
        release.set()
        service.stop()
