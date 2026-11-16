import json
import stat

import pytest

from jitca.config import load_config
from jitca.service import JITCAService
from test_e2e import config_file, tls_request


def capture_config(tmp_path, table="[capture]\nenabled = true\n"):
    path = config_file(tmp_path)
    path.write_text(path.read_text() + "\n" + table)
    return load_config(path)


def run_posts(cfg, bodies):
    service = JITCAService(cfg)
    service.start()
    try:
        for body in bodies:
            tls_request(service.tls_address[1], service.store.root_ca_path, path="/command", body=body)
    finally:
        service.stop()
    events = [json.loads(line) for line in (cfg.state_dir / "events.jsonl").read_text().splitlines()]
    return events, sorted((cfg.state_dir / "captures").glob("*.bin")) if (cfg.state_dir / "captures").exists() else []


def test_disabled_by_default_creates_nothing_and_adds_no_event_fields(tmp_path):
    cfg = load_config(config_file(tmp_path))
    assert cfg.capture is None
    events, files = run_posts(cfg, [b'{"a":1}'])
    assert files == []
    assert not (cfg.state_dir / "captures").exists()
    assert not any("request_capture" in e or "response_capture" in e for e in events)


def test_raw_request_and_response_bodies_are_captured_unredacted(tmp_path):
    cfg = capture_config(tmp_path)
    secret = b'{"user":"bob","token":"s3cr3t-value","pin":"1234"}'
    events, files = run_posts(cfg, [secret])
    by_direction = {f.name.split("_")[-2]: f for f in files}
    assert by_direction["request"].read_bytes() == secret          # raw, not redacted
    assert by_direction["response"].read_bytes() == b'{"accepted":true}'
    # The event log keeps redacting and only references the capture file.
    flow = next(e for e in events if e["event"] == "http_flow")
    assert "s3cr3t-value" not in json.dumps(events)
    assert flow["request_capture"]["file"] == by_direction["request"].name
    assert flow["request_capture"]["bytes"] == len(secret) and flow["request_capture"]["truncated"] is False
    assert flow["response_capture"]["file"] == by_direction["response"].name
    assert "token" in flow["request_preview"] and "[REDACTED]" in flow["request_preview"]


def test_non_json_binary_body_is_captured_byte_for_byte(tmp_path):
    cfg = capture_config(tmp_path)
    blob = bytes(range(256))
    _, files = run_posts(cfg, [blob])
    assert next(f for f in files if "_request_" in f.name).read_bytes() == blob


def test_capture_files_and_directory_are_private(tmp_path):
    cfg = capture_config(tmp_path)
    _, files = run_posts(cfg, [b"x"])
    assert files and stat.S_IMODE((cfg.state_dir / "captures").stat().st_mode) == 0o700
    assert all(stat.S_IMODE(f.stat().st_mode) == 0o600 for f in files)
    assert all("/" not in f.name and f.name.endswith(".bin") for f in files)


def test_oversize_body_is_truncated_and_flagged(tmp_path):
    cfg = capture_config(tmp_path, "[capture]\nenabled = true\nmax_body_bytes = 10\n")
    events, files = run_posts(cfg, [b"0123456789ABCDEF"])
    request_file = next(f for f in files if "_request_" in f.name)
    assert request_file.read_bytes() == b"0123456789"
    flow = next(e for e in events if e["event"] == "http_flow")
    assert flow["request_capture"]["truncated"] is True and flow["request_capture"]["bytes"] == 10


def test_oldest_captures_are_evicted_past_max_files(tmp_path):
    cfg = capture_config(tmp_path, "[capture]\nenabled = true\nmax_files = 3\n")
    _, files = run_posts(cfg, [b"one", b"two", b"three", b"four"])
    # 4 requests x (request + response) = 8 files; only the newest 3 survive.
    assert len(files) == 3
    assert [f.read_bytes() for f in files if "_request_" in f.name] == [b"four"]
    assert not any(f.read_bytes() in (b"one", b"two") for f in files)


def test_redact_mode_stores_redacted_json_and_skips_non_json(tmp_path):
    cfg = capture_config(tmp_path, "[capture]\nenabled = true\nredact = true\n")
    events, files = run_posts(cfg, [b'{"user":"bob","token":"s3cr3t-value"}', b"\x00\x01binary"])
    request_files = [f for f in files if "_request_" in f.name]
    assert len(request_files) == 1
    stored = json.loads(request_files[0].read_bytes())
    assert stored == {"user": "bob", "token": "[REDACTED]"}
    assert not any(b"s3cr3t-value" in f.read_bytes() for f in files)
    skipped = [e for e in events if e["event"] == "http_flow" and "skipped" in e.get("request_capture", {})]
    assert len(skipped) == 1


@pytest.mark.parametrize("table,message", [
    ("[capture]\nenabled = \"yes\"\n", "true or false"),
    ("[capture]\nenabled = true\nmax_body_bytes = 0\n", "max_body_bytes"),
    ("[capture]\nenabled = true\nmax_files = 0\n", "max_files"),
])
def test_capture_config_validation(tmp_path, table, message):
    path = config_file(tmp_path)
    path.write_text(path.read_text() + "\n" + table)
    with pytest.raises(ValueError, match=message):
        load_config(path)
