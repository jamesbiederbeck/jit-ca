import io
import json

import pytest

from jitca.config import load_config
from jitca.events import EventLog
from jitca.service import JITCAService
from test_e2e import config_file, lookup, tls_request


def test_events_are_mirrored_to_the_echo_stream_identically_to_the_file(tmp_path):
    echo = io.StringIO()
    log = EventLog(tmp_path / "events.jsonl", echo=echo)
    log.emit("one", value=1)
    log.emit("two", nested={"a": [1, 2]})
    log.close()
    assert echo.getvalue() == (tmp_path / "events.jsonl").read_text()
    assert [json.loads(line)["event"] for line in echo.getvalue().splitlines()] == ["one", "two"]


def test_broken_echo_stream_never_breaks_the_file_log(tmp_path):
    class Broken(io.StringIO):
        def write(self, text):
            raise BrokenPipeError("stdout closed")

    log = EventLog(tmp_path / "events.jsonl", echo=Broken())
    for number in range(3):
        log.emit("event", n=number)
    log.close()  # must not raise
    assert len((tmp_path / "events.jsonl").read_text().splitlines()) == 3


def test_service_prints_events_to_stdout_only_when_enabled(tmp_path, capsys):
    path = config_file(tmp_path)
    path.write_text(path.read_text() + "\n[logging]\nstdout = true\n")
    service = JITCAService(load_config(path))
    service.start()
    try:
        lookup(service.dns_address[1], "robot.example.test")
        tls_request(service.tls_address[1], service.store.root_ca_path)
    finally:
        service.stop()
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines() if line.startswith("{")]
    kinds = [line["event"] for line in lines]
    assert {"cert_issuers", "service_started", "dns_query", "http_request", "http_flow"} <= set(kinds)
    assert kinds == [json.loads(line)["event"] for line in (service.config.state_dir / "events.jsonl").read_text().splitlines()]


def test_stdout_is_quiet_by_default(tmp_path, capsys):
    service = JITCAService(load_config(config_file(tmp_path)))
    service.start()
    service.stop()
    assert capsys.readouterr().out == ""


def test_logging_stdout_must_be_a_boolean(tmp_path):
    path = config_file(tmp_path)
    path.write_text(path.read_text() + '\n[logging]\nstdout = "yes"\n')
    with pytest.raises(ValueError, match="logging.stdout"):
        load_config(path)
