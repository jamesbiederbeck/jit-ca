import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from jitca.config import load_config
from jitca.service import JITCAService
from test_e2e import config_file

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/export-curl.py'
spec = importlib.util.spec_from_file_location('export_curl', SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def record(body=b'{"value":1}'):
    return dict(event='http_request', hostname='robot.example.test', method='POST', path='/command',
                query_parameters={'x': ['1', '2'], 'q': ["a'b;$(false)"]},
                request_headers={'host': 'robot.example.test', 'authorization': 'Bearer synthetic-token',
                                 'connection': 'close, x-hop', 'x-hop': 'omit', 'content-type': 'application/json'},
                request_bytes=len(body), request_sha256=hashlib.sha256(body).hexdigest(),
                request_capture={'file': 'body.bin', 'bytes': len(body), 'truncated': False, 'redacted': False})


def setup_input(tmp_path):
    captures = tmp_path / 'captures'
    captures.mkdir()
    body = b'{"value":1}'
    (captures / 'body.bin').write_bytes(body)
    e = record(body)
    events = tmp_path / 'events.jsonl'
    events.write_text(json.dumps(e) + '\n')
    return events, captures, e


def invoke(events, output, *args):
    env = {k: v for k, v in os.environ.items() if not k.startswith('JITCA_')}
    return subprocess.run([sys.executable, str(SCRIPT), '--events', str(events), '--output-dir', str(output), *args],
                          env=env, capture_output=True, text=True)


@pytest.mark.skipif(not shutil.which('curl') or not shutil.which('bash'), reason='curl/bash required')
@pytest.mark.parametrize('scheme', ['http', 'https'])
def test_generated_commands_replay_to_local_listener_and_keep_credentials(tmp_path, scheme):
    events, captures, event = setup_input(tmp_path)
    event['scheme'] = scheme
    events.write_text(json.dumps(event) + '\n')
    config = config_file(tmp_path)
    config.write_text(config.read_text() + '\n[plain_http]\nport = 0\n[logging]\nredact = false\n')
    service = JITCAService(load_config(config))
    output = tmp_path / 'export'
    service.start()
    try:
        address = service.tls_address if scheme == 'https' else service.http_address
        result = invoke(events, output, '--target', 'local', '--port', str(address[1]),
                        '--ip', '127.0.0.1', '--cafile', str(service.store.root_ca_path))
        assert result.returncode == 0, result.stderr
        assert 'Bearer synthetic-token' not in result.stdout
        header = (output / 'headers/000001.headers').read_text()
        assert 'authorization: Bearer synthetic-token' in header and 'x-hop:' not in header
        assert not list((output / 'responses').glob('*')) if (output / 'responses').exists() else True
        subprocess.run(['bash', str(output / 'commands.sh')], check=True, capture_output=True)
    finally:
        service.stop()
    assert json.loads((output / 'responses/000001.body').read_text()) == {'accepted': True}
    observed = [json.loads(x) for x in service.log.path.read_text().splitlines()]
    replayed = next(e for e in observed if e['event'] == 'http_request')
    assert replayed['query_parameters'] == event['query_parameters']
    assert replayed['request_headers']['authorization'] == 'Bearer synthetic-token'
    assert replayed['request_sha256'] == event['request_sha256']
    assert (output / 'headers/000001.headers').stat().st_mode & 0o777 == 0o600
    assert (output / 'commands.sh').stat().st_mode & 0o777 == 0o700


def test_latest_filters_missing_body_and_no_execution(tmp_path):
    events, captures, event = setup_input(tmp_path)
    newer = dict(event, time='latest')
    missing = dict(event, path='/missing', request_capture={'file': 'missing.bin'})
    other = dict(event, hostname='other.test')
    events.write_text('\n'.join(json.dumps(x) for x in [event, newer, missing, other,
                        dict(event, event='http_flow')]) + '\n')
    output = tmp_path / 'export'
    result = invoke(events, output, '--latest', '--hostname', 'robot.example.test', '--quiet')
    assert result.returncode == 0, result.stderr
    assert result.stdout == ''
    manifest = json.loads((output / 'manifest.json').read_text())
    assert manifest['selected'] == 2 and manifest['exported'] == 1
    assert len(manifest['skipped']) == 1
    assert manifest['requests'][0]['event']['time'] == 'latest'
    assert '--resolve' not in (output / 'commands.sh').read_text()
    assert not (output / 'responses').exists()  # export does not run curl
    again = invoke(events, output)
    assert again.returncode != 0  # never overwrite an existing export


def test_tampered_and_redacted_bodies_are_not_exported(tmp_path):
    events, captures, event = setup_input(tmp_path)
    (captures / 'body.bin').write_bytes(b'changed')
    with pytest.raises(ValueError, match='size/hash'):
        module.body_bytes(event, captures)
    event['request_capture']['redacted'] = True
    with pytest.raises(ValueError, match='truncated or redacted'):
        module.body_bytes(event, captures)
    event['request_capture'] = {'file': '../outside'}
    with pytest.raises(ValueError, match='escapes'):
        module.body_bytes(event, captures)
