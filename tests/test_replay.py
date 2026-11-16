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

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/replay.py'
spec = importlib.util.spec_from_file_location('replay_script', SCRIPT)
replay_script = importlib.util.module_from_spec(spec)
spec.loader.exec_module(replay_script)


@pytest.mark.skipif(not shutil.which('curl'), reason='curl required')
@pytest.mark.parametrize('scheme', ['http', 'https'])
def test_replay_headers_query_and_body_over_real_listener(tmp_path, scheme):
    path = config_file(tmp_path)
    path.write_text(path.read_text() + '\n[plain_http]\nport = 0\n[logging]\nredact = false\n')
    service = JITCAService(load_config(path))
    captures = tmp_path / 'captures'
    captures.mkdir()
    body = b'{"token":"synthetic-body"}'
    (captures / 'body.bin').write_bytes(body)
    record = dict(event='http_request', scheme=scheme, hostname='robot.example.test',
                  method='POST', path='/command', query_parameters={'token': ['query-token'], 'x': ['1', '2']},
                  request_headers={'host': 'robot.example.test', 'authorization': 'Bearer synthetic-token',
                                   'content-type': 'application/json', 'content-length': '999'},
                  request_bytes=len(body), request_sha256=hashlib.sha256(body).hexdigest(),
                  request_capture={'file': 'body.bin', 'truncated': False, 'redacted': False})
    events = tmp_path / 'input.jsonl'
    events.write_text(json.dumps(record) + '\n')
    output = tmp_path / 'response'
    service.start()
    try:
        port = (service.tls_address if scheme == 'https' else service.http_address)[1]
        env = {k: v for k, v in os.environ.items() if not k.startswith('JITCA_')}
        env.update(JITCA_REPLAY_EVENTS=str(events), JITCA_REPLAY_HOSTNAME='robot.example.test',
                   JITCA_REPLAY_PATH='/command', JITCA_REPLAY_IP='127.0.0.1', JITCA_REPLAY_PORT=str(port),
                   JITCA_REPLAY_CAFILE=str(service.store.root_ca_path),
                   JITCA_REPLAY_OUTPUT_PREFIX=str(output))
        command = [sys.executable, str(SCRIPT)]
        if scheme == 'https':
            env['JITCA_REPLAY_PORT'] = '1'
            command += ['--port', str(port)]  # CLI overrides environment
        result = subprocess.run(command, env=env, capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        assert 'synthetic-token' not in result.stdout + result.stderr
    finally:
        service.stop()
    assert json.loads(Path(str(output) + '.body').read_text()) == {'accepted': True}
    assert Path(str(output) + '.body').stat().st_mode & 0o777 == 0o600
    observed = [json.loads(x) for x in service.log.path.read_text().splitlines()]
    request = next(x for x in observed if x['event'] == 'http_request')
    assert request['request_headers']['authorization'] == 'Bearer synthetic-token'
    assert request['query_parameters'] == record['query_parameters']
    assert request['request_sha256'] == record['request_sha256']


def test_selection_and_incomplete_or_modified_body_rejected(tmp_path):
    events = tmp_path / 'events.jsonl'
    events.write_text('\n'.join(json.dumps(x) for x in [
        {'event': 'http_request', 'hostname': 'a.test', 'path': '/a', 'n': 1},
        {'event': 'http_flow', 'hostname': 'a.test', 'path': '/a', 'n': 2},
        {'event': 'http_request', 'hostname': 'a.test', 'path': '/a', 'n': 3}]))
    assert replay_script.select_request(events, 'a.test', '/a')['n'] == 3
    with pytest.raises(ValueError, match='no matching'):
        replay_script.select_request(events, 'b.test', None)
    with pytest.raises(ValueError, match='complete, unredacted'):
        replay_script.captured_body({'request_bytes': 1}, tmp_path)
    (tmp_path / 'body').write_bytes(b'x')
    record = {'request_bytes': 1, 'request_sha256': 'wrong', 'request_capture': {'file': 'body'}}
    with pytest.raises(ValueError, match='size/hash'):
        replay_script.captured_body(record, tmp_path)
    record['request_capture']['file'] = '../outside'
    with pytest.raises(ValueError, match='directly inside'):
        replay_script.captured_body(record, tmp_path)


def test_redacted_headers_rejected_before_network(tmp_path):
    event = tmp_path / 'request.json'
    event.write_text(json.dumps({'request_headers': {'authorization': '[REDACTED]'}}))
    with pytest.raises(ValueError, match='redacted values'):
        replay_script.replay(replay_script.argparse.Namespace(event_file=event))
