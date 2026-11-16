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


def test_anonymized_export_covers_headers_nested_json_base64_and_manifest(tmp_path):
    import base64
    events, captures, event = setup_input(tmp_path)
    identity = '12345678-1234-4123-8123-123456789abc'
    serial = 'SYNTHETIC-SERIAL-42'
    inner = {'deviceId': identity, 'sessionId': identity, 'esn': serial,
             'timestamp': 1700000000000, 'model': 'ExampleModel',
             'url': 'https://example.test/a?identifier=' + identity + '&token=old-query-token'}
    body = json.dumps({'Records': [{'Data': base64.b64encode(json.dumps(inner).encode()).decode(),
                                    'PartitionKey': identity}], 'StreamName': 'analytics'}).encode()
    (captures / 'body.bin').write_bytes(body)
    event.update(hostname='kinesis.us-west-2.amazonaws.com', source='198.51.100.42',
                 path='/dms/api/devices/user/opaque-original-user', time='2026-01-02T00:00:00Z',
                 query_parameters={'identifier': [identity], 'token': ['old-query-token']},
                 request_bytes=len(body), request_sha256=hashlib.sha256(body).hexdigest(),
                 request_preview=body.decode())
    event['request_headers'].update(authorization='AWS4-HMAC-SHA256 Credential=OLD_KEY/oldscope, Signature=old-signature',
                                   **{'device-context': json.dumps({'SYSTEM_INFO': {'DIID': identity, 'SERIAL_NUMBER': serial},
                                                                   'CAST_NAME': 'Original room'}),
                                      'cookie': 'original-cookie', 'x-amz-date': '20260102T000000Z',
                                      'x-amz-security-token': 'old-session-token'})
    events.write_text(json.dumps(event) + '\n')
    output = tmp_path / 'anon'
    result = invoke(events, output, '--anonymize', '--anonymize-credentials',
                    '--shift-time-seconds=-86400', '--anonymize-seed', 'test-seed')
    assert result.returncode == 0, result.stderr
    manifest = json.loads((output / 'manifest.json').read_text())
    sanitized = manifest['requests'][0]['event']
    serialized = '\n'.join(p.read_text() for p in output.rglob('*') if p.is_file())
    for original in (identity, serial, 'Original room', 'old-query-token', 'original-cookie',
                     'OLD_KEY', 'old-signature', 'old-session-token', 'opaque-original-user', '198.51.100.42'):
        assert original not in serialized
    data = json.loads(next((output / 'bodies').iterdir()).read_bytes())
    decoded = json.loads(base64.b64decode(data['Records'][0]['Data']))
    context = json.loads(sanitized['request_headers']['device-context'])
    assert decoded['deviceId'] == context['SYSTEM_INFO']['DIID'] == sanitized['query_parameters']['identifier'][0]
    assert decoded['sessionId'] == data['Records'][0]['PartitionKey'] == decoded['deviceId']
    assert decoded['esn'] == context['SYSTEM_INFO']['SERIAL_NUMBER']
    assert decoded['timestamp'] == 1700000000000 - 86400000
    assert decoded['model'] == 'ExampleModel'
    assert identity not in decoded['url'] and 'old-query-token' not in decoded['url']
    assert sanitized['time'].startswith('2026-01-01')
    assert sanitized['request_sha256'] != event['request_sha256']
    assert sanitized['aws_authentication'] == 'fresh signature required'
    assert next((output / 'bodies').iterdir()).stat().st_mode & 0o777 == 0o600
    subprocess.run(['bash', '-n', str(output / 'commands.sh')], check=True)
    # Input files remain untouched.
    assert (captures / 'body.bin').read_bytes() == body
    assert json.loads(events.read_text()) == event


def test_sentry_lengths_timestamps_and_firehose_binary_fields():
    import base64
    sanitizer = module.Anonymizer(True, True, -3600, 'seed')
    session = {'sid': '12345678-1234-4123-8123-123456789abc', 'did': 'SERIAL-42',
               'started': '2026-01-02T00:00:00Z', 'duration': 180.5, 'errors': 0}
    item = json.dumps(session).encode()
    raw = (b'{"dsn":"https://OLD_PUBLIC_KEY@o1.ingest.sentry.io/123"}\n'
           + json.dumps({'type': 'session', 'length': len(item)}).encode() + b'\n' + item + b'\n')
    changed = sanitizer.payload(raw)
    lines = changed.splitlines()
    assert json.loads(lines[1])['length'] == len(lines[2])
    new = json.loads(lines[2])
    assert new['duration'] == 180.5 and new['started'] == '2026-01-01T23:00:00Z'
    assert b'OLD_PUBLIC_KEY' not in changed and b'SERIAL-42' not in changed
    kv = b'esn=SERIAL-42,boot_id=117,ts=1700000000000,act=\xff\xfe,s=INPUT_SWITCH'
    wrapper = json.dumps({'Records': [{'Data': base64.b64encode(kv).decode()}]}).encode()
    result = json.loads(sanitizer.payload(wrapper))
    text = base64.b64decode(result['Records'][0]['Data'])
    assert b'SERIAL-42' not in text and b'boot_id=117,' not in text
    assert b'act=\xff\xfe,' in text and b'ts=1699996400000,' in text


def test_optional_credentials_seed_custom_fields_and_unsupported_body():
    identity = '12345678-1234-4123-8123-123456789abc'
    obj = {'deviceId': identity, 'authorization': 'Bearer original-token', 'model': 'ExampleModel'}
    a = module.Anonymizer(True, seed='same')
    b = module.Anonymizer(True, seed='same')
    assert a.transform(obj) == b.transform(obj)
    assert a.transform(obj)['authorization'] == 'Bearer original-token'
    assert a.transform(obj)['model'] == 'ExampleModel'
    custom = module.Anonymizer(fields=['model'], seed='same')
    assert custom.transform(obj)['model'] != 'ExampleModel'
    assert custom.transform(obj)['deviceId'] == identity
    with pytest.raises(ValueError, match='unsupported body format'):
        a.payload(b'opaque\x00\xffbinary')


def test_aws_resign_uses_runtime_environment_without_replaying_network(tmp_path):
    events, captures, event = setup_input(tmp_path)
    event['hostname'] = 'firehose.us-east-2.amazonaws.com'
    event['request_headers'].update(authorization='AWS4-HMAC-SHA256 Credential=OLD_KEY, Signature=OLD_SIGNATURE',
                                   **{'x-amz-date': '20260101T000000Z', 'x-amz-security-token': 'OLD_SESSION'})
    events.write_text(json.dumps(event) + '\n')
    output = tmp_path / 'signed'
    result = invoke(events, output, '--aws-resign')
    assert result.returncode == 0, result.stderr
    serialized = '\n'.join(p.read_text() for p in output.rglob('*') if p.is_file())
    assert 'OLD_KEY' not in serialized and 'OLD_SIGNATURE' not in serialized and 'OLD_SESSION' not in serialized
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    stub = bin_dir / 'curl'
    stub.write_text(f'#!{sys.executable}\nimport os,sys,json\nopen(os.environ["TEST_CURL_ARGS"],"w").write(json.dumps(sys.argv[1:]))\n')
    stub.chmod(0o700)
    args_file = tmp_path / 'args.json'
    env = {**os.environ, 'PATH': str(bin_dir) + os.pathsep + os.environ['PATH'],
           'AWS_ACCESS_KEY_ID': 'NEW_KEY', 'AWS_SECRET_ACCESS_KEY': 'NEW_SECRET',
           'AWS_SESSION_TOKEN': 'NEW_SESSION', 'TEST_CURL_ARGS': str(args_file)}
    subprocess.run(['bash', str(output / 'commands.sh')], env=env, check=True, capture_output=True)
    args = json.loads(args_file.read_text())
    assert args[args.index('--aws-sigv4') + 1] == 'aws:amz:us-east-2:firehose'
    assert args[args.index('--user') + 1] == 'NEW_KEY:NEW_SECRET'
    assert 'X-Amz-Security-Token: NEW_SESSION' in args
