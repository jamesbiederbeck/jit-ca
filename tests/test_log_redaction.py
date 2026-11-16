import json
import socket
import ssl

import pytest

from jitca.config import load_config
from jitca.service import JITCAService
from test_e2e import config_file


@pytest.mark.parametrize('tls', [False, True])
@pytest.mark.parametrize('tables,redacted', [
    ('', True),
    ('[capture]\nenabled = true\nredact = false\n', False),
    ('[capture]\nenabled = true\nredact = true\n', True),
    ('[logging]\nredact = false\n', False),
    ('[capture]\nenabled = true\nredact = false\n[logging]\nredact = true\n', True),
    ('[capture]\nenabled = true\nredact = true\n[logging]\nredact = false\n', False),
])
def test_event_redaction_policy_on_http_and_https(tmp_path, tls, tables, redacted):
    path = config_file(tmp_path)
    text = path.read_text().replace("body = '{\"accepted\":true}'", "body = '{\"token\":\"response-secret\"}'")
    path.write_text(text + '\n[plain_http]\nport = 0\n' + tables)
    cfg = load_config(path)
    service = JITCAService(cfg)
    service.start()
    try:
        address = service.tls_address if tls else service.http_address
        with socket.create_connection(address, timeout=3) as raw:
            context = ssl.create_default_context(cafile=str(service.store.root_ca_path))
            stream = context.wrap_socket(raw, server_hostname='robot.example.test') if tls else raw
            with stream:
                body = b'{"token":"body-secret"}'
                stream.sendall((f'POST /command?token=query-secret HTTP/1.1\r\n'
                                f'Host: robot.example.test\r\nAuthorization: Bearer header-secret\r\n'
                                f'Cookie: session=cookie-secret\r\nContent-Length: {len(body)}\r\n'
                                f'Connection: close\r\n\r\n').encode() + body)
                response = b''
                while chunk := stream.recv(8192):
                    response += chunk
                assert b'response-secret' in response  # wire response is never log-redacted
    finally:
        service.stop()
    events = [json.loads(line) for line in service.log.path.read_text().splitlines()]
    for event in (e for e in events if e['event'] in ('http_request', 'http_flow')):
        assert event['request_headers']['authorization'] == ('[REDACTED]' if redacted else 'Bearer header-secret')
        assert event['request_headers']['cookie'] == ('[REDACTED]' if redacted else 'session=cookie-secret')
        assert event['query_parameters']['token'] == ('[REDACTED]' if redacted else ['query-secret'])
        assert ('body-secret' in event['request_preview']) is not redacted
    flow = next(e for e in events if e['event'] == 'http_flow')
    assert ('response-secret' in flow['response_preview']) is not redacted


@pytest.mark.parametrize('value', ['"false"', '0', '[]'])
def test_rejects_non_boolean_log_redaction(tmp_path, value):
    path = config_file(tmp_path)
    path.write_text(path.read_text() + f'\n[logging]\nredact = {value}\n')
    with pytest.raises(ValueError, match='logging.redact'):
        load_config(path)
