#!/usr/bin/env python3
"""Replay a captured HTTP request against a chosen jit-ca listener using curl."""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import tempfile
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[1]


def select_request(events: Path, hostname: str | None, path: str | None) -> dict:
    selected = None
    with events.open() as stream:
        for line in stream:
            if not line.strip():
                continue
            event = json.loads(line)
            if (event.get('event') == 'http_request'
                    and (hostname is None or event.get('hostname') == hostname)
                    and (path is None or event.get('path') == path)):
                selected = event
    if selected is None:
        raise ValueError('no matching http_request event')
    return selected


def captured_body(record: dict, captures: Path) -> Path | None:
    if not record.get('request_bytes', 0):
        return None
    capture = record.get('request_capture', {})
    if not capture.get('file') or capture.get('truncated') or capture.get('redacted'):
        raise ValueError('a complete, unredacted request-body capture is required')
    root = captures.resolve()
    body = (root / capture['file']).resolve()
    if body.parent != root:
        raise ValueError('capture file must be directly inside the captures directory')
    data = body.read_bytes()
    if (len(data) != record['request_bytes']
            or hashlib.sha256(data).hexdigest() != record.get('request_sha256')):
        raise ValueError('captured body size/hash mismatch')
    return body


def replay(args: argparse.Namespace) -> int:
    record = (json.loads(args.event_file.read_text()) if args.event_file
              else select_request(args.events, args.hostname, args.path))
    headers = record['request_headers']
    query = record.get('query_parameters', {})
    if '[REDACTED]' in json.dumps([headers, query]):
        raise ValueError('request contains redacted values; capture a fresh request')
    host = record['hostname']
    if not host or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-' for c in host):
        raise ValueError('request needs a valid DNS hostname')
    scheme = args.scheme or record.get('scheme', 'https')
    if scheme not in ('http', 'https'):
        raise ValueError('scheme must be http or https')
    port = args.port if args.port is not None else int(os.environ.get(
        'JITCA_TLS_PORT' if scheme == 'https' else 'JITCA_HTTP_PORT',
        '443' if scheme == 'https' else '80'))
    if not 1 <= port <= 65535:
        raise ValueError('port must be between 1 and 65535')
    ip = ipaddress.ip_address(args.ip)
    address = f'[{ip}]' if ip.version == 6 else str(ip)
    target = record['path']
    if not target.startswith('/') or any(c in target for c in '\r\n'):
        raise ValueError('invalid request path')
    if query:
        target += '?' + urlencode(query, doseq=True)
    captures = args.captures or args.events.parent / 'captures'
    body = captured_body(record, captures)
    skip = {'host', 'content-length', 'connection', 'transfer-encoding', 'accept-encoding',
            'proxy-connection', 'expect', 'keep-alive', 'te', 'trailer', 'upgrade',
            'proxy-authenticate', 'proxy-authorization'}
    skip.update(x.strip().lower() for x in headers.get('connection', '').split(','))
    args.output_prefix.parent.mkdir(parents=True, exist_ok=True)
    header_output = Path(str(args.output_prefix) + '.headers')
    body_output = Path(str(args.output_prefix) + '.body')
    with tempfile.NamedTemporaryFile(mode='w+') as header_file:
        for name, value in headers.items():
            if name.lower() not in skip:
                if any(c in str(name) + str(value) for c in '\r\n'):
                    raise ValueError('invalid recorded header')
                header_file.write(f'{name}: {value}\n')
        header_file.flush()
        command = ['curl', '--noproxy', '*', '--http1.1', '--compressed',
                   '--connect-timeout', str(args.connect_timeout), '--max-time', str(args.timeout),
                   '--resolve', f'{host}:{port}:{address}', '--request', record['method'],
                   '--header', f'@{header_file.name}']
        if scheme == 'https':
            command += ['--cacert', str(args.cafile)]
        if body is not None:
            command += ['--data-binary', f'@{body}']
        # Private outputs; keep response content and credentials out of the console.
        with header_output.open('wb') as head, body_output.open('wb') as payload:
            os.fchmod(head.fileno(), 0o600)
            os.fchmod(payload.fileno(), 0o600)
            command += ['--dump-header', str(header_output), '--output', str(body_output),
                        f'{scheme}://{host}:{port}{target}']
            result = subprocess.run(command, check=False)
    print(f'Response headers: {header_output}\nResponse body: {body_output}')
    return result.returncode


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    def option(name, env, default=None, **kwargs):
        p.add_argument(name, default=os.environ.get(env, default),
                       help=f'environment: {env}' + (f' (default: {default})' if default is not None else ''), **kwargs)
    option('--events', 'JITCA_REPLAY_EVENTS', 'state/events.jsonl', type=Path)
    option('--event-file', 'JITCA_REPLAY_EVENT_FILE', type=Path)
    option('--captures', 'JITCA_REPLAY_CAPTURES', type=Path)
    option('--hostname', 'JITCA_REPLAY_HOSTNAME')
    option('--path', 'JITCA_REPLAY_PATH')
    option('--ip', 'JITCA_REPLAY_IP', os.environ.get('JITCA_REDIRECT_IPV4', '127.0.0.1'))
    option('--port', 'JITCA_REPLAY_PORT', type=int)
    option('--scheme', 'JITCA_REPLAY_SCHEME', choices=['http', 'https'])
    option('--cafile', 'JITCA_REPLAY_CAFILE', str(ROOT / 'local_deployment/aaa-certificate-services.crt'), type=Path)
    option('--output-prefix', 'JITCA_REPLAY_OUTPUT_PREFIX', 'replay-response', type=Path)
    option('--connect-timeout', 'JITCA_REPLAY_CONNECT_TIMEOUT', '5', type=float)
    option('--timeout', 'JITCA_REPLAY_TIMEOUT', '30', type=float)
    args = p.parse_args()
    try:
        return replay(args)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        p.exit(1, f'replay: {exc}\n')


if __name__ == '__main__':
    raise SystemExit(main())
