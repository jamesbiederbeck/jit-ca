#!/usr/bin/env python3
"""Export captured http_request events as a portable shell script of curl commands.

Never executes curl. Preserves original credentials and payload bytes.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import sys
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[1]
HOP_HEADERS = {'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
               'te', 'trailer', 'transfer-encoding', 'upgrade', 'proxy-connection'}


def private_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    with path.open('xb') as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(data)


def body_bytes(event: dict, captures: Path) -> bytes | None:
    size = event.get('request_bytes', 0)
    if size == 0:
        return None
    capture = event.get('request_capture', {})
    if not capture.get('file'):
        raise ValueError('missing body capture')
    if capture.get('truncated') or capture.get('redacted'):
        raise ValueError('body capture is truncated or redacted')
    root = captures.resolve()
    path = (root / capture['file']).resolve()
    if path.parent != root:
        raise ValueError('capture path escapes captures directory')
    payload = path.read_bytes()
    if len(payload) != size or hashlib.sha256(payload).hexdigest() != event.get('request_sha256'):
        raise ValueError('body size/hash mismatch')
    return payload


def select_events(args: argparse.Namespace) -> list[dict]:
    result = []
    with args.events.open() as stream:
        for number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except ValueError as exc:
                raise ValueError(f'invalid JSON on line {number}') from exc
            if event.get('event') != 'http_request':
                continue
            if args.hostname and event.get('hostname') not in args.hostname:
                continue
            if args.path and event.get('path') != args.path:
                continue
            if args.method and event.get('method') != args.method.upper():
                continue
            result.append(event)
    if args.latest:
        latest = {}
        for event in result:
            key = (event.get('hostname'), event.get('method'), event.get('path'),
                   json.dumps(event.get('query_parameters', {}), sort_keys=True))
            latest[key] = event
        result = list(latest.values())
    return result[-args.limit:] if args.limit else result


def export(args: argparse.Namespace) -> tuple[str, int, int]:
    events = select_events(args)
    if not events:
        raise ValueError('no matching http_request events')
    captures = args.captures or args.events.parent / 'captures'
    prepared = []
    skipped = []
    for index, event in enumerate(events, 1):
        try:
            host = event.get('hostname')
            if not isinstance(host, str) or not re.fullmatch(r'[A-Za-z0-9.-]+', host):
                raise ValueError('missing or invalid DNS hostname')
            method = event.get('method', '')
            if not re.fullmatch('[A-Z]+', method):
                raise ValueError('invalid request method')
            scheme = event.get('scheme', 'https')
            if scheme not in ('http', 'https'):
                raise ValueError('unsupported scheme')
            target = event.get('path', '')
            if not target.startswith('/') or any(c in target for c in '\r\n'):
                raise ValueError('invalid path')
            query = event.get('query_parameters', {})
            if query:
                target += '?' + urlencode(query, doseq=True)
            headers = event.get('request_headers', {})
            skip = HOP_HEADERS | {'host', 'content-length', 'expect', 'accept-encoding'}
            skip |= {name.strip().lower() for name in headers.get('connection', '').split(',')}
            header_lines = []
            for name, value in headers.items():
                if name.lower() in skip:
                    continue
                if (not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name)
                        or not isinstance(value, str) or any(c in value for c in '\r\n')):
                    raise ValueError('invalid header')
                header_lines.append(f'{name}: {value}\n')
            payload = body_bytes(event, captures)
            prepared.append((index, event, host, method, scheme, target, ''.join(header_lines), payload))
        except (OSError, ValueError, KeyError, TypeError) as exc:
            skipped.append({'event_index': index, 'host': event.get('hostname'), 'reason': str(exc)})
    args.output_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    for name in ('headers', 'bodies'):
        (args.output_dir / name).mkdir(mode=0o700)
    script = ['#!/usr/bin/env bash', 'set -euo pipefail', 'umask 077',
              'cd "$(dirname "${BASH_SOURCE[0]}")"', 'mkdir -p responses',
              '# Export only: running this file sends the recorded requests.',
              '# Query strings are reconstructed; expired AWS signatures are not refreshed.', '']
    for index, event, host, method, scheme, target, header_text, payload in prepared:
        tag = f'{index:06d}'
        header_file = f'headers/{tag}.headers'
        private_write(args.output_dir / header_file, header_text.encode())
        command = ['curl', '--silent', '--show-error', '--globoff', '--path-as-is', '--http1.1',
                   '--compressed', '--connect-timeout', str(args.connect_timeout), '--max-time', str(args.timeout),
                   '--request', method, '--header', '@' + header_file,
                   '--dump-header', f'responses/{tag}.headers', '--output', f'responses/{tag}.body',
                   '--write-out', f'{tag} HTTP %{{http_code}}\\n']
        port = args.port
        if args.target == 'local':
            if port is None:
                port = int(os.environ.get('JITCA_TLS_PORT' if scheme == 'https' else 'JITCA_HTTP_PORT',
                                          '443' if scheme == 'https' else '80'))
            if not 1 <= port <= 65535:
                raise ValueError('port must be between 1 and 65535')
            ip = ipaddress.ip_address(args.ip)
            address = f'[{ip}]' if ip.version == 6 else str(ip)
            command += ['--noproxy', '*', '--resolve', f'{host}:{port}:{address}']
            if scheme == 'https':
                # Copy public chain material so the exported bundle is portable.
                if not (args.output_dir / 'ca.crt').exists():
                    private_write(args.output_dir / 'ca.crt', args.cafile.read_bytes())
                command += ['--cacert', 'ca.crt']
        if payload is not None:
            filename = 'bodies/' + hashlib.sha256(payload).hexdigest() + '.bin'
            if not (args.output_dir / filename).exists():
                private_write(args.output_dir / filename, payload)
            command += ['--data-binary', '@' + filename]
        url = f'{scheme}://{host}' + (f':{port}' if port is not None else '') + target
        command.append(url)
        script += [f'# {tag}: {method} {host} ({event.get("time", "time unknown")})', shlex.join(command), '']
    text = '\n'.join(script) + '\n'
    private_write(args.output_dir / 'commands.sh', text.encode(), 0o700)
    manifest = {'target': args.target, 'selected': len(events), 'exported': len(prepared),
                'skipped': skipped, 'requests': [{'index': row[0], 'event': row[1]} for row in prepared]}
    private_write(args.output_dir / 'manifest.json', (json.dumps(manifest, indent=2) + '\n').encode())
    return text, len(prepared), len(skipped)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--events', type=Path, default=Path(os.environ.get('JITCA_REPLAY_EVENTS', 'state/events.jsonl')))
    parser.add_argument('--captures', type=Path, default=os.environ.get('JITCA_REPLAY_CAPTURES'))
    parser.add_argument('--output-dir', type=Path, default=Path(os.environ.get('JITCA_CURL_OUTPUT_DIR', 'curl-export')),
                        help='new directory for commands, original headers, bodies and manifest')
    parser.add_argument('--hostname', action='append', help='repeat to select multiple hosts')
    parser.add_argument('--path', help='exact path filter')
    parser.add_argument('--method')
    parser.add_argument('--latest', action='store_true', help='last event per host/method/path/query combination')
    parser.add_argument('--limit', type=int, help='last N selected events')
    parser.add_argument('--target', choices=['origin', 'local'], default=os.environ.get('JITCA_CURL_TARGET', 'origin'))
    parser.add_argument('--ip', default=os.environ.get('JITCA_REPLAY_IP', os.environ.get('JITCA_REDIRECT_IPV4', '127.0.0.1')))
    parser.add_argument('--port', type=int, default=os.environ.get('JITCA_REPLAY_PORT'))
    parser.add_argument('--cafile', type=Path, default=Path(os.environ.get('JITCA_REPLAY_CAFILE',
                        str(ROOT / 'local_deployment/aaa-certificate-services.crt'))))
    parser.add_argument('--connect-timeout', type=float, default=5)
    parser.add_argument('--timeout', type=float, default=30)
    parser.add_argument('--quiet', action='store_true', help='save commands.sh without also printing it')
    args = parser.parse_args()
    if args.limit is not None and args.limit < 1:
        parser.error('--limit must be positive')
    try:
        text, count, skipped = export(args)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(1, f'export-curl: {exc}\n')
    if not args.quiet:
        print(text, end='')
    print(f'Exported {count}; skipped {skipped}. See {args.output_dir}/manifest.json', file=sys.stderr)
    return 0 if count else 1


if __name__ == '__main__':
    raise SystemExit(main())
