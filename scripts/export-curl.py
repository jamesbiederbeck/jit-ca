#!/usr/bin/env python3
"""Export captured http_request events as a portable shell script of curl commands.

Never executes curl. Preserves original values unless anonymization is requested.
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
sys.path.insert(0, str(Path(__file__).resolve().parent))
from curl_anonymize import Anonymizer
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
    transformed = bool(args.anonymize or args.anonymize_credentials or args.anonymize_field or args.shift_time_seconds)
    sanitizer = Anonymizer(args.anonymize, args.anonymize_credentials, args.shift_time_seconds,
                           args.anonymize_seed, args.anonymize_field)
    # Collect identifiers across selected requests before rewriting embedded strings.
    if transformed:
        for candidate in events:
            sanitizer.collect({k: v for k, v in candidate.items()
                               if k not in ('request_preview', 'request_capture')})

    for index, event in enumerate(events, 1):
        try:
            payload = body_bytes(event, captures)
            event = dict(event, request_headers={k.lower(): v for k, v in event.get('request_headers', {}).items()})
            original_aws = event.get('request_headers', {}).get('authorization', '').startswith('AWS4-HMAC-SHA256')
            if transformed:
                if payload is not None:
                    payload = sanitizer.payload(payload)
                event = sanitizer.event(event, payload)
            headers = dict(event.get('request_headers', {}))
            resign = args.aws_resign and original_aws
            aws_invalid = original_aws and transformed
            if resign or aws_invalid:
                headers.pop('authorization', None)
                headers.pop('x-amz-date', None)
                headers.pop('x-amz-security-token', None)
                if payload is not None:
                    headers['x-amz-content-sha256'] = hashlib.sha256(payload).hexdigest()
                if not resign:
                    headers['authorization'] = 'AWS4-HMAC-SHA256 REPLACE_WITH_NEW_SIGNATURE'
                # Do not retain the original key ID/signature in manifest metadata.
                event['request_headers'] = headers
                event['aws_authentication'] = 'resign from environment' if resign else 'fresh signature required'
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
            prepared.append((index, event, host, method, scheme, target, ''.join(header_lines), payload, resign))
        except (OSError, ValueError, KeyError, TypeError) as exc:
            skipped.append({'event_index': index, 'host': event.get('hostname'), 'reason': 'capture unavailable or unsupported for anonymization' if transformed else str(exc)})
    args.output_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    for name in ('headers', 'bodies'):
        (args.output_dir / name).mkdir(mode=0o700)
    script = ['#!/usr/bin/env bash', 'set -euo pipefail', 'umask 077',
              'cd "$(dirname "${BASH_SOURCE[0]}")"', 'mkdir -p responses',
              '# Export only: running this file sends the recorded requests.',
              '# Query strings are reconstructed; use --aws-resign when exporting to refresh AWS signatures.',
              'aws_session=()',
              '[[ -z ${AWS_SESSION_TOKEN:-} ]] || aws_session=(--header "X-Amz-Security-Token: $AWS_SESSION_TOKEN")', '']
    for index, event, host, method, scheme, target, header_text, payload, resign in prepared:
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
        rendered = shlex.join(command)
        if resign:
            match = re.fullmatch(r'(kinesis|firehose)\.([a-z0-9-]+)\.amazonaws\.com', host)
            if match is None:
                raise ValueError('--aws-resign only supports captured Kinesis/Firehose hosts')
            service, region = match.groups()
            rendered += ' --aws-sigv4 ' + shlex.quote(f'aws:amz:{region}:{service}')
            rendered += ' --user "${AWS_ACCESS_KEY_ID:?Set AWS_ACCESS_KEY_ID}:${AWS_SECRET_ACCESS_KEY:?Set AWS_SECRET_ACCESS_KEY}"'
            rendered += ' "${aws_session[@]}"'
        rendered += ' ' + shlex.quote(url)
        script += [f'# {tag}: {method} {host} ({event.get("time", "time unknown")})', rendered, '']
    text = '\n'.join(script) + '\n'
    private_write(args.output_dir / 'commands.sh', text.encode(), 0o700)
    manifest = {'target': args.target, 'selected': len(events), 'exported': len(prepared),
                'anonymization': {'identifiers': args.anonymize, 'credential_placeholders': args.anonymize_credentials,
                                  'time_shift_seconds': args.shift_time_seconds, 'extra_fields': args.anonymize_field},
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
    parser.add_argument('--anonymize', action='store_true', help='replace device, advertising, session and serial IDs consistently')
    parser.add_argument('--anonymize-credentials', action='store_true', help='replace auth, cookie, token and Sentry DSN keys with placeholders')
    parser.add_argument('--anonymize-field', action='append', default=[], metavar='NAME', help='additional field/header/query name to pseudonymize')
    parser.add_argument('--anonymize-seed', default=os.environ.get('JITCA_ANONYMIZE_SEED'), help='stable replacements across exports; default is random per export')
    parser.add_argument('--shift-time-seconds', type=int, default=0, help='shift absolute timestamps, preserving durations; 0 leaves times unchanged')
    parser.add_argument('--aws-resign', action='store_true', help='generate AWS signing from AWS_ACCESS_KEY_ID/SECRET_ACCESS_KEY at execution time')
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
