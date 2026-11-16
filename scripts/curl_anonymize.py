"""Standard-library transformations for curl exports; original captures stay untouched."""
from __future__ import annotations

import base64
import copy
from datetime import datetime, timedelta
import hashlib
import hmac
import io
import json
import re
import secrets
import uuid
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

UUID_RE = re.compile(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}')
IDENTITIES = {'esn', 'serial', 'serialnumber', 'diid', 'deviceid', 'deviceinstanceid',
              'identifier', 'partitionkey', 'tvadid', 'ifa', 'did', 'sid', 'sessionid',
              'castname', 'bootid', 'amzsdkinvocationid'}
CREDENTIALS = {'authorization', 'proxyauthorization', 'xsentryauth', 'cookie', 'setcookie',
               'token', 'token2', 'h', 'h2', 'apikey', 'xapikey', 'auth', 'sentrykey', 'sentrysecret', 'password', 'secret', 'credential',
               'credentials', 'accesskeyid', 'secretaccesskey', 'xamzsecuritytoken'}
TIMES = {'timestamp', 'ts', 'started', 'time', 'sentat', 'oobecompletiontimestamp'}
KV_RE = re.compile(r'(^|,)([A-Za-z_][A-Za-z_0-9]*)=([^,]*)')


def normalize(key):
    return re.sub('[^a-z0-9]', '', key.lower())


class Anonymizer:
    def __init__(self, identities=False, credentials=False, shift=0, seed=None, fields=()):
        self.identities = identities
        self.credentials = credentials
        self.shift = shift
        self.key = (seed or secrets.token_hex(32)).encode()
        self.fields = IDENTITIES | {normalize(x) for x in fields}
        self.extra_fields = {normalize(x) for x in fields}
        self.replacements = {}

    def digest(self, value):
        return hmac.new(self.key, str(value).encode('utf-8', 'surrogateescape'), hashlib.sha256).digest()

    def identity(self, value, field=''):
        if isinstance(value, list):
            return [self.identity(x, field) for x in value]
        if isinstance(value, dict):
            return self.transform(value)
        if value is None or isinstance(value, bool) or value == '':
            return value
        raw = str(value)
        if raw in self.replacements:
            existing = self.replacements[raw]
            return int(existing) if isinstance(value, int) else existing
        digest = self.digest(raw)
        if isinstance(value, int):
            new = int.from_bytes(digest[:4], 'big') % 1000000
        elif isinstance(value, str) and raw.isdigit():
            new = str(int.from_bytes(digest[:4], 'big') % (10 ** len(raw))).zfill(len(raw))
        elif UUID_RE.fullmatch(raw):
            new = str(uuid.UUID(bytes=digest[:16], version=4))
        elif field == 'castname':
            new = 'TV-' + digest.hex()[:8]
        elif field in ('esn', 'serial', 'serialnumber'):
            new = ('ANON' + digest.hex().upper())[:max(8, len(raw))]
        else:
            new = 'anon-' + digest.hex()[:20]
        self.replacements[raw] = str(new)
        return new

    def collect(self, value, field=''):
        """Discover identifiers before transforming any embedded occurrences."""
        if isinstance(value, dict):
            for key, child in value.items():
                self.collect(child, normalize(key))
        elif isinstance(value, list):
            for child in value:
                self.collect(child, field)
        elif isinstance(value, str):
            if (self.identities and field in self.fields) or field in self.extra_fields:
                self.identity(value, field)
            try:
                child = json.loads(value)
            except ValueError:
                child = None
            if isinstance(child, (dict, list)):
                self.collect(child)
            if field == 'data':
                try:
                    self.collect(base64.b64decode(value, validate=True).decode('utf-8', 'surrogateescape'))
                except ValueError:
                    pass
            if KV_RE.match(value):
                for match in KV_RE.finditer(value):
                    self.collect(match[3], normalize(match[2]))

    def timestamp(self, value):
        if not self.shift or value in (None, '', 0, '0'):
            return value
        if isinstance(value, (int, float)) or (isinstance(value, str) and value.isdigit()):
            number = float(value)
            shifted = number + self.shift * (1000 if abs(number) > 100000000000 else 1)
            return str(int(shifted)) if isinstance(value, str) else int(shifted) if isinstance(value, int) else shifted
        if isinstance(value, str):
            try:
                dt = datetime.fromisoformat(value.replace('Z', '+00:00')) + timedelta(seconds=self.shift)
                result = dt.isoformat(sep=' ' if ' ' in value else 'T')
                return result.replace('+00:00', 'Z') if value.endswith('Z') else result
            except ValueError:
                pass
        return value

    def text(self, text):
        try:
            nested = json.loads(text)
        except ValueError:
            nested = None
        if isinstance(nested, (dict, list)):
            return json.dumps(self.transform(nested), separators=(',', ':'))
        if text.startswith(('https://', 'http://')):
            parsed = urlsplit(text)
            netloc = parsed.netloc
            if self.credentials and parsed.username:
                netloc = 'REPLACE_PUBLIC_KEY@' + netloc.rsplit('@', 1)[-1]
            path = parsed.path
            if self.identities:
                path = re.sub(r'(/dms/api/devices/user/)([^/]+)',
                              lambda m: m[1] + str(self.identity(m[2])), path)
            query = self.transform(parse_qs(parsed.query, keep_blank_values=True))
            return urlunsplit((parsed.scheme, netloc, self.replace_known(path), urlencode(query, doseq=True), parsed.fragment))
        if KV_RE.match(text):
            text = KV_RE.sub(lambda m: m[1] + m[2] + '=' + str(self.transform(m[3], normalize(m[2]))), text)
        return self.replace_known(text)

    def replace_known(self, text):
        if not (self.identities or self.extra_fields):
            return text
        for old, new in sorted(self.replacements.items(), key=lambda x: -len(x[0])):
            # Only discover string IDs; do not globally replace short numeric values.
            if len(old) >= 4:
                text = text.replace(old, new)
        if self.identities:
            known_new = set(self.replacements.values())
            text = UUID_RE.sub(lambda m: m[0] if m[0] in known_new else str(self.identity(m[0])), text)
        return text

    def transform(self, value, field=''):
        if self.credentials and field in CREDENTIALS:
            if isinstance(value, list):
                return ['REPLACE_CREDENTIAL' for _ in value]
            if field == 'authorization' and isinstance(value, str):
                return value.split(' ', 1)[0] + ' REPLACE_CREDENTIAL'
            return 'REPLACE_CREDENTIAL'
        if (self.identities and field in self.fields) or field in self.extra_fields:
            return self.identity(value, field)
        if field in TIMES and self.shift:
            if isinstance(value, list):
                return [self.timestamp(x) for x in value]
            return self.timestamp(value)
        if isinstance(value, dict):
            result = {k: self.transform(v, normalize(k)) for k, v in value.items()}
            if self.shift and isinstance(result.get('timestamp'), str):
                try:
                    shifted = datetime.fromisoformat(result['timestamp'].replace('Z', '+00:00'))
                    for component in ('year', 'month', 'day', 'hour'):
                        if component in result:
                            result[component] = getattr(shifted, component)
                except ValueError:
                    pass
            return result
        if isinstance(value, list):
            return [self.transform(v, field) for v in value]
        if isinstance(value, str):
            if field in CREDENTIALS:  # retain usable credentials unless explicitly requested
                return value
            if field == 'data':
                try:
                    decoded = base64.b64decode(value, validate=True)
                    return base64.b64encode(self.payload(decoded)).decode()
                except ValueError as exc:
                    raise ValueError('cannot transform base64 Data record') from exc
            return self.text(value)
        return value

    def payload(self, raw):
        try:
            obj = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            obj = None
        if isinstance(obj, (dict, list)):
            self.collect(obj)
            return json.dumps(self.transform(obj), separators=(',', ':')).encode()
        # Sentry envelopes contain an envelope header followed by item header/payload pairs.
        stream = io.BytesIO(raw)
        try:
            envelope = json.loads(stream.readline())
            if not isinstance(envelope, dict):
                raise ValueError()
            self.collect(envelope)
            chunks = [json.dumps(self.transform(envelope), separators=(',', ':')).encode() + b'\n']
            count = 0
            while True:
                line = stream.readline()
                if not line:
                    break
                if not line.strip():
                    continue
                header = json.loads(line)
                length = header.get('length')
                item = stream.read(length) if isinstance(length, int) else stream.readline().rstrip(b'\n')
                if isinstance(length, int) and len(item) != length:
                    raise ValueError('truncated envelope item')
                if isinstance(length, int) and stream.read(1) not in (b'\n', b''):
                    raise ValueError('invalid envelope boundary')
                new_item = self.payload(item)
                header = self.transform(header)
                header['length'] = len(new_item)
                chunks.extend((json.dumps(header, separators=(',', ':')).encode()+b'\n', new_item+b'\n'))
                count += 1
            if count:
                return b''.join(chunks)
        except (ValueError, TypeError, UnicodeDecodeError):
            pass
        text = raw.decode('utf-8', 'surrogateescape')
        if KV_RE.match(text):
            self.collect(text)
            return self.text(text).encode('utf-8', 'surrogateescape')
        raise ValueError('unsupported body format for anonymization; original bytes not exported')

    def event(self, event, payload):
        event = copy.deepcopy(event)
        # These fields describe the original capture and must not survive in the sanitized manifest.
        for key in ('request_preview', 'request_sha256', 'request_capture', 'request_bytes'):
            event.pop(key, None)
        if self.identities:
            event.get('request_headers', {}).pop('if-none-match', None)
        self.collect(event)
        if self.identities and event.get('source'):
            event['source'] = '192.0.2.' + str(1 + self.digest(event['source'])[0] % 253)
        if self.identities:
            event['path'] = re.sub(r'(/dms/api/devices/user/)([^/]+)',
                                   lambda m: m[1] + str(self.identity(m[2])), event.get('path', ''))
        event = self.transform(event)
        if payload is not None:
            digest = hashlib.sha256(payload).hexdigest()
            event['request_bytes'] = len(payload)
            if 'content-length' in event.get('request_headers', {}):
                event['request_headers']['content-length'] = str(len(payload))
            event['request_sha256'] = digest
            event['request_capture'] = {'file': 'bodies/' + digest + '.bin', 'bytes': len(payload), 'transformed': True}
            event['request_preview'] = '[see transformed body]'
        else:
            event['request_bytes'] = 0
        return event
