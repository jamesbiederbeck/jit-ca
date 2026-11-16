#!/usr/bin/env python3
"""Stage complete operator CA chains, then seed the local Compose CA volume."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import ssl
import subprocess
import tempfile

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parents[1]


def complete_chain(cert, candidates):
    chain = [cert]
    while chain[-1].issuer != chain[-1].subject:
        for parent in candidates:
            try:
                chain[-1].verify_directly_issued_by(parent)
            except (ValueError, TypeError, InvalidSignature):
                # cryptography raises InvalidSignature for a same-name wrong key.
                continue
            if parent in chain:
                raise ValueError("cycle in CA chain")
            chain.append(parent)
            break
        else:
            raise ValueError(f"missing parent for {chain[-1].subject.rfc4514_string()}; supply --chain")
    return chain


def stage(source, destination, parents):
    pairs = sorted(source.glob('*.pem'))
    if not pairs:
        raise ValueError(f"no CA pairs in {source}; run git submodule update --init")
    prepared = []
    for pem in pairs:
        key_path = pem.with_suffix('.key')
        certs = x509.load_pem_x509_certificates(pem.read_bytes())
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        pub = lambda k: k.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        if pub(key.public_key()) != pub(certs[0].public_key()):
            raise ValueError(f"key mismatch: {pem.name}")
        if not certs[0].extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ValueError(f"not a CA: {pem.name}")
        chain = complete_chain(certs[0], certs[1:] + parents)
        prepared.append((pem.name, b''.join(c.public_bytes(serialization.Encoding.PEM) for c in chain), key_path))
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    for name, bundle, key_path in prepared:
        for path, data in ((destination / name, bundle), (destination / key_path.name, key_path.read_bytes())):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'wb') as f:
                os.fchmod(f.fileno(), 0o600)
                f.write(data)
        print(f"staged {name} (complete CA chain)")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, default=ROOT / 'third_party/emudrahahahahaha')
    p.add_argument('--chain', type=Path, action='append', default=[], help='additional parent/root PEM bundle; repeatable')
    p.add_argument('--output-dir', type=Path, help='stage only, without Docker')
    p.add_argument('--volume', default='ca-src-private')
    p.add_argument('--uid', type=int, default=int(os.environ.get('LOCAL_UID', '1000')))
    p.add_argument('--gid', type=int, default=int(os.environ.get('LOCAL_GID', '1000')))
    p.add_argument('--image', default='alpine:3.21', help='Docker helper image')
    args = p.parse_args()
    parents = [x509.load_der_x509_certificate(c) for c in ssl.create_default_context().get_ca_certs(binary_form=True)]
    bundled_root = ROOT / 'local_deployment/aaa-certificate-services.crt'
    parents.extend(x509.load_pem_x509_certificates(bundled_root.read_bytes()))
    for path in args.chain:
        parents.extend(x509.load_pem_x509_certificates(path.read_bytes()))
    with tempfile.TemporaryDirectory(prefix='jitca-seed-') as tmp:
        staged = args.output_dir or Path(tmp)
        stage(args.source, staged, parents)
        if args.output_dir:
            return
        subprocess.run(['docker', 'volume', 'create', args.volume], check=True)
        subprocess.run(['docker', 'run', '--rm', '--network=none', '-v', f'{staged.resolve()}:/src:ro',
                        '-v', f'{args.volume}:/dest', args.image, 'sh', '-ec',
                        'for f in /src/*.pem /src/*.key; do cp "$f" /dest/; chmod 600 "/dest/${f##*/}"; chown "$1:$2" "/dest/${f##*/}"; done',
                        'seed', str(args.uid), str(args.gid)], check=True)
        print(f'Seeded {args.volume}; restart local deployment to import the updated chains.')


if __name__ == '__main__':
    main()
