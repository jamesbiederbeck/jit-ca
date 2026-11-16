import importlib.util
from pathlib import Path
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from jitca.certs import _load_ca_directory

spec = importlib.util.spec_from_file_location('seed', Path(__file__).resolve().parents[1] / 'scripts/seed-ca-volume.py')
seed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(seed)


def test_seed_and_load_complete_chain(tmp_path):
    root_key = ec.generate_private_key(ec.SECP256R1())
    issuer_key = ec.generate_private_key(ec.SECP256R1())
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Root')])
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Intermediate')])
    now = datetime.now(timezone.utc)
    def cert(subject, issuer, key, signer):
        return (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=10))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
                .sign(signer, hashes.SHA256()))
    root = cert(root_name, root_name, root_key, root_key)
    intermediate = cert(name, root_name, issuer_key, root_key)
    src = tmp_path / 'src'
    src.mkdir()
    (src / 'issuer.pem').write_bytes(intermediate.public_bytes(serialization.Encoding.PEM))
    (src / 'issuer.key').write_bytes(issuer_key.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    dst = tmp_path / 'dst'
    with pytest.raises(ValueError, match='missing parent'):
        seed.stage(src, dst, [])
    assert not dst.exists()
    seed.stage(src, dst, [root])
    loaded = _load_ca_directory(dst)['issuer']
    assert loaded.chain == (root,)
    assert (dst / 'issuer.key').stat().st_mode & 0o777 == 0o600
    # A replacement root with the same subject must fail signature validation.
    wrong_key = ec.generate_private_key(ec.SECP256R1())
    wrong = cert(root_name, root_name, wrong_key, wrong_key)
    with pytest.raises(ValueError, match='missing parent'):
        seed.complete_chain(intermediate, [wrong])
    (dst / 'issuer.pem').write_bytes(intermediate.public_bytes(serialization.Encoding.PEM) + wrong.public_bytes(serialization.Encoding.PEM))
    with pytest.raises(Exception):
        _load_ca_directory(dst)
