import importlib.util
from pathlib import Path
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from jitca.certs import _load_ca_directory, CertificateStore
from jitca.config import load_config
from test_e2e import config_file
from dataclasses import replace

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
                .not_valid_before(now - timedelta(days=365)).not_valid_after(now + timedelta(days=10))
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
    cfg = replace(load_config(config_file(tmp_path)), issuer_mode="directory",
                  ca_dir=dst, default_issuer="Intermediate")
    store = CertificateStore(cfg)
    leaf_path, _, issued = store.get_or_issue("robot.example.test")
    leaf = x509.load_pem_x509_certificate(leaf_path.read_bytes())
    assert issued and leaf.not_valid_before_utc == intermediate.not_valid_before_utc
    assert leaf.not_valid_after_utc <= intermediate.not_valid_after_utc
    # Simulate a persisted leaf from the previous now-minus-two-days policy.
    builder = (x509.CertificateBuilder().subject_name(leaf.subject).issuer_name(leaf.issuer)
               .public_key(leaf.public_key()).serial_number(leaf.serial_number)
               .not_valid_before(now - timedelta(days=2)).not_valid_after(leaf.not_valid_after_utc))
    for ext in leaf.extensions:
        builder = builder.add_extension(ext.value, ext.critical)
    old_leaf = builder.sign(issuer_key, hashes.SHA256())
    leaf_path.write_bytes(old_leaf.public_bytes(serialization.Encoding.PEM)
                         + intermediate.public_bytes(serialization.Encoding.PEM)
                         + root.public_bytes(serialization.Encoding.PEM))
    restarted = CertificateStore(cfg)
    assert restarted.get_or_issue("robot.example.test")[2]
    repaired = x509.load_pem_x509_certificate(leaf_path.read_bytes())
    assert repaired.not_valid_before_utc == intermediate.not_valid_before_utc
    assert not restarted.get_or_issue("robot.example.test")[2]
    assert (dst / 'issuer.key').stat().st_mode & 0o777 == 0o600
    # A replacement root with the same subject must fail signature validation.
    wrong_key = ec.generate_private_key(ec.SECP256R1())
    wrong = cert(root_name, root_name, wrong_key, wrong_key)
    with pytest.raises(ValueError, match='missing parent'):
        seed.complete_chain(intermediate, [wrong])
    (dst / 'issuer.pem').write_bytes(intermediate.public_bytes(serialization.Encoding.PEM) + wrong.public_bytes(serialization.Encoding.PEM))
    with pytest.raises(Exception):
        _load_ca_directory(dst)
