from datetime import datetime, timedelta, timezone
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from jitca.config import load_config

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "discover-issuers.sh"
EXAMPLE = Path(__file__).resolve().parent.parent / "config.example.toml"

pytestmark = pytest.mark.skipif(
    not all(shutil.which(tool) for tool in ("openssl", "rg", "bash")),
    reason="discover-issuers.sh needs bash, openssl and ripgrep")


def write_pair(directory: Path, stem: str, cn: str, *, ca: bool, key_usage: bool = True):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - timedelta(days=1))
               .not_valid_after(now + timedelta(days=365))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if ca and key_usage:
        builder = builder.add_extension(x509.KeyUsage(
            digital_signature=False, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
            encipher_only=False, decipher_only=False), critical=True)
    cert = builder.sign(key, hashes.SHA256())
    (directory / f"{stem}.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (directory / f"{stem}.key").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))


def run(*args, cwd=None):
    return subprocess.run(["bash", str(SCRIPT), *map(str, args)], capture_output=True,
                          text=True, cwd=cwd)


@pytest.fixture
def workdir(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "config.toml").write_text(EXAMPLE.read_text())
    return tmp_path


def test_single_ca_sets_directory_mode_and_default_issuer(workdir):
    write_pair(workdir / "src", "ov", "Test OV TLS CA", ca=True)
    result = run(workdir / "src", workdir / "config.toml")
    assert result.returncode == 0, result.stderr
    ca_dir = workdir / "issuer" / "cas"
    assert (ca_dir / "ov.pem").exists() and (ca_dir / "ov.key").exists()
    cfg = load_config(workdir / "config.toml")
    assert cfg.issuer_mode == "directory"
    assert cfg.default_issuer == "Test OV TLS CA"
    assert cfg.ca_dir == ca_dir.resolve()


def test_filters_non_ca_orphans_and_ignores_filenames(workdir):
    src = workdir / "src"
    write_pair(src, "looks-like-a-ca", "Leaf Not CA", ca=False)
    write_pair(src, "orphan", "Orphan CA", ca=True)
    (src / "orphan.key").unlink()
    write_pair(src, "leaf-named", "Real CA", ca=True)
    result = run(src, workdir / "config.toml")
    assert result.returncode == 0, result.stderr
    assert "orphan" in result.stderr
    staged = sorted(p.name for p in (workdir / "issuer" / "cas").iterdir())
    assert staged == ["leaf-named.key", "leaf-named.pem"]
    assert load_config(workdir / "config.toml").default_issuer == "Real CA"


def test_staged_files_are_private(workdir):
    write_pair(workdir / "src", "ov", "Test OV TLS CA", ca=True)
    assert run(workdir / "src", workdir / "config.toml").returncode == 0
    ca_dir = workdir / "issuer" / "cas"
    assert stat.S_IMODE(ca_dir.stat().st_mode) == 0o700
    for path in ca_dir.iterdir():
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_multiple_cas_leave_default_issuer_unset(workdir):
    write_pair(workdir / "src", "ov", "Test OV TLS CA", ca=True)
    write_pair(workdir / "src", "ev", "Test EV TLS CA", ca=True)
    result = run(workdir / "src", workdir / "config.toml")
    assert result.returncode == 0, result.stderr
    assert "multiple issuers found" in result.stderr
    text = (workdir / "config.toml").read_text()
    assert 'mode = "directory"' in text
    assert "\ndefault_issuer" not in text
    # Directory mode with no selector is rejected until the operator picks one.
    with pytest.raises(ValueError, match="default_issuer"):
        load_config(workdir / "config.toml")


def test_no_ca_pairs_fails_and_leaves_config_alone(workdir):
    write_pair(workdir / "src", "leaf", "Leaf Not CA", ca=False)
    before = (workdir / "config.toml").read_text()
    result = run(workdir / "src", workdir / "config.toml")
    assert result.returncode != 0
    assert "no SSL-server CA pairs" in result.stderr
    assert (workdir / "config.toml").read_text() == before


def test_missing_arguments_and_paths(workdir):
    assert run().returncode != 0
    assert run(workdir / "nope", workdir / "config.toml").returncode != 0
    assert run(workdir / "src", workdir / "nope.toml").returncode != 0


def test_explicit_ca_dir_and_rerun_is_idempotent(workdir):
    write_pair(workdir / "src", "ov", "Test OV TLS CA", ca=True)
    assert run(workdir / "src", workdir / "config.toml", workdir / "mycas").returncode == 0
    assert (workdir / "mycas" / "ov.pem").exists()
    first = (workdir / "config.toml").read_text()
    assert run(workdir / "src", workdir / "config.toml").returncode == 0
    assert (workdir / "config.toml").read_text() == first
    assert load_config(workdir / "config.toml").ca_dir == (workdir / "mycas").resolve()
