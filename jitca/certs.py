from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import threading
from datetime import datetime, timedelta, timezone
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from .config import Config, canonical_hostname


def _save_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    with os.fdopen(os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as stream:
        stream.write(data)
    os.replace(temp, path)
    os.chmod(path, 0o600)


def _private_pem(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def _pub_der(key) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.DER,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)


def _sig_hash(key):
    if isinstance(key, ec.EllipticCurvePrivateKey) and key.key_size >= 384:
        return hashes.SHA384()
    return hashes.SHA256()


class CertificateStore:
    """Persistent cert+key cache with in-process singleflight issuance."""

    def __init__(self, config: Config):
        self.config = config
        self.root = config.state_dir / "certificates"
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._contexts: dict[str, ssl.SSLContext] = {}
        self._initialize_issuer()

    def _initialize_issuer(self):
        cfg = self.config
        if cfg.issuer_mode == "local":
            keyfile = self.root / "demo-root.key"
            certfile = self.root / "demo-root.crt"
            if keyfile.exists() != certfile.exists():
                raise ValueError("partial local CA state: issuer key/certificate mismatch")
            if not keyfile.exists():
                key = ec.generate_private_key(ec.SECP256R1())
                now = datetime.now(timezone.utc)
                subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "JIT CA LOCAL DEMO ROOT")])
                cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                        .public_key(key.public_key()).serial_number(x509.random_serial_number())
                        .not_valid_before(now - timedelta(days=1))
                        .not_valid_after(now + timedelta(days=3650))
                        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
                        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
                        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                       key_encipherment=False, data_encipherment=False, key_agreement=False,
                                       key_cert_sign=True, crl_sign=True, encipher_only=False,
                                       decipher_only=False), critical=True)
                        .sign(key, hashes.SHA256()))
                _save_private(keyfile, _private_pem(key))
                _save_private(certfile, cert.public_bytes(serialization.Encoding.PEM))
            self.root_ca_path = certfile
            self.issuer_cert = x509.load_pem_x509_certificate(certfile.read_bytes())
            self.issuer_key = serialization.load_pem_private_key(keyfile.read_bytes(), password=None)
            self.extra_chain = []
        else:
            self.root_ca_path = None
            self.issuer_cert = x509.load_pem_x509_certificate(cfg.issuer_cert.read_bytes())
            self.issuer_key = serialization.load_pem_private_key(cfg.issuer_key.read_bytes(), password=None)
            self.extra_chain = [x509.load_pem_x509_certificate(f.read_bytes()) for f in cfg.chain_files]
        if _pub_der(self.issuer_key) != self.issuer_cert.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo):
            raise ValueError("issuer key does not match issuer certificate")
        constraints = self.issuer_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        if not constraints.ca:
            raise ValueError("issuer certificate is not a CA")
        try:
            if not self.issuer_cert.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign:
                raise ValueError("issuer certificate lacks keyCertSign")
        except x509.ExtensionNotFound:
            pass
        now = datetime.now(timezone.utc)
        chain = [self.issuer_cert, *self.extra_chain]
        if any(c.not_valid_before_utc > now or c.not_valid_after_utc <= now for c in chain):
            raise ValueError("issuer chain not currently within X.509 validity window")
        self.not_after = min(c.not_valid_after_utc for c in chain)
        self.issuer_id = hashlib.sha256(b"".join(c.public_bytes(serialization.Encoding.DER)
                                     for c in chain)).hexdigest()[:20]

    def _path(self, hostname: str) -> Path:
        digest = hashlib.sha256((hostname + ":" + self.issuer_id + ":" + self.config.leaf_key)
                                .encode()).hexdigest()
        return self.root / digest

    def _valid(self, hostname: str, cert_path: Path, key_path: Path) -> bool:
        if not cert_path.exists() or not key_path.exists():
            return False
        try:
            # Split off the first certificate when a chain is concatenated.
            cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            remaining = cert.not_valid_after_utc - datetime.now(timezone.utc)
            return hostname in san.get_values_for_type(x509.DNSName) and remaining > timedelta(days=1)
        except (ValueError, x509.ExtensionNotFound):
            return False

    def get_or_issue(self, hostname: str) -> tuple[Path, Path, bool]:
        hostname = canonical_hostname(hostname)
        if hostname not in self.config.endpoints:
            raise PermissionError(f"hostname not approved: {hostname}")
        with self._lock:
            directory = self._path(hostname)
            cert_path, key_path = directory / "fullchain.pem", directory / "key.pem"
            if self._valid(hostname, cert_path, key_path):
                return cert_path, key_path, False
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048) if self.config.leaf_key == "rsa2048" else ec.generate_private_key(ec.SECP256R1())
            now = datetime.now(timezone.utc)
            leaf_end = min(now + timedelta(days=self.config.leaf_days), self.not_after - timedelta(minutes=1))
            if leaf_end <= now:
                raise ValueError("issuer expires too soon to issue a certificate")
            leaf_start = max(now - timedelta(days=2), self.issuer_cert.not_valid_before_utc)
            cert = (x509.CertificateBuilder()
                    .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
                    .issuer_name(self.issuer_cert.subject).public_key(key.public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(leaf_start).not_valid_after(leaf_end)
                    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                    .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                    .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.issuer_key.public_key()), critical=False)
                    .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                   key_encipherment=self.config.leaf_key == "rsa2048", data_encipherment=False, key_agreement=False,
                                   key_cert_sign=False, crl_sign=False, encipher_only=False,
                                   decipher_only=False), critical=True)
                    .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                    .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
                    .sign(self.issuer_key, _sig_hash(self.issuer_key)))
            chain = [self.issuer_cert, *self.extra_chain] if self.config.issuer_mode == "external" else []
            chain_pem = cert.public_bytes(serialization.Encoding.PEM) + b"".join(
                item.public_bytes(serialization.Encoding.PEM) for item in chain)
            _save_private(key_path, _private_pem(key))
            _save_private(cert_path, chain_pem)
            metadata = json.dumps({"hostname": hostname, "issuer_id": self.issuer_id,
                                  "not_before": cert.not_valid_before_utc.isoformat(),
                                  "not_after": cert.not_valid_after_utc.isoformat(),
                                  "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex()}, indent=2)
            _save_private(directory / "metadata.json", metadata.encode())
            self._contexts.pop(hostname, None)
            return cert_path, key_path, True

    def ssl_context(self, hostname: str) -> tuple[ssl.SSLContext, bool]:
        with self._lock:
            cert_path, key_path, issued = self.get_or_issue(hostname)
            context = self._contexts.get(hostname)
            if context is None or issued:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                context.set_alpn_protocols(["http/1.1"])
                context.load_cert_chain(str(cert_path), str(key_path))
                self._contexts[hostname] = context
            return context, issued

    def all_metadata(self) -> list[dict]:
        return sorted((json.loads(f.read_text()) for f in self.root.glob("*/metadata.json")),
                      key=lambda x: x["hostname"])
