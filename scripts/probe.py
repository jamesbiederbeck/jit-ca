#!/usr/bin/env python3
"""Probe a jit-ca instance: DNS lookup against IP, then HTTPS GET to IP with that SNI/Host.

Usage: probe.py <ip> <hostname> [--dns-port 53] [--port 443] [--path /] [--cafile CA.pem]

1. Sends an A query for <hostname> to <ip> (UDP) and prints the answer.
2. Connects to <ip>:<port> over TLS using <hostname> as SNI and Host header, sends an HTTP
   GET and prints the response status line and headers.
3. Prints the TLS session and certificate details (subject, issuer, serial, validity, SANs,
   key/signature algorithms, key usage, EKU, SKI/AKI, AIA, CRL DP, fingerprint), the served
   chain (Python 3.13+), and, with --cafile, each CA in that file and whether it issued the leaf.

The certificate is shown even when it is not trusted; --cafile additionally verifies the
chain against that CA and reports the result. Needs the `cryptography` package (a jitca
dependency, so run it from the project venv).
"""
from __future__ import annotations

import argparse
import hashlib
import socket
import ssl
import struct
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
RTYPES = {1: "A", 5: "CNAME", 28: "AAAA"}


def _skip_name(data: bytes, pos: int) -> int:
    while True:
        size = data[pos]
        if size & 0xC0 == 0xC0:
            return pos + 2
        pos += 1
        if size == 0:
            return pos
        pos += size


def dns_lookup(ip: str, hostname: str, port: int, timeout: float) -> list[str]:
    labels = b"".join(bytes([len(label)]) + label.encode("idna") for label in hostname.rstrip(".").split("."))
    query = struct.pack("!HHHHHH", 0x4A43, 0x0100, 1, 0, 0, 0) + labels + b"\x00" + struct.pack("!HH", 1, 1)
    print(f"== DNS: A {hostname} @ {ip}:{port}/udp")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(query, (ip, port))
        try:
            data = sock.recvfrom(4096)[0]
        except socket.timeout:
            sys.exit("   no DNS reply (timeout)")
    _, flags, qdcount, ancount = struct.unpack("!HHHH", data[:8])
    print(f"   rcode={RCODES.get(flags & 0xF, flags & 0xF)} authoritative={bool(flags & 0x400)} answers={ancount}")
    pos = 12
    for _ in range(qdcount):
        pos = _skip_name(data, pos) + 4
    addresses = []
    for _ in range(ancount):
        pos = _skip_name(data, pos)
        rtype, _, ttl, length = struct.unpack("!HHIH", data[pos:pos + 10])
        pos += 10
        if rtype == 1:
            address = socket.inet_ntoa(data[pos:pos + 4])
            addresses.append(address)
            print(f"   {RTYPES[rtype]} {address} ttl={ttl}")
        else:
            print(f"   {RTYPES.get(rtype, rtype)} (len {length}) ttl={ttl}")
        pos += length
    return addresses


def key_description(public_key) -> str:
    if isinstance(public_key, rsa.RSAPublicKey):
        return f"RSA {public_key.key_size}"
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return f"EC {public_key.curve.name}"
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519"
    return type(public_key).__name__


def _ext(cert: x509.Certificate, cls):
    try:
        return cert.extensions.get_extension_for_class(cls).value
    except x509.ExtensionNotFound:
        return None


def print_certificate(der: bytes, label: str = "leaf") -> x509.Certificate:
    cert = x509.load_der_x509_certificate(der)
    describe_certificate(cert, label)
    return cert


def describe_certificate(cert: x509.Certificate, label: str) -> None:
    print(f"== Certificate ({label})")
    print(f"   subject    : {cert.subject.rfc4514_string()}")
    print(f"   issuer     : {cert.issuer.rfc4514_string()}")
    print(f"   self-signed: {cert.subject == cert.issuer}")
    print(f"   serial     : {cert.serial_number:x}")
    print(f"   version    : {cert.version.name}")
    print(f"   not before : {cert.not_valid_before_utc.isoformat()}")
    print(f"   not after  : {cert.not_valid_after_utc.isoformat()}")
    san = _ext(cert, x509.SubjectAlternativeName)
    if san is None:
        print("   SAN        : (none)")
    else:
        names = [str(name.value) for name in san]
        print(f"   SAN        : {', '.join(names) or '(empty)'}")
    print(f"   public key : {key_description(cert.public_key())}")
    print(f"   signature  : {cert.signature_algorithm_oid._name} ({cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else 'n/a'})")
    basic = _ext(cert, x509.BasicConstraints)
    if basic is not None:
        print(f"   CA         : {basic.ca}" + (f" (pathlen={basic.path_length})" if basic.ca else ""))
    usage = _ext(cert, x509.KeyUsage)
    if usage is not None:
        names = [n for n in ("digital_signature", "content_commitment", "key_encipherment", "data_encipherment",
                             "key_agreement", "key_cert_sign", "crl_sign") if getattr(usage, n)]
        print(f"   key usage  : {', '.join(names)}")
    eku = _ext(cert, x509.ExtendedKeyUsage)
    if eku is not None:
        print(f"   ext key use: {', '.join(oid._name for oid in eku)}")
    ski = _ext(cert, x509.SubjectKeyIdentifier)
    if ski is not None:
        print(f"   SKI        : {ski.digest.hex(':')}")
    aki = _ext(cert, x509.AuthorityKeyIdentifier)
    if aki is not None and aki.key_identifier is not None:
        print(f"   AKI        : {aki.key_identifier.hex(':')}")
    aia = _ext(cert, x509.AuthorityInformationAccess)
    if aia is not None:
        for desc in aia:
            print(f"   AIA        : {desc.access_method._name} {desc.access_location.value}")
    crl = _ext(cert, x509.CRLDistributionPoints)
    if crl is not None:
        for point in crl:
            for name in point.full_name or []:
                print(f"   CRL DP     : {name.value}")
    policies = _ext(cert, x509.CertificatePolicies)
    if policies is not None:
        print(f"   policies   : {', '.join(p.policy_identifier.dotted_string for p in policies)}")
    print(f"   sha256 fp  : {cert.fingerprint(hashes.SHA256()).hex(':')}")


def signed_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    try:
        cert.verify_directly_issued_by(issuer)
        return True
    except Exception:
        return False


def print_ca_file(cafile: str, leaf: x509.Certificate) -> None:
    with open(cafile, "rb") as handle:
        data = handle.read()
    cas = x509.load_pem_x509_certificates(data)
    print(f"== CA file {cafile}: {len(cas)} certificate(s)")
    for index, ca in enumerate(cas):
        describe_certificate(ca, f"CA file #{index + 1}")
        print(f"   issued leaf: {signed_by(leaf, ca)}")


def https_get(ip: str, hostname: str, port: int, path: str, cafile: str | None, timeout: float) -> None:
    print(f"== HTTPS: GET https://{hostname}{path} via {ip}:{port} (SNI/Host={hostname})")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(["http/1.1"])
    with socket.create_connection((ip, port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=hostname) as tls:
            der = tls.getpeercert(binary_form=True)
            chain = []
            getter = getattr(tls, "get_unverified_chain", None)  # Python 3.13+
            if getter is not None:
                chain = [ssl.PEM_cert_to_DER_cert(c) if isinstance(c, str) else c for c in getter()]
            print(f"   {tls.version()}  cipher={tls.cipher()[0]}  alpn={tls.selected_alpn_protocol()}")
            request = f"GET {path} HTTP/1.1\r\nHost: {hostname}\r\nUser-Agent: jitca-probe/1\r\nAccept: */*\r\nConnection: close\r\n\r\n"
            tls.sendall(request.encode("ascii"))
            response = b""
            while chunk := tls.recv(8192):
                response += chunk
                if len(response) > 1 << 20:
                    break
    head, _, body = response.partition(b"\r\n\r\n")
    print("   --- response ---")
    for line in head.decode("latin-1").splitlines():
        print(f"   {line}")
    print(f"   [{len(body)} body byte(s)]" + (f" {body[:200].decode('utf-8', 'replace')!r}" if body else ""))
    leaf = print_certificate(der)
    if chain:
        print(f"== Served chain: {len(chain)} certificate(s)")
        for index, extra in enumerate(chain[1:], start=1):
            print_certificate(extra, f"chain #{index}")
    else:
        print("== Served chain: only the leaf is visible on this Python (<3.13); intermediates not shown")
    if cafile:
        print_ca_file(cafile, leaf)
        verifier = ssl.create_default_context(cafile=cafile)
        try:
            with socket.create_connection((ip, port), timeout=timeout) as raw:
                with verifier.wrap_socket(raw, server_hostname=hostname):
                    print(f"== Verification against {cafile}: OK (chain and hostname)")
        except ssl.SSLCertVerificationError as exc:
            print(f"== Verification against {cafile}: FAILED ({exc.verify_message})")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("ip", help="jit-ca host: DNS server and TLS endpoint")
    parser.add_argument("hostname", help="name to resolve and to request (SNI + Host header)")
    parser.add_argument("--dns-port", type=int, default=53)
    parser.add_argument("--port", type=int, default=443, help="HTTPS port on <ip>")
    parser.add_argument("--path", default="/")
    parser.add_argument("--cafile", help="CA PEM to verify the served chain against")
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()
    dns_lookup(args.ip, args.hostname, args.dns_port, args.timeout)
    https_get(args.ip, args.hostname, args.port, args.path, args.cafile, args.timeout)


if __name__ == "__main__":
    main()
