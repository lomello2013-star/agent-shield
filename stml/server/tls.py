"""TLS/mTLS helpers for STML (S2 prod slice)."""

from __future__ import annotations

import ipaddress
import ssl
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _write_key(path: Path, key: ec.EllipticCurvePrivateKey) -> None:
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))


def generate_dev_certs(directory: str | Path) -> dict[str, str]:
    """Create CA + server + client certs for local mTLS tests (ECC P-256)."""
    d = Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    ca_key = _key()
    ca_name = _name("STML Dev CA")
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name).issuer_name(ca_name)
        .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    def leaf(cn: str, eku: x509.ObjectIdentifier, san: bool = False) -> tuple:
        key = _key()
        builder = (
            x509.CertificateBuilder()
            .subject_name(_name(cn)).issuer_name(ca_name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
        )
        if san:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]), critical=False)
        cert = builder.sign(ca_key, hashes.SHA256())
        return key, cert

    server_key, server_cert = leaf("localhost", ExtendedKeyUsageOID.SERVER_AUTH, san=True)
    client_key, client_cert = leaf("stml-client", ExtendedKeyUsageOID.CLIENT_AUTH)

    paths = {
        "ca": d / "ca.pem",
        "server_cert": d / "server.pem",
        "server_key": d / "server.key",
        "client_cert": d / "client.pem",
        "client_key": d / "client.key",
    }
    paths["ca"].write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    paths["server_cert"].write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
    _write_key(paths["server_key"], server_key)
    paths["client_cert"].write_bytes(client_cert.public_bytes(serialization.Encoding.PEM))
    _write_key(paths["client_key"], client_key)
    return {k: str(v) for k, v in paths.items()}


def make_server_context(cert: str, key: str, ca: str = "",
                        require_client_cert: bool = True) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    if ca:
        ctx.load_verify_locations(ca)
    ctx.verify_mode = ssl.CERT_REQUIRED if require_client_cert else ssl.CERT_NONE
    return ctx


def make_client_context(ca: str, cert: str = "", key: str = "") -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_verify_locations(ca)
    if cert and key:
        ctx.load_cert_chain(cert, key)
    return ctx
