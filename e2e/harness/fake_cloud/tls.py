"""A throwaway certificate authority and loopback server certificate.

Generated once per test process with ``cryptography`` (already a Servonaut
runtime dependency). Child processes trust it through ``SSL_CERT_FILE``, which
both httpx and the standard library honour, so the fake endpoints are served
over real TLS without touching any system trust store.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import ssl
from dataclasses import dataclass
from pathlib import Path

CA_COMMON_NAME = "servonaut-e2e-test-ca"


@dataclass(frozen=True)
class TlsMaterial:
    """Paths of the generated PEM files."""

    ca_cert: Path
    server_cert: Path
    server_key: Path

    def server_context(self) -> ssl.SSLContext:
        """Return a server-side context presenting the loopback certificate."""
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(str(self.server_cert), str(self.server_key))
        return context


def generate(directory: Path) -> TlsMaterial:
    """Create a CA and a certificate for 127.0.0.1 / ::1 / localhost."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    directory.mkdir(parents=True, exist_ok=True)
    now = dt.datetime.now(dt.timezone.utc)
    not_before = now - dt.timedelta(hours=1)
    not_after = now + dt.timedelta(days=2)

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CA_COMMON_NAME)])
    ca_ski = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(ca_ski, critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    server_key = ec.generate_private_key(ec.SECP256R1())
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]))
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                    x509.IPAddress(ipaddress.ip_address("::1")),
                    x509.DNSName("localhost"),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    material = TlsMaterial(
        ca_cert=directory / "ca.pem",
        server_cert=directory / "server.pem",
        server_key=directory / "server-key.pem",
    )
    material.ca_cert.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    material.server_cert.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
    material.server_key.write_bytes(
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    material.server_key.chmod(0o600)
    return material
