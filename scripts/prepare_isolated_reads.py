"""Stage role-specific files; only this trusted operator script reads shared secrets."""

import json
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from psycopg.conninfo import conninfo_to_dict, make_conninfo

from service_desk.read_process import FILES, read_material

ROOT = Path(__file__).resolve().parents[1]


def issue_leaf(target: Path, service: str, ca: x509.Certificate, ca_key: rsa.RSAPrivateKey) -> None:
    now = datetime.now(UTC)
    pair = [target / "certificate.pem", target / "private.key"]
    if pair[0].exists() != pair[1].exists():
        raise ValueError("Partial read-service certificate; inspect before retrying")
    if not pair[0].exists():
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "desk-" + service)]))
            .issuer_name(ca.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(ca.not_valid_after_utc)
            .add_extension(
                x509.SubjectAlternativeName([x509.IPAddress(IPv4Address("127.0.0.1"))]), False
            )
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                True,
            )
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
            .sign(ca_key, hashes.SHA256())
        )
        pair[1].write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        pair[0].write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    cert = x509.load_pem_x509_certificate(pair[0].read_bytes())
    cert.verify_directly_issued_by(ca)
    if cert.not_valid_after_utc <= now + timedelta(hours=1):
        raise ValueError("Read-service certificate requires operator rotation")


def prepare(root: Path = ROOT) -> None:
    identity = root / ".lab/phase2"
    database = root / ".lab/phase2-read"
    destination = root / ".lab/phase3-reads"
    ca = x509.load_pem_x509_certificate((identity / "tls/certificate.pem").read_bytes())
    ca_key = serialization.load_pem_private_key((identity / "tls/private.key").read_bytes(), None)
    if not isinstance(ca_key, rsa.RSAPrivateKey):
        raise ValueError("Unsupported lab CA")
    now = datetime.now(UTC)
    if ca.not_valid_after_utc <= now + timedelta(hours=1):
        raise ValueError("Lab CA requires rotation before preparing read services")
    for service in ("knowledge", "tickets"):
        target = destination / service
        target.mkdir(parents=True, exist_ok=True)
        if set(p.name for p in target.iterdir()) - FILES:
            raise ValueError("Unexpected file in read-service directory")
        issue_leaf(target, service, ca, ca_key)
        options = conninfo_to_dict((database / (service + ".dsn")).read_text())
        options["host"] = "host.docker.internal"
        (target / "database.dsn").write_text(make_conninfo("", **options), encoding="utf-8")
        (target / "identities.json").write_text(
            json.dumps(json.loads((identity / "identities.json").read_text())), encoding="utf-8"
        )
        (target / "trust.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        read_material(target, service)


if __name__ == "__main__":
    try:
        prepare()
    except Exception:
        raise SystemExit("Read-service preparation failed; inspect local configuration") from None
    print("Prepared scoped read-service material; existing leaf keys and credentials preserved.")
