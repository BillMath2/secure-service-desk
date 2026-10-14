"""Create a separate disposable identity realm. Never print generated credentials."""

import argparse
import json
import secrets
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from service_desk.core.auth.lab import ISSUER, realm_configuration, subject_for
from service_desk.fixtures import load_fixtures

ROOT = Path(__file__).resolve().parents[1]


def write_web_credentials(root: Path) -> None:
    credentials = json.loads((root / "credentials.json").read_text())
    (root / "web-client.json").write_text(
        json.dumps({"clients": {k: credentials["clients"][k] for k in ("web", "gateway")}}),
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--refresh-realm",
        action="store_true",
        help="Regenerate realm from preserved secrets; stop Phase 2 services first",
    )
    args = parser.parse_args()
    root = ROOT / ".lab/phase2"
    root.mkdir(parents=True, exist_ok=True)
    expected = [
        root / p
        for p in (
            "credentials.json",
            "identities.json",
            "keycloak/realm.json",
            "tls/certificate.pem",
            "tls/private.key",
        )
    ]
    if any(p.exists() for p in expected):
        if not all(p.exists() for p in expected):
            raise SystemExit("Partial phase2 configuration; inspect it before preparing again.")
        certificate = x509.load_pem_x509_certificate((root / "tls/certificate.pem").read_bytes())
        if certificate.not_valid_after_utc <= datetime.now(UTC) + timedelta(minutes=5):
            raise SystemExit(
                "Stop Phase 2 services and rotate the expired disposable configuration."
            )
        if args.refresh_realm:
            credentials = json.loads((root / "credentials.json").read_text())
            fixtures = load_fixtures(ROOT / "fixtures/company.json")
            (root / "keycloak/realm.json").write_text(
                json.dumps(
                    realm_configuration(fixtures, credentials["clients"], credentials["users"]),
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
        write_web_credentials(root)
        print("Existing Phase 2 configuration preserved; scoped browser credentials refreshed.")
        return
    (root / "tls").mkdir(exist_ok=True)
    (root / "keycloak").mkdir(exist_ok=True)
    fixtures = load_fixtures(ROOT / "fixtures/company.json")
    clients = {name: secrets.token_urlsafe(32) for name in ("web", "gateway", "executor", "worker")}
    passwords = {p.id: secrets.token_urlsafe(24) for p in fixtures.principals if p.kind == "human"}
    credentials = {"clients": clients, "users": passwords}
    (root / "credentials.json").write_text(json.dumps(credentials), encoding="utf-8")
    write_web_credentials(root)
    (root / "identities.json").write_text(
        json.dumps(
            [{"issuer": ISSUER, "subject": subject_for(p), "principal_id": p} for p in passwords],
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (root / "keycloak/realm.json").write_text(
        json.dumps(
            realm_configuration(fixtures, clients, passwords),
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "service-desk-phase2")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=7))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(IPv4Address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    (root / "tls/certificate.pem").write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    (root / "tls/private.key").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    print("Prepared synthetic Phase 2 identity configuration under ignored .lab/phase2.")


if __name__ == "__main__":
    main()
