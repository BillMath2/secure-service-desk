"""Generate disposable test realm credentials locally; never print or commit secrets."""

import json
import secrets
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

root = Path(__file__).resolve().parents[1] / ".lab"
root.mkdir(exist_ok=True)
tls = root / "tls"
tls.mkdir(exist_ok=True)
refresh_certificate = not (tls / "certificate.pem").exists() or not (tls / "private.key").exists()
if not refresh_certificate:
    existing = x509.load_pem_x509_certificate((tls / "certificate.pem").read_bytes())
    refresh_certificate = existing.not_valid_after_utc <= datetime.now(UTC) + timedelta(
        minutes=5
    ) or not any(isinstance(extension.value, x509.KeyUsage) for extension in existing.extensions)
if refresh_certificate:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "service-desk-spike")])
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
    (tls / "certificate.pem").write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    (tls / "private.key").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
realm_dir = root / "keycloak"
realm_dir.mkdir(exist_ok=True)
if all(
    path.exists()
    for path in (
        root / "spike-credentials.json",
        root / "postgres-password",
        realm_dir / "realm.json",
    )
):
    print("Existing disposable spike credentials preserved.")
    raise SystemExit(0)
credentials = {
    "username": "alice",
    "password": secrets.token_urlsafe(24),
    "client_secret": secrets.token_urlsafe(32),
}
(root / "spike-credentials.json").write_text(json.dumps(credentials), encoding="utf-8")
(root / "postgres-password").write_text(secrets.token_urlsafe(32), encoding="utf-8")


def audience_scope(name: str, audience: str) -> dict[str, object]:
    return {
        "name": name,
        "protocol": "openid-connect",
        "attributes": {"include.in.token.scope": "true"},
        "protocolMappers": [
            {
                "name": audience,
                "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper",
                "config": {"included.client.audience": audience, "access.token.claim": "true"},
            }
        ],
    }


realm = {
    "realm": "service-desk-spike",
    "enabled": True,
    "sslRequired": "all",
    "registrationAllowed": False,
    "resetPasswordAllowed": False,
    "accessTokenLifespan": 120,
    "clientScopes": [
        audience_scope("agent-audience", "gateway"),
        audience_scope("knowledge:read", "knowledge"),
    ],
    "clients": [
        {
            "clientId": "web",
            "publicClient": True,
            "standardFlowEnabled": True,
            "directAccessGrantsEnabled": False,
            "redirectUris": ["http://127.0.0.1:18081/callback"],
            "attributes": {"pkce.code.challenge.method": "S256"},
            "defaultClientScopes": ["agent-audience"],
        },
        {
            "clientId": "gateway",
            "publicClient": False,
            "secret": credentials["client_secret"],
            "standardFlowEnabled": False,
            "directAccessGrantsEnabled": False,
            "fullScopeAllowed": False,
            "attributes": {"standard.token.exchange.enabled": "true"},
            "defaultClientScopes": ["knowledge:read"],
        },
        {"clientId": "knowledge", "bearerOnly": True, "publicClient": False},
    ],
    "users": [
        {
            "username": credentials["username"],
            "enabled": True,
            "emailVerified": True,
            "email": "alice@example.invalid",
            "firstName": "Alice",
            "lastName": "Synthetic",
            "credentials": [
                {"type": "password", "value": credentials["password"], "temporary": False}
            ],
        }
    ],
}
(realm_dir / "realm.json").write_text(json.dumps(realm, indent=2), encoding="utf-8")
print("Prepared disposable spike configuration in ignored .lab directory.")
