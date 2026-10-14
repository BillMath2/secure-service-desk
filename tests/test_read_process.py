"""Scoped material, leaf authority and pinned public-key routing fail closed."""

import json
import ssl
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from psycopg.conninfo import make_conninfo

from scripts.prepare_isolated_reads import prepare
from scripts.prepare_phase2 import write_web_credentials
from service_desk.core.auth.lab import ISSUER
from service_desk.read_process import DesktopKeys, read_material


@pytest.fixture
def staged(tmp_path: Path) -> Path:
    identity = tmp_path / ".lab/phase2"
    database = tmp_path / ".lab/phase2-read"
    (identity / "tls").mkdir(parents=True)
    database.mkdir()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-ca")])
    now = datetime.now(UTC)
    ca = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .add_extension(
            x509.KeyUsage(True, False, True, False, False, True, True, False, False), True
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .sign(key, hashes.SHA256())
    )
    (identity / "tls/certificate.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (identity / "tls/private.key").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    (identity / "identities.json").write_text(
        json.dumps([{"issuer": ISSUER, "subject": "subject-erin", "principal_id": "erin"}])
    )
    for service in ("knowledge", "tickets"):
        (database / (service + ".dsn")).write_text(
            make_conninfo(
                host="127.0.0.1",
                port=15433,
                dbname="service_desk_read_lab",
                user="read_" + service,
                password="synthetic-" + service,
            )
        )
    prepare(tmp_path)
    return tmp_path


def test_scoped_preparation_preserves_distinct_leaf_keys(staged: Path) -> None:
    root = staged / ".lab/phase3-reads"
    before = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}
    prepare(staged)
    assert all(p.read_bytes() == content for p, content in before.items())
    assert (root / "knowledge/private.key").read_bytes() != (
        root / "tickets/private.key"
    ).read_bytes()
    for service in ("knowledge", "tickets"):
        dsn, identities = read_material(root / service, service)
        assert "synthetic-" + service in dsn
        assert identities == {(ISSUER, "subject-erin"): "erin"}
        trust = ssl.create_default_context(cafile=str(root / service / "trust.pem"))
        assert trust.check_hostname and trust.verify_mode == ssl.CERT_REQUIRED
        assert "read_publisher" not in dsn


@pytest.mark.parametrize(
    "change",
    [
        "extra",
        "missing",
        "directory",
        "large",
        "role",
        "host",
        "options",
        "issuer",
        "ca_key",
        "sibling_key",
        "sibling_cert",
    ],
)
def test_material_rejects_wider_authority(staged: Path, change: str) -> None:
    root = staged / ".lab/phase3-reads/knowledge"
    if change == "extra":
        (root / "credentials.json").write_text("PRIVATE")
    elif change == "missing":
        (root / "identities.json").unlink()
    elif change == "directory":
        (root / "identities.json").unlink()
        (root / "identities.json").mkdir()
    elif change == "large":
        (root / "identities.json").write_bytes(b"x" * 65537)
    elif change in {"role", "host", "options"}:
        dsn = root / "database.dsn"
        value = dsn.read_text()
        value = value.replace("read_knowledge", "read_publisher") if change == "role" else value
        value = value.replace("host.docker.internal", "evil.invalid") if change == "host" else value
        dsn.write_text(value + (" options=PRIVATE" if change == "options" else ""))
    elif change == "issuer":
        (root / "identities.json").write_text(
            '[{"issuer":"wrong","subject":"s","principal_id":"erin"}]'
        )
    elif change == "ca_key":
        for name, source in (
            ("certificate.pem", "certificate.pem"),
            ("private.key", "private.key"),
        ):
            (root / name).write_bytes((staged / ".lab/phase2/tls" / source).read_bytes())
    else:
        name = "private.key" if change == "sibling_key" else "certificate.pem"
        (root / name).write_bytes((root.parent / "tickets" / name).read_bytes())
    with pytest.raises(ValueError, match="^Invalid read-service material$") as error:
        read_material(root, "knowledge")
    assert error.value.__suppress_context__


def test_browser_secret_export_excludes_users_executor_worker(tmp_path: Path) -> None:
    clients = {k: "secret-" + k for k in ("web", "gateway", "executor", "worker")}
    (tmp_path / "credentials.json").write_text(
        json.dumps({"clients": clients, "users": {"erin": "secret-user"}})
    )
    write_web_credentials(tmp_path)
    assert json.loads((tmp_path / "web-client.json").read_text()) == {
        "clients": {k: clients[k] for k in ("web", "gateway")}
    }


def test_jwks_route_keeps_issuer_name_and_cache_policy() -> None:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    payload = {"keys": [json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key()))]}

    def reply(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "192.0.2.10"
        assert request.url.port == 19443
        assert request.headers["host"] == "127.0.0.1:19443"
        assert request.extensions["sni_hostname"] == "127.0.0.1"
        assert "authorization" not in request.headers and "cookie" not in request.headers
        return httpx.Response(200, stream=httpx.ByteStream(json.dumps(payload).encode()))

    with httpx.Client(transport=httpx.MockTransport(reply)) as http:
        keys = DesktopKeys(http, "192.0.2.10")
        assert keys.uri == ISSUER + "/protocol/openid-connect/certs"
        assert keys.fetch_data() == payload
        assert keys.jwk_set_cache is not None and keys.jwk_set_cache.lifespan == 60
        assert keys.cooldown_duration == 5


@pytest.mark.parametrize("failure", ["redirect", "encoded", "oversized", "invalid", "exception"])
def test_jwks_failure_is_bounded_and_content_free(failure: str) -> None:
    def reply(request: httpx.Request) -> httpx.Response:
        if failure == "exception":
            raise httpx.ConnectError("PRIVATE", request=request)
        if failure == "redirect":
            return httpx.Response(302, headers={"location": "https://evil.invalid/PRIVATE"})
        if failure == "encoded":
            return httpx.Response(200, headers={"content-encoding": "identity"}, content=b"PRIVATE")
        return httpx.Response(
            200, stream=httpx.ByteStream(b"x" * 65537 if failure == "oversized" else b"PRIVATE")
        )

    with httpx.Client(transport=httpx.MockTransport(reply), follow_redirects=False) as http:
        keys = DesktopKeys(http, "192.0.2.10")
        with pytest.raises(jwt.PyJWKClientConnectionError, match="^Identity keys unavailable$"):
            keys.fetch_data()
