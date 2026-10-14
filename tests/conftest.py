import ipaddress
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from service_desk.audit import AuditCollector
from service_desk.contracts import FixtureSet, LabConfig, RequestContext
from service_desk.fixtures import fingerprint, load_config, load_fixtures
from service_desk.lab_store import LabStore

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def fixtures() -> FixtureSet:
    return load_fixtures(ROOT / "fixtures/company.json")


@pytest.fixture
def config() -> LabConfig:
    return load_config(ROOT / "config/lab.json")


@pytest.fixture
def context() -> RequestContext:
    return RequestContext(
        issuer="urn:service-desk:fixture",
        subject="erin",
        client_id="agent",
        token_audience="knowledge",
        scopes=frozenset({"knowledge:read"}),
        capabilities=frozenset({"read-document"}),
        recipients=("erin",),
        task_id=uuid4(),
        correlation_id=uuid4(),
        policy_version="policy-v1",
    )


@pytest.fixture
def store(tmp_path: Path, fixtures: FixtureSet) -> Iterator[LabStore]:
    with LabStore(tmp_path / "lab.sqlite") as database:
        database.reset(fixtures, fingerprint(fixtures))
        yield database


@pytest.fixture
def collector(tmp_path: Path) -> Iterator[AuditCollector]:
    with AuditCollector(tmp_path / "audit.sqlite") as audit:
        yield audit


@pytest.fixture
def tls_files(tmp_path: Path) -> Path:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    (tmp_path / "certificate.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "private.key").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return tmp_path
