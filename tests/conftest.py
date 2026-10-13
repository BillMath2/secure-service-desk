from collections.abc import Iterator
from pathlib import Path
from uuid import uuid4

import pytest

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
