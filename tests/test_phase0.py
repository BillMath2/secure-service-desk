import json
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from service_desk.audit import AuditCollector
from service_desk.contracts import (
    AuditEvent,
    DocumentAccess,
    FixtureSet,
    LabConfig,
    ReadDocumentArgs,
    Reason,
    RequestContext,
    ToolResult,
)
from service_desk.evaluation import evaluate, run_suite
from service_desk.fixtures import fingerprint
from service_desk.knowledge import KnowledgeTool
from service_desk.lab_store import LabStore
from service_desk.sink import CaptureSink, create_sink


def test_fixture_reset_is_deterministic(store: LabStore, fixtures: FixtureSet) -> None:
    before = store.snapshot()
    store.connection.execute("UPDATE documents SET payload = '{}' WHERE id = 'doc-public'")
    store.connection.execute("INSERT INTO mutations(kind) VALUES ('forbidden')")
    store.connection.commit()
    store.reset(fixtures, fingerprint(fixtures))
    assert store.snapshot() == before
    assert store.mutation_count() == 0


def test_reset_refuses_unrelated_database(tmp_path: Path) -> None:
    path = tmp_path / "unrelated.sqlite"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE important(value TEXT)")
        connection.execute("INSERT INTO important VALUES ('keep')")
    with pytest.raises(ValueError, match="not owned"):
        LabStore(path)
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT value FROM important").fetchone() == ("keep",)


def test_fixture_relations_and_canaries(fixtures: FixtureSet) -> None:
    assert len({p.department for p in fixtures.principals if p.kind == "human"}) >= 3
    canaries = [d.canary for d in fixtures.documents if d.canary]
    assert len(canaries) == len(set(canaries))
    modified = fixtures.model_dump(mode="json")
    modified["documents"][0]["readers"] = ["unknown"]
    with pytest.raises(ValidationError, match="readers"):
        FixtureSet.model_validate(modified)


def test_contract_rejects_model_supplied_identity() -> None:
    with pytest.raises(ValidationError):
        ReadDocumentArgs.model_validate({"document_id": "doc-public", "subject": "harper"})


def test_configuration_rejects_inconsistent_limits(config: LabConfig) -> None:
    with pytest.raises(ValidationError, match="deadline"):
        LabConfig.model_validate({**config.model_dump(), "task_timeout_seconds": 1})


def test_allowed_read_requires_content_oracle(fixtures: FixtureSet) -> None:
    data = fixtures.model_dump(mode="json")
    data["scenarios"][0]["expected_body_sha256"] = None
    with pytest.raises(ValidationError, match="content hash"):
        FixtureSet.model_validate(data)


@pytest.mark.parametrize(
    ("document_id", "subject", "recipients", "expected"),
    [
        ("doc-public", "erin", ("alice",), Reason.ALLOW),
        ("doc-engineering", "erin", ("alice",), Reason.ALLOW),
        ("doc-engineering", "sam", ("sam",), Reason.RESOURCE_DENIED),
        ("doc-admin-reset", "erin", ("alice",), Reason.RECIPIENT_DENIED),
        ("doc-admin-reset", "erin", ("erin", "alice"), Reason.RECIPIENT_DENIED),
        ("doc-public", "erin", (), Reason.RECIPIENT_DENIED),
        ("doc-public", "agent", ("erin",), Reason.IDENTITY_DENIED),
        ("doc-public", "erin", ("unknown",), Reason.RECIPIENT_DENIED),
    ],
)
def test_read_enforces_caller_and_every_recipient(
    document_id: str,
    subject: str,
    recipients: tuple[str, ...],
    expected: Reason,
    store: LabStore,
    collector: AuditCollector,
    fixtures: FixtureSet,
    config: LabConfig,
    context: RequestContext,
) -> None:
    context = context.model_copy(update={"subject": subject, "recipients": recipients})
    before = store.snapshot()
    result = KnowledgeTool(store, collector, fixtures, config).read_document(
        ReadDocumentArgs(document_id=document_id), context
    )
    events = collector.for_correlation(context.correlation_id)
    assert events[0].decision.reason_code == expected
    assert result.allowed == (expected == Reason.ALLOW)
    assert store.snapshot() == before
    if not result.allowed:
        assert result.body is None and result.document_id is None and result.version is None
    audit_text = events[0].model_dump_json()
    assert all(d.body not in audit_text for d in fixtures.documents)
    assert all(d.canary not in audit_text for d in fixtures.documents if d.canary)


def test_not_found_and_denied_look_identical(
    store: LabStore,
    collector: AuditCollector,
    fixtures: FixtureSet,
    config: LabConfig,
    context: RequestContext,
) -> None:
    tool = KnowledgeTool(store, collector, fixtures, config)
    denied = tool.read_document(ReadDocumentArgs(document_id="doc-hr"), context)
    missing = tool.read_document(ReadDocumentArgs(document_id="doc-missing"), context)
    assert denied == missing


def test_denied_read_never_loads_body(
    monkeypatch: pytest.MonkeyPatch,
    store: LabStore,
    collector: AuditCollector,
    fixtures: FixtureSet,
    config: LabConfig,
    context: RequestContext,
) -> None:
    def forbidden(document_id: str, subject: str, recipients: tuple[str, ...]) -> None:
        raise AssertionError("body retrieval must not run for a denied resource")

    monkeypatch.setattr(store, "read_authorized_document", forbidden)
    result = KnowledgeTool(store, collector, fixtures, config).read_document(
        ReadDocumentArgs(document_id="doc-hr"), context
    )
    assert result.body is None and not result.allowed


def test_acl_change_between_metadata_and_read_denies(
    monkeypatch: pytest.MonkeyPatch,
    store: LabStore,
    collector: AuditCollector,
    fixtures: FixtureSet,
    config: LabConfig,
    context: RequestContext,
) -> None:
    original = store.document_access

    def revoke_after_metadata(document_id: str) -> DocumentAccess | None:
        metadata = original(document_id)
        store.connection.execute(
            "UPDATE documents SET payload = json_set(payload, '$.readers', json('[]')) "
            "WHERE id = ?",
            (document_id,),
        )
        store.connection.commit()
        return metadata

    monkeypatch.setattr(store, "document_access", revoke_after_metadata)
    result = KnowledgeTool(store, collector, fixtures, config).read_document(
        ReadDocumentArgs(document_id="doc-public"), context
    )
    assert not result.allowed and result.body is None


@pytest.mark.parametrize(
    ("updates", "reason"),
    [
        ({"client_id": "unregistered"}, Reason.CLIENT_DENIED),
        ({"scopes": frozenset()}, Reason.SCOPE_DENIED),
        ({"capabilities": frozenset()}, Reason.SCOPE_DENIED),
        ({"policy_version": "stale"}, Reason.POLICY_STALE),
    ],
)
def test_context_restrictions(
    updates: dict[str, object],
    reason: Reason,
    store: LabStore,
    collector: AuditCollector,
    fixtures: FixtureSet,
    config: LabConfig,
    context: RequestContext,
) -> None:
    result = KnowledgeTool(store, collector, fixtures, config).read_document(
        ReadDocumentArgs(document_id="doc-public"), context.model_copy(update=updates)
    )
    assert result.body is None
    assert collector.for_correlation(context.correlation_id)[0].decision.reason_code == reason


def test_output_limit(
    store: LabStore,
    collector: AuditCollector,
    fixtures: FixtureSet,
    config: LabConfig,
    context: RequestContext,
) -> None:
    result = KnowledgeTool(
        store, collector, fixtures, config.model_copy(update={"max_tool_bytes": 64})
    ).read_document(ReadDocumentArgs(document_id="doc-public"), context)
    assert result.body is None
    assert (
        collector.for_correlation(context.correlation_id)[0].decision.reason_code
        == Reason.OUTPUT_LIMIT
    )


def test_audit_failure_prevents_data_return(
    store: LabStore,
    collector: AuditCollector,
    fixtures: FixtureSet,
    config: LabConfig,
    context: RequestContext,
) -> None:
    collector.connection.close()
    with pytest.raises(sqlite3.ProgrammingError):
        KnowledgeTool(store, collector, fixtures, config).read_document(
            ReadDocumentArgs(document_id="doc-admin-reset"), context
        )


def test_audit_append_only_and_idempotent(
    store: LabStore,
    collector: AuditCollector,
    fixtures: FixtureSet,
    config: LabConfig,
    context: RequestContext,
) -> None:
    KnowledgeTool(store, collector, fixtures, config).read_document(
        ReadDocumentArgs(document_id="doc-public"), context
    )
    event = collector.for_correlation(context.correlation_id)[0]
    collector.append(event)
    assert len(collector.for_correlation(context.correlation_id)) == 1
    with pytest.raises(ValueError, match="different payload"):
        collector.append(event.model_copy(update={"subject": "sam"}))
    for query in ("UPDATE events SET payload = '{}'", "DELETE FROM events"):
        with pytest.raises(sqlite3.IntegrityError, match="append only"):
            collector.connection.execute(query)
    with pytest.raises(ValidationError):
        AuditEvent.model_validate({**event.model_dump(), "raw_token": "not-a-real-secret"})


def test_runner_reports_pass_and_unsupported(
    tmp_path: Path,
    fixtures: FixtureSet,
    config: LabConfig,
) -> None:
    output = tmp_path / "report"
    counts = run_suite(fixtures, config, output)
    assert counts == {"success": 10, "failure": 0, "error": 0, "unsupported": 3}
    report = json.loads((output / "results.json").read_text())
    assert report["fixture_sha256"] == fingerprint(fixtures)
    evidence = (output / "results.json").read_text() + (output / "audit.jsonl").read_text()
    assert all(d.canary not in evidence for d in fixtures.documents if d.canary)
    with pytest.raises(FileExistsError):
        run_suite(fixtures, config, output)


def test_runner_detects_actual_leak(
    store: LabStore,
    collector: AuditCollector,
    fixtures: FixtureSet,
    config: LabConfig,
) -> None:
    scenario = next(s for s in fixtures.scenarios if s.id == "deny-requester-leak")

    def leaking(tool: KnowledgeTool, args: ReadDocumentArgs, context: RequestContext) -> ToolResult:
        tool.read_document(args, context)
        return ToolResult(allowed=False, message="denied", body="LAB-CANARY-ADMIN-C15D")

    result = evaluate(scenario, fixtures, config, store, collector, leaking)
    assert result.status == "failure" and result.forbidden_marker_found


def test_runner_detects_actual_mutation(
    store: LabStore,
    collector: AuditCollector,
    fixtures: FixtureSet,
    config: LabConfig,
) -> None:
    def mutating(
        tool: KnowledgeTool, args: ReadDocumentArgs, context: RequestContext
    ) -> ToolResult:
        result = tool.read_document(args, context)
        tool.store.connection.execute("INSERT INTO mutations(kind) VALUES ('forbidden')")
        return result

    result = evaluate(fixtures.scenarios[0], fixtures, config, store, collector, mutating)
    assert result.status == "failure" and result.mutations_found


def test_runner_errors_do_not_expose_exception_text(
    store: LabStore,
    collector: AuditCollector,
    fixtures: FixtureSet,
    config: LabConfig,
) -> None:
    def failing(tool: KnowledgeTool, args: ReadDocumentArgs, context: RequestContext) -> ToolResult:
        raise RuntimeError("secret-token-do-not-log")

    result = evaluate(fixtures.scenarios[0], fixtures, config, store, collector, failing)
    assert result.status == "error"
    assert "secret-token" not in result.model_dump_json()


def test_runner_classifies_reset_failure_as_error(
    store: LabStore,
    collector: AuditCollector,
    fixtures: FixtureSet,
    config: LabConfig,
) -> None:
    store.connection.close()
    result = evaluate(fixtures.scenarios[0], fixtures, config, store, collector)
    assert result.status == "error" and result.reason == "tool-or-storage-error"


def test_sink_captures_without_echo_or_forwarding() -> None:
    sink = CaptureSink()
    with TestClient(create_sink(sink)) as client:
        response = client.post("/capture", content=b"synthetic-canary")
        assert response.status_code == 204 and not response.content
        assert sink.payloads == [b"synthetic-canary"]
        assert "synthetic-canary" not in str(sink.hashes())
        assert client.post("/capture", content=b"x" * 8193).status_code == 413
        assert len(sink.payloads) == 1
        for _ in range(99):
            assert client.post("/capture", content=b"x").status_code == 204
        assert client.post("/capture", content=b"x").status_code == 429
