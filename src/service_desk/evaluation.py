"""Evaluate real output and store effects, not a model's description of its behavior."""

import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import TypedDict
from uuid import uuid4

from service_desk.audit import AuditCollector
from service_desk.contracts import (
    AuditEvent,
    FixtureSet,
    LabConfig,
    ReadDocumentArgs,
    RequestContext,
    Scenario,
    ScenarioResult,
    ToolResult,
)
from service_desk.fixtures import fingerprint
from service_desk.knowledge import KnowledgeTool
from service_desk.lab_store import LabStore
from service_desk.sink import CaptureSink

Invoker = Callable[[KnowledgeTool, ReadDocumentArgs, RequestContext], ToolResult]


class ResultMetadata(TypedDict):
    scenario_id: str
    actor: str
    entry_point: str
    requirements: tuple[str, ...]
    risks: tuple[str, ...]


def invoke(tool: KnowledgeTool, args: ReadDocumentArgs, context: RequestContext) -> ToolResult:
    return tool.read_document(args, context)


def evaluate(
    scenario: Scenario,
    fixtures: FixtureSet,
    config: LabConfig,
    store: LabStore,
    collector: AuditCollector,
    invoker: Invoker = invoke,
) -> ScenarioResult:
    base: ResultMetadata = {
        "scenario_id": scenario.id,
        "actor": scenario.actor,
        "entry_point": scenario.entry_point,
        "requirements": scenario.requirements,
        "risks": scenario.risks,
    }
    if scenario.tool != "read-document":
        return ScenarioResult(**base, status="unsupported", reason="tool-not-implemented")
    context = RequestContext(
        issuer="urn:service-desk:fixture",
        subject=scenario.subject,
        client_id=scenario.client_id,
        token_audience="knowledge",
        scopes=frozenset(scenario.scopes),
        capabilities=frozenset({"read-document"}),
        recipients=scenario.recipients,
        task_id=uuid4(),
        correlation_id=uuid4(),
        policy_version=config.policy_version,
    )
    sink = CaptureSink()
    try:
        store.reset(fixtures, fingerprint(fixtures))
        before = store.snapshot()
        result = invoker(
            KnowledgeTool(store, collector, fixtures, config),
            ReadDocumentArgs(document_id=scenario.resource_id),
            context,
        )
        output = result.model_dump_json().encode()
        sink.capture(output)
        events = collector.for_correlation(context.correlation_id)
        audit_text = "".join(e.model_dump_json() for e in events).encode()
        leaked = any(
            marker.encode() in payload
            for marker in scenario.forbidden_markers
            for payload in (*sink.payloads, audit_text)
        )
        body_hash = hashlib.sha256((result.body or "").encode()).hexdigest()
        changed = before != store.snapshot() or store.mutation_count() != 0
        audit_matches = (
            len(events) == 1
            and events[0].decision.reason_code == scenario.expected_reason
            and events[0].decision.allow == scenario.expected_allow
        )
        expected_output = (
            result.allowed == scenario.expected_allow
            and (scenario.expected_allow or result.body is None)
            and (
                scenario.expected_body_sha256 is None or body_hash == scenario.expected_body_sha256
            )
        )
        passed = audit_matches and expected_output and not leaked and not changed
        return ScenarioResult(
            **base,
            status="success" if passed else "failure",
            reason="oracle-satisfied" if passed else "oracle-mismatch",
            audit_event_ids=tuple(e.event_id for e in events),
            output_sha256=hashlib.sha256(output).hexdigest(),
            forbidden_marker_found=leaked,
            mutations_found=changed,
        )
    except Exception:
        # Exception messages can contain tokens/payloads. Reports expose only a stable code.
        return ScenarioResult(**base, status="error", reason="tool-or-storage-error")


def run_suite(fixtures: FixtureSet, config: LabConfig, output: Path) -> dict[str, int]:
    output.mkdir(parents=True, exist_ok=False)
    totals = dict.fromkeys(("success", "failure", "error", "unsupported"), 0)
    events: list[AuditEvent] = []
    results: list[ScenarioResult] = []
    # Only this automatically allocated disposable directory holds resettable state.
    with TemporaryDirectory(prefix="service-desk-phase0-") as temporary:
        root = Path(temporary)
        with (
            LabStore(root / "fixtures.sqlite") as store,
            AuditCollector(root / "audit.sqlite") as audit,
        ):
            for scenario in fixtures.scenarios:
                result = evaluate(scenario, fixtures, config, store, audit)
                results.append(result)
                totals[result.status] += 1
            rows = audit.connection.execute("SELECT payload FROM events ORDER BY sequence")
            events = [AuditEvent.model_validate_json(row[0]) for row in rows]
    report = {
        "schema_version": 1,
        "variant": "phase0-fixture-adapter",
        "authentication": "fixture-only-not-oidc",
        "fixture_sha256": fingerprint(fixtures),
        "policy": config.model_dump(mode="json"),
        "counts": totals,
        "results": [r.model_dump(mode="json") for r in results],
    }
    (output / "results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (output / "audit.jsonl").write_text(
        "".join(event.model_dump_json() + "\n" for event in events), encoding="utf-8"
    )
    return totals
