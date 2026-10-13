"""First instrumented domain tool. HTTP/MCP authentication is intentionally not claimed here."""

from collections.abc import Callable
from datetime import UTC, datetime
from uuid import uuid4

from service_desk.audit import AuditCollector
from service_desk.contracts import (
    AuditEvent,
    Decision,
    DocumentAccess,
    FixtureSet,
    LabConfig,
    ReadDocumentArgs,
    Reason,
    RequestContext,
    ToolResult,
)
from service_desk.lab_store import LabStore


def authorize_read(
    context: RequestContext,
    document: DocumentAccess | None,
    fixtures: FixtureSet,
    config: LabConfig,
) -> Decision:
    humans = {p.id for p in fixtures.principals if p.kind == "human"}
    reason = Reason.ALLOW
    if context.policy_version != config.policy_version:
        reason = Reason.POLICY_STALE
    elif context.subject not in humans:
        reason = Reason.IDENTITY_DENIED
    elif context.client_id != "agent":
        reason = Reason.CLIENT_DENIED
    elif "knowledge:read" not in context.scopes or "read-document" not in context.capabilities:
        reason = Reason.SCOPE_DENIED
    elif document is None or context.subject not in document.readers:
        reason = Reason.RESOURCE_DENIED
    elif not context.recipients or not set(context.recipients) <= set(document.readers) & humans:
        reason = Reason.RECIPIENT_DENIED
    return Decision(
        allow=reason == Reason.ALLOW, reason_code=reason, policy_version=config.policy_version
    )


class KnowledgeTool:
    def __init__(
        self,
        store: LabStore,
        collector: AuditCollector,
        fixtures: FixtureSet,
        config: LabConfig,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.store = store
        self.collector = collector
        self.fixtures = fixtures
        self.config = config
        self.clock = clock

    def read_document(self, args: ReadDocumentArgs, context: RequestContext) -> ToolResult:
        metadata = self.store.document_access(args.document_id)
        decision = authorize_read(context, metadata, self.fixtures, self.config)
        if decision.allow:
            document = self.store.read_authorized_document(
                args.document_id, context.subject, context.recipients
            )
            if document is None:
                decision = Decision(
                    allow=False,
                    reason_code=Reason.RESOURCE_DENIED,
                    policy_version=self.config.policy_version,
                )
        if decision.allow and document is not None:
            result = ToolResult(
                allowed=True,
                message="Document returned",
                document_id=document.id,
                version=document.version,
                body=document.body,
            )
            if len(result.model_dump_json().encode()) > self.config.max_tool_bytes:
                decision = Decision(
                    allow=False,
                    reason_code=Reason.OUTPUT_LIMIT,
                    policy_version=self.config.policy_version,
                )
        if not decision.allow:
            result = ToolResult(allowed=False, message="Resource unavailable")
        event = AuditEvent(
            event_id=uuid4(),
            correlation_id=context.correlation_id,
            task_id=context.task_id,
            occurred_at=self.clock(),
            producer="knowledge",
            subject=context.subject,
            client_id=context.client_id,
            resource_id=metadata.id if metadata else None,
            operation="read_document",
            decision=decision,
            outcome="returned" if decision.allow else "denied",
        )
        # Audit must persist before any body is returned; storage failures propagate to the runner.
        self.collector.append(event)
        return result
