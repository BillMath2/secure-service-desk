"""Strict boundary schemas shared by the fixture harness and future services."""

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

Identifier = Annotated[str, Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")]
Positive = Annotated[int, Field(gt=0)]


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class LabConfig(Contract):
    policy_version: Identifier
    max_tool_calls: Positive = 12
    max_model_tokens: Positive = 16000
    task_timeout_seconds: Positive = 120
    tool_timeout_seconds: Positive = 10
    provider_timeout_seconds: Positive = 45
    max_retries: Annotated[int, Field(ge=0, le=1)] = 1
    max_tool_bytes: Positive = 32768
    max_draft_bytes: Positive = 8192
    approval_requests_per_hour: Positive = 5
    confirmation_seconds: Positive = 600
    approval_seconds: Positive = 900
    standard_grant_seconds: Annotated[int, Field(gt=0, le=2592000)] = 2592000
    privileged_grant_seconds: Annotated[int, Field(gt=0, le=28800)] = 28800
    cleanup_seconds: Positive = 60
    review_interval_seconds: Positive = 604800
    review_window_seconds: Positive = 86400

    @model_validator(mode="after")
    def deadlines(self) -> Self:
        if (
            max(self.tool_timeout_seconds, self.provider_timeout_seconds)
            > self.task_timeout_seconds
        ):
            raise ValueError("call timeouts must fit within the task deadline")
        return self


class Principal(Contract):
    id: Identifier
    kind: Literal["human", "workload"]
    department: Identifier
    roles: tuple[Identifier, ...]
    manager: Identifier | None = None


class DocumentAccess(Contract):
    id: Identifier
    version: Positive
    classification: Literal["public", "team", "hr", "privileged"]
    readers: tuple[Identifier, ...]


class Document(DocumentAccess):
    title: str
    body: str
    canary: str | None = None
    variant_of: Identifier | None = None


class Comment(Contract):
    id: Identifier
    visibility: Literal["requester", "internal"]
    readers: tuple[Identifier, ...]
    body: str


class Ticket(Contract):
    id: Identifier
    requester: Identifier
    team: Identifier
    readers: tuple[Identifier, ...]
    body: str
    submitted_at: datetime
    comments: tuple[Comment, ...] = ()
    variant_of: Identifier | None = None


class Group(Contract):
    id: Identifier
    risk: Literal["standard", "sensitive"]
    owner: Identifier
    eligible_departments: tuple[Identifier, ...]


class Scenario(Contract):
    id: Identifier
    requirements: tuple[str, ...]
    actor: Literal["benign", "external", "employee", "author", "mcp-server"]
    entry_point: Identifier
    controlled_content: str
    objective: str
    tool: Identifier
    subject: Identifier
    client_id: Identifier = "agent"
    resource_id: Identifier
    recipients: tuple[Identifier, ...]
    scopes: tuple[str, ...] = ("knowledge:read",)
    expected_allow: bool
    expected_reason: str
    expected_body_sha256: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")] | None = None
    forbidden_markers: tuple[str, ...] = ()
    risks: tuple[str, ...] = ()

    @model_validator(mode="after")
    def allowed_read_has_oracle(self) -> Self:
        if self.tool == "read-document" and self.expected_allow and not self.expected_body_sha256:
            raise ValueError("allowed read needs an expected content hash")
        return self


class FixtureSet(Contract):
    version: Literal[1]
    principals: tuple[Principal, ...]
    documents: tuple[Document, ...]
    tickets: tuple[Ticket, ...]
    groups: tuple[Group, ...]
    scenarios: tuple[Scenario, ...]

    @model_validator(mode="after")
    def references(self) -> Self:
        for records in (self.principals, self.documents, self.tickets, self.groups, self.scenarios):
            ids = [record.id for record in records]
            if len(ids) != len(set(ids)):
                raise ValueError("duplicate fixture identifiers")
        people = {p.id: p for p in self.principals}
        docs = {d.id for d in self.documents}
        tickets = {t.id for t in self.tickets}
        for person in self.principals:
            if person.manager and person.manager not in people:
                raise ValueError("unknown manager")
        for doc in self.documents:
            if not doc.readers or any(p not in people for p in doc.readers):
                raise ValueError("invalid document readers")
            if doc.variant_of and doc.variant_of not in docs:
                raise ValueError("unknown document variant source")
            if doc.canary and doc.canary not in doc.body:
                raise ValueError("canary missing from document")
        for ticket in self.tickets:
            if ticket.requester not in ticket.readers or any(
                p not in people for p in ticket.readers
            ):
                raise ValueError("invalid ticket readers")
            if ticket.variant_of and ticket.variant_of not in tickets:
                raise ValueError("unknown ticket variant source")
            for comment in ticket.comments:
                if not comment.readers or not set(comment.readers) <= set(ticket.readers):
                    raise ValueError("invalid comment readers")
                if comment.visibility == "internal" and ticket.requester in comment.readers:
                    raise ValueError("requester cannot read internal comment")
        for group in self.groups:
            if group.owner not in people or people[group.owner].kind != "human":
                raise ValueError("group owner must be a known human")
        for scenario in self.scenarios:
            if scenario.subject not in people or any(p not in people for p in scenario.recipients):
                raise ValueError("unknown scenario principal")
        return self


class RequestContext(Contract):
    """Created by trusted fixture setup only; NOT an authentication mechanism."""

    issuer: Literal["urn:service-desk:fixture"]
    subject: Identifier
    client_id: Identifier
    token_audience: Literal["knowledge"]
    scopes: frozenset[str]
    capabilities: frozenset[str]
    recipients: tuple[Identifier, ...]
    task_id: UUID
    correlation_id: UUID
    policy_version: Identifier


class Reason(StrEnum):
    ALLOW = "ALLOW"
    IDENTITY_DENIED = "IDENTITY_DENIED"
    CLIENT_DENIED = "CLIENT_DENIED"
    SCOPE_DENIED = "SCOPE_DENIED"
    RESOURCE_DENIED = "RESOURCE_DENIED"
    RECIPIENT_DENIED = "RECIPIENT_DENIED"
    POLICY_STALE = "POLICY_STALE"
    OUTPUT_LIMIT = "OUTPUT_LIMIT"


class Decision(Contract):
    allow: bool
    reason_code: Reason
    policy_version: Identifier
    obligations: tuple[str, ...] = ()


class ReadDocumentArgs(Contract):
    document_id: Identifier


class ToolResult(Contract):
    allowed: bool
    message: str
    document_id: Identifier | None = None
    version: int | None = None
    body: str | None = None


class AuditEvent(Contract):
    schema_version: Literal[1] = 1
    event_id: UUID
    correlation_id: UUID
    task_id: UUID
    occurred_at: datetime
    producer: Literal["knowledge"]
    subject: Identifier
    client_id: Identifier
    resource_id: Identifier | None
    operation: Literal["read_document"]
    decision: Decision
    outcome: Literal["returned", "denied"]


class ScenarioResult(Contract):
    scenario_id: Identifier
    status: Literal["success", "failure", "error", "unsupported"]
    reason: str
    actor: str
    entry_point: str
    requirements: tuple[str, ...]
    risks: tuple[str, ...]
    audit_event_ids: tuple[UUID, ...] = ()
    output_sha256: str | None = None
    forbidden_marker_found: bool = False
    mutations_found: bool = False
