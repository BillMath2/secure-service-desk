"""PostgreSQL task reservations; no model or MCP identity header can create a task."""

import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

import psycopg

from service_desk.core.auth.tokens import VerifiedIdentity
from service_desk.core.gateway.registry import BoundaryDenied, argument_hash, safe_operation


@dataclass(frozen=True)
class TaskContext:
    id: UUID
    correlation_id: UUID
    issuer: str
    subject: str
    principal_id: str
    client_id: str
    ticket_id: str
    recipients: tuple[str, ...]
    capabilities: frozenset[str]
    policy_version: str
    deadline: datetime
    max_bytes: int
    draft_audience: str | None = None

    @classmethod
    def from_record(cls, data: dict[str, Any]) -> "TaskContext":
        return cls(
            UUID(data["id"]),
            UUID(data["correlation_id"]),
            data["issuer"],
            data["subject"],
            data["principal_id"],
            data["client_id"],
            data["ticket_id"],
            tuple(data["recipients"]),
            frozenset(data["capabilities"]),
            data["policy_version"],
            datetime.fromisoformat(data["deadline"]),
            data["max_bytes"],
            data.get("draft_audience"),
        )


@dataclass(frozen=True)
class TaskStore:
    dsn: str = field(repr=False)

    def connect(self) -> psycopg.Connection[tuple[Any, ...]]:
        return psycopg.connect(
            self.dsn, connect_timeout=3, options="-c statement_timeout=10000 -c lock_timeout=3000"
        )

    @contextmanager
    def admission(self) -> Iterator[psycopg.Connection[tuple[Any, ...]]]:
        """Translate only the database's named admission denial; rollback before release."""
        try:
            with self.connect() as db:
                yield db
        except psycopg.errors.RaiseException as error:
            if error.diag.constraint_name == "task_admission_limit":
                raise BoundaryDenied("BUDGET_EXHAUSTED") from None
            raise

    @staticmethod
    def check_identity(identity: VerifiedIdentity, *, login: bool = False) -> None:
        if (
            identity.client_id != ("web" if login else "gateway")
            or identity.expires_at <= time.time()
        ):
            raise BoundaryDenied("TASK_DENIED")

    def create(self, identity: VerifiedIdentity, ticket_id: str, audience: str = "self") -> UUID:
        self.check_identity(identity, login=True)
        task_id = uuid4()
        with self.admission() as db:
            row = db.execute(
                "SELECT service_desk.create_read_task(%s,%s,%s,%s,%s,%s)",
                (task_id, uuid4(), identity.issuer, identity.subject, ticket_id, audience),
            ).fetchone()
            if not row or not row[0]:
                raise BoundaryDenied("RESOURCE_DENIED")
        return task_id

    def reserve(
        self,
        identity: VerifiedIdentity,
        task_id: UUID,
        service: str,
        name: str,
        arguments: dict[str, Any],
    ) -> UUID:
        self.check_identity(identity)
        attempt = uuid4()
        with self.connect() as db:
            row = db.execute(
                "SELECT service_desk.reserve_read_attempt(%s,%s,%s,%s,%s,%s,%s)",
                (
                    attempt,
                    task_id,
                    identity.issuer,
                    identity.subject,
                    service,
                    safe_operation(name),
                    argument_hash(arguments),
                ),
            ).fetchone()
        if not row or row[0] != "ALLOW":
            raise BoundaryDenied(row[0] if row else "TASK_DENIED")
        return attempt

    def consume(
        self,
        identity: VerifiedIdentity,
        task_id: UUID,
        attempt: UUID,
        service: str,
        name: str,
        arguments: dict[str, Any],
    ) -> TaskContext:
        self.check_identity(identity)
        with self.connect() as db:
            row = db.execute(
                "SELECT service_desk.consume_read_attempt(%s,%s,%s,%s,%s,%s,%s)",
                (
                    attempt,
                    task_id,
                    identity.issuer,
                    identity.subject,
                    service,
                    safe_operation(name),
                    argument_hash(arguments),
                ),
            ).fetchone()
        if not row or not row[0]:
            raise BoundaryDenied("TASK_DENIED")
        return TaskContext.from_record(row[0])

    def finish(self, attempt: UUID, reason: str) -> bool:
        with self.connect() as db:
            row = db.execute(
                "SELECT service_desk.finish_read_attempt(%s,%s)", (attempt, reason)
            ).fetchone()
        return bool(row and row[0])
