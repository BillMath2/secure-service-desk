"""Narrow service-role calls; immutable arguments and authority are checked in PostgreSQL."""

import secrets
import time
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import psycopg
from psycopg import sql
from psycopg.types.json import Jsonb

from service_desk.app.publication import token_hash
from service_desk.core.auth.tokens import VerifiedIdentity
from service_desk.core.gateway.registry import BoundaryDenied
from service_desk.core.gateway.store import TaskStore


class AccessStore(TaskStore):
    def connect(self) -> psycopg.Connection[tuple[Any, ...]]:
        return psycopg.connect(
            self.dsn,
            autocommit=True,
            connect_timeout=3,
            options="-c statement_timeout=5000 -c transaction_timeout=5000 -c lock_timeout=2000",
        )

    def call(self, name: str, *args: Any) -> Any:
        with self.connect() as db:
            row = db.execute(
                sql.SQL("SELECT service_desk.{}({})").format(
                    sql.Identifier(name), sql.SQL(",").join(sql.Placeholder() for _ in args)
                ),
                args,
            ).fetchone()
        if row is None:
            raise BoundaryDenied("SERVICE_ERROR")
        result = row[0]
        if isinstance(result, dict) and result.get("reason") != "ALLOW":
            raise BoundaryDenied(result.get("reason", "SERVICE_ERROR"))
        return result

    @staticmethod
    def deadline(identity: VerifiedIdentity | None = None) -> datetime:
        return datetime.fromtimestamp(
            min(time.time() + 5, identity.expires_at if identity else time.time() + 5), UTC
        )

    def draft(
        self,
        identity: VerifiedIdentity,
        ticket: str,
        resource: str,
        duration: int | None,
        justification: str,
    ) -> dict[str, Any]:
        self.check_identity(identity, login=True)
        result: dict[str, Any] = self.call(
            "access_draft",
            identity.issuer,
            identity.subject,
            ticket,
            resource,
            duration,
            justification,
            None,
        )
        return result

    def view(self, identity: VerifiedIdentity, request_id: UUID) -> dict[str, Any]:
        self.check_identity(identity, login=True)
        result: dict[str, Any] = self.call(
            "access_view", identity.issuer, identity.subject, request_id
        )
        return result

    def review(
        self, identity: VerifiedIdentity, request_id: UUID, session: str, operation: str
    ) -> dict[str, Any]:
        self.check_identity(identity, login=True)
        token = secrets.token_urlsafe(32)
        result: dict[str, Any] = self.call(
            "access_review",
            identity.issuer,
            identity.subject,
            request_id,
            token_hash(session),
            token_hash(token),
            operation,
            datetime.fromtimestamp(identity.expires_at, UTC),
        )
        return {**result, "confirmation_token": token}

    def confirm(
        self,
        identity: VerifiedIdentity,
        request_id: UUID,
        session: str,
        token: str,
        action_hash: str,
    ) -> dict[str, Any]:
        self.check_identity(identity, login=True)
        result: dict[str, Any] = self.call(
            "access_confirm",
            identity.issuer,
            identity.subject,
            request_id,
            token_hash(session),
            token_hash(token),
            action_hash,
            self.deadline(identity),
        )
        return result

    def execute(
        self, request_id: UUID, action_hash: str, identity: VerifiedIdentity | None = None
    ) -> dict[str, Any]:
        result: dict[str, Any] = self.call(
            "access_execute", request_id, action_hash, self.deadline(identity)
        )
        return result

    def reconcile(self) -> dict[str, Any]:
        result: dict[str, Any] = self.call("access_reconcile", self.deadline())
        return result

    def check(self, identity: VerifiedIdentity, beneficiary: str, resource: str) -> dict[str, Any]:
        self.check_identity(identity, login=True)
        result: dict[str, Any] = self.call(
            "access_check", identity.issuer, identity.subject, beneficiary, resource
        )
        return result

    def audit(self, identity: VerifiedIdentity, correlation: UUID) -> dict[str, Any]:
        self.check_identity(identity, login=True)
        result: dict[str, Any] = self.call(
            "audit_query", identity.issuer, identity.subject, correlation
        )
        return result

    def accept(self, writer: str, event_id: UUID, payload: dict[str, Any]) -> bool:
        result: bool = self.call("audit_accept", writer, event_id, Jsonb(payload))
        return result
