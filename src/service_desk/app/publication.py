"""Human endpoint credential boundary; never passed to Assistant or an MCP service."""

import hashlib
import secrets
import time
from datetime import UTC, datetime
from typing import Any, ClassVar
from uuid import UUID

import psycopg
from psycopg import sql

from service_desk.core.auth.tokens import VerifiedIdentity
from service_desk.core.gateway.registry import BoundaryDenied
from service_desk.core.gateway.store import TaskStore


def token_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class PublicationStore(TaskStore):
    review_function: ClassVar[str] = "issue_draft_confirmation"
    confirm_function: ClassVar[str] = "confirm_requester_reply"

    def connect(self) -> psycopg.Connection[tuple[Any, ...]]:
        # One function call is one server-side transaction, with no client commit gap.
        return psycopg.connect(
            self.dsn,
            autocommit=True,
            connect_timeout=3,
            options="-c statement_timeout=5000 -c transaction_timeout=5000 -c lock_timeout=2000",
        )

    def review(self, identity: VerifiedIdentity, draft_id: UUID, session: str) -> dict[str, Any]:
        self.check_identity(identity, login=True)
        token = secrets.token_urlsafe(32)
        with self.connect() as db:
            row = db.execute(
                sql.SQL("SELECT service_desk.{}(%s,%s,%s,%s,%s,%s)").format(
                    sql.Identifier(self.review_function)
                ),
                (
                    draft_id,
                    identity.issuer,
                    identity.subject,
                    token_hash(session),
                    token_hash(token),
                    datetime.fromtimestamp(identity.expires_at, UTC),
                ),
            ).fetchone()
        if not row or row[0]["reason"] != "ALLOW":
            raise BoundaryDenied(row[0]["reason"] if row else "TASK_DENIED")
        self.check_identity(identity, login=True)
        result: dict[str, Any] = row[0]["draft"]
        return {
            **result,
            "confirmation_token": token,
            "confirmation_expires_at": row[0]["confirmation_expires_at"],
        }

    def confirm(
        self,
        identity: VerifiedIdentity,
        draft_id: UUID,
        session: str,
        token: str,
        body_hash: str,
    ) -> dict[str, Any]:
        self.check_identity(identity, login=True)
        deadline = datetime.fromtimestamp(min(time.time() + 5, identity.expires_at), UTC)
        with self.connect() as db:
            row = db.execute(
                sql.SQL("SELECT service_desk.{}(%s,%s,%s,%s,%s,%s,%s)").format(
                    sql.Identifier(self.confirm_function)
                ),
                (
                    draft_id,
                    identity.issuer,
                    identity.subject,
                    token_hash(session),
                    token_hash(token),
                    body_hash,
                    deadline,
                ),
            ).fetchone()
        if not row or row[0]["reason"] != "ALLOW":
            raise BoundaryDenied(row[0]["reason"] if row else "TASK_DENIED")
        result: dict[str, Any] = row[0]["receipt"]
        return result


class InternalPublicationStore(PublicationStore):
    review_function = "issue_internal_confirmation"
    confirm_function = "confirm_internal_comment"
