"""Durable run admission, model reservations and final authorization checks."""

from typing import Any
from uuid import UUID

from psycopg.types.json import Jsonb

from service_desk.core.auth.tokens import VerifiedIdentity
from service_desk.core.gateway.registry import BoundaryDenied
from service_desk.core.gateway.store import TaskContext, TaskStore


class AgentStore(TaskStore):
    def action(
        self,
        identity: VerifiedIdentity,
        task_id: UUID,
        action: str,
        tokens: int = 0,
        sources: list[dict[str, Any]] | None = None,
    ) -> TaskContext:
        if action != "stop":
            self.check_identity(identity, login=True)
        with self.connect() as db:
            row = db.execute(
                "SELECT service_desk.agent_action(%s,%s,%s,%s,%s,%s)",
                (task_id, identity.issuer, identity.subject, action, tokens, Jsonb(sources or [])),
            ).fetchone()
        # Commit denials as well as successful reservations before returning.
        if not row or row[0]["reason"] != "ALLOW":
            raise BoundaryDenied(row[0]["reason"] if row else "TASK_DENIED")
        return TaskContext.from_record(row[0]["context"])
