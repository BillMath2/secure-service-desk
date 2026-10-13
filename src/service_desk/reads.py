"""Independent ACL enforcement and bounded retrieval in each read service."""

import hashlib
import time
from contextlib import suppress
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import psycopg
from psycopg.rows import dict_row

from service_desk.core.auth.tokens import VerifiedIdentity
from service_desk.core.gateway.registry import (
    BoundaryDenied,
    canonical,
    definition,
    validate_arguments,
)
from service_desk.core.gateway.store import TaskContext, TaskStore


def denied(reason: str) -> dict[str, Any]:
    return {"allowed": False, "reason": reason, "message": "Resource unavailable"}


class ReadService:
    def __init__(self, service: str, store: TaskStore) -> None:
        if service not in ("knowledge", "tickets"):
            raise ValueError("Unregistered read service")
        self.service = service
        self.store = store

    def invoke(
        self,
        identity: VerifiedIdentity,
        task_id: UUID,
        name: str,
        arguments: dict[str, Any],
        attempt: UUID | None = None,
    ) -> dict[str, Any]:
        reservation = attempt
        owned = False
        operation_deadline = time.time() + 10
        try:
            if reservation is None:
                reservation = self.store.reserve(identity, task_id, self.service, name, arguments)
                owned = True
            try:
                context = self.store.consume(
                    identity, task_id, reservation, self.service, name, arguments
                )
            except BoundaryDenied:
                if attempt is not None:
                    # Invalid/replayed references are new rejected attempts, not a free bypass.
                    # Charge only the verified task owner, and never alter the referenced attempt.
                    reservation = self.store.reserve(
                        identity, task_id, self.service, name, arguments
                    )
                    owned = True
                raise
            owned = True
            context = replace(
                context,
                deadline=min(context.deadline, datetime.fromtimestamp(operation_deadline, UTC)),
            )
            tool = definition(name)
            if tool.service != self.service or name not in context.capabilities:
                raise BoundaryDenied("TOOL_DENIED")
            if tool.scope not in identity.scopes:
                raise BoundaryDenied("SCOPE_DENIED")
            args = validate_arguments(name, arguments).model_dump()
            result = self._read(context, name, args)
            # Count escaping in the actual text-content envelope, plus JSON-RPC overhead.
            envelope = {"content": [{"type": "text", "text": canonical(result)}], "isError": False}
            if len(canonical(envelope).encode()) > min(context.max_bytes, 32768) - 256:
                raise BoundaryDenied("OUTPUT_LIMIT")
            if context.deadline.timestamp() <= time.time() or identity.expires_at <= time.time():
                raise BoundaryDenied("TASK_EXPIRED")
            if not self.store.finish(reservation, "ALLOW"):
                return denied("TASK_DENIED")
            if context.deadline.timestamp() <= time.time() or identity.expires_at <= time.time():
                return denied("TASK_EXPIRED")
            return result
        except BoundaryDenied as error:
            if reservation is not None and owned:
                try:
                    self.store.finish(reservation, error.reason)
                except psycopg.Error:
                    return denied("SERVICE_ERROR")
            return denied(error.reason)
        except (psycopg.Error, ValueError, TypeError):
            # Never include database exception text, queries, arguments or partial content.
            if reservation is not None and owned:
                with suppress(psycopg.Error):
                    self.store.finish(reservation, "SERVICE_ERROR")
            return denied("SERVICE_ERROR")

    def _read(self, context: TaskContext, name: str, args: dict[str, Any]) -> dict[str, Any]:
        viewers = sorted({context.principal_id, *context.recipients})
        remaining_ms = int((context.deadline.timestamp() - time.time()) * 1000)
        if remaining_ms <= 0:
            raise BoundaryDenied("TASK_EXPIRED")
        with self.store.connect() as db:
            db.execute(
                "SELECT set_config('statement_timeout', %s, true)", (str(min(remaining_ms, 10000)),)
            )
            # Current ticket visibility anchors every read, including knowledge searches.
            visible = db.execute(
                """
                SELECT NOT EXISTS (
                  SELECT 1 FROM unnest(%s::text[]) AS v(id)
                  WHERE NOT EXISTS (SELECT 1 FROM service_desk.ticket_reader r
                                    WHERE r.ticket_id = %s AND r.principal_id = v.id)
                     OR NOT EXISTS (SELECT 1 FROM service_desk.principal p
                                    WHERE p.id = v.id AND p.kind = 'human'))
            """,
                (viewers, context.ticket_id),
            ).fetchone()
            if not visible or not visible[0]:
                raise BoundaryDenied("RESOURCE_DENIED")
            with db.cursor(row_factory=dict_row) as cursor:
                if name in ("read_document", "search_documents"):
                    # Materialization is intentional: disallowed rows never reach ranking/snippets.
                    authorized = """WITH authorized AS MATERIALIZED (
                      SELECT d.* FROM service_desk.document d WHERE NOT EXISTS (
                        SELECT 1 FROM unnest(%s::text[]) AS v(id) WHERE NOT EXISTS (
                          SELECT 1 FROM service_desk.document_reader r
                          WHERE r.document_id = d.id AND r.principal_id = v.id))) """
                    if name == "read_document":
                        cursor.execute(
                            authorized
                            + """
                            SELECT id, version, title, body FROM authorized WHERE id = %s
                        """,
                            (viewers, args["document_id"]),
                        )
                        doc = cursor.fetchone()
                        if doc is None:
                            raise BoundaryDenied("RESOURCE_DENIED")
                        return {
                            "allowed": True,
                            "document": {
                                **doc,
                                "citation": f"document:{doc['id']}@{doc['version']}",
                                "body_sha256": hashlib.sha256(doc["body"].encode()).hexdigest(),
                            },
                        }
                    cursor.execute(
                        authorized
                        + """
                        , query AS (SELECT websearch_to_tsquery('english', %s) AS q)
                        SELECT id, version, title,
                          ts_headline('english', body, q,
                            'StartSel=,StopSel=,MaxWords=24,MinWords=8,MaxFragments=1') AS snippet
                        FROM authorized, query WHERE search_vector @@ q
                        ORDER BY ts_rank_cd(search_vector, q) DESC, id LIMIT %s
                    """,
                        (viewers, args["query"], args["limit"]),
                    )
                    return {
                        "allowed": True,
                        "documents": [
                            {**d, "citation": f"document:{d['id']}@{d['version']}"}
                            for d in cursor.fetchall()
                        ],
                    }
                if args["ticket_id"] != context.ticket_id:
                    raise BoundaryDenied("RESOURCE_DENIED")
                cursor.execute(
                    """SELECT id, version, body FROM service_desk.ticket WHERE id = %s""",
                    (context.ticket_id,),
                )
                ticket = cursor.fetchone()
                if ticket is None:
                    raise BoundaryDenied("RESOURCE_DENIED")
                cursor.execute(
                    """
                    SELECT c.id, c.visibility, c.body FROM service_desk.ticket_comment c
                    JOIN service_desk.ticket t ON t.id = c.ticket_id
                    WHERE c.ticket_id = %s
                      AND (c.visibility = 'requester' OR NOT (t.requester = ANY(%s::text[])))
                      AND NOT EXISTS (SELECT 1 FROM unnest(%s::text[]) AS v(id) WHERE NOT EXISTS (
                        SELECT 1 FROM service_desk.comment_reader r
                        WHERE r.comment_id = c.id AND r.principal_id = v.id)) ORDER BY c.id
                """,
                    (context.ticket_id, viewers, viewers),
                )
                return {
                    "allowed": True,
                    "ticket": {
                        **ticket,
                        "comments": cursor.fetchall(),
                        "citation": f"ticket:{ticket['id']}@{ticket['version']}",
                    },
                }
