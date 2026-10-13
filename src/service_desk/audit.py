"""Minimal durable collector; process/database-role isolation arrives with services."""

import sqlite3
from pathlib import Path
from types import TracebackType
from typing import Self
from uuid import UUID

from service_desk.contracts import AuditEvent


class AuditCollector:
    def __init__(self, path: Path) -> None:
        self.connection = sqlite3.connect(path)
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT UNIQUE NOT NULL,
                correlation_id TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events
            BEGIN SELECT RAISE(ABORT, 'audit events are append only'); END;
            CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
            BEGIN SELECT RAISE(ABORT, 'audit events are append only'); END;
            """
        )

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.connection.close()

    def append(self, event: AuditEvent) -> None:
        with self.connection:
            existing = self.connection.execute(
                "SELECT payload FROM events WHERE event_id = ?", (str(event.event_id),)
            ).fetchone()
            payload = event.model_dump_json()
            if existing:
                if existing[0] != payload:
                    raise ValueError("duplicate event ID with different payload")
                return
            self.connection.execute(
                "INSERT INTO events(event_id, correlation_id, payload) VALUES (?, ?, ?)",
                (str(event.event_id), str(event.correlation_id), payload),
            )

    def for_correlation(self, correlation_id: UUID) -> tuple[AuditEvent, ...]:
        rows = self.connection.execute(
            "SELECT payload FROM events WHERE correlation_id = ? ORDER BY sequence",
            (str(correlation_id),),
        )
        return tuple(AuditEvent.model_validate_json(row[0]) for row in rows)
