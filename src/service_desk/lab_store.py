"""Disposable SQLite fixture store. Production persistence is PostgreSQL, not this adapter."""

import json
import sqlite3
from pathlib import Path
from types import TracebackType
from typing import Self

from service_desk.contracts import Document, DocumentAccess, FixtureSet

APPLICATION_ID = 0x53444C30


class LabStore:
    def __init__(self, path: Path) -> None:
        if path.is_symlink():
            raise ValueError("lab database must not be a symlink")
        self.connection = sqlite3.connect(path)
        existing = self.connection.execute("SELECT name FROM sqlite_master").fetchall()
        app_id = self.connection.execute("PRAGMA application_id").fetchone()[0]
        if existing and app_id != APPLICATION_ID:
            self.connection.close()
            raise ValueError("refusing to use a database not owned by this disposable lab")
        self.connection.executescript(
            f"""
            PRAGMA application_id = {APPLICATION_ID};
            CREATE TABLE IF NOT EXISTS documents (id TEXT PRIMARY KEY, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS mutations (id INTEGER PRIMARY KEY, kind TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS fixture_meta (id INTEGER PRIMARY KEY CHECK(id=1), hash TEXT);
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

    def reset(self, fixtures: FixtureSet, fixture_hash: str) -> None:
        """Reset only known tables in a database bearing the lab ownership marker."""
        with self.connection:
            self.connection.execute("DELETE FROM documents")
            self.connection.execute("DELETE FROM mutations")
            self.connection.execute("DELETE FROM fixture_meta")
            self.connection.executemany(
                "INSERT INTO documents(id, payload) VALUES (?, ?)",
                [(d.id, d.model_dump_json()) for d in fixtures.documents],
            )
            self.connection.execute("INSERT INTO fixture_meta VALUES (1, ?)", (fixture_hash,))

    def document_access(self, document_id: str) -> DocumentAccess | None:
        row = self.connection.execute(
            """SELECT json_object(
                'id', id, 'version', json_extract(payload, '$.version'),
                'classification', json_extract(payload, '$.classification'),
                'readers', json_extract(payload, '$.readers'))
            FROM documents WHERE id = ?""",
            (document_id,),
        ).fetchone()
        return DocumentAccess.model_validate_json(row[0]) if row else None

    def read_authorized_document(
        self, document_id: str, subject: str, recipients: tuple[str, ...]
    ) -> Document | None:
        # Repeat the ACL predicate in the content query so an intervening ACL
        # change cannot make a stale metadata decision release a document body.
        row = self.connection.execute(
            """SELECT payload FROM documents WHERE id = ?
            AND ? IN (SELECT value FROM json_each(documents.payload, '$.readers'))
            AND json_array_length(?) > 0
            AND NOT EXISTS (
                SELECT 1 FROM json_each(?) AS recipient
                WHERE recipient.value NOT IN (
                    SELECT value FROM json_each(documents.payload, '$.readers')
                )
            )""",
            (document_id, subject, json.dumps(recipients), json.dumps(recipients)),
        ).fetchone()
        return Document.model_validate_json(row[0]) if row else None

    def snapshot(self) -> tuple[tuple[str, str], ...]:
        return tuple(self.connection.execute("SELECT id, payload FROM documents ORDER BY id"))

    def mutation_count(self) -> int:
        return int(self.connection.execute("SELECT count(*) FROM mutations").fetchone()[0])
