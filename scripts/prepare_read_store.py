"""Prepare/apply only the dedicated, disposable Phase 2 read database."""

import argparse
import json
import secrets
from pathlib import Path

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo

from service_desk.contracts import FixtureSet
from service_desk.core.auth.lab import ISSUER, subject_for
from service_desk.core.database import configure_login
from service_desk.fixtures import fingerprint, load_fixtures

ROOT = Path(__file__).resolve().parents[1]
LOCAL = ROOT / ".lab/phase2-read"
ROLES = {
    "creator": ("read_app", "desk_task_creator"),
    "gateway": ("read_gateway", "desk_gateway"),
    "knowledge": ("read_knowledge", "desk_knowledge"),
    "tickets": ("read_tickets", "desk_tickets"),
    "publisher": ("read_publisher", "desk_ticket_publisher"),
    "workflow": ("access_workflow", "desk_workflow"),
    "proposals": ("access_proposals", "desk_access"),
    "execution": ("access_executor", "desk_executor"),
    "lifecycle": ("access_lifecycle", "desk_lifecycle"),
    "collector": ("access_collector", "desk_collector"),
    "delivery": ("access_delivery", "desk_audit_delivery"),
}


def seed_access(db: psycopg.Connection, fixtures: FixtureSet) -> None:
    if db.execute("SELECT 1 FROM service_desk.access_fixture_state").fetchone():
        return
    for group in fixtures.groups:
        db.execute(
            "INSERT INTO service_desk.resource_group VALUES(%s,%s,%s)",
            (group.id, group.risk, group.owner),
        )
        for department in group.eligible_departments:
            db.execute(
                "INSERT INTO service_desk.resource_department VALUES(%s,%s)", (group.id, department)
            )
    for principal in fixtures.principals:
        if principal.kind == "human" and "analyst" in principal.roles:
            db.execute("INSERT INTO service_desk.access_analyst VALUES(%s)", (principal.id,))
    # Explicit lab auditor; ordinary analysts and resource owners are not audit readers.
    db.execute("INSERT INTO service_desk.audit_reader VALUES('harper')")
    db.execute("INSERT INTO service_desk.access_fixture_state VALUES(true)")


def seed_internal_members(db: psycopg.Connection, fixtures: FixtureSet) -> None:
    """Trusted fixture staff membership, initialized once without restoring revoked grants."""
    if db.execute("SELECT 1 FROM service_desk.internal_fixture_state").fetchone():
        return
    staff = {
        p.id
        for p in fixtures.principals
        if p.kind == "human" and set(p.roles) & {"analyst", "manager", "resource-owner"}
    }
    for ticket in fixtures.tickets:
        for reader in sorted(staff.intersection(ticket.readers) - {ticket.requester}):
            db.execute(
                "INSERT INTO service_desk.ticket_internal_member VALUES(%s,%s)",
                (ticket.id, reader),
            )
    db.execute("INSERT INTO service_desk.internal_fixture_state VALUES(true)")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    LOCAL.mkdir(parents=True, exist_ok=True)
    password_file = LOCAL / "postgres-password"
    connection_file = LOCAL / "connections.json"
    if password_file.exists() != connection_file.exists():
        raise SystemExit("Partial read-lab credentials; inspect before proceeding.")
    if not password_file.exists():
        password = secrets.token_urlsafe(32)
        password_file.write_text(password, encoding="utf-8")
        options = {"host": "127.0.0.1", "port": "15433", "dbname": "service_desk_read_lab"}
        connections = {
            "admin": make_conninfo(**options, user="read_lab_migrator", password=password)
        }
        connections.update(
            {
                name: make_conninfo(**options, user=role[0], password=secrets.token_urlsafe(32))
                for name, role in ROLES.items()
            }
        )
        connection_file.write_text(json.dumps(connections), encoding="utf-8")
    connections = json.loads(connection_file.read_text())
    # Add a new service credential without rotating existing running-service credentials.
    existing = conninfo_to_dict(connections["admin"])
    for name, (login, _) in ROLES.items():
        if name not in connections:
            connections[name] = make_conninfo(
                host=existing["host"],
                port=existing["port"],
                dbname=existing["dbname"],
                user=login,
                password=secrets.token_urlsafe(32),
            )
    connection_file.write_text(json.dumps(connections), encoding="utf-8")
    for name in ROLES:
        (LOCAL / (name + ".dsn")).write_text(connections[name], encoding="utf-8")
    if not args.apply:
        print("Disposable read-lab credentials prepared; no database changes applied.")
        return
    fixtures = load_fixtures(ROOT / "fixtures/company.json")
    with psycopg.connect(connections["admin"], autocommit=True, connect_timeout=3) as db:
        if db.execute("SELECT current_database()").fetchone() != ("service_desk_read_lab",):
            raise SystemExit("Refusing to migrate a different database.")
        exists = db.execute("SELECT to_regclass('service_desk.schema_version')").fetchone()
        applied = (
            set()
            if not exists or exists[0] is None
            else {r[0] for r in db.execute("SELECT version FROM service_desk.schema_version")}
        )
        for migration in sorted((ROOT / "migrations").glob("*.sql")):
            if int(migration.name.split("_")[0]) not in applied:
                db.execute(migration.read_text())
        with db.transaction():
            for name, (login, role) in ROLES.items():
                if not db.execute("SELECT 1 FROM pg_roles WHERE rolname=%s", (login,)).fetchone():
                    role_password = conninfo_to_dict(connections[name])["password"]
                    db.execute(
                        sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(
                            sql.Identifier(login), sql.Literal(role_password)
                        )
                    )
                    db.execute(
                        sql.SQL("GRANT {} TO {}").format(
                            sql.Identifier(role), sql.Identifier(login)
                        )
                    )
                configure_login(db, login)
            seeded = db.execute("SELECT count(*) FROM service_desk.principal").fetchone()
            if seeded and seeded[0]:
                recorded = db.execute(
                    "SELECT sha256 FROM service_desk.read_fixture_state"
                ).fetchone()
                if recorded != (fingerprint(fixtures),):
                    raise SystemExit(
                        "Existing fixture hash differs; recreate only the disposable read project."
                    )
                seed_internal_members(db, fixtures)
                seed_access(db, fixtures)
                print("Existing read-lab fixtures preserved.")
                return
            db.execute(
                "INSERT INTO service_desk.read_fixture_state VALUES(true,%s)",
                (fingerprint(fixtures),),
            )
            for p in fixtures.principals:
                db.execute(
                    "INSERT INTO service_desk.principal VALUES(%s,%s,%s,%s)",
                    (p.id, p.kind, p.department, p.manager),
                )
                if p.kind == "human":
                    db.execute(
                        "INSERT INTO service_desk.identity_binding VALUES(%s,%s,%s)",
                        (ISSUER, subject_for(p.id), p.id),
                    )
            for d in fixtures.documents:
                db.execute(
                    "INSERT INTO service_desk.document(id,version,classification,title,body) "
                    "VALUES(%s,%s,%s,%s,%s)",
                    (d.id, d.version, d.classification, d.title, d.body),
                )
                for reader in d.readers:
                    db.execute(
                        "INSERT INTO service_desk.document_reader VALUES(%s,%s)", (d.id, reader)
                    )
            for t in fixtures.tickets:
                db.execute(
                    "INSERT INTO service_desk.ticket(id,requester,team,body,submitted_at) "
                    "VALUES(%s,%s,%s,%s,%s)",
                    (t.id, t.requester, t.team, t.body, t.submitted_at),
                )
                for reader in t.readers:
                    db.execute(
                        "INSERT INTO service_desk.ticket_reader VALUES(%s,%s)", (t.id, reader)
                    )
                for c in t.comments:
                    db.execute(
                        "INSERT INTO service_desk.ticket_comment VALUES(%s,%s,%s,%s)",
                        (c.id, t.id, c.visibility, c.body),
                    )
                    for reader in c.readers:
                        db.execute(
                            "INSERT INTO service_desk.comment_reader VALUES(%s,%s)", (c.id, reader)
                        )
            seed_internal_members(db, fixtures)
            seed_access(db, fixtures)
    print("Applied migrations and synthetic fixtures. SHA256: " + fingerprint(fixtures))


if __name__ == "__main__":
    main()
