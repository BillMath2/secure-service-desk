"""Actual service-role saturation, fail-closed reads/publication and capacity recovery."""

import os
from contextlib import ExitStack

import psycopg
import pytest
from psycopg import sql
from test_phase2_reads import connections, identity, scalar, service, task
from test_publication import actor_ticket, post, ready

from service_desk.core.database import LOGIN_LIMITS, check_database, configure_login

__all__ = ["connections", "actor_ticket"]
pytestmark = [
    pytest.mark.postgres,
    pytest.mark.skipif(os.environ.get("DESK_READ_INTEGRATION") != "1", reason="Opt-in PostgreSQL"),
]
SERVICES = {
    "creator": "read_app",
    "gateway": "read_gateway",
    "knowledge": "read_knowledge",
    "tickets": "read_tickets",
    "publisher": "read_publisher",
}


@pytest.mark.parametrize("name", SERVICES)
def test_role_saturation_and_recovery(connections: dict[str, str], name: str) -> None:
    login = SERVICES[name]
    assert all(check_database(connections[name], login).values())
    with ExitStack() as stack:
        held = [
            stack.enter_context(psycopg.connect(connections[name], autocommit=True))
            for _ in range(LOGIN_LIMITS[login])
        ]
        with (
            pytest.raises(psycopg.OperationalError),
            psycopg.connect(connections[name], connect_timeout=3),
        ):
            pytest.fail("Excess service connection accepted")
        # The other service and existing admitted connection remain usable.
        other = "tickets" if name != "tickets" else "knowledge"
        with psycopg.connect(connections[other]) as db:
            assert db.execute("SELECT 1").fetchone() == (1,)
        assert held[0].execute("SELECT 1").fetchone() == (1,)
    assert all(check_database(connections[name], login).values())


def test_read_capacity_failure_returns_no_content(connections: dict[str, str]) -> None:
    task_id = task(connections)
    tool = service(connections)
    with ExitStack() as stack:
        for _ in range(LOGIN_LIMITS["read_knowledge"]):
            stack.enter_context(psycopg.connect(connections["knowledge"], autocommit=True))
        result = tool.invoke(identity(), task_id, "read_document", {"document_id": "doc-public"})
        assert result == {
            "allowed": False,
            "reason": "SERVICE_ERROR",
            "message": "Resource unavailable",
        }
    assert tool.invoke(identity(), task_id, "read_document", {"document_id": "doc-public"})[
        "allowed"
    ]


def test_publication_capacity_failure_has_no_effect_and_can_retry(
    connections: dict[str, str], actor_ticket: tuple[str, str]
) -> None:
    store, who, review = ready(connections, actor_ticket)
    with ExitStack() as stack:
        for _ in range(LOGIN_LIMITS["read_publisher"]):
            stack.enter_context(psycopg.connect(connections["publisher"], autocommit=True))
        with pytest.raises(psycopg.OperationalError):
            post(store, who, review)
        assert (
            scalar(
                connections,
                "SELECT count(*) FROM service_desk.ticket_publication WHERE draft_id=%s",
                (review["draft_id"],),
            )
            == 0
        )
        assert (
            scalar(
                connections,
                "SELECT version FROM service_desk.ticket WHERE id=%s",
                (actor_ticket[1],),
            )
            == 1
        )
    receipt = post(store, who, review)
    assert receipt["status"] == "published" and post(store, who, review) == receipt


def test_preparation_restores_limits_without_rotating_password(connections: dict[str, str]) -> None:
    with psycopg.connect(connections["admin"], autocommit=True) as db:
        try:
            db.execute("ALTER ROLE read_gateway CONNECTION LIMIT -1")
            db.execute("ALTER ROLE read_gateway RESET idle_session_timeout")
            with pytest.raises(RuntimeError, match="Database capacity check failed"):
                check_database(connections["gateway"], "read_gateway")
        finally:
            configure_login(db, "read_gateway")
            configure_login(db, "read_gateway")
    assert all(check_database(connections["gateway"], "read_gateway").values())


@pytest.mark.parametrize("name", SERVICES)
def test_service_cannot_raise_its_connection_limit(connections: dict[str, str], name: str) -> None:
    with (
        psycopg.connect(connections[name]) as db,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        db.execute(
            sql.SQL("ALTER ROLE {} CONNECTION LIMIT -1").format(sql.Identifier(SERVICES[name]))
        )
