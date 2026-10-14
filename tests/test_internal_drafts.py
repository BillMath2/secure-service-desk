"""Internal staff audience, channel binding, and exact human publication in PostgreSQL."""

import asyncio
import json
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
from uuid import UUID

import psycopg
import pytest
from test_agent_tasks import RecordingProvider, setup
from test_phase2_reads import connections, identity, scalar, service, task, update
from test_publication import actor_ticket, post

from scripts.prepare_read_store import seed_internal_members
from service_desk.agent.provider import AnswerTurn, ProviderReply
from service_desk.agent.requester import (
    InternalDrafter,
    InternalStore,
    RequesterDrafter,
)
from service_desk.app.publication import InternalPublicationStore, PublicationStore
from service_desk.core.auth.tokens import VerifiedIdentity
from service_desk.core.gateway.registry import BoundaryDenied
from service_desk.fixtures import load_fixtures

__all__ = ["connections", "actor_ticket"]
pytestmark = [
    pytest.mark.postgres,
    pytest.mark.skipif(os.environ.get("DESK_READ_INTEGRATION") != "1", reason="Opt-in PostgreSQL"),
]


@pytest.fixture
def internal_ticket(connections: dict[str, str], actor_ticket: tuple[str, str]) -> tuple[str, str]:
    actor, ticket = actor_ticket
    with psycopg.connect(connections["admin"]) as db:
        for member in (actor, "morgan"):
            db.execute(
                "INSERT INTO service_desk.ticket_internal_member VALUES(%s,%s)", (ticket, member)
            )
        db.execute(
            "INSERT INTO service_desk.ticket_comment VALUES(%s,%s,'internal',%s)",
            ("source-" + ticket, ticket, "Staff handoff: LAB-CANARY-STAFF-" + ticket.upper()),
        )
        for member in (actor, "morgan"):
            db.execute(
                "INSERT INTO service_desk.comment_reader VALUES(%s,%s)",
                ("source-" + ticket, member),
            )
    return actor_ticket


class StaffProvider(RecordingProvider):
    async def generate(self, request: str, *, max_output: int) -> ProviderReply:
        self.requests.append(request)
        ticket = json.loads(request)["history"][0]["result"]["ticket"]
        return ProviderReply(
            turn=AnswerTurn(text=ticket["comments"][0]["body"], citations=[ticket["citation"]]),
            input_tokens=10,
            output_tokens=10,
        )


def ready_internal(
    values: dict[str, str], pair: tuple[str, str]
) -> tuple[InternalPublicationStore, VerifiedIdentity, dict[str, Any]]:
    assistant, login = setup(values, pair[0])
    assistant.provider = StaffProvider()
    drafter = InternalDrafter(assistant)
    t = drafter.store.create_draft(login.identity, pair[1])
    result = asyncio.run(drafter.run(login, t))
    assert result["allowed"] and result["audience"] == "internal"
    store = InternalPublicationStore(values["publisher"])
    return (
        store,
        login.identity,
        store.review(login.identity, UUID(result["draft_id"]), "session-one"),
    )


def test_internal_comment_exact_readers_and_concurrent_confirmation(
    connections: dict[str, str], internal_ticket: tuple[str, str]
) -> None:
    store, who, review = ready_internal(connections, internal_ticket)
    assert review["recipients"] == sorted([internal_ticket[0], "morgan"])
    assert "LAB-CANARY-STAFF" in review["draft"]
    with ThreadPoolExecutor(max_workers=6) as pool:
        receipts = list(pool.map(lambda _: post(store, who, review), range(6)))
    assert all(r == receipts[0] for r in receipts)
    comment = receipts[0]["comment_id"]
    assert (
        scalar(
            connections,
            "SELECT visibility FROM service_desk.ticket_comment WHERE id=%s",
            (comment,),
        )
        == "internal"
    )
    assert (
        scalar(connections, "SELECT body FROM service_desk.ticket_comment WHERE id=%s", (comment,))
        == review["draft"]
    )
    assert (
        scalar(
            connections,
            "SELECT version FROM service_desk.ticket WHERE id=%s",
            (internal_ticket[1],),
        )
        == 2
    )
    for reader in (internal_ticket[0], "morgan", "alice"):
        result = service(connections, "tickets").invoke(
            identity(reader),
            task(connections, reader, ticket=internal_ticket[1]),
            "read_ticket",
            {"ticket_id": internal_ticket[1]},
        )
        assert result["allowed"]
        assert (comment in {c["id"] for c in result["ticket"]["comments"]}) == (reader != "alice")


@pytest.mark.parametrize("channel", ["requester", "internal"])
def test_task_review_confirmation_and_retry_cannot_cross_channels(
    connections: dict[str, str], internal_ticket: tuple[str, str], channel: str
) -> None:
    assistant, login = setup(connections, internal_ticket[0])
    actual = InternalDrafter(assistant) if channel == "internal" else RequesterDrafter(assistant)
    other = RequesterDrafter(assistant) if channel == "internal" else InternalDrafter(assistant)
    t = actual.store.create_draft(login.identity, internal_ticket[1])
    assert not asyncio.run(other.run(login, t))["allowed"]
    assert not asyncio.run(assistant.run(login, t, "reuse as chat"))["allowed"]
    result = asyncio.run(actual.run(login, t))
    assert result["allowed"]
    target = UUID(result["draft_id"])
    with pytest.raises(BoundaryDenied):
        other.store.review(login.identity, target)
    wrong = (
        PublicationStore(connections["publisher"])
        if channel == "internal"
        else InternalPublicationStore(connections["publisher"])
    )
    right = (
        InternalPublicationStore(connections["publisher"])
        if channel == "internal"
        else PublicationStore(connections["publisher"])
    )
    with pytest.raises(BoundaryDenied):
        wrong.review(login.identity, target, "session-one")
    review = right.review(login.identity, target, "session-one")
    with pytest.raises(BoundaryDenied):
        post(wrong, login.identity, review)
    assert post(right, login.identity, review)["allowed"]
    with pytest.raises(BoundaryDenied):
        post(wrong, login.identity, review)


@pytest.mark.parametrize("invalid", ["requester", "workload", "unreadable", "empty", "caller"])
def test_invalid_internal_audience_fails_closed(
    connections: dict[str, str], internal_ticket: tuple[str, str], invalid: str
) -> None:
    actor, ticket = internal_ticket
    if invalid in ("requester", "workload", "unreadable"):
        member = {"requester": "alice", "workload": "agent", "unreadable": "bob"}[invalid]
        update(
            connections,
            "INSERT INTO service_desk.ticket_internal_member VALUES(%s,%s)",
            (ticket, member),
        )
    else:
        update(
            connections,
            "DELETE FROM service_desk.ticket_internal_member "
            "WHERE ticket_id=%s AND (%s OR principal_id=%s)",
            (ticket, invalid == "empty", actor),
        )
    with pytest.raises(BoundaryDenied):
        InternalStore(connections["creator"]).create_draft(identity(actor, "web"), ticket)
    # Requester privilege never grants internal admission, even with a mistaken membership.
    with pytest.raises(BoundaryDenied):
        InternalStore(connections["creator"]).create_draft(identity("alice", "web"), ticket)


@pytest.mark.parametrize("change", ["member", "ticket_acl", "comment_acl", "guide_acl"])
def test_internal_membership_or_acl_change_and_restore_invalidates_review(
    connections: dict[str, str], internal_ticket: tuple[str, str], change: str
) -> None:
    store, who, review = ready_internal(connections, internal_ticket)
    table, column, resource = {
        "member": ("ticket_internal_member", "ticket_id", internal_ticket[1]),
        "ticket_acl": ("ticket_reader", "ticket_id", internal_ticket[1]),
        "comment_acl": ("comment_reader", "comment_id", "source-" + internal_ticket[1]),
        "guide_acl": ("document_reader", "document_id", "doc-public"),
    }[change]
    update(
        connections,
        f"DELETE FROM service_desk.{table} WHERE {column}=%s AND principal_id='morgan'",
        (resource,),
    )
    update(connections, f"INSERT INTO service_desk.{table} VALUES(%s,'morgan')", (resource,))
    with pytest.raises(BoundaryDenied, match="POLICY_STALE"):
        post(store, who, review)
    assert (
        scalar(
            connections,
            "SELECT count(*) FROM service_desk.ticket_publication WHERE draft_id=%s",
            (review["draft_id"],),
        )
        == 0
    )


def test_internal_context_is_fresh_and_never_reused_for_requester(
    connections: dict[str, str], internal_ticket: tuple[str, str]
) -> None:
    assistant, login = setup(connections, internal_ticket[0])
    assert isinstance(assistant.provider, RecordingProvider)
    internal = InternalDrafter(assistant)
    t = internal.store.create_draft(login.identity, internal_ticket[1])
    assert asyncio.run(internal.run(login, t))["allowed"]
    assert "LAB-CANARY-STAFF" in assistant.provider.requests[-1]
    requester = RequesterDrafter(assistant)
    t = requester.store.create_draft(login.identity, internal_ticket[1])
    result = asyncio.run(requester.run(login, t))
    assert result["allowed"] and result["recipients"] == ["alice"]
    assert "LAB-CANARY-STAFF" not in assistant.provider.requests[-1]
    assert "internal" not in assistant.provider.requests[-1]


def test_internal_sources_require_every_staff_members_comment_access(
    connections: dict[str, str], internal_ticket: tuple[str, str]
) -> None:
    update(
        connections,
        "DELETE FROM service_desk.comment_reader WHERE comment_id=%s AND principal_id='morgan'",
        ("source-" + internal_ticket[1],),
    )
    assistant, login = setup(connections, internal_ticket[0])
    assert isinstance(assistant.provider, RecordingProvider)
    drafter = InternalDrafter(assistant)
    t = drafter.store.create_draft(login.identity, internal_ticket[1])
    result = asyncio.run(drafter.run(login, t))
    assert result["allowed"]
    assert not any(s["kind"] == "comment" for s in result["sources"])
    assert "LAB-CANARY-STAFF" not in assistant.provider.requests[-1]


def test_internal_membership_change_during_generation_prevents_persistence(
    connections: dict[str, str], internal_ticket: tuple[str, str]
) -> None:
    class ChangingProvider(StaffProvider):
        async def generate(self, request: str, *, max_output: int) -> ProviderReply:
            update(
                connections,
                "DELETE FROM service_desk.ticket_internal_member "
                "WHERE ticket_id=%s AND principal_id='morgan'",
                (internal_ticket[1],),
            )
            return await super().generate(request, max_output=max_output)

    assistant, login = setup(connections, internal_ticket[0])
    assistant.provider = ChangingProvider()
    drafter = InternalDrafter(assistant)
    t = drafter.store.create_draft(login.identity, internal_ticket[1])
    result = asyncio.run(drafter.run(login, t))
    assert not result["allowed"] and "draft" not in result
    assert (
        scalar(
            connections, "SELECT count(*) FROM service_desk.requester_draft WHERE task_id=%s", (t,)
        )
        == 0
    )


def test_fixture_setup_does_not_restore_revoked_staff_membership(
    connections: dict[str, str],
) -> None:
    with psycopg.connect(connections["admin"]) as db:
        assert db.execute(
            "SELECT principal_id FROM service_desk.ticket_internal_member "
            "WHERE ticket_id='ticket-alice' ORDER BY principal_id"
        ).fetchall() == [("erin",), ("morgan",), ("olivia",)]
        db.execute(
            "DELETE FROM service_desk.ticket_internal_member "
            "WHERE ticket_id='ticket-alice' AND principal_id='morgan'"
        )
        seed_internal_members(db, load_fixtures(Path("fixtures/company.json")))
        assert (
            db.execute(
                "SELECT 1 FROM service_desk.ticket_internal_member "
                "WHERE ticket_id='ticket-alice' AND principal_id='morgan'"
            ).fetchone()
            is None
        )
        db.rollback()


def test_internal_output_guard_still_blocks_other_audiences(
    connections: dict[str, str], internal_ticket: tuple[str, str], caplog: pytest.LogCaptureFixture
) -> None:
    class LeakingProvider(RecordingProvider):
        async def generate(self, request: str, *, max_output: int) -> ProviderReply:
            return ProviderReply(
                turn=AnswerTurn(text="LAB-CANARY-HR-A69F", citations=["document:doc-public@1"]),
                input_tokens=10,
                output_tokens=10,
            )

    assistant, login = setup(connections, internal_ticket[0])
    assistant.provider = LeakingProvider()
    drafter = InternalDrafter(assistant)
    t = drafter.store.create_draft(login.identity, internal_ticket[1])
    result = asyncio.run(drafter.run(login, t))
    assert not result["allowed"] and result["reason"] == "OUTPUT_DENIED"
    assert (
        scalar(
            connections, "SELECT count(*) FROM service_desk.requester_draft WHERE task_id=%s", (t,)
        )
        == 0
    )
    assert "LAB-CANARY-HR-A69F" not in caplog.text


def test_internal_audience_and_generic_helpers_are_not_app_writable(
    connections: dict[str, str],
) -> None:
    for role in ("creator", "gateway", "knowledge", "tickets", "publisher"):
        with psycopg.connect(connections[role]) as db:
            assert db.execute(
                "SELECT has_table_privilege(current_user,'service_desk.ticket_internal_member',"
                "'SELECT,INSERT,UPDATE,DELETE')"
            ).fetchone() == (False,)
            for signature in (
                "create_ticket_draft_task(uuid,uuid,text,text,text,text)",
                "ticket_draft_action(uuid,text,text,text,integer,jsonb)",
                "save_ticket_draft(uuid,uuid,text,text,text,jsonb,jsonb,timestamptz)",
                "review_ticket_draft(uuid,text,text)",
                "issue_ticket_confirmation(uuid,text,text,text,text,timestamptz)",
                "confirm_ticket_draft(uuid,text,text,text,text,text,timestamptz)",
            ):
                assert db.execute(
                    "SELECT has_function_privilege(current_user,%s,'EXECUTE')",
                    ("service_desk." + signature,),
                ).fetchone() == (False,)
            if role != "publisher":
                assert db.execute(
                    "SELECT has_function_privilege(current_user,"
                    "'service_desk.confirm_internal_comment"
                    "(uuid,text,text,text,text,text,timestamptz)','EXECUTE')"
                ).fetchone() == (False,)
