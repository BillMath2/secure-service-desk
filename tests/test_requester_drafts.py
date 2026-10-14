"""Phase 3 F4 recipient boundary: actual SQL roles, signed identities, hostile providers."""

import asyncio
import json
import os
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import psycopg
import pytest
from test_agent_tasks import RecordingProvider, setup
from test_phase2_reads import connections, identity, scalar, task, update

from service_desk.agent.provider import AnswerTurn, ProviderReply, ToolTurn
from service_desk.agent.requester import RequesterDrafter, RequesterStore
from service_desk.core.gateway.registry import BoundaryDenied

__all__ = ["connections"]
pytestmark = [
    pytest.mark.postgres,
    pytest.mark.skipif(
        os.environ.get("DESK_READ_INTEGRATION") != "1",
        reason="Opt-in disposable PostgreSQL required",
    ),
]


@pytest.fixture(autouse=True)
def requester_comment(connections: dict[str, str]) -> Iterator[None]:
    with psycopg.connect(connections["admin"]) as db:
        db.execute(
            "INSERT INTO service_desk.ticket_comment VALUES"
            "('phase3-public-comment','ticket-alice','requester','Please help with support hours.')"
        )
        db.execute(
            "INSERT INTO service_desk.comment_reader VALUES"
            "('phase3-public-comment','alice'),('phase3-public-comment','erin'),"
            "('phase3-public-comment','morgan')"
        )
    try:
        yield
    finally:
        with psycopg.connect(connections["admin"]) as db:
            db.execute(
                "DELETE FROM service_desk.comment_reader WHERE comment_id='phase3-public-comment'"
            )
            db.execute("DELETE FROM service_desk.ticket_comment WHERE id='phase3-public-comment'")


def test_fresh_draft_manifest_and_private_chat_separation(connections: dict[str, str]) -> None:
    assistant, login = setup(connections)
    private = asyncio.run(assistant.run(login, task(connections), "PRIVATE ANALYST CONTEXT"))
    assert private["allowed"]
    drafter = RequesterDrafter(assistant)
    t = drafter.store.create_requester(login.identity, "ticket-alice")
    result = asyncio.run(drafter.run(login, t))
    assert result["allowed"] and result["status"] == "unreviewed"
    assert result["recipients"] == ["alice"]
    assert result["citations"] == ["document:doc-public@1"]
    assert {s["kind"] for s in result["sources"]} >= {"ticket", "document"}
    assert all(len(s["body_sha256"]) == 64 for s in result["sources"])
    assert isinstance(assistant.provider, RecordingProvider)
    request = assistant.provider.requests[-1]
    assert json.loads(request)["tools"] == []
    for secret in ("PRIVATE ANALYST CONTEXT", "internal", "C15D", "A69F", login.access_token):
        assert secret not in request
    assert (
        scalar(connections, "SELECT model_calls FROM service_desk.read_task WHERE id=%s", (t,)) == 1
    )
    assert not asyncio.run(drafter.run(login, t))["allowed"]
    assert not asyncio.run(assistant.run(login, t, "Reuse as chat"))["allowed"]


def test_requester_cannot_reuse_private_chat_even_when_same_audience(
    connections: dict[str, str],
) -> None:
    assistant, login = setup(connections, "alice")
    drafter = RequesterDrafter(assistant)
    draft_task = drafter.store.create_requester(login.identity, "ticket-alice")
    assert not asyncio.run(assistant.run(login, draft_task, "Injected private prompt"))["allowed"]
    assert asyncio.run(drafter.run(login, draft_task))["allowed"]
    assert not asyncio.run(drafter.run(login, task(connections, "alice")))["allowed"]


@pytest.mark.parametrize("recipient", ["bob", "agent"])
def test_ineligible_participant_prevents_admission(
    connections: dict[str, str], recipient: str
) -> None:
    # Both exist, but neither is a permitted human reader of this ticket.
    update(
        connections,
        "INSERT INTO service_desk.ticket_reply_participant VALUES('ticket-alice',%s)",
        (recipient,),
    )
    try:
        with pytest.raises(BoundaryDenied):
            RequesterStore(connections["creator"]).create_requester(
                identity(client="web"), "ticket-alice"
            )
    finally:
        update(
            connections,
            "DELETE FROM service_desk.ticket_reply_participant WHERE ticket_id='ticket-alice'",
        )


def test_all_participants_are_resolved_by_policy(connections: dict[str, str]) -> None:
    update(
        connections,
        "INSERT INTO service_desk.ticket_reply_participant VALUES('ticket-alice','morgan')",
    )
    try:
        assistant, login = setup(connections)
        drafter = RequesterDrafter(assistant)
        t = drafter.store.create_requester(login.identity, "ticket-alice")
        result = asyncio.run(drafter.run(login, t))
        assert result["allowed"] and result["recipients"] == ["alice", "morgan"]
        assert all(
            s["kind"] != "comment" or s["visibility"] == "requester" for s in result["sources"]
        )
    finally:
        update(
            connections,
            "DELETE FROM service_desk.ticket_reply_participant WHERE ticket_id='ticket-alice'",
        )


@pytest.mark.parametrize(
    "change",
    [
        "body",
        "title",
        "ticket_body",
        "version",
        "acl",
        "ticket_acl",
        "participant",
        "policy",
        "comment",
        "comment_acl",
    ],
)
def test_changes_during_generation_withhold_entire_draft(
    connections: dict[str, str], change: str
) -> None:
    assistant, login = setup(connections)
    # Restore only fixture changes; task/audit transactions remain as evidence.
    queries = {
        "body": "UPDATE service_desk.document SET body=body || ' changed' WHERE id='doc-public'",
        "title": "UPDATE service_desk.document SET title=title || ' changed' WHERE id='doc-public'",
        "ticket_body": "UPDATE service_desk.ticket SET body=body || ' changed' "
        "WHERE id='ticket-alice'",
        "version": "UPDATE service_desk.document SET version=version+1 WHERE id='doc-public'",
        "acl": "DELETE FROM service_desk.document_reader "
        "WHERE document_id='doc-public' AND principal_id='alice'",
        "ticket_acl": "DELETE FROM service_desk.ticket_reader "
        "WHERE ticket_id='ticket-alice' AND principal_id='alice'",
        "participant": "INSERT INTO service_desk.ticket_reply_participant "
        "VALUES('ticket-alice','morgan')",
        "policy": "UPDATE service_desk.read_policy SET version='policy-changed'",
        "comment": "UPDATE service_desk.ticket_comment SET body=body || ' changed' "
        "WHERE ticket_id='ticket-alice' AND visibility='requester'",
        "comment_acl": "DELETE FROM service_desk.comment_reader "
        "WHERE comment_id='phase3-public-comment' AND principal_id='alice'",
    }
    with psycopg.connect(connections["admin"]) as db:
        original_doc = db.execute(
            "SELECT body,title,version FROM service_desk.document WHERE id='doc-public'"
        ).fetchone()
        original_ticket = db.execute(
            "SELECT body FROM service_desk.ticket WHERE id='ticket-alice'"
        ).fetchone()
        original_comments = db.execute(
            "SELECT id,body FROM service_desk.ticket_comment WHERE ticket_id='ticket-alice'"
        ).fetchall()
    assert original_doc and original_ticket

    class MutatingProvider(RecordingProvider):
        async def generate(self, request: str, *, max_output: int) -> ProviderReply:
            reply = await super().generate(request, max_output=max_output)
            update(connections, queries[change])
            return reply

    assistant.provider = MutatingProvider()
    drafter = RequesterDrafter(assistant)
    t = drafter.store.create_requester(login.identity, "ticket-alice")
    try:
        result = asyncio.run(drafter.run(login, t))
        assert result["allowed"] is False and "draft" not in result and "sources" not in result
        assert (
            scalar(connections, "SELECT agent_state FROM service_desk.read_task WHERE id=%s", (t,))
            == "stopped"
        )
    finally:
        with psycopg.connect(connections["admin"]) as db:
            db.execute(
                "UPDATE service_desk.document SET body=%s,title=%s,version=%s "
                "WHERE id='doc-public'",
                original_doc,
            )
            db.execute(
                "UPDATE service_desk.ticket SET body=%s WHERE id='ticket-alice'", original_ticket
            )
            for cid, body in original_comments:
                db.execute(
                    "UPDATE service_desk.ticket_comment SET body=%s WHERE id=%s", (body, cid)
                )
            db.execute(
                "INSERT INTO service_desk.document_reader VALUES('doc-public','alice') "
                "ON CONFLICT DO NOTHING"
            )
            db.execute(
                "INSERT INTO service_desk.ticket_reader VALUES('ticket-alice','alice') "
                "ON CONFLICT DO NOTHING"
            )
            db.execute(
                "DELETE FROM service_desk.ticket_reply_participant WHERE ticket_id='ticket-alice'"
            )
            db.execute("UPDATE service_desk.read_policy SET version='policy-v1'")


@pytest.mark.parametrize("case", ["owner", "expired", "policy", "cancelled"])
def test_draft_admission_denies_before_provider(connections: dict[str, str], case: str) -> None:
    assistant, login = setup(connections, "alice" if case == "owner" else "erin")
    drafter = RequesterDrafter(assistant)
    t = drafter.store.create_requester(identity(client="web"), "ticket-alice")
    if case != "owner":
        clause = {
            "expired": "deadline=clock_timestamp()-interval '1 second'",
            "policy": "policy_version='stale'",
            "cancelled": "active=false",
        }[case]
        update(connections, f"UPDATE service_desk.read_task SET {clause} WHERE id=%s", (t,))
    assert not asyncio.run(drafter.run(login, t))["allowed"]
    assert isinstance(assistant.provider, RecordingProvider) and assistant.provider.requests == []


@pytest.mark.parametrize("tamper", ["omit_comment", "body", "extra_metadata"])
def test_manifest_is_checked_before_model_receives_context(
    connections: dict[str, str], tamper: str
) -> None:
    assistant, login = setup(connections)
    real = assistant.gateway

    class TamperedGateway:
        def call(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            result = real.call(*args, **kwargs)
            if "ticket" in result:
                if tamper == "omit_comment":
                    assert result["ticket"]["comments"]
                    result["ticket"]["comments"] = []
                elif tamper == "body":
                    result["ticket"]["body"] = "UNTRACKED SECRET"
                else:
                    result["untracked"] = "UNTRACKED SECRET"
            return result

    assistant.gateway = TamperedGateway()
    drafter = RequesterDrafter(assistant)
    t = drafter.store.create_requester(login.identity, "ticket-alice")
    result = asyncio.run(drafter.run(login, t))
    assert isinstance(assistant.provider, RecordingProvider)
    if tamper == "extra_metadata":
        assert result["allowed"]
        assert "UNTRACKED SECRET" not in assistant.provider.requests[0]
    else:
        assert not result["allowed"]
        assert assistant.provider.requests == []


@pytest.mark.parametrize("failure", ["tool", "citation", "error", "timeout"])
def test_provider_failure_never_releases_partial_content(
    connections: dict[str, str], failure: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    assistant, login = setup(connections)

    class HostileProvider:
        async def generate(self, request: str, *, max_output: int) -> ProviderReply:
            if failure == "error":
                raise ValueError("SECRET FAILED DRAFT")
            if failure == "timeout":
                await asyncio.sleep(1)
            return ProviderReply(
                turn=ToolTurn(name="read_document", arguments={"document_id": "doc-admin-reset"})
                if failure == "tool"
                else AnswerTurn(
                    text="SECRET FAILED DRAFT", citations=["document:doc-admin-reset@1"]
                ),
                input_tokens=1,
                output_tokens=10,
            )

    monkeypatch.setattr("service_desk.agent.requester.PROVIDER_TIMEOUT", 0.02)
    assistant.provider = HostileProvider()
    drafter = RequesterDrafter(assistant)
    t = drafter.store.create_requester(login.identity, "ticket-alice")
    result = asyncio.run(drafter.run(login, t))
    assert not result["allowed"] and "SECRET" not in json.dumps(result)
    assert (
        scalar(connections, "SELECT model_calls FROM service_desk.read_task WHERE id=%s", (t,)) == 1
    )
    assert (
        scalar(connections, "SELECT used_calls FROM service_desk.read_task WHERE id=%s", (t,)) == 2
    )


def test_concurrent_claim_single_winner_and_restricted_database_roles(
    connections: dict[str, str],
) -> None:
    store = RequesterStore(connections["creator"])
    who = identity(client="web")
    t = store.create_requester(who, "ticket-alice")

    def claim(_: int) -> bool:
        try:
            store.action(who, t, "claim")
            return True
        except BoundaryDenied:
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(claim, range(16))) == 1
    sources = scalar(
        connections,
        "SELECT service_desk.requester_manifest(t) FROM service_desk.read_task t WHERE id=%s",
        (t,),
    )

    def reserve(_: int) -> bool:
        try:
            store.action(who, t, "reserve", 4000, sources)
            return True
        except BoundaryDenied:
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(reserve, range(16))) == 1
    assert (
        scalar(connections, "SELECT model_tokens FROM service_desk.read_task WHERE id=%s", (t,))
        == 4000
    )
    with psycopg.connect(connections["creator"]) as db:
        for table in ("requester_run", "ticket_reply_participant", "ticket"):
            assert db.execute(
                "SELECT has_table_privilege(current_user,%s,'INSERT,UPDATE,DELETE,SELECT')",
                ("service_desk." + table,),
            ).fetchone() == (False,)
        assert db.execute(
            "SELECT has_function_privilege(current_user,"
            "'service_desk.chat_action(uuid,text,text,text,integer,jsonb)','EXECUTE')"
        ).fetchone() == (False,)
    store.action(who, t, "stop")


def test_cancellation_closes_task_and_keeps_reservation(connections: dict[str, str]) -> None:
    assistant, login = setup(connections)
    entered = asyncio.Event()

    class HangingProvider:
        async def generate(self, request: str, *, max_output: int) -> ProviderReply:
            entered.set()
            await asyncio.Future[None]()
            raise AssertionError("unreachable")

    assistant.provider = HangingProvider()
    drafter = RequesterDrafter(assistant)
    t = drafter.store.create_requester(login.identity, "ticket-alice")

    async def cancel() -> None:
        run = asyncio.create_task(drafter.run(login, t))
        await asyncio.wait_for(entered.wait(), timeout=10)
        run.cancel()
        with pytest.raises(asyncio.CancelledError):
            await run

    asyncio.run(cancel())
    assert (
        scalar(connections, "SELECT agent_state FROM service_desk.read_task WHERE id=%s", (t,))
        == "stopped"
    )
    assert (
        scalar(connections, "SELECT model_tokens FROM service_desk.read_task WHERE id=%s", (t,)) > 0
    )
