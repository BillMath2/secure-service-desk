"""Persisted requester drafts: independent screening, immutable binding and stale review denial."""

import asyncio
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from typing import Any
from uuid import UUID

import psycopg
import pytest
from test_agent_tasks import RecordingProvider, setup
from test_phase2_reads import connections, identity, scalar, update

from service_desk.agent.provider import AnswerTurn, ProviderReply
from service_desk.agent.requester import RequesterDrafter, RequesterStore, digest
from service_desk.core.gateway.registry import BoundaryDenied

__all__ = ["connections"]
pytestmark = [
    pytest.mark.postgres,
    pytest.mark.skipif(os.environ.get("DESK_READ_INTEGRATION") != "1", reason="Opt-in PostgreSQL"),
]


def create_draft(values: dict[str, str]) -> tuple[RequesterStore, dict[str, Any]]:
    assistant, login = setup(values)
    drafter = RequesterDrafter(assistant)
    t = drafter.store.create_requester(login.identity, "ticket-alice")
    result = asyncio.run(drafter.run(login, t))
    assert result["allowed"]
    return drafter.store, result


def admitted(values: dict[str, str]) -> tuple[RequesterStore, UUID, list[dict[str, Any]]]:
    store = RequesterStore(values["creator"])
    who = identity(client="web")
    t = store.create_requester(who, "ticket-alice")
    store.action(who, t, "claim")
    sources: list[dict[str, Any]] = scalar(
        values,
        "SELECT service_desk.requester_manifest(t) FROM service_desk.read_task t WHERE id=%s",
        (t,),
    )
    store.action(who, t, "reserve", 4000, sources)
    return store, t, sources


@pytest.mark.parametrize(
    "leak", ["canary", "normalized_canary", "body", "normalized_body", "title", "comment", "ticket"]
)
def test_restricted_output_is_never_persisted_or_previewed(
    connections: dict[str, str], leak: str, caplog: pytest.LogCaptureFixture
) -> None:
    protected = {
        "canary": "LAB-CANARY-ADMIN-C15D",
        "normalized_canary": "lab-canary-hr-a69f",
        "body": "Synthetic privileged reset instructions: consult the resource owner.",
        "normalized_body": "SYNTHETIC\nPRIVILEGED   RESET instructions: "
        "consult the resource owner.",
        "title": "Internal admin reset procedure",
        "comment": scalar(
            connections, "SELECT body FROM service_desk.ticket_comment WHERE id='comment-private'"
        ),
        "ticket": scalar(connections, "SELECT body FROM service_desk.ticket WHERE id='ticket-bob'"),
    }[leak]
    assistant, login = setup(connections)

    class LeakingProvider(RecordingProvider):
        async def generate(self, request: str, *, max_output: int) -> ProviderReply:
            self.requests.append(request)
            return ProviderReply(
                turn=AnswerTurn(text=protected, citations=["document:doc-public@1"]),
                input_tokens=1,
                output_tokens=100,
            )

    assistant.provider = LeakingProvider()
    drafter = RequesterDrafter(assistant)
    t = drafter.store.create_requester(login.identity, "ticket-alice")
    result = asyncio.run(drafter.run(login, t))
    assert result["reason"] == "OUTPUT_DENIED"
    assert "draft" not in result and protected not in json.dumps(result) + caplog.text
    assert protected not in assistant.provider.requests[0]
    assert (
        scalar(
            connections, "SELECT count(*) FROM service_desk.requester_draft WHERE task_id=%s", (t,)
        )
        == 0
    )
    assert (
        scalar(
            connections,
            "SELECT reason FROM service_desk.read_audit "
            "WHERE task_id=%s AND operation='draft_save'",
            (t,),
        )
        == "OUTPUT_DENIED"
    )
    assert (
        scalar(connections, "SELECT agent_state FROM service_desk.read_task WHERE id=%s", (t,))
        == "stopped"
    )


def test_benign_draft_exact_binding_and_owner_only_review(connections: dict[str, str]) -> None:
    store, result = create_draft(connections)
    who = identity(client="web")
    draft_id = UUID(result["draft_id"])
    assert result == store.review(who, draft_id)
    assert result["body_sha256"] == digest(result["draft"])
    assert result["ticket_id"] == "ticket-alice" and result["recipients"] == ["alice"]
    for outsider in ("alice", "morgan", "bob"):
        with pytest.raises(BoundaryDenied):
            store.review(identity(outsider, "web"), draft_id)
    with pytest.raises(BoundaryDenied):
        store.review(replace(who, expires_at=0), draft_id)


def test_immutable_even_for_direct_updates_and_no_app_table_access(
    connections: dict[str, str],
) -> None:
    _, result = create_draft(connections)
    for assignment in (
        "body='changed'",
        "recipients=ARRAY['bob']",
        "expires_at=expires_at+interval '1 hour'",
    ):
        with pytest.raises(psycopg.Error), psycopg.connect(connections["admin"]) as db:
            db.execute(
                f"UPDATE service_desk.requester_draft SET {assignment} WHERE id=%s",
                (result["draft_id"],),
            )
    with psycopg.connect(connections["creator"]) as db:
        for table in ("requester_draft", "draft_epoch"):
            assert db.execute(
                "SELECT has_table_privilege(current_user,%s,"
                "'SELECT,INSERT,UPDATE,DELETE,TRUNCATE')",
                ("service_desk." + table,),
            ).fetchone() == (False,)
        assert db.execute(
            "SELECT has_function_privilege(current_user,"
            "'service_desk.draft_output_safe(service_desk.read_task,text)','EXECUTE')"
        ).fetchone() == (False,)


@pytest.mark.parametrize("mutation", ["acl", "source", "participant", "policy"])
def test_change_then_restore_cannot_revive_a_review(
    connections: dict[str, str], mutation: str
) -> None:
    store, result = create_draft(connections)
    who = identity(client="web")
    operations = {
        "acl": (
            "DELETE FROM service_desk.document_reader "
            "WHERE document_id='doc-public' AND principal_id='alice'",
            "INSERT INTO service_desk.document_reader VALUES('doc-public','alice')",
        ),
        "source": (
            "UPDATE service_desk.document SET version=version+1 WHERE id='doc-public'",
            "UPDATE service_desk.document SET version=version-1 WHERE id='doc-public'",
        ),
        "participant": (
            "INSERT INTO service_desk.ticket_reply_participant VALUES('ticket-alice','morgan')",
            "DELETE FROM service_desk.ticket_reply_participant WHERE ticket_id='ticket-alice'",
        ),
        "policy": (
            "UPDATE service_desk.read_policy SET version='policy-changed'",
            "UPDATE service_desk.read_policy SET version='policy-v1'",
        ),
    }
    change, restore = operations[mutation]
    update(connections, change)
    try:
        with pytest.raises(BoundaryDenied):
            store.review(who, UUID(result["draft_id"]))
    finally:
        update(connections, restore)
    with pytest.raises(BoundaryDenied):
        store.review(who, UUID(result["draft_id"]))
    # Regeneration after a deliberate change remains available.
    assert create_draft(connections)[1]["allowed"]


def test_expiry_is_bound_to_verified_identity_and_not_extended_by_review(
    connections: dict[str, str],
) -> None:
    store, t, sources = admitted(connections)
    who = identity(client="web")
    short = replace(who, expires_at=int(time.time()) + 2)
    result = store.save(
        short, t, "Support is available on weekdays.", ["document:doc-public@1"], sources
    )
    time.sleep(2)
    with pytest.raises(BoundaryDenied, match="TASK_EXPIRED"):
        store.review(who, UUID(result["draft_id"]))


def test_concurrent_save_has_one_immutable_winner(connections: dict[str, str]) -> None:
    store, t, sources = admitted(connections)
    who = identity(client="web")

    def save(i: int) -> bool:
        try:
            store.save(who, t, f"Support draft {i}.", ["document:doc-public@1"], sources)
            return True
        except BoundaryDenied:
            return False

    with ThreadPoolExecutor(max_workers=6) as pool:
        assert sum(pool.map(save, range(12))) == 1
    assert (
        scalar(
            connections, "SELECT count(*) FROM service_desk.requester_draft WHERE task_id=%s", (t,)
        )
        == 1
    )


def test_audit_failure_rolls_back_body_and_completion(connections: dict[str, str]) -> None:
    store, t, sources = admitted(connections)
    update(
        connections,
        """
      CREATE FUNCTION service_desk.test_draft_audit_failure() RETURNS trigger LANGUAGE plpgsql
      AS $$ BEGIN IF NEW.operation='draft_save' THEN RAISE EXCEPTION 'audit unavailable'; END IF;
      RETURN NEW; END $$;
      CREATE TRIGGER test_draft_audit_failure BEFORE INSERT ON service_desk.read_audit
      FOR EACH ROW EXECUTE FUNCTION service_desk.test_draft_audit_failure();
    """,
    )
    try:
        with pytest.raises(psycopg.Error):
            store.save(
                identity(client="web"), t, "Safe support draft.", ["document:doc-public@1"], sources
            )
        assert (
            scalar(
                connections,
                "SELECT count(*) FROM service_desk.requester_draft WHERE task_id=%s",
                (t,),
            )
            == 0
        )
        assert (
            scalar(connections, "SELECT agent_state FROM service_desk.read_task WHERE id=%s", (t,))
            == "running"
        )
    finally:
        update(
            connections,
            "DROP TRIGGER test_draft_audit_failure ON service_desk.read_audit; "
            "DROP FUNCTION service_desk.test_draft_audit_failure()",
        )
        store.action(identity(client="web"), t, "stop")


def test_database_screen_cannot_be_bypassed_by_direct_save(connections: dict[str, str]) -> None:
    store, t, sources = admitted(connections)
    with pytest.raises(BoundaryDenied, match="OUTPUT_DENIED"):
        store.save(
            identity(client="web"), t, "LAB-CANARY-HR-A69F", ["document:doc-public@1"], sources
        )
    assert (
        scalar(
            connections, "SELECT count(*) FROM service_desk.requester_draft WHERE task_id=%s", (t,)
        )
        == 0
    )
    store.action(identity(client="web"), t, "stop")


@pytest.mark.parametrize("case", ["bytes", "empty", "citations", "manifest"])
def test_invalid_bound_record_is_rejected_before_insert(
    connections: dict[str, str], case: str
) -> None:
    store, t, sources = admitted(connections)
    body = {"bytes": "x" * 8193, "empty": ""}.get(case, "Safe support draft.")
    citations = ["document:doc-hr@1" if case == "citations" else "document:doc-public@1"]
    if case == "manifest":
        sources = [dict(s, body_sha256="0" * 64) for s in sources]
    with pytest.raises(BoundaryDenied):
        store.save(identity(client="web"), t, body, citations, sources)
    assert (
        scalar(
            connections, "SELECT count(*) FROM service_desk.requester_draft WHERE task_id=%s", (t,)
        )
        == 0
    )
    store.action(identity(client="web"), t, "stop")


def test_screen_uses_recipient_permissions_not_a_blanket_canary_ban(
    connections: dict[str, str],
) -> None:
    store, t, sources = admitted(connections)
    # Both Erin and Alice may read this canary. This is an ACL screening control,
    # not a claim that an otherwise valid citation entails the answer's assertions.
    result = store.save(
        identity(client="web"), t, "LAB-CANARY-ENG-71B3", ["document:doc-public@1"], sources
    )
    assert result["allowed"]


def test_public_overlap_does_not_exempt_a_restricted_suffix(connections: dict[str, str]) -> None:
    original = scalar(
        connections, "SELECT body FROM service_desk.ticket_comment WHERE id='comment-private'"
    )
    public = scalar(connections, "SELECT body FROM service_desk.document WHERE id='doc-public'")
    restricted = "Confidential escalation phrase unique to this internal engineering comment."
    update(
        connections,
        "UPDATE service_desk.ticket_comment SET body=%s WHERE id='comment-private'",
        (public + " " + restricted,),
    )
    try:
        store, t, sources = admitted(connections)
        with pytest.raises(BoundaryDenied, match="OUTPUT_DENIED"):
            store.save(
                identity(client="web"),
                t,
                public + " " + restricted,
                ["document:doc-public@1"],
                sources,
            )
        assert store.save(identity(client="web"), t, public, ["document:doc-public@1"], sources)[
            "allowed"
        ]
    finally:
        update(
            connections,
            "UPDATE service_desk.ticket_comment SET body=%s WHERE id='comment-private'",
            (original,),
        )
