"""Human confirmation and atomic requester publication against disposable PostgreSQL."""

import asyncio
import os
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from typing import Any
from uuid import UUID, uuid4

import psycopg
import pytest
from test_agent_tasks import setup
from test_phase2_reads import connections, identity, scalar, service, task, update

from service_desk.agent.requester import RequesterDrafter
from service_desk.app.publication import PublicationStore
from service_desk.core.auth.lab import ISSUER, subject_for
from service_desk.core.auth.tokens import VerifiedIdentity
from service_desk.core.gateway.registry import BoundaryDenied

__all__ = ["connections"]
pytestmark = [
    pytest.mark.postgres,
    pytest.mark.skipif(os.environ.get("DESK_READ_INTEGRATION") != "1", reason="Opt-in PostgreSQL"),
]


@pytest.fixture
def actor_ticket(connections: dict[str, str]) -> tuple[str, str]:
    # Isolated synthetic principals/tickets avoid changing canonical fixture versions or
    # sharing per-user confirmation throttles. All live only in the disposable database.
    suffix = uuid4().hex[:12]
    actor, ticket = "publisher-" + suffix, "write-" + suffix
    with psycopg.connect(connections["admin"]) as db:
        db.execute(
            "INSERT INTO service_desk.principal VALUES(%s,'human','engineering',NULL)", (actor,)
        )
        db.execute(
            "INSERT INTO service_desk.identity_binding VALUES(%s,%s,%s)",
            (ISSUER, subject_for(actor), actor),
        )
        db.execute("INSERT INTO service_desk.document_reader VALUES('doc-public',%s)", (actor,))
        db.execute(
            "INSERT INTO service_desk.ticket VALUES(%s,'alice','engineering',"
            "'Please explain support hours.',1,clock_timestamp())",
            (ticket,),
        )
        for reader in (actor, "alice", "morgan"):
            db.execute("INSERT INTO service_desk.ticket_reader VALUES(%s,%s)", (ticket, reader))
    return actor, ticket


def draft(values: dict[str, str], pair: tuple[str, str]) -> tuple[VerifiedIdentity, dict[str, Any]]:
    assistant, login = setup(values, pair[0])
    drafter = RequesterDrafter(assistant)
    t = drafter.store.create_requester(login.identity, pair[1])
    result = asyncio.run(drafter.run(login, t))
    assert result["allowed"]
    return login.identity, result


def ready(
    values: dict[str, str], pair: tuple[str, str]
) -> tuple[PublicationStore, VerifiedIdentity, dict[str, Any]]:
    who, result = draft(values, pair)
    store = PublicationStore(values["publisher"])
    return store, who, store.review(who, UUID(result["draft_id"]), "session-one")


def post(store: PublicationStore, who: VerifiedIdentity, review: dict[str, Any]) -> dict[str, Any]:
    return store.confirm(
        who,
        UUID(review["draft_id"]),
        "session-one",
        review["confirmation_token"],
        review["body_sha256"],
    )


def test_exact_reply_and_readers_with_lost_response_retry(
    connections: dict[str, str], actor_ticket: tuple[str, str]
) -> None:
    store, who, review = ready(connections, actor_ticket)
    receipt = post(store, who, review)
    assert receipt["status"] == "published" and post(store, who, review) == receipt
    assert (
        scalar(
            connections,
            "SELECT body FROM service_desk.ticket_comment WHERE id=%s",
            (receipt["comment_id"],),
        )
        == review["draft"]
    )
    assert (
        scalar(
            connections, "SELECT version FROM service_desk.ticket WHERE id=%s", (actor_ticket[1],)
        )
        == 2
    )
    assert (
        scalar(
            connections,
            "SELECT count(*) FROM service_desk.ticket_publication WHERE draft_id=%s",
            (review["draft_id"],),
        )
        == 1
    )
    for reader in ("alice", actor_ticket[0], "morgan"):
        t = task(connections, reader, ticket=actor_ticket[1])
        result = service(connections, "tickets").invoke(
            identity(reader), t, "read_ticket", {"ticket_id": actor_ticket[1]}
        )
        assert result["allowed"]
        ids = {c["id"] for c in result["ticket"]["comments"]}
        assert (receipt["comment_id"] in ids) == (reader != "morgan")


@pytest.mark.parametrize("case", ["session", "owner", "token", "hash", "draft"])
def test_confirmation_cannot_be_rebound(
    connections: dict[str, str], actor_ticket: tuple[str, str], case: str
) -> None:
    store, who, review = ready(connections, actor_ticket)
    target = UUID(review["draft_id"])
    if case == "draft":
        _, another = draft(connections, actor_ticket)
        target = UUID(another["draft_id"])
    with pytest.raises(BoundaryDenied):
        store.confirm(
            identity("alice", "web") if case == "owner" else who,
            target,
            "wrong-session" if case == "session" else "session-one",
            "invented" if case == "token" else review["confirmation_token"],
            "0" * 64 if case == "hash" else review["body_sha256"],
        )
    assert (
        scalar(
            connections,
            "SELECT count(*) FROM service_desk.ticket_comment WHERE ticket_id=%s",
            (actor_ticket[1],),
        )
        == 0
    )


@pytest.mark.parametrize("case", ["source", "acl", "participant", "ticket", "policy"])
def test_changed_state_invalidates_confirmation(
    connections: dict[str, str], actor_ticket: tuple[str, str], case: str
) -> None:
    store, who, review = ready(connections, actor_ticket)
    if case == "source":
        update(
            connections, "UPDATE service_desk.document SET version=version+1 WHERE id='doc-public'"
        )
        update(
            connections, "UPDATE service_desk.document SET version=version-1 WHERE id='doc-public'"
        )
    elif case == "acl":
        update(
            connections,
            "DELETE FROM service_desk.ticket_reader WHERE ticket_id=%s AND principal_id=%s",
            (actor_ticket[1], actor_ticket[0]),
        )
    elif case == "participant":
        update(
            connections,
            "INSERT INTO service_desk.ticket_reply_participant VALUES(%s,'morgan')",
            (actor_ticket[1],),
        )
    elif case == "ticket":
        update(
            connections,
            "UPDATE service_desk.ticket SET version=version+1 WHERE id=%s",
            (actor_ticket[1],),
        )
    else:
        update(connections, "UPDATE service_desk.read_policy SET version='policy-v1'")
    with pytest.raises(BoundaryDenied):
        post(store, who, review)
    assert (
        scalar(
            connections,
            "SELECT count(*) FROM service_desk.ticket_comment WHERE ticket_id=%s",
            (actor_ticket[1],),
        )
        == 0
    )


def test_concurrent_confirmations_create_one_reply(
    connections: dict[str, str], actor_ticket: tuple[str, str]
) -> None:
    store, who, review = ready(connections, actor_ticket)
    with ThreadPoolExecutor(max_workers=6) as pool:
        receipts = list(pool.map(lambda _: post(store, who, review), range(12)))
    assert all(r == receipts[0] for r in receipts)
    assert (
        scalar(
            connections,
            "SELECT count(*) FROM service_desk.ticket_comment WHERE ticket_id=%s",
            (actor_ticket[1],),
        )
        == 1
    )
    assert (
        scalar(
            connections, "SELECT version FROM service_desk.ticket WHERE id=%s", (actor_ticket[1],)
        )
        == 2
    )


@pytest.mark.parametrize("published", [False, True])
def test_expired_confirmation_cannot_create_new_effect(
    connections: dict[str, str], actor_ticket: tuple[str, str], published: bool
) -> None:
    who, result = draft(connections, actor_ticket)
    store = PublicationStore(connections["publisher"])
    review = store.review(
        replace(who, expires_at=int(time.time()) + 2), UUID(result["draft_id"]), "session-one"
    )
    if published:
        receipt = post(store, who, review)
    time.sleep(2)
    if published:
        assert post(store, who, review) == receipt
    else:
        with pytest.raises(BoundaryDenied):
            post(store, who, review)
    assert scalar(
        connections,
        "SELECT count(*) FROM service_desk.ticket_comment WHERE ticket_id=%s",
        (actor_ticket[1],),
    ) == int(published)


def test_confirmation_issuance_is_bounded(
    connections: dict[str, str], actor_ticket: tuple[str, str]
) -> None:
    store, who, review = ready(connections, actor_ticket)
    for _ in range(4):
        store.review(who, UUID(review["draft_id"]), "session-one")
    with pytest.raises(BoundaryDenied, match="BUDGET_EXHAUSTED"):
        store.review(who, UUID(review["draft_id"]), "session-one")
    # Only the exact confirmation used for publication is a retry credential.
    second = store.review(who, UUID(draft(connections, actor_ticket)[1]["draft_id"]), "session-one")
    assert second["confirmation_token"] != review["confirmation_token"]


def test_user_confirmation_limit_is_shared_across_drafts(
    connections: dict[str, str], actor_ticket: tuple[str, str]
) -> None:
    who, initial = draft(connections, actor_ticket)
    store = PublicationStore(connections["publisher"])
    for i in range(4):
        result = initial if i == 0 else draft(connections, actor_ticket)[1]
        for _ in range(5):
            store.review(who, UUID(result["draft_id"]), "session-one")
    other = draft(connections, actor_ticket)[1]
    with pytest.raises(BoundaryDenied, match="BUDGET_EXHAUSTED"):
        store.review(who, UUID(other["draft_id"]), "session-one")


def test_other_confirmation_for_same_draft_cannot_be_reused_after_posting(
    connections: dict[str, str], actor_ticket: tuple[str, str]
) -> None:
    store, who, first = ready(connections, actor_ticket)
    second = store.review(who, UUID(first["draft_id"]), "session-one")
    post(store, who, first)
    with pytest.raises(BoundaryDenied):
        post(store, who, second)
    assert (
        scalar(
            connections,
            "SELECT count(*) FROM service_desk.ticket_comment WHERE ticket_id=%s",
            (actor_ticket[1],),
        )
        == 1
    )


def test_agent_and_read_service_roles_cannot_publish(connections: dict[str, str]) -> None:
    for role in ("creator", "gateway", "knowledge", "tickets"):
        with psycopg.connect(connections[role]) as db:
            for name in (
                "issue_draft_confirmation(uuid,text,text,text,text,timestamptz)",
                "confirm_requester_reply(uuid,text,text,text,text,text,timestamptz)",
            ):
                assert db.execute(
                    "SELECT has_function_privilege(current_user,%s,'EXECUTE')",
                    ("service_desk." + name,),
                ).fetchone() == (False,)
    with psycopg.connect(connections["publisher"]) as db:
        for table in (
            "ticket",
            "ticket_comment",
            "comment_reader",
            "requester_draft",
            "draft_confirmation",
            "ticket_publication",
        ):
            assert db.execute(
                "SELECT has_table_privilege(current_user,%s,'SELECT,INSERT,UPDATE,DELETE')",
                ("service_desk." + table,),
            ).fetchone() == (False,)


@pytest.mark.parametrize("failure", ["audit", "deadline"])
def test_failure_rolls_back_comment_readers_version_and_receipt(
    connections: dict[str, str], actor_ticket: tuple[str, str], failure: str
) -> None:
    store, who, review = ready(connections, actor_ticket)
    body = (
        "IF NEW.operation='requester_publish' THEN RAISE EXCEPTION 'audit unavailable'; END IF;"
        if failure == "audit"
        else "PERFORM pg_sleep(2);"
    )
    table = "read_audit" if failure == "audit" else "ticket_comment"
    update(
        connections,
        f"""
      CREATE FUNCTION service_desk.test_publication_failure() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN {body} RETURN NEW; END $$;
      CREATE TRIGGER test_publication_failure BEFORE INSERT ON service_desk.{table}
      FOR EACH ROW EXECUTE FUNCTION service_desk.test_publication_failure();
    """,
    )
    try:
        if failure == "deadline":
            who = replace(who, expires_at=int(time.time()) + 1)
        with pytest.raises((psycopg.Error, BoundaryDenied)):
            post(store, who, review)
        assert (
            scalar(
                connections,
                "SELECT count(*) FROM service_desk.ticket_comment WHERE ticket_id=%s",
                (actor_ticket[1],),
            )
            == 0
        )
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
    finally:
        update(
            connections,
            f"DROP TRIGGER test_publication_failure ON service_desk.{table}; "
            "DROP FUNCTION service_desk.test_publication_failure()",
        )
    assert post(store, identity(actor_ticket[0], "web"), review)["allowed"]


def test_lock_timeout_cannot_write_later(
    connections: dict[str, str], actor_ticket: tuple[str, str]
) -> None:
    store, who, review = ready(connections, actor_ticket)
    with ThreadPoolExecutor(max_workers=1) as pool:
        with psycopg.connect(connections["admin"]) as db:
            db.execute("SELECT * FROM service_desk.draft_epoch FOR UPDATE")
            pending = pool.submit(post, store, who, review)
            with pytest.raises(psycopg.Error):
                pending.result(timeout=4)
        assert (
            scalar(
                connections,
                "SELECT count(*) FROM service_desk.ticket_comment WHERE ticket_id=%s",
                (actor_ticket[1],),
            )
            == 0
        )
    assert post(store, who, review)["allowed"]
