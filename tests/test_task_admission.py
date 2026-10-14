"""Persistent admission across sessions, channels and concurrent database connections."""

import asyncio
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from uuid import UUID, uuid4

import psycopg
import pytest
from test_agent_tasks import RecordingProvider, setup
from test_phase2_reads import connections, identity, scalar, update

from service_desk.agent.provider import ProviderReply
from service_desk.agent.requester import InternalStore, RequesterDrafter, RequesterStore
from service_desk.agent.store import AgentStore
from service_desk.core.auth.lab import ISSUER
from service_desk.core.gateway.registry import BoundaryDenied

__all__ = ["connections"]
pytestmark = [
    pytest.mark.postgres,
    pytest.mark.skipif(os.environ.get("DESK_READ_INTEGRATION") != "1", reason="Opt-in PostgreSQL"),
]


def create(values: dict[str, str], channel: str = "chat", user: str = "erin") -> UUID:
    who = identity(user, "web")
    if channel == "chat":
        return AgentStore(values["creator"]).create(who, "ticket-alice")
    store = (
        InternalStore(values["creator"])
        if channel == "internal"
        else RequesterStore(values["creator"])
    )
    return store.create_draft(who, "ticket-alice")


def stop(values: dict[str, str], channel: str, task_id: UUID) -> None:
    who = identity("erin", "web")
    store: AgentStore | RequesterStore
    if channel == "chat":
        store = AgentStore(values["creator"])
    elif channel == "internal":
        store = InternalStore(values["creator"])
    else:
        store = RequesterStore(values["creator"])
    store.action(who, task_id, "claim")
    store.action(who, task_id, "stop")


def test_concurrent_channel_starts_share_one_person_limit(connections: dict[str, str]) -> None:
    def attempt(i: int) -> UUID | None:
        try:
            return create(connections, ("chat", "requester", "internal")[i % 3])
        except BoundaryDenied as error:
            assert error.reason == "BUDGET_EXHAUSTED"
            return None

    with ThreadPoolExecutor(max_workers=12) as pool:
        admitted = [t for t in pool.map(attempt, range(18)) if t is not None]
    assert len(admitted) == 4
    assert scalar(connections, "SELECT count(*) FROM service_desk.read_task WHERE active") == 4
    assert (
        scalar(
            connections,
            "SELECT count(*) FROM service_desk.read_task WHERE model_calls>0 AND active",
        )
        == 0
    )


def test_concurrent_people_share_global_active_limit(connections: dict[str, str]) -> None:
    update(connections, "UPDATE service_desk.task_admission_policy SET global_active=6")

    def attempt(i: int) -> bool:
        try:
            create(connections, user=("erin", "morgan", "olivia")[i % 3])
            return True
        except BoundaryDenied as error:
            assert error.reason == "BUDGET_EXHAUSTED"
            return False

    with ThreadPoolExecutor(max_workers=12) as pool:
        assert sum(pool.map(attempt, range(18))) == 6
    assert scalar(connections, "SELECT count(*) FROM service_desk.read_task WHERE active") == 6


@pytest.mark.parametrize("channel", ["chat", "requester", "internal"])
def test_stopping_releases_active_slot_but_not_start_budget(
    connections: dict[str, str], channel: str
) -> None:
    update(connections, "UPDATE service_desk.task_admission_policy SET user_active=1,user_minute=2")
    first = create(connections, channel)
    with pytest.raises(BoundaryDenied, match="BUDGET_EXHAUSTED"):
        create(connections, channel)
    stop(connections, channel, first)
    second = create(connections, channel)
    stop(connections, channel, second)
    with pytest.raises(BoundaryDenied, match="BUDGET_EXHAUSTED"):
        create(connections, channel)


def test_twenty_starts_persist_across_new_stores_and_channels(connections: dict[str, str]) -> None:
    for i in range(20):
        channel = ("chat", "requester", "internal")[i % 3]
        stop(connections, channel, create(connections, channel))
    for channel in ("chat", "requester", "internal"):
        with pytest.raises(BoundaryDenied, match="BUDGET_EXHAUSTED"):
            create(connections, channel)
    # Another person still has capacity under the global start limit.
    assert create(connections, user="morgan")


def test_global_start_limit_includes_completed_users(connections: dict[str, str]) -> None:
    update(
        connections, "UPDATE service_desk.task_admission_policy SET user_minute=2,global_minute=3"
    )
    for user in ("erin", "morgan", "olivia"):
        task_id = create(connections, user=user)
        store = AgentStore(connections["creator"])
        who = identity(user, "web")
        store.action(who, task_id, "claim")
        store.action(who, task_id, "stop")
    with pytest.raises(BoundaryDenied, match="BUDGET_EXHAUSTED"):
        create(connections)


def test_alias_subject_cannot_reset_person_quota(connections: dict[str, str]) -> None:
    update(connections, "UPDATE service_desk.task_admission_policy SET user_active=1")
    create(connections)
    alias = "admission-alias-" + uuid4().hex
    update(
        connections,
        "INSERT INTO service_desk.identity_binding VALUES(%s,%s,'erin')",
        (ISSUER, alias),
    )
    with pytest.raises(BoundaryDenied, match="BUDGET_EXHAUSTED"):
        AgentStore(connections["creator"]).create(
            replace(identity("erin", "web"), subject=alias), "ticket-alice"
        )


def test_expired_slots_and_aged_start_window_recover(connections: dict[str, str]) -> None:
    update(connections, "UPDATE service_desk.task_admission_policy SET user_active=1,user_minute=2")
    first = create(connections)
    update(
        connections,
        "UPDATE service_desk.read_task SET deadline=clock_timestamp()-interval '1 second' "
        "WHERE id=%s",
        (first,),
    )
    second = create(connections)
    stop(connections, "chat", second)
    with pytest.raises(BoundaryDenied, match="BUDGET_EXHAUSTED"):
        create(connections)
    update(
        connections,
        "UPDATE service_desk.read_task SET created_at=clock_timestamp()-interval '61 seconds' "
        "WHERE id IN (%s,%s)",
        (first, second),
    )
    assert create(connections)


def test_invalid_draft_rolls_back_admission(connections: dict[str, str]) -> None:
    update(connections, "UPDATE service_desk.task_admission_policy SET user_active=1,user_minute=1")
    for _ in range(3):
        with pytest.raises(BoundaryDenied, match="RESOURCE_DENIED"):
            InternalStore(connections["creator"]).create_draft(
                identity("alice", "web"), "ticket-alice"
            )
    assert create(connections, user="alice")


@pytest.mark.parametrize("failure", [False, True])
def test_generated_or_failed_draft_keeps_its_start_charge(
    connections: dict[str, str], failure: bool
) -> None:
    class FailingProvider(RecordingProvider):
        async def generate(self, request: str, *, max_output: int) -> ProviderReply:
            raise RuntimeError("Provider unavailable")

    update(connections, "UPDATE service_desk.task_admission_policy SET user_active=1,user_minute=1")
    assistant, login = setup(connections)
    if failure:
        assistant.provider = FailingProvider()
    drafter = RequesterDrafter(assistant)
    task_id = drafter.store.create_draft(login.identity, "ticket-alice")
    result = asyncio.run(drafter.run(login, task_id))
    assert result["allowed"] is not failure
    assert (
        scalar(connections, "SELECT active FROM service_desk.read_task WHERE id=%s", (task_id,))
        is False
    )
    assert (
        scalar(
            connections, "SELECT model_calls FROM service_desk.read_task WHERE id=%s", (task_id,)
        )
        == 1
    )
    with pytest.raises(BoundaryDenied, match="BUDGET_EXHAUSTED"):
        create(connections)


@pytest.mark.parametrize("isolation", ["REPEATABLE READ", "SERIALIZABLE"])
def test_stale_transaction_cannot_oversubscribe(
    connections: dict[str, str], isolation: str
) -> None:
    update(connections, "UPDATE service_desk.task_admission_policy SET user_active=1")
    with psycopg.connect(connections["creator"]) as db:
        db.execute("SET TRANSACTION ISOLATION LEVEL " + isolation)
        # A permitted task-creation function establishes a snapshot without creating a task.
        db.execute(
            "SELECT service_desk.create_read_task(%s,%s,%s,%s,'missing','self')",
            (uuid4(), uuid4(), ISSUER, identity().subject),
        )
        create(connections)
        with pytest.raises(psycopg.errors.SerializationFailure):
            db.execute(
                "SELECT service_desk.create_read_task(%s,%s,%s,%s,'ticket-alice','self')",
                (uuid4(), uuid4(), ISSUER, identity().subject),
            )
    assert scalar(connections, "SELECT count(*) FROM service_desk.read_task WHERE active") == 1


def test_transaction_rollback_does_not_leak_capacity(connections: dict[str, str]) -> None:
    update(connections, "UPDATE service_desk.task_admission_policy SET user_active=1,user_minute=1")
    with psycopg.connect(connections["creator"]) as db:
        db.execute(
            "SELECT service_desk.create_read_task(%s,%s,%s,%s,'ticket-alice','self')",
            (uuid4(), uuid4(), ISSUER, identity().subject),
        )
        db.rollback()
    assert create(connections)


def test_service_roles_cannot_change_admission_policy_or_task_time(
    connections: dict[str, str],
) -> None:
    for role in ("creator", "gateway", "knowledge", "tickets", "publisher"):
        with psycopg.connect(connections[role]) as db:
            assert db.execute(
                "SELECT has_table_privilege(current_user,'service_desk.task_admission_policy',"
                "'SELECT,INSERT,UPDATE,DELETE')"
            ).fetchone() == (False,)
            assert db.execute(
                "SELECT has_column_privilege(current_user,'service_desk.read_task',"
                "'created_at','UPDATE')"
            ).fetchone() == (False,)
