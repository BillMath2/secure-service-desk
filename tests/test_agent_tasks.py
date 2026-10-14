"""Database-backed assistant controls with signed identities and deterministic providers."""

import asyncio
import json
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from typing import Any
from uuid import UUID

import psycopg
import pytest
from test_phase2_identity import RotatingKeys
from test_phase2_reads import connections, identity, scalar, service, task, update

from service_desk.agent.loop import Assistant
from service_desk.agent.provider import (
    AnswerTurn,
    DeterministicProvider,
    ProviderReply,
    ToolTurn,
    input_reservation,
)
from service_desk.agent.store import AgentStore
from service_desk.core.auth.lab import ISSUER, subject_for
from service_desk.core.auth.oidc import LoginResult
from service_desk.core.auth.tokens import TokenValidator
from service_desk.core.gateway.registry import BoundaryDenied, definition

__all__ = ["connections"]
pytestmark = [
    pytest.mark.postgres,
    pytest.mark.skipif(
        os.environ.get("DESK_READ_INTEGRATION") != "1",
        reason="Opt-in disposable PostgreSQL required",
    ),
]


class LocalGateway:
    def __init__(self, values: dict[str, str]) -> None:
        self.values = values
        self.calls: list[str] = []

    def call(
        self, login: LoginResult, task_id: UUID, name: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        self.calls.append(name)
        try:
            route = definition(name).service
        except BoundaryDenied:
            route = "knowledge"
        return service(self.values, route).invoke(
            replace(login.identity, client_id="gateway"), task_id, name, arguments
        )


class RecordingProvider(DeterministicProvider):
    def __init__(self) -> None:
        self.requests: list[str] = []

    async def generate(self, request: str, *, max_output: int) -> ProviderReply:
        self.requests.append(request)
        return await super().generate(request, max_output=max_output)


def setup(values: dict[str, str], user: str = "erin") -> tuple[Assistant, LoginResult]:
    keys = RotatingKeys()
    validator = TokenValidator(ISSUER, keys, {(ISSUER, subject_for(user)): user}, "web")
    token = keys.sign(
        iss=ISSUER,
        sub=subject_for(user),
        azp="web",
        aud="gateway",
        scope="knowledge:read tickets:read",
    )
    login = LoginResult(validator.access(token, "gateway"), token)
    return Assistant(
        validator, AgentStore(values["creator"]), LocalGateway(values), RecordingProvider()
    ), login


def test_cited_run_fresh_context_and_no_credentials(connections: dict[str, str]) -> None:
    assistant, login = setup(connections)
    provider = assistant.provider
    assert isinstance(provider, RecordingProvider)
    for marker in ("first-task-marker", "second-task-marker"):
        t = task(connections)
        result = asyncio.run(assistant.run(login, t, marker))
        assert result["allowed"] and result["citations"] == ["document:doc-public@1"]
        assert (
            scalar(connections, "SELECT agent_state FROM service_desk.read_task WHERE id=%s", (t,))
            == "completed"
        )
        assert (
            scalar(connections, "SELECT model_calls FROM service_desk.read_task WHERE id=%s", (t,))
            == 3
        )
        assert not asyncio.run(assistant.run(login, t, marker))["allowed"]
    assert len(provider.requests) == 6
    # Growing history must not displace the stable policy/catalog prefix; all
    # source results remain in each complete request and each new task starts fresh.
    prefixes = [request.split(',"history":', 1)[0] for request in provider.requests]
    assert prefixes[0] == prefixes[1] == prefixes[2]
    assert prefixes[3] == prefixes[4] == prefixes[5]
    assert "first-task-marker" not in "".join(provider.requests[3:])
    assert all(json.loads(r)["history"] == [] for r in provider.requests[::3])
    for forbidden in (login.access_token, login.identity.subject, "A69F", "C15D", "csrf"):
        assert forbidden not in "".join(provider.requests)


def test_claim_and_model_reservations_are_atomic_and_persistent(
    connections: dict[str, str],
) -> None:
    t = task(connections)

    def attempt(action: str, units: int = 0) -> bool:
        try:
            AgentStore(connections["creator"]).action(identity(client="web"), t, action, units)
            return True
        except BoundaryDenied:
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(lambda _: attempt("claim"), range(16))) == 1
        assert sum(pool.map(lambda _: attempt("reserve", 4000), range(16))) == 4
    assert (
        scalar(connections, "SELECT model_tokens FROM service_desk.read_task WHERE id=%s", (t,))
        == 16000
    )


@pytest.mark.parametrize("case", ["owner", "requester", "expired", "stale", "cancelled"])
def test_no_provider_call_before_task_admission(connections: dict[str, str], case: str) -> None:
    assistant, login = setup(connections, "alice" if case == "owner" else "erin")
    t = task(connections, audience="requester" if case == "requester" else "self")
    if case in ("expired", "stale", "cancelled"):
        assignments = {
            "expired": "deadline=clock_timestamp()-interval '1 second'",
            "stale": "policy_version='stale'",
            "cancelled": "active=false",
        }
        update(
            connections, f"UPDATE service_desk.read_task SET {assignments[case]} WHERE id=%s", (t,)
        )
    assert not asyncio.run(assistant.run(login, t, "Read guidance"))["allowed"]
    assert isinstance(assistant.provider, RecordingProvider)
    assert assistant.provider.requests == []


class RepeatingProvider:
    def __init__(self, name: str = "execute_approved_change") -> None:
        self.name = name
        self.calls = 0

    async def generate(self, request: str, *, max_output: int) -> ProviderReply:
        self.calls += 1
        return ProviderReply(
            turn=ToolTurn(name=self.name, arguments={}),
            input_tokens=input_reservation(request),
            output_tokens=20,
        )


def test_unknown_tools_and_repeated_calls_stop_at_durable_budget(
    connections: dict[str, str],
) -> None:
    assistant, login = setup(connections)
    provider = RepeatingProvider()
    assistant.provider = provider
    t = task(connections)
    result = asyncio.run(assistant.run(login, t, "Repeat forever"))
    assert result["reason"] == "BUDGET_EXHAUSTED" and provider.calls <= 8
    assert (
        scalar(connections, "SELECT used_calls FROM service_desk.read_task WHERE id=%s", (t,))
        == provider.calls
    )
    assert (
        scalar(connections, "SELECT active FROM service_desk.read_task WHERE id=%s", (t,)) is False
    )


class ForgedCitation:
    async def generate(self, request: str, *, max_output: int) -> ProviderReply:
        return ProviderReply(
            turn=AnswerTurn(text="Fabricated", citations=["document:doc-hr@1"]),
            input_tokens=1,
            output_tokens=10,
        )


def test_fabricated_citations_are_not_released(connections: dict[str, str]) -> None:
    assistant, login = setup(connections)
    assistant.provider = ForgedCitation()
    result = asyncio.run(assistant.run(login, task(connections), "Show HR"))
    assert result["reason"] == "RESOURCE_DENIED" and "doc-hr" not in json.dumps(result)


@pytest.mark.parametrize("change", ["acl", "version", "comment", "ticket"])
def test_changes_during_generation_block_entire_answer(
    connections: dict[str, str], change: str
) -> None:
    assistant, login = setup(connections)
    t = task(connections)

    class MutatingProvider(DeterministicProvider):
        async def generate(self, request: str, *, max_output: int) -> ProviderReply:
            reply = await super().generate(request, max_output=max_output)
            if isinstance(reply.turn, AnswerTurn):
                changes = {
                    "acl": "DELETE FROM service_desk.document_reader "
                    "WHERE document_id='doc-public' AND principal_id='erin'",
                    "version": "UPDATE service_desk.document SET version=version+1 "
                    "WHERE id='doc-public'",
                    "comment": "DELETE FROM service_desk.comment_reader WHERE principal_id='erin'",
                    "ticket": "DELETE FROM service_desk.ticket_reader "
                    "WHERE ticket_id='ticket-alice' AND principal_id='erin'",
                }
                update(connections, changes[change])
            return reply

    assistant.provider = MutatingProvider()
    with psycopg.connect(connections["admin"]) as db:
        comments = db.execute(
            "SELECT comment_id FROM service_desk.comment_reader WHERE principal_id='erin'"
        ).fetchall()
    try:
        result = asyncio.run(assistant.run(login, t, "Read guidance"))
        assert result["reason"] == "RESOURCE_DENIED" and "answer" not in result
    finally:
        if change == "acl":
            update(
                connections, "INSERT INTO service_desk.document_reader VALUES('doc-public','erin')"
            )
        elif change == "version":
            update(
                connections,
                "UPDATE service_desk.document SET version=version-1 WHERE id='doc-public'",
            )
        elif change == "ticket":
            update(
                connections, "INSERT INTO service_desk.ticket_reader VALUES('ticket-alice','erin')"
            )
        else:
            for row in comments:
                update(
                    connections, "INSERT INTO service_desk.comment_reader VALUES(%s,'erin')", row
                )


def test_timeout_retains_reservation_and_closes_task(
    connections: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    class SlowProvider:
        async def generate(self, request: str, *, max_output: int) -> ProviderReply:
            await asyncio.sleep(1)
            raise AssertionError("Late provider result")

    monkeypatch.setattr("service_desk.agent.loop.PROVIDER_TIMEOUT", 0.01)
    assistant, login = setup(connections)
    assistant.provider = SlowProvider()
    t = task(connections)
    assert asyncio.run(assistant.run(login, t, "Read guidance"))["reason"] == "TIMEOUT"
    assert (
        scalar(connections, "SELECT model_tokens FROM service_desk.read_task WHERE id=%s", (t,))
        > 512
    )
    assert (
        scalar(connections, "SELECT agent_state FROM service_desk.read_task WHERE id=%s", (t,))
        == "stopped"
    )


def test_read_roles_cannot_claim_or_reset_model_budgets(connections: dict[str, str]) -> None:
    for role in ("knowledge", "tickets", "gateway"):
        with psycopg.connect(connections[role], autocommit=True) as db:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                db.execute("SELECT service_desk.agent_action(NULL,NULL,NULL,'claim',0)")
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                db.execute("UPDATE service_desk.read_task SET model_tokens=0")


@pytest.mark.parametrize("case", ["usage", "failure", "output"])
def test_provider_limits_and_failures_never_release_partial_content(
    connections: dict[str, str], case: str
) -> None:
    class BadProvider:
        async def generate(self, request: str, *, max_output: int) -> ProviderReply:
            if case == "failure":
                raise RuntimeError("sensitive-provider-error")
            return ProviderReply(
                turn=ToolTurn(
                    name="read_document",
                    arguments={"document_id": "x" * (9000 if case == "output" else 1)},
                ),
                input_tokens=16001 if case == "usage" else 1,
                output_tokens=1,
            )

    assistant, login = setup(connections)
    assistant.provider = BadProvider()
    result = asyncio.run(assistant.run(login, task(connections), "Read guidance"))
    assert (
        result["reason"]
        == {"usage": "BUDGET_EXHAUSTED", "failure": "SERVICE_ERROR", "output": "OUTPUT_LIMIT"}[case]
    )
    assert "sensitive-provider-error" not in json.dumps(result)
    assert isinstance(assistant.gateway, LocalGateway) and assistant.gateway.calls == []


def test_revoked_context_never_reaches_next_provider_call(connections: dict[str, str]) -> None:
    assistant, login = setup(connections)
    t = task(connections)

    class RevokingGateway(LocalGateway):
        def call(
            self, login: LoginResult, task_id: UUID, name: str, arguments: dict[str, Any]
        ) -> dict[str, Any]:
            result = super().call(login, task_id, name, arguments)
            update(connections, "DELETE FROM service_desk.comment_reader WHERE principal_id='erin'")
            return result

    with psycopg.connect(connections["admin"]) as db:
        comments = db.execute(
            "SELECT comment_id FROM service_desk.comment_reader WHERE principal_id='erin'"
        ).fetchall()
    assistant.gateway = RevokingGateway(connections)
    try:
        result = asyncio.run(assistant.run(login, t, "Read guidance"))
        assert result["reason"] == "RESOURCE_DENIED"
        assert isinstance(assistant.provider, RecordingProvider)
        assert len(assistant.provider.requests) == 1
    finally:
        for row in comments:
            update(connections, "INSERT INTO service_desk.comment_reader VALUES(%s,'erin')", row)


def test_cancellation_closes_task_and_keeps_reservation(connections: dict[str, str]) -> None:
    assistant, login = setup(connections)
    t = task(connections)

    async def run() -> None:
        started = asyncio.Event()

        class WaitingProvider:
            async def generate(self, request: str, *, max_output: int) -> ProviderReply:
                started.set()
                await asyncio.Event().wait()
                raise AssertionError("Unreachable")

        assistant.provider = WaitingProvider()
        running = asyncio.create_task(assistant.run(login, t, "Read guidance"))
        await asyncio.wait_for(started.wait(), timeout=5)
        running.cancel()
        with pytest.raises(asyncio.CancelledError):
            await running

    asyncio.run(run())
    assert (
        scalar(connections, "SELECT agent_state FROM service_desk.read_task WHERE id=%s", (t,))
        == "stopped"
    )
    assert (
        scalar(connections, "SELECT model_tokens FROM service_desk.read_task WHERE id=%s", (t,))
        > 512
    )
