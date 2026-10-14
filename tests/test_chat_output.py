"""Self-audience output screening and runtime audit-table isolation."""

import asyncio
import os

import psycopg
import pytest
from test_agent_tasks import setup
from test_phase2_reads import connections, scalar

from service_desk.agent.provider import AnswerTurn, DeterministicProvider, ProviderReply

__all__ = ["connections"]
pytestmark = [
    pytest.mark.postgres,
    pytest.mark.skipif(os.environ.get("DESK_READ_INTEGRATION") != "1", reason="Opt-in PostgreSQL"),
]


@pytest.mark.parametrize(
    "user,body",
    [
        ("erin", "LAB-CANARY-HR-A69F"),
        ("erin", "Synthetic HR procedure"),
        ("alice", "Internal support note; never copy into requester context."),
        ("alice", "Synthetic privileged reset instructions: consult the resource owner."),
        ("alice", "LAB-CANARY-ADMIN-C15D"),
    ],
)
def test_chat_cannot_release_restricted_model_output(
    connections: dict[str, str],
    user: str,
    body: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    assistant, login = setup(connections, user)

    class Hostile(DeterministicProvider):
        async def generate(self, request: str, *, max_output: int) -> ProviderReply:
            reply = await super().generate(request, max_output=max_output)
            if not isinstance(reply.turn, AnswerTurn):
                return reply
            return ProviderReply(
                turn=AnswerTurn(kind="answer", text=body, citations=reply.turn.citations),
                input_tokens=1,
                output_tokens=1,
            )

    assistant.provider = Hostile()
    task = assistant.store.create(login.identity, "ticket-alice")
    result = asyncio.run(assistant.run(login, task, "Help with this ticket."))
    assert result["allowed"] is False and result["reason"] == "OUTPUT_DENIED"
    assert "answer" not in result
    assert body not in caplog.text
    assert (
        scalar(connections, "SELECT agent_state FROM service_desk.read_task WHERE id=%s", (task,))
        == "stopped"
    )
    assert (
        scalar(
            connections,
            "SELECT count(*) FROM service_desk.read_audit WHERE task_id=%s "
            "AND operation='agent_finish' AND reason='OUTPUT_DENIED'",
            (task,),
        )
        == 1
    )


@pytest.mark.parametrize("role", ["creator", "gateway", "knowledge", "tickets", "publisher"])
def test_runtime_credentials_cannot_read_or_mutate_audit(
    connections: dict[str, str], role: str
) -> None:
    with psycopg.connect(connections[role]) as db:
        for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE"):
            assert db.execute(
                "SELECT has_table_privilege(current_user,'service_desk.read_audit',%s)",
                (privilege,),
            ).fetchone() == (False,)
