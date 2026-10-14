"""Independent user/service authentication and narrow RPC schemas."""

from typing import Any, Literal
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from test_phase2_identity import IDENTITIES, ISSUER, RotatingKeys, keys

from service_desk.app.backend import Channel, LocalTaskBackend
from service_desk.app.publication import PublicationStore
from service_desk.app.rpc import service_app
from service_desk.core.auth.oidc import LoginResult
from service_desk.core.auth.tokens import TokenValidator, VerifiedIdentity

__all__ = ["keys"]
SECRET = "s" * 43


class Agent(LocalTaskBackend):
    def __init__(self) -> None:
        self.calls = 0

    async def submit(
        self, login: LoginResult, channel: Channel, ticket_id: str, question: str | None
    ) -> dict[str, Any]:
        self.calls += 1
        assert login.identity.principal_id == "erin"
        return {"allowed": True, "task_id": str(uuid4())}


class Publisher(PublicationStore):
    def __init__(self) -> None:
        super().__init__("unused")
        self.calls = 0

    def review(self, identity: VerifiedIdentity, draft_id: UUID, session: str) -> dict[str, Any]:
        self.calls += 1
        assert identity.principal_id == "erin" and session == "c" * 43
        return {"allowed": True, "confirmation_token": "t" * 43}

    def confirm(
        self, identity: VerifiedIdentity, draft_id: UUID, session: str, token: str, body_hash: str
    ) -> dict[str, Any]:
        self.calls += 1
        assert identity.principal_id == "erin"
        assert session == "c" * 43 and token == "t" * 43 and body_hash == "a" * 64
        return {"comment_id": str(uuid4())}


@pytest.mark.parametrize("role", ["agent", "publisher"])
@pytest.mark.parametrize(
    "failure",
    [
        "none",
        "no_service",
        "wrong_service",
        "duplicate_service",
        "no_user",
        "wrong_audience",
        "wrong_client",
        "forged_user",
        "expired",
    ],
)
def test_rpc_requires_both_authorities(
    keys: RotatingKeys, role: Literal["agent", "publisher"], failure: str
) -> None:
    agent, publisher = Agent(), Publisher()
    validator = TokenValidator(ISSUER, keys, IDENTITIES, "web")
    changes: dict[str, Any] = {"aud": "gateway", "azp": "web"}
    if failure == "wrong_audience":
        changes["aud"] = "knowledge"
    if failure == "wrong_client":
        changes["azp"] = "gateway"
    if failure == "forged_user":
        changes["sub"] = "unknown"
    if failure == "expired":
        changes["exp"] = 1
    headers = [("authorization", "Bearer " + keys.sign(**changes)), ("x-desk-service", SECRET)]
    if failure == "no_service":
        headers.pop()
    if failure == "wrong_service":
        headers[-1] = ("x-desk-service", "wrong")
    if failure == "duplicate_service":
        headers.append(("x-desk-service", SECRET))
    if failure == "no_user":
        headers.pop(0)
    app = service_app(
        role,
        validator,
        SECRET,
        agent=agent if role == "agent" else None,
        publisher=publisher if role == "publisher" else None,
    )
    body = (
        {"channel": "requester", "ticket_id": "ticket-alice"}
        if role == "agent"
        else {"channel": "requester", "draft_id": str(uuid4()), "session": "c" * 43}
    )
    with TestClient(app, base_url="https://127.0.0.1") as client:
        response = client.post("/run" if role == "agent" else "/review", json=body, headers=headers)
    assert response.status_code == (200 if failure == "none" else 401)
    assert agent.calls + publisher.calls == (1 if failure == "none" else 0)
    assert SECRET not in response.text


@pytest.mark.parametrize(
    "change", ["recipients", "identity", "draft_question", "body", "operation", "too_large"]
)
def test_agent_rejects_caller_authority_overrides(keys: RotatingKeys, change: str) -> None:
    agent = Agent()
    app = service_app("agent", TokenValidator(ISSUER, keys, IDENTITIES, "web"), SECRET, agent=agent)
    body: dict[str, Any] = {"channel": "requester", "ticket_id": "ticket-alice"}
    body[{"draft_question": "question", "too_large": "question"}.get(change, change)] = (
        "x" * 9000 if change == "too_large" else "PRIVATE"
    )
    with TestClient(app, base_url="https://127.0.0.1") as client:
        result = client.post(
            "/run",
            json=body,
            headers={
                "X-Desk-Service": SECRET,
                "Authorization": "Bearer " + keys.sign(aud="gateway", azp="web"),
            },
        )
    assert result.status_code in {413, 422} and agent.calls == 0
    assert "PRIVATE" not in result.text


def test_publisher_has_no_generation_and_agent_has_no_confirmation(keys: RotatingKeys) -> None:
    validator = TokenValidator(ISSUER, keys, IDENTITIES, "web")
    headers = {
        "X-Desk-Service": SECRET,
        "Authorization": "Bearer " + keys.sign(aud="gateway", azp="web"),
    }
    publisher = Publisher()
    with TestClient(
        service_app("publisher", validator, SECRET, publisher=publisher),
        base_url="https://127.0.0.1",
    ) as client:
        assert client.post("/run", json={}, headers=headers).status_code == 404
        result = client.post(
            "/confirm",
            headers=headers,
            json={
                "channel": "requester",
                "draft_id": str(uuid4()),
                "session": "c" * 43,
                "confirmation_token": "t" * 43,
                "body_sha256": "a" * 64,
            },
        )
        assert result.status_code == 200 and publisher.calls == 1
    with TestClient(
        service_app("agent", validator, SECRET, agent=Agent()), base_url="https://127.0.0.1"
    ) as client:
        assert client.post("/confirm", json={}, headers=headers).status_code == 404
