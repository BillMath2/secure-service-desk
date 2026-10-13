"""Browser boundary checks independent of the opt-in PostgreSQL runtime."""

from typing import Any
from urllib.parse import parse_qs, urlsplit
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from test_phase2_identity import RotatingKeys, client_for, keys

from service_desk.agent.loop import Assistant
from service_desk.agent.provider import DeterministicProvider
from service_desk.agent.store import AgentStore
from service_desk.app.identity import create_identity_app
from service_desk.core.auth.oidc import LoginResult
from service_desk.core.auth.tokens import VerifiedIdentity

__all__ = ["keys"]
ORIGIN = "https://127.0.0.1:19481"


class UIStore(AgentStore):
    def create(self, identity: VerifiedIdentity, ticket_id: str, audience: str = "self") -> UUID:
        assert identity.principal_id == "erin" and audience == "self"
        assert ticket_id == "ticket-alice"
        return uuid4()


class UnusedGateway:
    def call(
        self, login: LoginResult, task_id: UUID, name: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        raise AssertionError("UI test must not dispatch tools")


class UIAssistant(Assistant):
    async def run(self, login: LoginResult, task_id: UUID, question: str) -> dict[str, Any]:
        return {
            "allowed": True,
            "answer": '<script>alert("unsafe")</script>',
            "citations": ["document:doc-public@1"],
        }


def browser(keys: RotatingKeys) -> TestClient:
    oidc, provider = client_for(keys)
    assistant = UIAssistant(
        oidc.validator, UIStore("unused"), UnusedGateway(), DeterministicProvider()
    )
    http = TestClient(create_identity_app(oidc, assistant=assistant), base_url=ORIGIN)
    start = http.get("/login", follow_redirects=False)
    query = parse_qs(urlsplit(start.headers["location"]).query)
    provider.nonce = query["nonce"][0]
    result = http.get(
        "/callback", params={"state": query["state"][0], "code": "code"}, follow_redirects=False
    )
    assert result.status_code == 303 and result.headers["location"] == "/"
    return http


def test_form_escapes_source_and_model_text(keys: RotatingKeys) -> None:
    with browser(keys) as http:
        info = http.get("/session").json()
        home = http.get("/")
        assert "Deterministic demo" in home.text
        assert "form-action 'self'" in home.headers["content-security-policy"]
        response = http.post(
            "/tasks",
            headers={"Origin": ORIGIN},
            data={"ticket_id": "ticket-alice", "question": "Help", "csrf": info["csrf"]},
        )
        assert response.status_code == 200
        assert "<script>" not in response.text and "&lt;script&gt;" in response.text
        assert "document:doc-public@1" in response.text
        assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("case", ["origin", "csrf", "identity", "audience", "history", "large"])
def test_task_input_cannot_override_context(keys: RotatingKeys, case: str) -> None:
    with browser(keys) as http:
        csrf = http.get("/session").json()["csrf"]
        headers = {"Origin": ORIGIN, "X-CSRF-Token": csrf}
        data = {"ticket_id": "ticket-alice", "question": "Help"}
        if case == "origin":
            headers["Origin"] = "https://evil.invalid"
        elif case == "csrf":
            headers["X-CSRF-Token"] = "wrong"
        elif case == "large":
            data["question"] = "x" * 9000
        else:
            data[case] = "attacker-controlled"
        response = http.post("/tasks", headers=headers, json=data)
        assert response.status_code in (403, 413, 422)
        assert "attacker-controlled" not in response.text


def test_api_and_unauthenticated_boundary(keys: RotatingKeys) -> None:
    with browser(keys) as http:
        csrf = http.get("/session").json()["csrf"]
        assert http.post(
            "/tasks",
            headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
            json={"ticket_id": "ticket-alice", "question": "Help"},
        ).json()["allowed"]
        http.cookies.clear()
        assert (
            http.post(
                "/tasks",
                json={"ticket_id": "ticket-alice", "question": "Help"},
                headers={"X-User": "erin"},
            ).status_code
            == 401
        )
        assert 'href="/login"' in http.get("/").text
