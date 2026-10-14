"""Signed RPC/MCP authority, provenance order, CSRF and scoped collector authentication."""

from typing import Any
from urllib.parse import parse_qs, urlsplit
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from test_phase2_identity import IDENTITIES, ISSUER, RotatingKeys, client_for, keys

from service_desk.app.access_api import (
    AccessDraftInput,
    LocalAccessBackend,
    create_collector_app,
    create_workflow_app,
)
from service_desk.app.access_ui import review_html
from service_desk.app.identity import create_identity_app
from service_desk.core.access import AccessStore
from service_desk.core.auth.oidc import LoginResult
from service_desk.core.auth.tokens import AuthenticationDenied, TokenValidator, VerifiedIdentity
from service_desk.mcp.execution import WorkloadValidator, create_execution_mcp

__all__ = ["keys"]
SECRET = "s" * 43
ORIGIN = "https://127.0.0.1:19481"


class Store(AccessStore):
    def __init__(self) -> None:
        super().__init__("unused")
        self.calls = 0

    def draft(
        self,
        identity: VerifiedIdentity,
        ticket: str,
        resource: str,
        duration: int | None,
        justification: str,
    ) -> dict[str, Any]:
        self.calls += 1
        return {"reason": "ALLOW", "request_id": str(uuid4())}

    def accept(self, writer: str, event_id: UUID, payload: dict[str, Any]) -> bool:
        self.calls += 1
        return writer == payload.get("writer")

    def call(self, name: str, *args: Any) -> Any:
        self.calls += 1
        return []


@pytest.mark.parametrize(
    "case", ["valid", "service", "duplicate", "user", "client", "audience", "expired", "override"]
)
def test_workflow_requires_both_service_and_exact_signed_user(
    keys: RotatingKeys, case: str
) -> None:
    store = Store()
    token = keys.sign(
        azp="gateway" if case == "client" else "web",
        aud="execution" if case == "audience" else "gateway",
        **({"exp": 1} if case == "expired" else {}),
    )
    headers = [("Authorization", "Bearer " + token), ("X-Desk-Service", SECRET)]
    if case == "service":
        headers[-1] = ("X-Desk-Service", "wrong")
    if case == "duplicate":
        headers.append(("X-Desk-Service", SECRET))
    if case == "user":
        headers.pop(0)
    body = {
        "ticket_id": "ticket-alice",
        "resource_id": "engineering-workspace",
        "justification": "Review required",
    }
    if case == "override":
        body["approver"] = "erin"
    app = create_workflow_app(
        LocalAccessBackend(TokenValidator(ISSUER, keys, IDENTITIES, "web"), store), SECRET
    )
    with TestClient(app, base_url="https://127.0.0.1:19488") as client:
        result = client.post("/draft", json=body, headers=headers)
    assert result.status_code == (200 if case == "valid" else 422 if case == "override" else 401)
    assert store.calls == (1 if case == "valid" else 0)


@pytest.mark.parametrize("case", ["valid", "client", "audience", "scope", "expired", "forged"])
def test_executor_token_cannot_be_replaced_by_user_or_gateway_token(
    keys: RotatingKeys, case: str
) -> None:
    validator = WorkloadValidator(ISSUER, keys, {}, "executor")
    token = keys.sign(
        azp="gateway" if case == "client" else "executor",
        aud="access" if case == "audience" else "execution",
        scope="access:read" if case == "scope" else "access:execute",
        **({"exp": 1} if case == "expired" else {}),
    )
    if case == "forged":
        token = token.rsplit(".", 1)[0] + ".invalid"
    if case == "valid":
        assert validator.access(token, "execution").principal_id == "executor"
    else:
        with pytest.raises(AuthenticationDenied):
            validator.access(token, "execution")


def test_execution_catalog_is_only_available_to_executor(keys: RotatingKeys) -> None:
    app = create_execution_mcp(WorkloadValidator(ISSUER, keys, {}, "executor"), Store())
    with TestClient(app, base_url="https://127.0.0.1:19489") as client:
        for who, audience, status in (
            ("web", "gateway", 401),
            ("gateway", "access", 401),
            ("executor", "execution", 200),
        ):
            result = client.post(
                "/mcp",
                headers={
                    "Authorization": "Bearer "
                    + keys.sign(azp=who, aud=audience, scope="access:execute"),
                    "Accept": "application/json, text/event-stream",
                },
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            )
            assert result.status_code == status
            if status == 200:
                assert {t["name"] for t in result.json()["result"]["tools"]} == {
                    "execute_approved_change",
                    "pending_approved_changes",
                }


@pytest.mark.parametrize("case", ["valid", "wrong_writer", "missing", "duplicate"])
def test_collector_writer_tokens_are_scoped(keys: RotatingKeys, case: str) -> None:
    store = Store()
    app = create_collector_app(store, {"workflow": SECRET, "execution": "x" * 43})
    headers = [("X-Desk-Service", SECRET)]
    if case == "missing":
        headers = []
    if case == "duplicate":
        headers *= 2
    with TestClient(app, base_url="https://127.0.0.1:19490") as client:
        result = client.post(
            "/events/" + ("execution" if case == "wrong_writer" else "workflow"),
            headers=headers,
            json={"event_id": str(uuid4()), "payload": {"writer": "workflow"}},
        )
    assert result.status_code == (200 if case == "valid" else 401)
    assert store.calls == (1 if case == "valid" else 0)


def test_review_orders_provenance_before_action_and_escapes_untrusted_text() -> None:
    record = {
        "ticket": {"body": "<script>steal()</script>"},
        "sources": ["ticket:1"],
        "policy_version": "1",
        "policy_valid": True,
        "state": "pending",
        "expires_at": "tomorrow",
        "approvals": [],
        "action": {"beneficiary": "alice"},
        "justification": "<img src=https://sink.invalid>",
        "request_id": str(uuid4()),
        "correlation_id": str(uuid4()),
    }
    html = review_html(record, SECRET)
    positions = [
        html.index(label)
        for label in (
            "Original ticket",
            "Source provenance",
            "Policy results",
            "Recorded approvals",
            "Exact proposed change",
            "Untrusted proposal justification",
        )
    ]
    assert positions == sorted(positions)
    assert "<script>" not in html and "<img" not in html and "&lt;img" in html


class Backend:
    def __init__(self) -> None:
        self.calls = 0

    async def invoke(
        self, login: LoginResult, operation: str, data: dict[str, Any]
    ) -> dict[str, Any]:
        if operation == "draft":
            AccessDraftInput.model_validate(data, strict=True)
        self.calls += 1
        return {"request_id": str(uuid4()), "reason": "ALLOW", "requests": []}


@pytest.mark.parametrize("case", ["valid", "origin", "csrf", "actor", "session_override"])
def test_browser_submission_keeps_session_identity_and_csrf(keys: RotatingKeys, case: str) -> None:
    oidc, provider = client_for(keys)
    backend = Backend()
    with TestClient(create_identity_app(oidc, access_backend=backend), base_url=ORIGIN) as client:
        start = client.get("/login", follow_redirects=False)
        query = parse_qs(urlsplit(start.headers["location"]).query)
        provider.nonce = query["nonce"][0]
        client.get("/callback", params={"state": query["state"][0], "code": "code"})
        csrf = client.get("/session").json()["csrf"]
        headers = {"Origin": ORIGIN, "X-CSRF-Token": csrf}
        if case == "origin":
            headers["Origin"] = "https://evil.invalid"
        if case == "csrf":
            headers["X-CSRF-Token"] = "wrong"
        body = {
            "ticket_id": "ticket-alice",
            "resource_id": "engineering-workspace",
            "justification": "Review",
        }
        if case == "actor":
            body["actor"] = "harper"
        if case == "session_override":
            body["session"] = SECRET
        result = client.post("/access/drafts", json=body, headers=headers)
        assert result.status_code == (
            200 if case == "valid" else 403 if case in {"origin", "csrf"} else 422
        )
        assert backend.calls == (1 if case == "valid" else 0)
