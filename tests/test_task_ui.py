"""Browser boundary checks independent of the opt-in PostgreSQL runtime."""

from typing import Any
from urllib.parse import parse_qs, urlsplit
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from test_phase2_identity import RotatingKeys, client_for, keys

from service_desk.agent.loop import Assistant
from service_desk.agent.provider import DeterministicProvider
from service_desk.agent.requester import RequesterDrafter, RequesterStore
from service_desk.agent.store import AgentStore
from service_desk.app.identity import create_identity_app
from service_desk.app.publication import PublicationStore
from service_desk.core.auth.oidc import LoginResult
from service_desk.core.auth.tokens import VerifiedIdentity
from service_desk.core.gateway.registry import BoundaryDenied

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


def browser(keys: RotatingKeys, publisher: PublicationStore | None = None) -> TestClient:
    oidc, provider = client_for(keys)
    assistant = UIAssistant(
        oidc.validator, UIStore("unused"), UnusedGateway(), DeterministicProvider()
    )
    http = TestClient(
        create_identity_app(oidc, assistant=assistant, publisher=publisher), base_url=ORIGIN
    )
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


class UIDraftStore(RequesterStore):
    def create_draft(self, identity: VerifiedIdentity, ticket_id: str) -> UUID:
        assert identity.principal_id == "erin" and ticket_id == "ticket-alice"
        return uuid4()


class UIDrafter(RequesterDrafter):
    def __init__(self, assistant: Assistant) -> None:
        super().__init__(assistant)
        self.store = UIDraftStore("unused")

    async def run(self, login: LoginResult, task_id: UUID) -> dict[str, Any]:
        return {
            "allowed": True,
            "draft_id": str(task_id),
            "draft": '<img src="https://sink.invalid/leak">![image](https://sink.invalid/leak)',
            "recipients": ["alice"],
            "citations": ["document:doc-public@1"],
        }


def test_requester_preview_is_plain_text_and_not_a_confirmation(
    keys: RotatingKeys, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("service_desk.app.backend.RequesterDrafter", UIDrafter)
    with browser(keys) as http:
        csrf = http.get("/session").json()["csrf"]
        assert 'action="/requester-drafts"' in http.get("/").text
        response = http.post(
            "/requester-drafts",
            headers={"Origin": ORIGIN},
            data={"csrf": csrf, "ticket_id": "ticket-alice"},
        )
        assert response.status_code == 200
        assert "Unreviewed requester draft" in response.text
        assert "Nothing has been posted" in response.text
        assert "Recipients: alice" in response.text
        assert "<img" not in response.text and "&lt;img" in response.text
        assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize(
    "field", ["question", "history", "recipients", "audience", "body", "sources", "task_id"]
)
@pytest.mark.parametrize("channel", ["requester", "internal"])
def test_draft_endpoint_rejects_privileged_context_and_overrides(
    keys: RotatingKeys, field: str, channel: str
) -> None:
    with browser(keys) as http:
        csrf = http.get("/session").json()["csrf"]
        response = http.post(
            f"/{channel}-drafts",
            headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
            json={"ticket_id": "ticket-alice", field: "PRIVILEGED CONTEXT"},
        )
        assert response.status_code == 422 and "PRIVILEGED CONTEXT" not in response.text


@pytest.mark.parametrize("case", ["origin", "csrf", "unauthenticated"])
@pytest.mark.parametrize("channel", ["requester", "internal"])
def test_draft_endpoint_requires_authenticated_human_and_csrf(
    keys: RotatingKeys, case: str, channel: str
) -> None:
    with browser(keys) as http:
        csrf = http.get("/session").json()["csrf"]
        if case == "unauthenticated":
            http.cookies.clear()
        response = http.post(
            f"/{channel}-drafts",
            headers={
                "Origin": "https://evil.invalid" if case == "origin" else ORIGIN,
                "X-CSRF-Token": "wrong" if case == "csrf" else csrf,
            },
            json={"ticket_id": "ticket-alice"},
        )
        assert response.status_code == (401 if case == "unauthenticated" else 403)


def test_saved_draft_review_is_escaped_and_has_no_edit_or_publish_action(
    keys: RotatingKeys, monkeypatch: pytest.MonkeyPatch
) -> None:
    draft_id = uuid4()

    class SavedStore(RequesterStore):
        def review(self, identity: VerifiedIdentity, requested: UUID) -> dict[str, Any]:
            assert identity.principal_id == "erin" and requested == draft_id
            return {
                "allowed": True,
                "draft_id": str(draft_id),
                "ticket_id": "ticket-alice",
                "draft": '<img src="https://sink.invalid/leak">',
                "recipients": ["alice"],
                "policy_version": "policy-v1",
                "expires_at": "2026-10-13T23:59:00Z",
                "body_sha256": "a" * 64,
                "sources": [{"kind": "document", "id": "<script>", "version": 1}],
            }

    monkeypatch.setattr("service_desk.app.backend.RequesterStore", SavedStore)
    with browser(keys) as http:
        response = http.get(f"/requester-drafts/{draft_id}")
        assert response.status_code == 200
        assert "&lt;img" in response.text and "<img" not in response.text
        assert "&lt;script&gt;" in response.text and "<script>" not in response.text
        assert "Expires:" in response.text and "Body fingerprint" in response.text
        assert "<form" not in response.text and "generate a new one" in response.text
        assert response.headers["cache-control"] == "no-store"
        assert http.get(
            f"/requester-drafts/{draft_id}", headers={"Accept": "application/json"}
        ).json()["allowed"]
        assert (
            http.patch(f"/requester-drafts/{draft_id}", json={"body": "changed"}).status_code == 405
        )
        http.cookies.clear()
        assert http.get(f"/requester-drafts/{draft_id}").status_code == 401


def test_failed_review_returns_only_generic_metadata(
    keys: RotatingKeys, monkeypatch: pytest.MonkeyPatch
) -> None:
    class StaleStore(RequesterStore):
        def review(self, identity: VerifiedIdentity, requested: UUID) -> dict[str, Any]:
            raise BoundaryDenied("POLICY_STALE")

    monkeypatch.setattr("service_desk.app.backend.RequesterStore", StaleStore)
    with browser(keys) as http:
        response = http.get(f"/requester-drafts/{uuid4()}")
        assert response.status_code == 403 and response.json() == {"detail": "Draft unavailable"}


class UIPublisher(PublicationStore):
    def review(self, identity: VerifiedIdentity, draft_id: UUID, session: str) -> dict[str, Any]:
        assert identity.principal_id == "erin" and session
        return {
            "allowed": True,
            "draft_id": str(draft_id),
            "ticket_id": "ticket-alice",
            "draft": "Exact reviewed reply.",
            "recipients": ["alice"],
            "policy_version": "policy-v1",
            "expires_at": "2026-10-13T23:59:00Z",
            "body_sha256": "b" * 64,
            "sources": [],
            "confirmation_token": "a" * 43,
            "confirmation_expires_at": "2026-10-13T23:58:00Z",
        }

    def confirm(
        self,
        identity: VerifiedIdentity,
        draft_id: UUID,
        session: str,
        token: str,
        body_hash: str,
    ) -> dict[str, Any]:
        assert identity.principal_id == "erin" and session
        assert token == "a" * 43 and body_hash == "b" * 64
        return {"allowed": True, "status": "published", "comment_id": "reply-" + str(draft_id)}


def test_review_form_and_exact_confirmation(keys: RotatingKeys) -> None:
    with browser(keys, UIPublisher("unused")) as http:
        draft_id = uuid4()
        review = http.get(f"/requester-drafts/{draft_id}")
        assert review.status_code == 200 and "Confirm and post this reply" in review.text
        assert "Exact reviewed reply." in review.text and "Recipients: alice" in review.text
        assert 'name="body"' not in review.text
        csrf = http.get("/session").json()["csrf"]
        result = http.post(
            f"/requester-drafts/{draft_id}/confirm",
            headers={"Origin": ORIGIN},
            data={"csrf": csrf, "confirmation_token": "a" * 43, "body_sha256": "b" * 64},
        )
        assert result.status_code == 200 and "Reply posted" in result.text


@pytest.mark.parametrize(
    "case",
    [
        "csrf",
        "origin",
        "unauthenticated",
        "body",
        "recipients",
        "sources",
        "missing",
        "oversized",
        "duplicate",
    ],
)
@pytest.mark.parametrize("channel", ["requester", "internal"])
def test_confirmation_endpoint_rejects_context_overrides_and_csrf(
    keys: RotatingKeys,
    case: str,
    channel: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class NeverPublish(UIPublisher):
        def confirm(
            self,
            identity: VerifiedIdentity,
            draft_id: UUID,
            session: str,
            token: str,
            body_hash: str,
        ) -> dict[str, Any]:
            raise AssertionError("Invalid requests must never reach publication")

    monkeypatch.setattr("service_desk.app.backend.InternalPublicationStore", NeverPublish)
    with browser(keys, NeverPublish("unused")) as http:
        csrf = http.get("/session").json()["csrf"]
        data = {"confirmation_token": "a" * 43, "body_sha256": "b" * 64}
        headers = {"Origin": ORIGIN, "X-CSRF-Token": csrf}
        if case == "csrf":
            headers["X-CSRF-Token"] = "wrong"
        elif case == "origin":
            headers["Origin"] = "https://evil.invalid"
        elif case == "unauthenticated":
            http.cookies.clear()
        elif case == "missing":
            data.pop("confirmation_token")
        elif case == "oversized":
            data["confirmation_token"] = "x" * 3000
        elif case != "duplicate":
            data[case] = "PRIVILEGED CONTEXT"
        url = f"/{channel}-drafts/{uuid4()}/confirm"
        if case == "duplicate":
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            result = http.post(url, headers=headers, content="csrf=a&csrf=b&confirmation_token=c")
        else:
            result = http.post(url, headers=headers, json=data)
        assert result.status_code in (401, 403, 413, 422)
        assert "PRIVILEGED CONTEXT" not in result.text


def test_stale_confirmation_error_does_not_echo_proof_or_body(keys: RotatingKeys) -> None:
    class StalePublisher(UIPublisher):
        def confirm(
            self,
            identity: VerifiedIdentity,
            draft_id: UUID,
            session: str,
            token: str,
            body_hash: str,
        ) -> dict[str, Any]:
            raise BoundaryDenied("POLICY_STALE")

    with browser(keys, StalePublisher("unused")) as http:
        csrf = http.get("/session").json()["csrf"]
        result = http.post(
            f"/requester-drafts/{uuid4()}/confirm",
            headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
            json={"confirmation_token": "a" * 43, "body_sha256": "b" * 64},
        )
        assert result.status_code == 403
        assert result.json() == {"detail": "Confirmation unavailable"}


def test_internal_browser_flow_uses_separate_channel(
    keys: RotatingKeys, monkeypatch: pytest.MonkeyPatch
) -> None:
    class InternalUI(UIDrafter):
        async def run(self, login: LoginResult, task_id: UUID) -> dict[str, Any]:
            result = await super().run(login, task_id)
            return {**result, "recipients": ["erin", "morgan"]}

    class InternalPublisher(UIPublisher):
        def review(
            self, identity: VerifiedIdentity, draft_id: UUID, session: str
        ) -> dict[str, Any]:
            result = super().review(identity, draft_id, session)
            return {**result, "recipients": ["erin", "morgan"], "draft": "<b>Staff-only text</b>"}

    class WrongChannel(UIPublisher):
        def review(
            self, identity: VerifiedIdentity, draft_id: UUID, session: str
        ) -> dict[str, Any]:
            raise AssertionError("Internal review must not use the requester publisher")

        def confirm(
            self,
            identity: VerifiedIdentity,
            draft_id: UUID,
            session: str,
            token: str,
            body_hash: str,
        ) -> dict[str, Any]:
            raise AssertionError("Internal confirmation must not use the requester publisher")

    monkeypatch.setattr("service_desk.app.backend.InternalDrafter", InternalUI)
    monkeypatch.setattr("service_desk.app.backend.InternalPublicationStore", InternalPublisher)
    with browser(keys, WrongChannel("unused")) as http:
        csrf = http.get("/session").json()["csrf"]
        assert 'action="/internal-drafts"' in http.get("/").text
        preview = http.post(
            "/internal-drafts",
            headers={"Origin": ORIGIN},
            data={"csrf": csrf, "ticket_id": "ticket-alice"},
        )
        assert preview.status_code == 200
        assert "Unreviewed internal draft" in preview.text
        assert "Recipients: erin, morgan" in preview.text
        assert '<a href="/internal-drafts/' in preview.text
        assert "<img" not in preview.text and "&lt;img" in preview.text
        draft_id = uuid4()
        review = http.get(f"/internal-drafts/{draft_id}")
        assert review.status_code == 200
        assert "Confirm and post this internal comment" in review.text
        assert "&lt;b&gt;Staff-only text&lt;/b&gt;" in review.text
        assert f'action="/internal-drafts/{draft_id}/confirm"' in review.text
        assert "Recipients: erin, morgan" in review.text
        assert review.headers["cache-control"] == "no-store"
        result = http.post(
            f"/internal-drafts/{draft_id}/confirm",
            headers={"Origin": ORIGIN},
            data={"csrf": csrf, "confirmation_token": "a" * 43, "body_sha256": "b" * 64},
        )
        assert result.status_code == 200 and "Internal comment posted" in result.text


@pytest.mark.parametrize("path", ["/tasks", "/requester-drafts", "/internal-drafts"])
@pytest.mark.parametrize("form", [False, True])
def test_task_admission_denial_is_safe_retryable_response(
    keys: RotatingKeys, monkeypatch: pytest.MonkeyPatch, path: str, form: bool
) -> None:
    def exhausted(*args: Any, **kwargs: Any) -> UUID:
        raise BoundaryDenied("BUDGET_EXHAUSTED")

    monkeypatch.setattr(UIStore, "create", exhausted)
    monkeypatch.setattr(RequesterStore, "create_draft", exhausted)
    with browser(keys) as http:
        csrf = http.get("/session").json()["csrf"]
        data = {"ticket_id": "ticket-alice"}
        if path == "/tasks":
            data["question"] = "Help"
        headers = {"Origin": ORIGIN, "X-CSRF-Token": csrf}
        if form:
            result = http.post(path, data={**data, "csrf": csrf}, headers=headers)
        else:
            result = http.post(path, json=data, headers=headers)
        assert result.status_code == 429 and result.headers["retry-after"] == "60"
        assert result.json() == {"detail": "Task limit reached. Try again later."}
        assert result.headers["cache-control"] == "no-store"
