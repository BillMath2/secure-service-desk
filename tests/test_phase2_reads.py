"""Opt-in real PostgreSQL, separate service roles, signed MCP and concurrent calls."""

import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import httpx
import psycopg
import pytest
from fastapi.testclient import TestClient
from test_phase2_identity import RotatingKeys

from service_desk.core.auth.lab import ISSUER, RESOURCES, subject_for
from service_desk.core.auth.oidc import LoginResult, OIDCClient
from service_desk.core.auth.tokens import TokenValidator, VerifiedIdentity
from service_desk.core.gateway.dispatch import ReadGateway
from service_desk.core.gateway.registry import BoundaryDenied, catalog
from service_desk.core.gateway.store import TaskStore
from service_desk.mcp.reads import create_read_mcp
from service_desk.reads import ReadService

pytestmark = [
    pytest.mark.postgres,
    pytest.mark.skipif(
        os.environ.get("DESK_READ_INTEGRATION") != "1",
        reason="Opt-in disposable PostgreSQL required",
    ),
]
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def connections() -> dict[str, str]:
    values: dict[str, str] = json.loads((ROOT / ".lab/phase2-read/connections.json").read_text())
    with psycopg.connect(values["admin"]) as db:
        assert db.execute("SELECT current_database()").fetchone() == ("service_desk_read_lab",)
        # Each integration case gets a fresh admission window. Keep production defaults
        # enabled, and preserve historical tasks/drafts needed by their immutable FKs.
        db.execute(
            "UPDATE service_desk.read_task SET active=false, "
            "created_at=clock_timestamp()-interval '2 minutes'"
        )
        db.execute(
            "UPDATE service_desk.task_admission_policy SET "
            "user_active=4,global_active=32,user_minute=20,global_minute=100"
        )
    return values


def identity(principal: str = "erin", client: str = "gateway") -> VerifiedIdentity:
    return VerifiedIdentity(
        ISSUER,
        subject_for(principal),
        principal,
        client,
        frozenset({"knowledge:read", "tickets:read"}),
        int(time.time()) + 120,
    )


def task(
    connections: dict[str, str],
    principal: str = "erin",
    audience: str = "self",
    ticket: str = "ticket-alice",
) -> UUID:
    return TaskStore(connections["creator"]).create(identity(principal, "web"), ticket, audience)


def service(connections: dict[str, str], name: str = "knowledge") -> ReadService:
    return ReadService(name, TaskStore(connections[name]))


def scalar(connections: dict[str, str], query: str, parameters: tuple[Any, ...] = ()) -> Any:
    with psycopg.connect(connections["admin"]) as db:
        row = db.execute(query, parameters).fetchone()
    assert row is not None
    return row[0]


def update(connections: dict[str, str], query: str, parameters: tuple[Any, ...] = ()) -> None:
    with psycopg.connect(connections["admin"]) as db:
        db.execute(query, parameters)


def test_allowed_document_is_cited_and_denied_ids_are_indistinguishable(
    connections: dict[str, str],
) -> None:
    t = task(connections)
    tool = service(connections)
    allowed = tool.invoke(identity(), t, "read_document", {"document_id": "doc-public"})
    assert allowed["allowed"] and allowed["document"]["citation"] == "document:doc-public@1"
    outputs = [
        tool.invoke(identity(), t, "read_document", {"document_id": d})
        for d in ("doc-hr", "doc-sales", "doc-missing")
    ]
    assert outputs[0] == outputs[1] == outputs[2]
    assert "LAB-CANARY" not in json.dumps(outputs)


def test_retrieval_filters_before_ranking_snippets_and_counts(connections: dict[str, str]) -> None:
    t = task(connections, "alice")
    tool = service(connections)
    result = tool.invoke(
        identity("alice"),
        t,
        "search_documents",
        {"query": "HR OR admin OR support OR engineering", "limit": 10},
    )
    assert result["allowed"]
    output = json.dumps(result)
    assert "doc-public" in output and "doc-engineering" in output
    for forbidden in (
        "doc-hr",
        "doc-admin-reset",
        "LAB-CANARY-HR",
        "LAB-CANARY-ADMIN",
        "Synthetic HR procedure",
        "Internal admin reset procedure",
        "total_count",
    ):
        assert forbidden not in output
    assert tool.invoke(identity("alice"), t, "search_documents", {"query": "A69F"}) == {
        "allowed": True,
        "documents": [],
    }


def test_recipient_intersection_and_comment_visibility(connections: dict[str, str]) -> None:
    mine = task(connections)
    requester = task(connections, audience="requester")
    knowledge, tickets = service(connections), service(connections, "tickets")
    assert knowledge.invoke(identity(), mine, "read_document", {"document_id": "doc-admin-reset"})[
        "allowed"
    ]
    result = knowledge.invoke(
        identity(), requester, "read_document", {"document_id": "doc-admin-reset"}
    )
    assert not result["allowed"] and "LAB-CANARY" not in json.dumps(result)
    private = tickets.invoke(identity(), mine, "read_ticket", {"ticket_id": "ticket-alice"})
    public = tickets.invoke(identity(), requester, "read_ticket", {"ticket_id": "ticket-alice"})
    # Live publication checks intentionally leave legitimate comments in the lab.
    # Verify the seeded private row and every returned visibility, not an empty history.
    assert "comment-private" in {c["id"] for c in private["ticket"]["comments"]}
    assert "comment-private" not in {c["id"] for c in public["ticket"]["comments"]}
    assert all(c["visibility"] == "requester" for c in public["ticket"]["comments"])
    assert "Internal support note" not in json.dumps(public)
    assert not tickets.invoke(identity(), mine, "read_ticket", {"ticket_id": "ticket-bob"})[
        "allowed"
    ]


def test_changed_acl_is_rechecked_on_read(connections: dict[str, str]) -> None:
    t = task(connections, "alice")
    tool = service(connections)
    assert tool.invoke(identity("alice"), t, "search_documents", {"query": "engineering"})[
        "documents"
    ]
    update(
        connections,
        "DELETE FROM service_desk.document_reader "
        "WHERE document_id='doc-engineering' AND principal_id='alice'",
    )
    try:
        assert not tool.invoke(
            identity("alice"), t, "read_document", {"document_id": "doc-engineering"}
        )["allowed"]
    finally:
        update(
            connections,
            "INSERT INTO service_desk.document_reader VALUES('doc-engineering','alice')",
        )


def test_shared_concurrent_budget_across_two_services(connections: dict[str, str]) -> None:
    t = task(connections)

    def read(index: int) -> dict[str, Any]:
        if index % 2:
            return service(connections).invoke(
                identity(), t, "read_document", {"document_id": "doc-public"}
            )
        return service(connections, "tickets").invoke(
            identity(), t, "read_ticket", {"ticket_id": "ticket-alice"}
        )

    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(read, range(24)))
    assert sum(r["allowed"] for r in results) == 12
    assert sum(r.get("reason") == "BUDGET_EXHAUSTED" for r in results) == 12
    assert (
        scalar(connections, "SELECT used_calls FROM service_desk.read_task WHERE id=%s", (t,)) == 12
    )
    assert (
        scalar(
            connections,
            "SELECT count(*) FROM service_desk.read_audit WHERE task_id=%s AND reason='ALLOW'",
            (t,),
        )
        == 12
    )


def test_rejected_calls_consume_budget_and_work_after_service_restart(
    connections: dict[str, str],
) -> None:
    t = task(connections)
    for index in range(12):
        name, args = (
            ("unknown", {})
            if index % 2
            else ("read_document", {"document_id": "doc-public", "subject": "harper"})
        )
        result = service(connections).invoke(identity(), t, name, args)
        assert not result["allowed"]
    result = service(connections).invoke(
        identity(), t, "read_document", {"document_id": "doc-public"}
    )
    assert result["reason"] == "BUDGET_EXHAUSTED"


def test_reservation_argument_binding_and_single_use(connections: dict[str, str]) -> None:
    t = task(connections)
    gateway = TaskStore(connections["gateway"])
    args = {"document_id": "doc-public"}
    attempt = gateway.reserve(identity(), t, "knowledge", "read_document", args)
    tool = service(connections)
    forged = tool.invoke(
        identity(), t, "read_document", {"document_id": "doc-admin-reset"}, attempt
    )
    assert not forged["allowed"]
    assert tool.invoke(identity(), t, "read_document", args, attempt)["allowed"]
    assert not tool.invoke(identity(), t, "read_document", args, attempt)["allowed"]
    assert (
        scalar(connections, "SELECT used_calls FROM service_desk.read_task WHERE id=%s", (t,)) == 3
    )


def test_forged_reservation_references_also_exhaust_budget(connections: dict[str, str]) -> None:
    t = task(connections)
    for _ in range(12):
        result = service(connections).invoke(
            identity(), t, "read_document", {"document_id": "doc-public"}, uuid4()
        )
        assert result["reason"] == "TASK_DENIED"
    result = service(connections).invoke(
        identity(), t, "read_document", {"document_id": "doc-public"}
    )
    assert result["reason"] == "BUDGET_EXHAUSTED"


def test_task_identity_ticket_and_recipient_cannot_be_overridden(
    connections: dict[str, str],
) -> None:
    t = task(connections)
    result = service(connections).invoke(
        identity("alice"), t, "read_document", {"document_id": "doc-public"}
    )
    assert not result["allowed"]
    assert (
        scalar(connections, "SELECT used_calls FROM service_desk.read_task WHERE id=%s", (t,)) == 0
    )
    with pytest.raises(BoundaryDenied):
        task(connections, "alice", ticket="ticket-bob")
    with pytest.raises(BoundaryDenied):
        task(connections, audience="all-users")


@pytest.mark.parametrize(
    "alteration,reason",
    [
        ("deadline=clock_timestamp()-interval '1 second'", "TASK_EXPIRED"),
        ("policy_version='old-policy'", "POLICY_STALE"),
        ("active=false", "TASK_DENIED"),
        ("max_bytes=256", "OUTPUT_LIMIT"),
    ],
)
def test_stale_tasks_and_output_limits(
    connections: dict[str, str], alteration: str, reason: str
) -> None:
    t = task(connections)
    # SQL fragments are fixed parametrized test cases, never application input.
    update(connections, "UPDATE service_desk.read_task SET " + alteration + " WHERE id=%s", (t,))
    result = service(connections).invoke(
        identity(), t, "read_document", {"document_id": "doc-public"}
    )
    assert result["reason"] == reason and "document" not in result


def test_durable_audit_failure_prevents_output(
    connections: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    t = task(connections)

    def fail(self: TaskStore, attempt: UUID, reason: str) -> bool:
        raise psycopg.OperationalError("must not expose internal database details")

    monkeypatch.setattr(TaskStore, "finish", fail)
    result = service(connections).invoke(
        identity(), t, "read_document", {"document_id": "doc-public"}
    )
    assert result == {
        "allowed": False,
        "reason": "SERVICE_ERROR",
        "message": "Resource unavailable",
    }


def test_database_roles_cannot_reset_budgets_create_tasks_or_edit_audit(
    connections: dict[str, str],
) -> None:
    for role in ("gateway", "knowledge", "tickets"):
        for statement in (
            "UPDATE service_desk.read_task SET used_calls=0",
            "DELETE FROM service_desk.read_audit",
            "UPDATE service_desk.document SET body=body",
        ):
            with (
                psycopg.connect(connections[role]) as db,
                pytest.raises(psycopg.errors.InsufficientPrivilege),
            ):
                db.execute(statement)
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        TaskStore(connections["gateway"]).create(identity(client="web"), "ticket-alice")


@pytest.mark.parametrize("name", ["knowledge", "tickets"])
def test_signed_direct_mcp_calls_enforce_task_schema_and_acl(
    connections: dict[str, str], name: str
) -> None:
    keys = RotatingKeys()
    validator = TokenValidator(ISSUER, keys, {(ISSUER, subject_for("erin")): "erin"})
    binding = next(r for r in RESOURCES if r.audience == name)
    app = create_read_mcp(validator, binding, service(connections, name))
    t = task(connections)
    token = keys.sign(iss=ISSUER, sub=subject_for("erin"), aud=name, scope=name + ":read")
    headers = {
        "Accept": "application/json, text/event-stream",
        "Authorization": "Bearer " + token,
        "X-Desk-Task": str(t),
    }
    with TestClient(app, base_url=binding.url.removesuffix("/mcp")) as http:

        def call(method: str, params: dict[str, Any]) -> dict[str, Any]:
            value: dict[str, Any] = http.post(
                "/mcp",
                headers=headers,
                json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
            ).json()
            return value

        call(
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1"},
            },
        )
        assert call("tools/list", {})["result"]["tools"] == catalog(name)
        bad = call("tools/call", {"name": "unknown", "arguments": {}})["result"]
        assert bad["isError"]
        tool, args = (
            ("read_document", {"document_id": "doc-hr"})
            if name == "knowledge"
            else ("read_ticket", {"ticket_id": "ticket-bob"})
        )
        bad = call("tools/call", {"name": tool, "arguments": args})["result"]
        assert bad["isError"] and "LAB-CANARY" not in json.dumps(bad)
        good_args = (
            {"document_id": "doc-public"} if name == "knowledge" else {"ticket_id": "ticket-alice"}
        )
        good = call("tools/call", {"name": tool, "arguments": good_args})["result"]
        assert not good["isError"]
        oversized = http.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": "x" * 1024,
                "method": "tools/call",
                "params": {"name": tool, "arguments": good_args},
            },
        ).json()["result"]
        assert oversized["isError"]
        assert (
            scalar(connections, "SELECT used_calls FROM service_desk.read_task WHERE id=%s", (t,))
            == 3
        )


def test_gateway_quarantines_remote_tool_change_before_dispatch(
    connections: dict[str, str],
) -> None:
    keys = RotatingKeys()
    mapping = {(ISSUER, subject_for("erin")): "erin"}
    login_validator = TokenValidator(ISSUER, keys, mapping, "web")
    delegated_validator = TokenValidator(ISSUER, keys, mapping)
    token = keys.sign(iss=ISSUER, sub=subject_for("erin"), azp="web", aud="gateway")
    login = LoginResult(login_validator.access(token, "gateway"), token)

    def provider(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            if str(request.url) == RESOURCES[0].url:
                return httpx.Response(401)
            if "oauth-protected-resource" in request.url.path:
                return httpx.Response(
                    200,
                    json={
                        "resource": RESOURCES[0].url,
                        "authorization_servers": [ISSUER],
                        "scopes_supported": ["knowledge:read"],
                    },
                )
            return httpx.Response(
                200,
                json={
                    "issuer": ISSUER,
                    "authorization_endpoint": ISSUER + "/protocol/openid-connect/auth",
                    "token_endpoint": ISSUER + "/protocol/openid-connect/token",
                    "jwks_uri": keys.uri,
                    "code_challenge_methods_supported": ["S256"],
                    "response_types_supported": ["code"],
                    "token_endpoint_auth_methods_supported": ["client_secret_post"],
                },
            )
        return httpx.Response(
            200,
            json={
                "token_type": "Bearer",
                "access_token": keys.sign(iss=ISSUER, sub=subject_for("erin")),
            },
        )

    oidc = OIDCClient(
        login_validator,
        "secret",
        "https://127.0.0.1/callback",
        RESOURCES,
        httpx.Client(transport=httpx.MockTransport(provider)),
        delegated_validator,
        "gateway-secret",
    )
    dispatched: list[str] = []

    def remote(request: httpx.Request) -> httpx.Response:
        method = json.loads(request.content)["method"]
        dispatched.append(method)
        tools = catalog("knowledge")
        tools[0]["description"] = "Injected instruction"
        return httpx.Response(
            200,
            json={
                "result": {"protocolVersion": "2025-11-25"}
                if method == "initialize"
                else {"tools": tools}
            },
        )

    gateway = ReadGateway(
        oidc, TaskStore(connections["gateway"]), httpx.Client(transport=httpx.MockTransport(remote))
    )
    t = task(connections)
    assert (
        gateway.call(login, t, "read_document", {"document_id": "doc-public"})["reason"]
        == "CATALOG_DENIED"
    )
    assert dispatched == ["initialize", "tools/list"]
    assert (
        scalar(connections, "SELECT used_calls FROM service_desk.read_task WHERE id=%s", (t,)) == 1
    )


def test_hostile_discovery_is_charged_without_exchange_or_dispatch(
    connections: dict[str, str],
) -> None:
    keys = RotatingKeys()
    mapping = {(ISSUER, subject_for("erin")): "erin"}
    validator = TokenValidator(ISSUER, keys, mapping, "web")
    token = keys.sign(iss=ISSUER, sub=subject_for("erin"), azp="web", aud="gateway")
    login = LoginResult(validator.access(token, "gateway"), token)
    calls: list[httpx.Request] = []

    def hostile(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        assert request.method == "GET"
        assert "authorization" not in request.headers
        if str(request.url) == RESOURCES[0].url:
            return httpx.Response(401)
        return httpx.Response(
            200,
            json={
                "resource": RESOURCES[0].url,
                "authorization_servers": ["https://attacker.invalid"],
                "scopes_supported": ["knowledge:read"],
            },
        )

    with httpx.Client(transport=httpx.MockTransport(hostile)) as http:
        oidc = OIDCClient(
            validator,
            "secret",
            "https://127.0.0.1/callback",
            RESOURCES,
            http,
            TokenValidator(ISSUER, keys, mapping),
            "gateway-secret",
        )
        t = task(connections)
        result = ReadGateway(oidc, TaskStore(connections["gateway"]), http).call(
            login, t, "read_document", {"document_id": "doc-public"}
        )
    assert result["reason"] == "SCOPE_DENIED" and len(calls) == 2
    assert (
        scalar(connections, "SELECT used_calls FROM service_desk.read_task WHERE id=%s", (t,)) == 1
    )
    assert (
        scalar(
            connections,
            "SELECT count(*) FROM service_desk.read_audit "
            "WHERE task_id=%s AND reason='SCOPE_DENIED'",
            (t,),
        )
        == 1
    )


def test_escaped_content_cannot_exceed_wire_limit(connections: dict[str, str]) -> None:
    t = task(connections)
    doc_id = "doc-wire-" + uuid4().hex
    update(
        connections,
        "INSERT INTO service_desk.document(id,version,classification,title,body) "
        "VALUES(%s,1,%s,%s,%s)",
        (doc_id, "team", "Large escaped source", "\\" * 10000),
    )
    update(connections, "INSERT INTO service_desk.document_reader VALUES(%s,%s)", (doc_id, "erin"))
    try:
        result = service(connections).invoke(
            identity(), t, "read_document", {"document_id": doc_id}
        )
        assert result["reason"] == "OUTPUT_LIMIT" and "document" not in result
    finally:
        update(
            connections, "DELETE FROM service_desk.document_reader WHERE document_id=%s", (doc_id,)
        )
        update(connections, "DELETE FROM service_desk.document WHERE id=%s", (doc_id,))


@pytest.mark.parametrize(
    "alteration",
    ["active=false", "policy_version='stale'", "deadline=clock_timestamp()-interval '1 second'"],
)
def test_task_invalidated_during_read_never_returns_body(
    connections: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
    alteration: str,
) -> None:
    from service_desk.core.gateway.store import TaskContext

    t = task(connections)
    read = ReadService._read

    def changed(
        self: ReadService, context: TaskContext, name: str, args: dict[str, Any]
    ) -> dict[str, Any]:
        result = read(self, context, name, args)
        update(
            connections, "UPDATE service_desk.read_task SET " + alteration + " WHERE id=%s", (t,)
        )
        return result

    monkeypatch.setattr(ReadService, "_read", changed)
    result = service(connections).invoke(
        identity(), t, "read_document", {"document_id": "doc-public"}
    )
    assert not result["allowed"] and "document" not in result


def test_concurrent_reservation_replay_returns_content_once(connections: dict[str, str]) -> None:
    t = task(connections)
    args = {"document_id": "doc-public"}
    attempt = TaskStore(connections["gateway"]).reserve(
        identity(), t, "knowledge", "read_document", args
    )

    def read(_: int) -> dict[str, Any]:
        return service(connections).invoke(identity(), t, "read_document", args, attempt)

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(read, range(8)))
    assert sum(r["allowed"] for r in results) == 1
    assert (
        scalar(
            connections,
            "SELECT count(*) FROM service_desk.read_audit WHERE task_id=%s AND reason='ALLOW'",
            (t,),
        )
        == 1
    )
