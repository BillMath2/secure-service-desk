"""Real browser login -> task form/API -> bounded stub -> gateway -> TLS MCP -> PostgreSQL."""

import hashlib
import json
import ssl
import threading
import time
from datetime import UTC, datetime
from urllib.parse import urlsplit

import httpx
import psycopg
import uvicorn
from check_phase2_identity import LoginForm
from phase2_runtime import LOCAL, ROOT, create_server, load_client

from service_desk.agent.loop import Assistant
from service_desk.agent.provider import DeterministicProvider, ProviderReply
from service_desk.agent.store import AgentStore
from service_desk.app.identity import create_identity_app
from service_desk.core.auth.lab import ISSUER, RESOURCES
from service_desk.core.gateway.dispatch import ReadGateway
from service_desk.core.gateway.store import TaskStore
from service_desk.mcp.reads import create_read_mcp
from service_desk.reads import ReadService

ORIGIN = "https://127.0.0.1:19481"


class CaptureProvider(DeterministicProvider):
    def __init__(self) -> None:
        self.requests: list[str] = []

    async def generate(self, request: str, *, max_output: int) -> ProviderReply:
        self.requests.append(request)
        return await super().generate(request, max_output=max_output)


def main() -> None:
    checks: dict[str, bool] = {}
    report: dict[str, object] = {
        "phase": "2-deterministic-assistant",
        "recorded_at": datetime.now(UTC).isoformat(),
        "checks": checks,
        "provider": "deterministic-stub",
        "real_model_invoked": False,
    }
    servers: list[tuple[uvicorn.Server, threading.Thread]] = []
    stage = "startup"

    def check(name: str, condition: bool) -> None:
        checks[name] = bool(condition)
        if not condition:
            raise AssertionError(name)

    def start(app: object, port: int) -> None:
        server = create_server(app, port)
        thread = threading.Thread(target=server.run, daemon=True)
        servers.append((server, thread))
        thread.start()

    try:
        connections = json.loads((ROOT / ".lab/phase2-read/connections.json").read_text())
        credentials = json.loads((LOCAL / "credentials.json").read_text())
        trust = ssl.create_default_context(cafile=str(LOCAL / "tls/certificate.pem"))
        provider = CaptureProvider()
        with httpx.Client(
            verify=trust, trust_env=False, timeout=10, follow_redirects=False
        ) as http:
            oidc = load_client(http, trust)
            deadline = time.monotonic() + 45
            while True:
                try:
                    if (
                        http.get(
                            ISSUER + "/.well-known/openid-configuration", timeout=2
                        ).status_code
                        == 200
                    ):
                        break
                except httpx.TransportError:
                    pass
                if time.monotonic() >= deadline:
                    check("issuer_ready", False)
                time.sleep(0.5)
            oidc.check_discovery()
            for binding in RESOURCES[:2]:
                start(
                    create_read_mcp(
                        oidc.delegated_validator,
                        binding,
                        ReadService(binding.audience, TaskStore(connections[binding.audience])),
                    ),
                    urlsplit(binding.url).port,
                )
            assistant = Assistant(
                oidc.validator,
                AgentStore(connections["creator"]),
                ReadGateway(oidc, TaskStore(connections["gateway"]), http),
                provider,
            )
            start(create_identity_app(oidc, assistant=assistant), 19481)
            deadline = time.monotonic() + 10
            while not all(s.started for s, _ in servers) and time.monotonic() < deadline:
                time.sleep(0.05)
            check("tls_services_ready", all(s.started for s, _ in servers))
            check(
                "unauthenticated_task_denied",
                http.post(ORIGIN + "/tasks", json={}).status_code == 401,
            )
            for user in ("erin", "alice"):
                stage = "browser-" + user
                provider.requests.clear()
                with httpx.Client(
                    verify=trust, trust_env=False, timeout=120, follow_redirects=False
                ) as browser:
                    login = browser.get(ORIGIN + "/login")
                    form = LoginForm()
                    form.feed(browser.get(login.headers["location"]).text)
                    check(
                        user + "_issuer_form",
                        bool(form.action and form.action.startswith(ISSUER + "/")),
                    )
                    authorized = browser.post(
                        form.action, data={"username": user, "password": credentials["users"][user]}
                    )
                    check(
                        user + "_login_redirect",
                        authorized.status_code == 302
                        and authorized.headers["location"].startswith(ORIGIN + "/callback?"),
                    )
                    callback = browser.get(authorized.headers["location"])
                    check(user + "_session_created", callback.status_code == 303)
                    info = browser.get(ORIGIN + "/session").json()
                    headers = {"Origin": ORIGIN, "X-CSRF-Token": info["csrf"]}
                    payload = {"ticket_id": "ticket-alice", "question": user + "-private-question"}
                    check(
                        user + "_csrf_required",
                        browser.post(ORIGIN + "/tasks", json=payload).status_code == 403,
                    )
                    check(
                        user + "_audience_override_denied",
                        browser.post(
                            ORIGIN + "/tasks",
                            headers=headers,
                            json={**payload, "audience": "requester"},
                        ).status_code
                        == 422,
                    )
                    result = browser.post(ORIGIN + "/tasks", headers=headers, json=payload)
                    body = result.json()
                    check(
                        user + "_cited_answer",
                        body.get("allowed") is True
                        and body.get("citations") == ["document:doc-public@1"],
                    )
                    check(user + "_no_cache", result.headers["cache-control"] == "no-store")
                    check(
                        user + "_fresh_context",
                        len(provider.requests) == 3
                        and json.loads(provider.requests[0])["history"] == [],
                    )
                    prompts = "".join(provider.requests)
                    check(
                        user + "_credentials_absent",
                        info["csrf"] not in prompts
                        and all(
                            secret not in prompts for secret in credentials["clients"].values()
                        ),
                    )
                    check(
                        user + "_restricted_canaries_absent",
                        "A69F" not in prompts and "C15D" not in prompts,
                    )
                    if user == "alice":
                        check(
                            "requester_context_isolated",
                            "erin-private-question" not in prompts
                            and '"visibility":"internal"' not in prompts,
                        )
                    with psycopg.connect(connections["admin"]) as db:
                        row = db.execute(
                            "SELECT agent_state,active,model_calls,model_tokens,used_calls "
                            "FROM service_desk.read_task WHERE id=%s",
                            (body["task_id"],),
                        ).fetchone()
                        check(
                            user + "_durable_limits",
                            bool(
                                row
                                and row[:3] == ("completed", False, 3)
                                and 0 < row[3] <= 16000
                                and row[4] == 2
                            ),
                        )
                        events = db.execute(
                            "SELECT operation,reason FROM service_desk.read_audit WHERE task_id=%s",
                            (body["task_id"],),
                        ).fetchall()
                        check(
                            user + "_audit",
                            events.count(("agent_reserve", "ALLOW")) == 3
                            and ("agent_finish", "ALLOW") in events,
                        )
            report["passed"] = True
    except Exception:
        # Never serialize exception text, response bodies, credentials or prompts.
        report["passed"] = False
        report["failure_stage"] = stage
    finally:
        for server, _ in servers:
            server.should_exit = True
        for _, thread in servers:
            thread.join(10)
        files = [
            *sorted((ROOT / "src/service_desk").rglob("*.py")),
            *sorted((ROOT / "migrations").glob("*.sql")),
            ROOT / "scripts/check_phase2_assistant.py",
        ]
        report["source_sha256"] = {
            p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in files
        }
        destination = (
            ROOT / "reports/phase2-assistant/runs" / datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        )
        destination.mkdir(parents=True, exist_ok=True)
        (destination / "results.json").write_text(
            json.dumps(report, indent=2) + "\n", encoding="utf-8"
        )
        print(
            json.dumps(
                {
                    "passed": report["passed"],
                    "checks": len(checks),
                    "report": str(destination.relative_to(ROOT) / "results.json"),
                }
            )
        )
    if not report.get("passed"):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
