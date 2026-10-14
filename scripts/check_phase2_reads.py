"""Real user login -> pinned gateway -> TLS MCP -> PostgreSQL ACLs and task limits."""

import hashlib
import json
import ssl
import threading
import time
from datetime import UTC, datetime
from importlib.metadata import version
from urllib.parse import parse_qs, urlsplit

import httpx
import psycopg
import uvicorn
from check_phase2_identity import LoginForm
from phase2_runtime import LOCAL, ROOT, create_server, load_client

from service_desk.core.auth.lab import ISSUER, RESOURCES
from service_desk.core.gateway.dispatch import ReadGateway
from service_desk.core.gateway.store import TaskStore
from service_desk.mcp.reads import create_read_mcp
from service_desk.reads import ReadService


def main() -> None:
    checks: dict[str, bool] = {}
    report: dict[str, object] = {
        "schema_version": 1,
        "recorded_at": datetime.now(UTC).isoformat(),
        "phase": "2-authorized-reads",
        "checks": checks,
        "model_invoked": False,
        "versions": {p: version(p) for p in ("mcp", "psycopg", "PyJWT")},
    }
    servers: list[tuple[uvicorn.Server, threading.Thread]] = []
    stage = "startup"

    def check(name: str, condition: bool) -> None:
        checks[name] = bool(condition)
        if not condition:
            raise AssertionError(name)

    def unpack(result: dict) -> dict:
        return json.loads(result["content"][0]["text"]) if "content" in result else result

    try:
        connections = json.loads((ROOT / ".lab/phase2-read/connections.json").read_text())
        with psycopg.connect(connections["admin"]) as db:
            report["postgres_version"] = db.execute("SHOW server_version").fetchone()[0]
        credentials = json.loads((LOCAL / "credentials.json").read_text())
        trust = ssl.create_default_context(cafile=str(LOCAL / "tls/certificate.pem"))
        with httpx.Client(
            verify=trust, timeout=10, trust_env=False, follow_redirects=False
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
                app = create_read_mcp(
                    oidc.delegated_validator,
                    binding,
                    ReadService(binding.audience, TaskStore(connections[binding.audience])),
                )
                runner = create_server(app, urlsplit(binding.url).port)
                thread = threading.Thread(target=runner.run, daemon=True)
                servers.append((runner, thread))
                thread.start()
            deadline = time.monotonic() + 10
            while not all(s.started for s, _ in servers) and time.monotonic() < deadline:
                time.sleep(0.05)
            check("tls_read_services", all(s.started for s, _ in servers))
            gateway = ReadGateway(oidc, TaskStore(connections["gateway"]), http)

            def caller(active_login, active_task):
                def call(name: str, args: dict) -> dict:
                    return unpack(gateway.call(active_login, active_task, name, args))

                return call

            for user in ("erin", "alice"):
                stage = "login-" + user
                attempt, url = oidc.begin(RESOURCES[0].url)
                with httpx.Client(verify=trust, timeout=10, trust_env=False) as browser:
                    page = browser.get(url)
                    form = LoginForm()
                    form.feed(page.text)
                    check(
                        user + "_form_origin",
                        bool(form.action and form.action.startswith(ISSUER + "/")),
                    )
                    redirected = browser.post(
                        form.action, data={"username": user, "password": credentials["users"][user]}
                    )
                    check(user + "_login_redirect", redirected.status_code == 302)
                    query = parse_qs(urlsplit(redirected.headers["location"]).query)
                login = oidc.finish(attempt, query["state"][0], query["code"][0])
                stage = "reads-" + user
                task = TaskStore(connections["creator"]).create(login.identity, "ticket-alice")

                call = caller(login, task)

                ticket = call("read_ticket", {"ticket_id": "ticket-alice"})
                check(user + "_ticket_allowed", ticket.get("allowed") is True)
                check(
                    user + "_comment_visibility",
                    len(ticket["ticket"]["comments"]) == (1 if user == "erin" else 0),
                )
                doc = call("read_document", {"document_id": "doc-public"})
                check(
                    user + "_public_citation",
                    doc.get("allowed") is True
                    and doc["document"]["citation"] == "document:doc-public@1",
                )
                restricted = call("read_document", {"document_id": "doc-hr"})
                missing = call("read_document", {"document_id": "doc-missing"})
                check(
                    user + "_no_existence_leak", restricted == missing and not restricted["allowed"]
                )
                search = call("search_documents", {"query": "HR OR admin OR support", "limit": 10})
                check(user + "_search_allowed", search.get("allowed") is True)
                check(
                    user + "_hr_absent_from_search",
                    "doc-hr" not in json.dumps(search) and "A69F" not in json.dumps(search),
                )
                admin = call("read_document", {"document_id": "doc-admin-reset"})
                check(user + "_admin_acl", admin.get("allowed") == (user == "erin"))
                if user == "alice":
                    check(
                        "requester_admin_snippet_absent",
                        "doc-admin-reset" not in json.dumps(search)
                        and "C15D" not in json.dumps(search),
                    )
                task = TaskStore(connections["creator"]).create(
                    login.identity, "ticket-alice", "requester"
                )
                call = caller(login, task)
                audience = call("read_document", {"document_id": "doc-admin-reset"})
                check(user + "_recipient_intersection", not audience.get("allowed"))
                # Direct calls still need a stored task and spend the same task's budget.
                delegated = oidc.exchange(login, RESOURCES[0].url)
                headers = {
                    "Accept": "application/json, text/event-stream",
                    "Authorization": "Bearer " + delegated,
                }
                message = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "read_document", "arguments": {"document_id": "doc-public"}},
                }
                without = http.post(
                    RESOURCES[0].url, headers={**headers, "X-User": "erin"}, json=message
                )
                check(user + "_direct_task_required", without.json()["result"]["isError"])
                valid = http.post(
                    RESOURCES[0].url, headers={**headers, "X-Desk-Task": str(task)}, json=message
                )
                check(user + "_direct_allowed", not valid.json()["result"]["isError"])
                with psycopg.connect(connections["admin"]) as db:
                    used = db.execute(
                        "SELECT used_calls FROM service_desk.read_task WHERE id=%s", (task,)
                    ).fetchone()[0]
                check(user + "_gateway_and_direct_share_budget", used == 2)
                for _ in range(10):
                    check(
                        user + "_unknown_tool_denied",
                        call("invented_tool", {})["reason"] == "TOOL_DENIED",
                    )
                exhausted = call("read_document", {"document_id": "doc-public"})
                check(user + "_budget_exhausted", exhausted["reason"] == "BUDGET_EXHAUSTED")
                with psycopg.connect(connections["admin"]) as db:
                    audit = db.execute(
                        "SELECT operation,reason FROM service_desk.read_audit WHERE task_id=%s",
                        (task,),
                    ).fetchall()
                check(
                    user + "_audit_outcomes",
                    len(audit) == 25 and ("read_document", "ALLOW") in audit,
                )
            report["status"] = "success"
    except Exception as error:
        report.update(status="error", error_type=type(error).__name__, stage=stage)
    finally:
        for server, _ in servers:
            server.should_exit = True
        for _, thread in servers:
            thread.join(timeout=5)
        files = [
            *(ROOT / "src/service_desk/core/gateway").glob("*.py"),
            ROOT / "src/service_desk/reads.py",
            ROOT / "src/service_desk/mcp/reads.py",
            ROOT / "migrations/0003_read_tasks.sql",
            ROOT / "docs/contracts/read-tools-v1.json",
            ROOT / "uv.lock",
            ROOT / "fixtures/company.json",
            ROOT / "scripts/check_phase2_reads.py",
            ROOT / "scripts/prepare_read_store.py",
            ROOT / "scripts/read_runtime.py",
            ROOT / "infra/compose.phase2-reads.yaml",
        ]
        report["source_sha256"] = {
            str(p.relative_to(ROOT)).replace("\\", "/"): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in files
        }
        output = ROOT / "reports/runs/phase2-reads"
        output.mkdir(parents=True, exist_ok=True)
        (output / (str(time.time_ns()) + ".json")).write_text(
            json.dumps(report, indent=2) + "\n", encoding="utf-8"
        )
        print(json.dumps(report, indent=2))
    if report.get("status") != "success":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
