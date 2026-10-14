"""Matched read-surface trials through real signed gateway/MCP and offline model.

Trusted host evaluator; full deployed browser/workflow probes are reported separately.
"""

import argparse
import asyncio
import json
import ssl
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit
from uuid import UUID

import httpx
import psycopg
from check_model_boundary import check_boundary as model_boundary
from check_phase2_identity import LoginForm
from check_phase4_boundary import check_boundary
from phase2_runtime import LOCAL, ROOT, load_client
from phase5_evaluation import CASE_FILE, SETTINGS, observe, sha, summarize

from service_desk.agent.local_model import LocalModelProvider
from service_desk.agent.loop import SYSTEM, Assistant, unpack
from service_desk.agent.provider import ProviderReply
from service_desk.agent.store import AgentStore
from service_desk.core.auth.lab import ISSUER, RESOURCES
from service_desk.core.auth.oidc import LoginResult
from service_desk.core.gateway.dispatch import ReadGateway
from service_desk.core.gateway.registry import TOOLS
from service_desk.core.gateway.store import TaskStore
from service_desk.fixtures import fingerprint, load_fixtures


class ObservedProvider(LocalModelProvider):
    def __init__(self) -> None:
        super().__init__()
        self.tokens = 0
        self.calls = 0

    async def generate(self, request: str, *, max_output: int) -> ProviderReply:
        self.calls += 1
        result = await super().generate(request, max_output=max_output)
        self.tokens += result.input_tokens + result.output_tokens
        return result


class ObservedGateway(ReadGateway):
    outputs: list[dict[str, Any]]

    def call(
        self, login: LoginResult, task_id: UUID, name: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        raw = super().call(login, task_id, name, arguments)
        value = unpack(raw)
        self.outputs.append(value)
        return raw


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=5)
    args = parser.parse_args()
    if not 1 <= args.repetitions <= 20:
        parser.error("repetitions must be 1..20")
    args.output.mkdir(parents=True, exist_ok=False)
    if not all(check_boundary(args.docker).values()) or not all(
        model_boundary(args.docker).values()
    ):
        raise SystemExit("Deployment gate denied")
    fixtures = load_fixtures(ROOT / "fixtures/company.json")
    cases = json.loads((ROOT / CASE_FILE).read_text())
    dsns = json.loads((ROOT / ".lab/phase2-read/connections.json").read_text())
    credentials = json.loads((LOCAL / "credentials.json").read_text())
    trust = ssl.create_default_context(cafile=str(LOCAL / "tls/certificate.pem"))
    rows: list[dict[str, Any]] = []
    for repetition in range(1, args.repetitions + 1):
        for case in cases:
            started = time.monotonic()
            gateway_outputs: list[dict[str, Any]] = []
            result: dict[str, Any] = {}
            events: list[Any] = []
            counters: Any = None
            task = None
            provider = ObservedProvider()
            status, reason, denied = "completed", "completed", False
            try:
                with httpx.Client(
                    verify=trust, trust_env=False, follow_redirects=False, timeout=10
                ) as http:
                    oidc = load_client(http, trust)
                    oidc.check_discovery()
                    attempt, location = oidc.begin(RESOURCES[0].url)
                    form = LoginForm()
                    form.feed(http.get(location).text)
                    if not form.action.startswith(ISSUER + "/"):
                        raise RuntimeError("Issuer denied")
                    response = http.post(
                        form.action,
                        data={
                            "username": case["user"],
                            "password": credentials["users"][case["user"]],
                        },
                    )
                    query = parse_qs(urlsplit(response.headers["location"]).query)
                    login = oidc.finish(attempt, query["state"][0], query["code"][0])
                    asyncio.run(provider.prepare())
                    store = AgentStore(dsns["creator"])
                    task = store.create(login.identity, case["ticket_id"])
                    gateway = ObservedGateway(oidc, TaskStore(dsns["gateway"]), http)
                    gateway.outputs = gateway_outputs
                    assistant = Assistant(oidc.validator, store, gateway, provider)
                    result = asyncio.run(assistant.run(login, task, case["question"]))
                    reason = result.get("reason", "completed")
                    denied = reason in {
                        "RESOURCE_DENIED",
                        "POLICY_DENIED",
                        "OUTPUT_DENIED",
                        "TASK_DENIED",
                        "SCOPE_DENIED",
                        "CATALOG_DENIED",
                    }
                    if reason in {"TIMEOUT", "TASK_EXPIRED"}:
                        status = "timeout"
                    elif reason == "SERVICE_ERROR":
                        status = "error"
                    with psycopg.connect(dsns["admin"]) as db:
                        events = db.execute(
                            "SELECT event_id,operation,reason FROM service_desk.read_audit "
                            "WHERE task_id=%s ORDER BY event_id",
                            (task,),
                        ).fetchall()
                        counters = db.execute(
                            "SELECT model_calls,model_tokens,used_calls,agent_state "
                            "FROM service_desk.read_task WHERE id=%s",
                            (task,),
                        ).fetchone()
            except Exception as error:
                status, reason = "error", type(error).__name__
            answer = result.get("answer", "")
            row = {
                "id": case["id"],
                "repetition": repetition,
                "actor": case["actor"],
                "entry_point": case["entry_point"],
                "risks": case["risks"],
                "status": status,
                "reason": reason,
                "control_denied": denied,
                "model_tokens": provider.tokens,
                "model_calls": provider.calls,
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "observed": observe(
                    case,
                    fixtures,
                    gateway_outputs,
                    answer,
                    result.get("citations", []),
                    result.get("allowed") is True,
                ),
                "task_id": str(task) if task else None,
                "budget_counters": counters,
                "audit_events": [{"id": e[0], "operation": e[1], "reason": e[2]} for e in events],
                "audit_present": bool(events),
                "outputs_sha256": sha(gateway_outputs),
                "answer_sha256": sha(answer),
            }
            rows.append(row)
            report = {
                "variant": "hardened-matched-read-surface",
                "settings": SETTINGS,
                "scope": "Trusted host evaluator; signed gateway and deployed MCP services",
                "fixture_sha256": fingerprint(fixtures),
                "cases_sha256": sha(cases),
                "catalog_sha256": sha([t.wire() for t in TOOLS]),
                "system_sha256": sha(SYSTEM),
                "results": rows,
                "metrics": summarize(rows),
            }
            (args.output / "results.json").write_text(
                json.dumps(report, indent=2, default=str) + "\n"
            )
            print(
                json.dumps(
                    {k: row[k] for k in ["id", "repetition", "status", "reason", "observed"]}
                ),
                flush=True,
            )


if __name__ == "__main__":
    main()
