"""Read-surface matched v0 experiment inside the existing isolated baseline only."""

import asyncio
import json
import time
from pathlib import Path
from typing import Any

import httpx

from lab_baseline.runner import MCPTools
from scripts.phase5_evaluation import CASE_FILE, SETTINGS, observe, sha, summarize
from service_desk.agent.local_model import LocalModelProvider
from service_desk.agent.loop import SYSTEM
from service_desk.agent.provider import MAX_OUTPUT, AnswerTurn, input_reservation
from service_desk.core.gateway.registry import TOOLS, BoundaryDenied
from service_desk.fixtures import fingerprint, load_fixtures


class ModelTransport(httpx.AsyncBaseTransport):
    """Fixed container destination; no caller-controlled routing."""

    def __init__(self) -> None:
        self.inner = httpx.AsyncHTTPTransport()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        request.url = request.url.copy_with(host="model", port=11434)
        request.headers["host"] = "model:11434"
        return await self.inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self.inner.aclose()


def envelope(name: str, value: dict[str, Any]) -> dict[str, Any]:
    """Normalize only read presentation, never add an authorization check to v0."""
    if name == "read_document":
        ident = value["document_id"]
        return {
            "allowed": True,
            "document": {
                "id": ident,
                "version": value["version"],
                "body": value["body"],
                "citation": f"document:{ident}@{value['version']}",
            },
        }
    if name == "read_ticket":
        ident = value["id"]
        return {
            "allowed": True,
            "ticket": {**value, "version": 1, "comments": [], "citation": f"ticket:{ident}@1"},
        }
    return {
        "allowed": True,
        "documents": [
            {
                **d,
                "id": d["document_id"],
                "version": 1,
                "citation": f"document:{d['document_id']}@1",
            }
            for d in value["documents"]
        ],
    }


async def run() -> None:
    fixtures = load_fixtures(Path("fixtures/company.json"))
    cases = json.loads(Path(CASE_FILE).read_text())
    rows: list[dict[str, Any]] = []
    async with MCPTools() as tools:
        for case in cases:
            outputs: list[dict[str, Any]] = []
            history: list[dict[str, Any]] = []
            final, citations, completed = "", [], False
            tokens, reserved, model_calls = 0, 0, 0
            status, reason = "completed", "completed"
            started = time.monotonic()
            try:
                async with asyncio.timeout(120):
                    provider = LocalModelProvider(transport=ModelTransport())
                    await provider.prepare()
                    for _ in range(8):
                        request = json.dumps(
                            {
                                "system": SYSTEM,
                                "tools": [t.wire() for t in TOOLS],
                                "ticket_id": case["ticket_id"],
                                "question": case["question"],
                                "history": history,
                            },
                            separators=(",", ":"),
                            ensure_ascii=True,
                            allow_nan=False,
                        )
                        reserved += input_reservation(request) + MAX_OUTPUT
                        if reserved > 16000:
                            raise BoundaryDenied("BUDGET_EXHAUSTED")
                        model_calls += 1
                        reply = await provider.generate(request, max_output=MAX_OUTPUT)
                        tokens += reply.input_tokens + reply.output_tokens
                        if isinstance(reply.turn, AnswerTurn):
                            final, citations, completed = (
                                reply.turn.text,
                                reply.turn.citations,
                                True,
                            )
                            break
                        name = reply.turn.name
                        if name not in {t.name for t in TOOLS}:
                            raise BoundaryDenied("TOOL_DENIED")
                        raw = await tools.call(name, reply.turn.arguments)
                        outputs.append(raw)
                        history.append(
                            {"call": reply.turn.model_dump(), "result": envelope(name, raw)}
                        )
                    else:
                        reason = "BUDGET_EXHAUSTED"
            except (TimeoutError, httpx.TimeoutException):
                status, reason = "timeout", "TIMEOUT"
            except BoundaryDenied as error:
                reason = error.reason
                status = "error" if reason == "SERVICE_ERROR" else "completed"
            except Exception:
                status, reason = "error", "PROVIDER_OR_TOOL_ERROR"
            rows.append(
                {
                    "id": case["id"],
                    "actor": case["actor"],
                    "entry_point": case["entry_point"],
                    "risks": case["risks"],
                    "status": status,
                    "reason": reason,
                    "model_tokens": tokens,
                    "model_calls": model_calls,
                    "elapsed_seconds": round(time.monotonic() - started, 3),
                    "control_denied": False,
                    "observed": observe(case, fixtures, outputs, final, citations, completed),
                    "outputs_sha256": sha(outputs),
                    "answer_sha256": sha(final),
                    "audit_scope": "v0 in-memory instrumentation; not durable collector",
                }
            )
            folder = Path("/results/run")
            folder.mkdir(parents=True, exist_ok=True)
            (folder / "results.json").write_text(
                json.dumps(
                    {
                        "variant": "v0-matched-read-surface",
                        "settings": SETTINGS,
                        "fixture_sha256": fingerprint(fixtures),
                        "cases_sha256": sha(cases),
                        "catalog_sha256": sha([t.wire() for t in TOOLS]),
                        "system_sha256": sha(SYSTEM),
                        "results": rows,
                        "metrics": summarize(rows),
                    },
                    indent=2,
                )
                + "\n"
            )


if __name__ == "__main__":
    asyncio.run(run())
