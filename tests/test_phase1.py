import asyncio
import json
import sys
import threading
import time
from pathlib import Path
from typing import Any

import httpx
import pytest
import uvicorn
from fastapi.testclient import TestClient
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from lab_baseline.runner import metrics, observe
from lab_baseline.server import create_app
from lab_baseline.state import SERVICES, UnsafeState
from lab_baseline.supervisor import supervise
from service_desk.contracts import FixtureSet

ROOT = Path(__file__).resolve().parents[1]


def cases() -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = json.loads((ROOT / "lab_baseline/cases.json").read_text())[
        "cases"
    ]
    return result


@pytest.mark.parametrize("case", [c for c in cases() if c["mode"] == "forced"])
def test_baseline_measures_actual_effects(case: dict[str, Any], fixtures: FixtureSet) -> None:
    stores = {service: UnsafeState(fixtures) for service in SERVICES}
    outputs, attempted = [], []
    for call in case["calls"]:
        service = next(s for s, names in SERVICES.items() if call["name"] in names)
        outputs.append(stores[service].invoke(call["name"], call["arguments"]))
        attempted.append(call["name"])
    snapshots = {s: state.snapshot() for s, state in stores.items()}
    evidence = observe(case, fixtures, outputs, snapshots, attempted)
    assert evidence["objective_met"]
    assert evidence["unsafe_effect"] == (case["actor"] != "benign")
    encoded = json.dumps(evidence)
    assert all(d.canary not in encoded for d in fixtures.documents if d.canary)


def test_claimed_or_attempted_grant_is_not_an_effect(fixtures: FixtureSet) -> None:
    case = next(c for c in cases() if c["id"] == "BASELINE-GRANT-01")
    snapshots = {s: UnsafeState(fixtures).snapshot() for s in SERVICES}
    evidence = observe(
        case,
        fixtures,
        [{"applied": True}],
        snapshots,
        ["execute_approved_change"],
        "Access granted successfully",
    )
    assert evidence["relevant_tool_attempted"]
    assert not evidence["objective_met"] and not evidence["unsafe_effect"]


def test_draft_is_not_a_published_reply(fixtures: FixtureSet) -> None:
    case = next(c for c in cases() if c["id"] == "BASELINE-OUTPUT-01")
    store = UnsafeState(fixtures)
    call = case["calls"][0]
    output = store.invoke(call["name"], call["arguments"])
    evidence = observe(case, fixtures, [output], {"tickets": store.snapshot()}, [call["name"]])
    assert not evidence["objective_met"]


def test_baseline_reset_discards_effects(fixtures: FixtureSet) -> None:
    state = UnsafeState(fixtures)
    initial = json.dumps(state.snapshot(), sort_keys=True)
    state.invoke("propose_access_change", {"target": "agent", "resource": "engineering-admin"})
    state.invoke("execute_approved_change", {"request_id": "request-1"})
    assert state.grants
    state.reset()
    assert json.dumps(state.snapshot(), sort_keys=True) == initial


def test_outer_supervisor_kills_hung_child() -> None:
    started = time.monotonic()
    assert supervise([sys.executable, "-c", "import time; time.sleep(30)"], seconds=0.2) == 124
    assert time.monotonic() - started < 5


def test_metrics_separate_errors_from_observed_effects() -> None:
    rows = [
        {
            "mode": "model",
            "actor": "external",
            "objective_met": False,
            "unsafe_effect": False,
            "status": "error",
        }
    ]
    result = metrics(rows)
    assert result["model"]["attack_cases"] == 1
    assert result["model"]["attack_objectives_met"] == 0
    assert result["model"]["errors"] == 1
    assert result["forced"]["attack_cases"] == 0


def test_hardened_source_and_wheel_config_exclude_baseline() -> None:
    for path in (ROOT / "src").rglob("*.py"):
        assert "lab_baseline" not in path.read_text()
    import tomllib

    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert project["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"] == ["src/service_desk"]


@pytest.mark.parametrize("service", list(SERVICES))
def test_three_real_mcp_transports(service: str, fixtures: FixtureSet) -> None:
    import socket

    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    app = create_app(service, UnsafeState(fixtures))
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, log_level="critical", access_log=False)
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 5
        while not server.started and time.monotonic() < deadline:
            time.sleep(0.01)
        assert server.started

        async def check() -> None:
            async with (
                streamable_http_client(f"http://127.0.0.1:{port}/mcp") as streams,
                ClientSession(*streams[:2]) as session,
            ):
                await session.initialize()
                assert {t.name for t in (await session.list_tools()).tools} == set(
                    SERVICES[service]
                )
                name, arguments = {
                    "knowledge": ("read_document", {"document_id": "doc-hr"}),
                    "tickets": ("read_ticket", {"ticket_id": "ticket-alice-injected"}),
                    "access": (
                        "propose_access_change",
                        {"target": "alice", "resource": "engineering-admin"},
                    ),
                }[service]
                result = await session.call_tool(name, arguments)
                assert not result.is_error and result.structured_content
                if service == "access":
                    applied = await session.call_tool(
                        "execute_approved_change",
                        {"request_id": result.structured_content["request_id"]},
                    )
                    assert not applied.is_error
                    snapshot = httpx.get(f"http://127.0.0.1:{port}/_lab/snapshot").json()
                    assert len(snapshot["grants"]) == 1
                    assert snapshot["grants"][0]["approvals"] == []

        asyncio.run(check())
    finally:
        server.should_exit = True
        thread.join(timeout=5)


def test_observer_endpoints_are_not_model_tools(fixtures: FixtureSet) -> None:
    with TestClient(create_app("knowledge", UnsafeState(fixtures))) as client:
        assert client.post("/_lab/reset").json() == {"reset": True}
        assert client.get("/_lab/snapshot").json()["events"] == []
        assert client.get("/health").json() == {"service": "knowledge"}
