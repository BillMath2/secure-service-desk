"""MCP denial handling must preserve safe control codes without retry or error text."""

import json

import pytest

from service_desk.agent.loop import unpack
from service_desk.core.gateway.registry import BoundaryDenied


@pytest.mark.parametrize("reason", ["POLICY_DENIED", "BUDGET_EXHAUSTED", "RESOURCE_DENIED"])
def test_authenticated_mcp_denial_stops_with_original_code(reason: str) -> None:
    envelope = {
        "isError": True,
        "content": [{"type": "text", "text": json.dumps({"allowed": False, "reason": reason})}],
    }
    with pytest.raises(BoundaryDenied, match="^" + reason + "$"):
        unpack(envelope)


@pytest.mark.parametrize(
    "payload",
    [
        {"allowed": False, "reason": "private provider failure"},
        {"allowed": False, "reason": ["POLICY_DENIED"]},
        {"allowed": True, "reason": "POLICY_DENIED"},
        ["private provider failure"],
    ],
)
def test_malformed_mcp_errors_never_release_arbitrary_error_text(payload: object) -> None:
    with pytest.raises(BoundaryDenied, match="^SERVICE_ERROR$"):
        unpack({"isError": True, "content": [{"type": "text", "text": json.dumps(payload)}]})


def test_successful_mcp_result_is_preserved() -> None:
    result = {"allowed": True, "request_id": "stored-request"}
    assert (
        unpack({"isError": False, "content": [{"type": "text", "text": json.dumps(result)}]})
        == result
    )
