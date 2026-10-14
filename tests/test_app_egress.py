"""Reject broader outbound authority for each distinct application role."""

import json
from pathlib import Path
from typing import Any

import pytest

from scripts.read_deployment import firewall_matches


@pytest.mark.parametrize("role", ["browser", "agent", "publisher"])
@pytest.mark.parametrize(
    "change",
    ["none", "accept", "family", "priority", "port", "address", "reply", "extra", "missing"],
)
def test_application_policy(role: str, change: str) -> None:
    policy: dict[str, Any] = json.loads(
        (Path(__file__).parent / "fixtures" / (role + "-policy.json")).read_text()
    )
    chain = next(e["chain"] for e in policy["nftables"] if "chain" in e)
    rules = [e["rule"] for e in policy["nftables"] if "rule" in e]
    if change == "accept":
        chain["policy"] = "accept"
    elif change == "family":
        chain["family"] = "ip"
    elif change == "priority":
        chain["prio"] = 0
    elif change == "port":
        rules[-1]["expr"][1]["match"]["right"] = 443
    elif change == "address":
        rules[-1]["expr"][0]["match"]["right"] = "192.0.2.11"
    elif change == "reply":
        rules[0]["expr"].pop(0)
    elif change == "extra":
        policy["nftables"].append({"rule": {"expr": [{"accept": None}]}})
    elif change == "missing":
        policy["nftables"].pop()
    assert firewall_matches(policy, role, "192.0.2.10", application=True) is (change == "none")
