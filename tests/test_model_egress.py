"""The model may answer clients and contact its local runner, but cannot initiate egress."""

import json
from pathlib import Path

import pytest

from scripts.check_model_boundary import model_firewall_matches


@pytest.mark.parametrize(
    "change", ["none", "accept", "dns", "interface", "udp", "reply", "family", "priority", "extra"]
)
def test_exact_model_policy(change: str) -> None:
    policy = json.loads((Path(__file__).parent / "fixtures/model-policy.json").read_text())
    chain = policy["nftables"][2]["chain"]
    loopback = policy["nftables"][4]["rule"]["expr"]
    if change == "accept":
        chain["policy"] = "accept"
    elif change == "dns":
        loopback[0]["match"]["right"] = "127.0.0.11"
    elif change == "interface":
        loopback[1]["match"]["right"] = "eth0"
    elif change == "udp":
        loopback[2]["match"]["right"] = 17
    elif change == "reply":
        policy["nftables"][3]["rule"]["expr"].pop(0)
    elif change == "family":
        chain["family"] = "ip"
    elif change == "priority":
        chain["prio"] = 0
    elif change == "extra":
        policy["nftables"].append({"rule": {"expr": [{"accept": None}]}})
    assert model_firewall_matches(policy) is (change == "none")
