"""Fail closed on firewall setup errors, relaxed rules or retained runtime privileges."""

import json
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest

from scripts import relay_bootstrap
from scripts.check_model_boundary import firewall_matches, runtime_checks

MODEL_IP = "192.0.2.10"


def policy() -> dict[str, Any]:
    return dict(json.loads((Path(__file__).parent / "fixtures/relay-policy.json").read_text()))


def test_observed_policy_matches() -> None:
    assert firewall_matches(policy(), MODEL_IP)


@pytest.mark.parametrize(
    "change", ["accept", "family", "priority", "port", "address", "reply", "extra", "missing"]
)
def test_relaxed_policy_rejected(change: str) -> None:
    value = policy()
    chain = value["nftables"][2]["chain"]
    reply = value["nftables"][3]["rule"]
    model = value["nftables"][4]["rule"]
    if change == "accept":
        chain["policy"] = "accept"
    elif change == "family":
        chain["family"] = "ip"
    elif change == "priority":
        chain["prio"] = 0
    elif change == "port":
        model["expr"][1]["match"]["right"] = 443
    elif change == "address":
        model["expr"][0]["match"]["right"] = "192.0.2.11"
    elif change == "reply":
        reply["expr"].pop(0)
    elif change == "extra":
        value["nftables"].append({"rule": {"expr": [{"accept": None}]}})
    else:
        value["nftables"].pop()
    assert not firewall_matches(value, MODEL_IP)


def status() -> dict[str, str]:
    return {
        "Uid": "65532 65532 65532 65532",
        "Gid": "65532 65532 65532 65532",
        "Groups": "",
        "CapInh": "0000000000000000",
        "CapPrm": "0000000000000000",
        "CapEff": "0000000000000000",
        "CapBnd": "0000000000000000",
        "CapAmb": "0000000000000000",
        "NoNewPrivs": "1",
        "Seccomp": "2",
    }


@pytest.mark.parametrize(
    "field",
    [
        "Uid",
        "Gid",
        "Groups",
        "CapInh",
        "CapPrm",
        "CapEff",
        "CapBnd",
        "CapAmb",
        "NoNewPrivs",
        "Seccomp",
        "command",
        "none",
    ],
)
def test_runtime_privileges_and_command_checked(field: str) -> None:
    fields = status()
    command = ["python", "-I", "-B", "/relay.py", MODEL_IP]
    if field == "command":
        command[-1] = "192.0.2.11"
    elif field != "none":
        fields[field] = "0" if field in {"NoNewPrivs", "Seccomp"} else "1"
    checks = runtime_checks("\n".join(f"{k}:\t{v}" for k, v in fields.items()), command, MODEL_IP)
    assert all(checks.values()) is (field == "none")


@pytest.mark.parametrize("failure", ["resolve", "install"])
def test_bootstrap_failure_never_launches_listener(
    monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    resolve = Mock(return_value=MODEL_IP)
    install = Mock()
    launch = Mock()
    monkeypatch.setattr("scripts.relay_bootstrap.socket.gethostbyname", resolve)
    monkeypatch.setattr("scripts.relay_bootstrap.subprocess.run", install)
    monkeypatch.setattr("scripts.relay_bootstrap.os.execv", launch)
    if failure == "resolve":
        resolve.side_effect = OSError("unavailable")
    else:
        install.side_effect = subprocess.CalledProcessError(1, "nft")
    with pytest.raises((OSError, subprocess.CalledProcessError)):
        relay_bootstrap.main()
    launch.assert_not_called()


@pytest.mark.parametrize("address", ["127.0.0.1", "0.0.0.0", "224.0.0.1", "::1", "model; accept"])
def test_bootstrap_rejects_invalid_destination(address: str) -> None:
    with pytest.raises(ValueError):
        relay_bootstrap.rules(address)
