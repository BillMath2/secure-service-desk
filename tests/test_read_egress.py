"""Reject altered policies and ensure setup failures cannot launch a listener."""

import json
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest

from scripts.read_deployment import firewall_matches
from service_desk import read_bootstrap

HOST = "192.0.2.10"


@pytest.mark.parametrize("service", ["knowledge", "tickets"])
@pytest.mark.parametrize(
    "change",
    ["none", "accept", "family", "priority", "port", "address", "reply", "extra", "missing"],
)
def test_exact_read_policy(service: str, change: str) -> None:
    policy: dict[str, Any] = json.loads(
        (Path(__file__).parent / "fixtures/read-policy.json").read_text()
    )
    policy["nftables"][3]["rule"]["expr"][2]["match"]["right"] = read_bootstrap.PORTS[service]
    chain = policy["nftables"][2]["chain"]
    allowed = policy["nftables"][5]["rule"]
    if change == "accept":
        chain["policy"] = "accept"
    elif change == "family":
        chain["family"] = "ip"
    elif change == "priority":
        chain["prio"] = 0
    elif change == "port":
        allowed["expr"][1]["match"]["right"] = 443
    elif change == "address":
        allowed["expr"][0]["match"]["right"] = "192.0.2.11"
    elif change == "reply":
        policy["nftables"][3]["rule"]["expr"].pop(0)
    elif change == "extra":
        policy["nftables"].append({"rule": {"expr": [{"accept": None}]}})
    elif change == "missing":
        policy["nftables"].pop()
    assert firewall_matches(policy, service, HOST) is (change == "none")


@pytest.mark.parametrize("failure", ["resolve", "install"])
def test_failed_setup_never_launches(monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    resolve, install, launch = Mock(return_value=HOST), Mock(), Mock()
    monkeypatch.setattr("service_desk.read_bootstrap.socket.gethostbyname", resolve)
    monkeypatch.setattr("service_desk.read_bootstrap.subprocess.run", install)
    monkeypatch.setattr("service_desk.read_bootstrap.os.execv", launch)
    if failure == "resolve":
        resolve.side_effect = OSError("unavailable")
    else:
        install.side_effect = subprocess.CalledProcessError(1, "nft")
    with pytest.raises((OSError, subprocess.CalledProcessError)):
        read_bootstrap.launch("knowledge")
    launch.assert_not_called()


def test_privileges_drop_after_policy_install(monkeypatch: pytest.MonkeyPatch) -> None:
    installed = False

    def install(*args: Any, **kwargs: Any) -> None:
        nonlocal installed
        assert args[0] == ["/usr/sbin/nft", "-f", "-"]
        assert kwargs["check"] is True and kwargs["timeout"] == 5
        assert kwargs["input"] == read_bootstrap.rules("tickets", HOST)
        installed = True

    def launch(path: str, arguments: list[str]) -> None:
        assert installed and path == "/usr/bin/setpriv"
        assert arguments == [
            "setpriv",
            "--reuid=65532",
            "--regid=65532",
            "--clear-groups",
            "--bounding-set=-all",
            "--inh-caps=-all",
            "--ambient-caps=-all",
            "--no-new-privs",
            "python",
            "-I",
            "-B",
            "-m",
            "service_desk.read_process",
            "tickets",
            HOST,
        ]

    resolve = Mock(return_value=HOST)
    monkeypatch.setattr("service_desk.read_bootstrap.socket.gethostbyname", resolve)
    monkeypatch.setattr("service_desk.read_bootstrap.subprocess.run", install)
    monkeypatch.setattr("service_desk.read_bootstrap.os.execv", launch)
    read_bootstrap.launch("tickets")
    resolve.assert_called_once_with("host.docker.internal")


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "0.0.0.0", "224.0.0.1", "169.254.169.254", "255.255.255.255", "::1", "x; accept"],
)
def test_reject_unsafe_dependency_address(address: str) -> None:
    with pytest.raises(ValueError):
        read_bootstrap.rules("knowledge", address)
