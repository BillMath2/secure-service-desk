"""Reject extra read-service authority even when an added mount is read-only."""

from pathlib import Path
from typing import Any

import pytest

from scripts.read_deployment import deployment_checks


def record(root: Path) -> dict[str, Any]:
    return {
        "State": {"Running": True},
        "Image": "sha256:pinned",
        "Config": {
            "Image": "sha256:pinned",
            "Env": [],
            "User": "0:0",
            "Entrypoint": ["python", "-I", "-B", "-m", "service_desk.read_bootstrap"],
            "Cmd": ["knowledge"],
        },
        "HostConfig": {
            "Privileged": False,
            "CapAdd": ["NET_ADMIN", "SETUID", "SETGID", "SETPCAP"],
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "PidMode": "",
            "IpcMode": "private",
            "ReadonlyRootfs": True,
            "Memory": 256 * 1024 * 1024,
            "PidsLimit": 64,
            "NanoCpus": 1000000000,
            "LogConfig": {"Type": "none"},
            "PortBindings": {"19482/tcp": [{"HostIp": "127.0.0.1", "HostPort": "19482"}]},
        },
        "Mounts": [
            {
                "Type": "bind",
                "Destination": "/run/desk",
                "RW": False,
                "Source": str(root / ".lab/phase3-reads/knowledge"),
            }
        ],
        "NetworkSettings": {"Networks": {"service-desk-phase3-reads_knowledge": {}}},
    }


@pytest.mark.parametrize(
    "change",
    [
        "none",
        "extra_mount",
        "wrong_mount",
        "writable",
        "env",
        "pid",
        "root",
        "image",
        "command",
        "port",
        "network",
        "caps",
        "limits",
    ],
)
def test_exact_deployment_inventory(tmp_path: Path, change: str) -> None:
    value = record(tmp_path)
    if change == "extra_mount":
        value["Mounts"].append(
            {"Type": "bind", "Destination": "/other", "RW": False, "Source": "/secrets"}
        )
    elif change == "wrong_mount":
        value["Mounts"][0]["Source"] = str(tmp_path / ".lab/phase3-reads/tickets")
    elif change == "writable":
        value["Mounts"][0]["RW"] = True
    elif change == "env":
        value["Config"]["Env"] = ["PRIVATE=value"]
    elif change == "pid":
        value["HostConfig"]["PidMode"] = "host"
    elif change == "root":
        value["Config"]["User"] = "65532:65532"
    elif change == "image":
        value["Image"] = "sha256:other"
    elif change == "command":
        value["Config"]["Cmd"] = ["tickets"]
    elif change == "port":
        value["HostConfig"]["PortBindings"]["19482/tcp"][0]["HostIp"] = "0.0.0.0"
    elif change == "network":
        value["NetworkSettings"]["Networks"]["other"] = {}
    elif change == "caps":
        value["HostConfig"]["CapAdd"] = ["SYS_ADMIN"]
    elif change == "limits":
        value["HostConfig"]["Memory"] = 0
    checks = deployment_checks(
        value, "knowledge", {"Id": "sha256:pinned", "Config": {"Env": []}}, tmp_path
    )
    assert all(checks.values()) is (change == "none")
