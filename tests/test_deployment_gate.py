"""A container can be read-only and still expose secrets through unexpected mounts."""

from typing import Any

import pytest

from scripts.check_model_boundary import (
    BOOTSTRAP_CAPS,
    MODEL_IMAGE,
    PYTHON_IMAGE,
    RELAY_IMAGE,
    deployment_checks,
)


def records() -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name in ("model", "verify", "relay"):
        result[name] = {
            "State": {"Running": name != "verify", "Status": "exited", "ExitCode": 0},
            "Config": {
                "Image": MODEL_IMAGE if name == "model" else PYTHON_IMAGE,
                "User": "65532:65532",
                "Env": ["OLLAMA_NO_CLOUD=1"],
                "Cmd": ["serve"] if name == "model" else ["python", "-B", f"/{name}.py"],
                "Entrypoint": ["/bin/ollama"] if name == "model" else None,
            },
            "HostConfig": {
                "ReadonlyRootfs": True,
                "Privileged": False,
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges:true"],
                "LogConfig": {"Type": "none"},
                "PortBindings": {},
                "NetworkMode": "none" if name == "verify" else "bridge",
                "Memory": 128 * 1024 * 1024,
                "PidsLimit": 32,
                "IpcMode": "private",
                "Tmpfs": {"/tmp": "size=512m,mode=1777"} if name == "model" else {},
            },
            "NetworkSettings": {"Networks": {"service-desk-phase2-model_model": {}}},
            "Mounts": [],
        }
    cache = {
        "Type": "volume",
        "Destination": "/models",
        "RW": False,
        "Name": "service-desk-baseline-model",
    }
    result["model"]["Mounts"] = [dict(cache)]
    result["verify"]["Mounts"] = [
        dict(cache),
        {"Type": "bind", "Destination": "/verify.py", "RW": False},
        {"Type": "bind", "Destination": "/model.lock.json", "RW": False},
    ]
    result["relay"]["Mounts"] = [{"Type": "bind", "Destination": "/relay.py", "RW": False}]
    result["relay"]["HostConfig"]["PortBindings"] = {
        "8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "19485"}]
    }
    result["relay"]["NetworkSettings"]["Networks"]["service-desk-phase2-model_ingress"] = {}
    result["relay"]["Image"] = RELAY_IMAGE
    result["relay"]["Config"].update(
        Image=RELAY_IMAGE, User="0:0", Cmd=["python", "-I", "-B", "/bootstrap.py"]
    )
    result["relay"]["HostConfig"]["CapAdd"] = sorted(BOOTSTRAP_CAPS)
    result["model"]["Image"] = MODEL_IMAGE
    result["model"]["Config"].update(User="0:0", Cmd=[], Entrypoint=["/model-bootstrap.sh"])
    result["model"]["HostConfig"]["CapAdd"] = sorted(BOOTSTRAP_CAPS)
    result["model"]["HostConfig"].update(Memory=8 * 1024**3, PidsLimit=256, NanoCpus=4_000_000_000)
    return result


def test_expected_deployment_passes() -> None:
    assert all(deployment_checks(records(), {"Internal": True}).values())


@pytest.mark.parametrize("limit", ["Memory", "PidsLimit", "NanoCpus"])
def test_unbounded_model_is_denied(limit: str) -> None:
    containers = records()
    containers["model"]["HostConfig"][limit] = 0
    assert not deployment_checks(containers, {"Internal": True})["model_resource_bounds"]


@pytest.mark.parametrize("service", ["model", "relay", "verify"])
def test_extra_read_only_secret_mount_is_denied(service: str) -> None:
    containers = records()
    containers[service]["Mounts"].append(
        {"Type": "bind", "Destination": "/run/secrets/publisher.dsn", "RW": False}
    )
    assert not deployment_checks(containers, {"Internal": True})[service + "_mount_inventory"]


@pytest.mark.parametrize(
    "change", ["writable", "capability", "pid", "entrypoint", "network", "queue", "tmpfs"]
)
def test_relaxed_relay_configuration_is_denied(change: str) -> None:
    containers = records()
    relay = containers["relay"]
    if change == "writable":
        relay["Mounts"][0]["RW"] = True
    elif change == "capability":
        relay["HostConfig"]["CapAdd"] = ["NET_ADMIN"]
    elif change == "pid":
        relay["HostConfig"]["PidMode"] = "host"
    elif change == "entrypoint":
        relay["Config"]["Entrypoint"] = ["sh", "-c"]
    elif change == "network":
        relay["NetworkSettings"]["Networks"]["private-database"] = {}
    elif change == "queue":
        relay["HostConfig"]["PidsLimit"] = 0
    else:
        relay["HostConfig"]["Tmpfs"] = {"/tmp": "size=4g"}
    assert not all(deployment_checks(containers, {"Internal": True}).values())
