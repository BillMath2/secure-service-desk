"""Host-owned deployment gate and model-namespace probes; no fixture content sent."""

import argparse
import hashlib
import json
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PYTHON_IMAGE = (
    "python:3.13.16-slim@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f"
)
MODEL_IMAGE = "sha256:1fd54fb0c2eb0ce358ad8736096fc1c53657e74fc40d0fbbbadf324ba0f348bb"
RELAY_IMAGE = "sha256:69f0328dc75aad42c44b9894961d84d6f700ad359ebdc36a0132c5ecdfe22472"
BOOTSTRAP_CAPS = {"NET_ADMIN", "SETUID", "SETGID", "SETPCAP"}
PROBE = """
import json,socket,sys
host,relay=sys.argv[1:]
def reachable(address,port):
    try:
        with socket.create_connection((address,port),timeout=1): return True
    except OSError: return False
print(json.dumps({
 "model_reachable":reachable("127.0.0.1",11434),
 "external_ip_denied":not reachable("1.1.1.1",443),
 "runtime_dns_denied":not reachable("127.0.0.11",53),
 "host_database_denied":not reachable(host,15433),
 "host_identity_denied":not reachable(host,19443),
 "model_cannot_initiate_relay":not reachable(relay,8080),
}))
"""


def deployment_checks(records: dict[str, Any], network: dict[str, Any]) -> dict[str, bool]:
    """Inspect the complete mount inventory; an extra read-only secret is still forbidden."""
    model, gate, relay = records["model"], records["verify"], records["relay"]
    checks = {
        "model_running": model["State"]["Running"],
        "offline_cache_gate_passed": gate["State"]["Status"] == "exited"
        and gate["State"]["ExitCode"] == 0,
        "images_pinned": model["Config"]["Image"] == MODEL_IMAGE
        and gate["Config"]["Image"] == PYTHON_IMAGE
        and relay["Config"]["Image"] == RELAY_IMAGE
        and relay["Image"] == RELAY_IMAGE
        and model["Image"] == MODEL_IMAGE,
        "model_internal_network_only": network["Internal"]
        and set(model["NetworkSettings"]["Networks"]) == {"service-desk-phase2-model_model"},
        "no_model_host_port": not model["HostConfig"]["PortBindings"],
        "cloud_disabled": "OLLAMA_NO_CLOUD=1" in model["Config"]["Env"],
        "model_cache_read_only": all(
            m["Type"] == "tmpfs"
            or (
                m["Type"] == "volume"
                and m["Name"] == "service-desk-baseline-model"
                and not m["RW"]
                and m["Destination"] == "/models"
            )
            for m in model["Mounts"]
        ),
        "restricted_containers": all(
            c["HostConfig"]["ReadonlyRootfs"]
            and not c["HostConfig"]["Privileged"]
            and (
                {cap.removeprefix("CAP_") for cap in c["HostConfig"].get("CapAdd") or []}
                == BOOTSTRAP_CAPS
                if name in {"relay", "model"}
                else not c["HostConfig"].get("CapAdd")
            )
            and not c["HostConfig"].get("Devices")
            and not c["HostConfig"].get("PidMode")
            and c["HostConfig"].get("IpcMode") == "private"
            and c["Config"]["User"] == ("0:0" if name in {"relay", "model"} else "65532:65532")
            and "ALL" in c["HostConfig"]["CapDrop"]
            and "no-new-privileges:true" in c["HostConfig"]["SecurityOpt"]
            and c["HostConfig"]["LogConfig"]["Type"] == "none"
            for name, c in records.items()
        ),
        "relay_loopback_only": relay["HostConfig"]["PortBindings"]
        == {"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "19485"}]},
    }
    expected_mounts = {
        "model": {"/models": "volume"},
        "verify": {"/models": "volume", "/verify.py": "bind", "/model.lock.json": "bind"},
        "relay": {"/relay.py": "bind"},
    }
    for name, expected in expected_mounts.items():
        mounts = records[name]["Mounts"]
        checks[name + "_mount_inventory"] = (
            {m["Destination"]: m["Type"] for m in mounts} == expected
            and len(mounts) == len(expected)
            and all(
                m["Type"] == "tmpfs"
                or (
                    not m["RW"]
                    and (m["Type"] != "volume" or m.get("Name") == "service-desk-baseline-model")
                )
                for m in mounts
            )
        )
    checks["temporary_mounts_bounded"] = (
        model["HostConfig"].get("Tmpfs") == {"/tmp": "size=512m,mode=1777"}
        and not relay["HostConfig"].get("Tmpfs")
        and not gate["HostConfig"].get("Tmpfs")
    )
    checks["relay_running"] = relay["State"]["Running"]
    checks["relay_command_pinned"] = relay["Config"]["Cmd"] == [
        "python",
        "-I",
        "-B",
        "/bootstrap.py",
    ] and not relay["Config"].get("Entrypoint")
    checks["verifier_command_pinned"] = gate["Config"]["Cmd"] == [
        "python",
        "-B",
        "/verify.py",
    ] and not gate["Config"].get("Entrypoint")
    checks["model_command_pinned"] = not model["Config"]["Cmd"] and model["Config"].get(
        "Entrypoint"
    ) == ["/model-bootstrap.sh"]
    checks["verifier_offline"] = gate["HostConfig"]["NetworkMode"] == "none"
    checks["relay_network_inventory"] = set(relay["NetworkSettings"]["Networks"]) == {
        "service-desk-phase2-model_model",
        "service-desk-phase2-model_ingress",
    }
    checks["relay_resource_bounds"] = (
        0 < relay["HostConfig"]["Memory"] <= 128 * 1024 * 1024
        and 0 < relay["HostConfig"]["PidsLimit"] <= 32
    )
    checks["model_resource_bounds"] = (
        0 < model["HostConfig"]["Memory"] <= 8 * 1024**3
        and 0 < model["HostConfig"]["PidsLimit"] <= 256
        and 0 < model["HostConfig"].get("NanoCpus", 0) <= 4_000_000_000
    )
    return checks


def unprivileged(status: str) -> bool:
    fields = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
    return (
        all(fields.get(key, "").split() == ["65532"] * 4 for key in ("Uid", "Gid"))
        and fields.get("Groups", "missing").strip() == ""
        and all(
            fields.get(key, "").strip() == "0000000000000000"
            for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
        )
        and fields.get("NoNewPrivs", "").strip() == "1"
        and fields.get("Seccomp", "").strip() == "2"
    )


def runtime_checks(status: str, command: list[str], model_ip: str) -> dict[str, bool]:
    return {
        "relay_runtime_unprivileged": unprivileged(status),
        "relay_runtime_command": command == ["python", "-I", "-B", "/relay.py", model_ip],
    }


def firewall_matches(policy: dict[str, Any], model_ip: str) -> bool:
    """Require the complete table, including default deny and both precise exceptions."""

    def match(left: dict[str, Any], right: Any, op: str = "==") -> dict[str, Any]:
        return {"match": {"op": op, "left": left, "right": right}}

    expected = [
        {"table": {"family": "inet", "name": "service_desk_relay"}},
        {
            "chain": {
                "family": "inet",
                "table": "service_desk_relay",
                "name": "output",
                "type": "filter",
                "hook": "output",
                "prio": -150,
                "policy": "drop",
            }
        },
        {
            "rule": {
                "family": "inet",
                "table": "service_desk_relay",
                "chain": "output",
                "expr": [
                    match({"ct": {"key": "direction"}}, "reply"),
                    match({"ct": {"key": "state"}}, "established", "in"),
                    match({"payload": {"protocol": "tcp", "field": "sport"}}, 8080),
                    {"accept": None},
                ],
            }
        },
        {
            "rule": {
                "family": "inet",
                "table": "service_desk_relay",
                "chain": "output",
                "expr": [
                    match({"payload": {"protocol": "ip", "field": "daddr"}}, model_ip),
                    match({"payload": {"protocol": "tcp", "field": "dport"}}, 11434),
                    match({"ct": {"key": "state"}}, {"set": ["established", "new"]}),
                    {"accept": None},
                ],
            }
        },
    ]
    actual = [
        {kind: {key: value for key, value in record.items() if key != "handle"}}
        for entry in policy.get("nftables", [])
        for kind, record in entry.items()
        if kind != "metainfo"
    ]
    return actual == expected


def model_firewall_matches(policy: dict[str, Any]) -> bool:
    def match(left: dict[str, Any], right: Any, op: str = "==") -> dict[str, Any]:
        return {"match": {"op": op, "left": left, "right": right}}

    expected = [
        {"table": {"family": "inet", "name": "service_desk_model"}},
        {
            "chain": {
                "family": "inet",
                "table": "service_desk_model",
                "name": "output",
                "type": "filter",
                "hook": "output",
                "prio": -150,
                "policy": "drop",
            }
        },
        {
            "rule": {
                "family": "inet",
                "table": "service_desk_model",
                "chain": "output",
                "expr": [
                    match({"ct": {"key": "direction"}}, "reply"),
                    match({"ct": {"key": "state"}}, "established", "in"),
                    match({"payload": {"protocol": "tcp", "field": "sport"}}, 11434),
                    {"accept": None},
                ],
            }
        },
        {
            "rule": {
                "family": "inet",
                "table": "service_desk_model",
                "chain": "output",
                "expr": [
                    match({"payload": {"protocol": "ip", "field": "daddr"}}, "127.0.0.1"),
                    match({"meta": {"key": "oifname"}}, "lo"),
                    match({"meta": {"key": "l4proto"}}, 6),
                    {"accept": None},
                ],
            }
        },
    ]
    actual = [
        {kind: {key: value for key, value in record.items() if key != "handle"}}
        for entry in policy.get("nftables", [])
        for kind, record in entry.items()
        if kind != "metainfo"
    ]
    return actual == expected


def check_boundary(docker_path: str | None = None) -> dict[str, bool]:
    binary = docker_path or shutil.which("docker")
    if not binary:
        raise RuntimeError("Docker executable required for model containment checks")

    def docker(*args: str) -> str:
        result = subprocess.run(
            [binary, *args], cwd=ROOT, capture_output=True, text=True, timeout=45, check=False
        )
        if result.returncode:
            raise RuntimeError("Model deployment check failed")
        return result.stdout.strip()

    records = {
        s: json.loads(docker("inspect", "service-desk-phase2-model-" + s + "-1"))[0]
        for s in ("model", "verify", "relay")
    }
    network = json.loads(docker("network", "inspect", "service-desk-phase2-model_model"))[0]
    checks = deployment_checks(records, network)
    relay_image = json.loads(docker("image", "inspect", RELAY_IMAGE))[0]
    checks["relay_environment_pinned"] = (
        records["relay"]["Config"]["Env"] == relay_image["Config"]["Env"]
    )
    model = records["model"]
    model_environment = dict(
        entry.split("=", 1)
        for entry in json.loads(docker("image", "inspect", MODEL_IMAGE))[0]["Config"]["Env"]
    )
    model_environment.update(
        HOME="/tmp",
        OLLAMA_MODELS="/models",
        OLLAMA_HOST="0.0.0.0:11434",
        OLLAMA_NO_CLOUD="1",
        OLLAMA_NUM_PARALLEL="1",
        OLLAMA_MAX_LOADED_MODELS="1",
        OLLAMA_MAX_QUEUE="1",
        OLLAMA_CONTEXT_LENGTH="8192",
    )
    checks["model_environment_pinned"] = sorted(model["Config"]["Env"]) == sorted(
        key + "=" + value for key, value in model_environment.items()
    )
    model_ip = model["NetworkSettings"]["Networks"]["service-desk-phase2-model_model"]["IPAddress"]
    relay_id = records["relay"]["Id"]
    runtime = json.loads(
        docker(
            "exec",
            relay_id,
            "python",
            "-I",
            "-B",
            "-c",
            "import json;from pathlib import Path;print(json.dumps({"
            "'status':Path('/proc/1/status').read_text(),"
            "'command':Path('/proc/1/cmdline').read_bytes().decode().rstrip(chr(0)).split(chr(0))}))",
        )
    )
    checks.update(runtime_checks(runtime["status"], runtime["command"], model_ip))
    checks["relay_egress_policy_exact"] = firewall_matches(
        json.loads(
            docker("exec", relay_id, "nft", "-j", "list", "table", "inet", "service_desk_relay")
        ),
        model_ip,
    )
    checks["relay_bootstrap_matches"] = (
        docker(
            "exec",
            relay_id,
            "python",
            "-I",
            "-B",
            "-c",
            "import hashlib;print(hashlib.sha256(open('/bootstrap.py','rb').read()).hexdigest())",
        )
        == hashlib.sha256((ROOT / "scripts/relay_bootstrap.py").read_bytes()).hexdigest()
    )
    checks["relay_code_matches"] = (
        docker(
            "exec",
            records["relay"]["Id"],
            "python",
            "-B",
            "-c",
            "import hashlib;print(hashlib.sha256(open('/relay.py','rb').read()).hexdigest())",
        )
        == hashlib.sha256((ROOT / "scripts/model_relay.py").read_bytes()).hexdigest()
    )
    checks["model_runtime_unprivileged"] = unprivileged(
        docker("exec", model["Id"], "cat", "/proc/1/status")
    )
    checks["model_runtime_command"] = docker("exec", model["Id"], "cat", "/proc/1/cmdline").rstrip(
        chr(0)
    ).split(chr(0)) == ["/bin/ollama", "serve"]
    checks["model_bootstrap_matches"] = (
        docker("exec", model["Id"], "sha256sum", "/model-bootstrap.sh").split()[0]
        == hashlib.sha256((ROOT / "scripts/model_bootstrap.sh").read_bytes()).hexdigest()
    )
    checks["model_egress_policy_exact"] = model_firewall_matches(
        json.loads(
            docker("exec", model["Id"], "nft", "-j", "list", "table", "inet", "service_desk_model")
        )
    )
    running = docker("ps", "-q").split()
    live = json.loads(docker("inspect", *running)) if running else []
    checks["no_live_cache_writer"] = not any(
        m.get("Name") == "service-desk-baseline-model" and m["RW"]
        for c in live
        for m in c["Mounts"]
    )
    if not all(checks.values()):
        raise RuntimeError("Model deployment check failed")
    host_ip = docker(
        "run",
        "--rm",
        "--pull=never",
        "--network",
        "service-desk-phase2-model_ingress",
        "--read-only",
        "--cap-drop=ALL",
        "--user=65532:65532",
        PYTHON_IMAGE,
        "python",
        "-c",
        "import socket; print(socket.gethostbyname('host.docker.internal'))",
    )
    relay_ip = records["relay"]["NetworkSettings"]["Networks"]["service-desk-phase2-model_model"][
        "IPAddress"
    ]
    raw = docker(
        "run",
        "--rm",
        "--pull=never",
        "--network",
        "container:" + model["Id"],
        "--read-only",
        "--user",
        "65532:65532",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--memory=128m",
        "--pids-limit=32",
        "--log-driver=none",
        PYTHON_IMAGE,
        "python",
        "-B",
        "-c",
        PROBE,
        host_ip,
        relay_ip,
    )
    checks.update(json.loads(raw))
    if not all(checks.values()):
        raise RuntimeError("Model network containment failed")
    return checks


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker")
    args = parser.parse_args()
    checks = check_boundary(args.docker)
    destination = (
        ROOT / "reports/phase3-deployment/runs" / datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    )
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "containment.json").write_text(
        json.dumps({"checks": checks, "passed": True}, indent=2) + "\n"
    )
    print(
        json.dumps(
            {"passed": True, "checks": len(checks), "report": str(destination.relative_to(ROOT))}
        )
    )
