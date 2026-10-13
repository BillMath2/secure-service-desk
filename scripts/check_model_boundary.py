"""Host-owned deployment gate and model-namespace probes; no fixture content sent."""

import argparse
import json
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYTHON_IMAGE = (
    "python:3.13.16-slim@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f"
)
MODEL_IMAGE = (
    "ollama/ollama:0.40.3@sha256:adca95a12c2b386a8f9a995e7fa0600e187e3323b5e5522f5a6c3b1ec73eff99"
)
PROBE = """
import json,socket,urllib.request
def reachable(host,port):
    try:
        with socket.create_connection((host,port),timeout=2): return True
    except OSError: return False
checks={
 "model_reachable":reachable("127.0.0.1",11434),
 "external_ip_denied":not reachable("1.1.1.1",443),
 "external_name_denied":not reachable("example.com",443),
 "host_database_denied":not reachable("host.docker.internal",15433),
 "host_identity_denied":not reachable("host.docker.internal",19443),
}
try:
    urllib.request.urlopen(urllib.request.Request("http://relay:8080/api/pull",data=b'{}'),timeout=3)
    checks["relay_cannot_download_models"]=False
except urllib.error.HTTPError as e: checks["relay_cannot_download_models"]=e.code==404
print(json.dumps(checks))
"""


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
    model, gate, relay = records["model"], records["verify"], records["relay"]
    network = json.loads(docker("network", "inspect", "service-desk-phase2-model_model"))[0]
    checks = {
        "model_running": model["State"]["Running"],
        "offline_cache_gate_passed": gate["State"]["Status"] == "exited"
        and gate["State"]["ExitCode"] == 0,
        "images_pinned": model["Config"]["Image"] == MODEL_IMAGE
        and all(records[s]["Config"]["Image"] == PYTHON_IMAGE for s in ("verify", "relay")),
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
            and c["Config"]["User"] == "65532:65532"
            and "ALL" in c["HostConfig"]["CapDrop"]
            and "no-new-privileges:true" in c["HostConfig"]["SecurityOpt"]
            and c["HostConfig"]["LogConfig"]["Type"] == "none"
            for c in records.values()
        ),
        "relay_loopback_only": relay["HostConfig"]["PortBindings"]
        == {"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "19485"}]},
    }
    running = docker("ps", "-q").split()
    live = json.loads(docker("inspect", *running)) if running else []
    checks["no_live_cache_writer"] = not any(
        m.get("Name") == "service-desk-baseline-model" and m["RW"]
        for c in live
        for m in c["Mounts"]
    )
    if not all(checks.values()):
        raise RuntimeError("Model deployment check failed")
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
    destination = ROOT / "reports/phase2-model/runs" / datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "containment.json").write_text(
        json.dumps({"checks": checks, "passed": True}, indent=2) + "\n"
    )
    print(
        json.dumps(
            {"passed": True, "checks": len(checks), "report": str(destination.relative_to(ROOT))}
        )
    )
