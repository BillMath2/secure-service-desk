"""Positive-controlled relay egress checks with disposable neutral TCP/UDP responders."""

import argparse
import hashlib
import json
import shutil
import subprocess
import uuid
from datetime import UTC, datetime
from typing import Any

from check_model_boundary import PYTHON_IMAGE, ROOT, check_boundary

TARGET = """
import socket,threading,time
def serve(port,kind):
    with socket.socket(socket.AF_INET,kind) as server:
        server.bind(('0.0.0.0',port))
        if kind==socket.SOCK_STREAM:
            server.listen(8)
            while True:
                client,_=server.accept()
                with client: client.sendall(b'neutral-control')
        else:
            while True:
                _,peer=server.recvfrom(512)
                server.sendto(b'neutral-control',peer)
for port in (11434,15433,19443):
    threading.Thread(target=serve,args=(port,socket.SOCK_STREAM),daemon=True).start()
threading.Thread(target=serve,args=(53,socket.SOCK_DGRAM),daemon=True).start()
while True: time.sleep(60)
"""
PROBE = """
import json,socket,sys
target,model,target_name=sys.argv[1:]
def tcp(host,port,marker=False):
    try:
        with socket.create_connection((host,port),timeout=1) as client:
            return not marker or client.recv(64)==b'neutral-control'
    except OSError: return False
def udp(host,port,payload):
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
            client.settimeout(1)
            client.connect((host,port))
            client.send(payload)
            return bool(client.recv(512))
    except OSError: return False
question=b''.join(bytes([len(part)])+part.encode() for part in target_name.split('.'))
dns=bytes.fromhex('123401000001000000000000')+question+bytes.fromhex('0000010001')
print(json.dumps({
    'other_model_port':tcp(target,11434,True),
    'database_port':tcp(target,15433,True),
    'identity_port':tcp(target,19443,True),
    'udp':udp(target,53,b'neutral-control'),
    'docker_dns_udp':udp('127.0.0.11',53,dns),
    'docker_dns_tcp':tcp('127.0.0.11',53),
    'allowed_model':tcp(model,11434),
}))
"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker")
    args = parser.parse_args()
    binary = args.docker or shutil.which("docker")
    if not binary:
        raise RuntimeError("Docker executable required")

    def docker(*arguments: str) -> str:
        result = subprocess.run(
            [binary, *arguments],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=45,
            check=False,
        )
        if result.returncode:
            raise RuntimeError("Relay egress probe setup failed")
        return result.stdout.strip()

    checks = check_boundary(binary)
    relay_id = docker("inspect", "-f", "{{.Id}}", "service-desk-phase2-model-relay-1")
    model = json.loads(docker("inspect", "service-desk-phase2-model-model-1"))[0]
    model_ip = model["NetworkSettings"]["Networks"]["service-desk-phase2-model_model"]["IPAddress"]
    network = "service-desk-phase2-model_ingress"
    restricted = [
        "--pull=never",
        "--read-only",
        "--user",
        "65532:65532",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--memory=128m",
        "--pids-limit=32",
        "--log-driver=none",
    ]
    target_name = "service-desk-egress-control-" + uuid.uuid4().hex[:12]
    target_id = docker(
        "create",
        "--name",
        target_name,
        "--network",
        network,
        *restricted,
        PYTHON_IMAGE,
        "python",
        "-I",
        "-B",
        "-c",
        TARGET,
    )
    try:
        docker("start", target_id)
        target = json.loads(docker("inspect", target_id))[0]
        target_ip = target["NetworkSettings"]["Networks"][network]["IPAddress"]

        def probe(namespace: str) -> dict[str, Any]:
            return dict(
                json.loads(
                    docker(
                        "run",
                        "--rm",
                        "--network",
                        namespace,
                        *restricted,
                        PYTHON_IMAGE,
                        "python",
                        "-I",
                        "-B",
                        "-c",
                        PROBE,
                        target_ip,
                        model_ip,
                        target_name,
                    )
                )
            )

        before = probe(network)
        denied = probe("container:" + relay_id)
        after = probe(network)
        for name in before:
            if name == "allowed_model":
                checks["relay_allowed_model_reachable"] = denied[name] is True
                continue
            checks["positive_control_" + name] = before[name] is True and after[name] is True
            checks["relay_denied_" + name] = denied[name] is False
    finally:
        docker("rm", "-f", target_id)

    files = [
        "scripts/model_relay.py",
        "scripts/relay_bootstrap.py",
        "infra/relay.Dockerfile",
        "scripts/check_model_boundary.py",
        "scripts/check_phase3_egress.py",
        "infra/compose.phase2-model.yaml",
    ]
    report = {
        "phase": "3-relay-egress",
        "recorded_at": datetime.now(UTC).isoformat(),
        "checks": checks,
        "passed": all(checks.values()),
        "source_sha256": {
            name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in files
        },
        "scope": "Neutral TCP/UDP controls reachable from an unfiltered ingress peer before "
        "and after attempts from the relay network namespace. Includes a different destination "
        "on model port 11434, simulated database/identity ports, UDP 53 and Docker DNS over "
        "TCP/UDP. These are synthetic responders, not the actual database/identity services. "
        "IPv6 denial is policy-inspected only. No ticket content or model task was sent. "
        "Host application credential separation and other ingress limits remain open.",
    }
    destination = (
        ROOT / "reports/phase3-deployment/runs" / datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    )
    destination.mkdir(parents=True, exist_ok=True)
    path = destination / "egress.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    print(
        json.dumps(
            {
                "passed": report["passed"],
                "checks": len(checks),
                "report": str(path.relative_to(ROOT)),
            }
        )
    )
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
