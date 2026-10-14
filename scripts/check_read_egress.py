"""Positive-controlled read egress, including host ports and runtime DNS denial."""

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import uuid
from datetime import UTC, datetime
from typing import Any

from check_model_boundary import PYTHON_IMAGE, ROOT
from check_phase3_egress import TARGET

PROBE = """
import json,socket,sys
target,host,target_name,host_port=sys.argv[1:]
def tcp(address,port,marker=False):
    try:
        with socket.socket() as client:
            client.settimeout(1)
            client.connect((address,port))
            return not marker or client.recv(64)==b'neutral-control'
    except OSError: return False
def udp(address,port,payload):
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
            client.settimeout(1);client.connect((address,port));client.send(payload)
            return bool(client.recv(512))
    except OSError: return False
question=b''.join(bytes([len(p)])+p.encode() for p in target_name.split('.'))
dns=bytes.fromhex('123401000001000000000000')+question+bytes.fromhex('0000010001')
print(json.dumps({
    'other_database':tcp(target,15433,True),
    'other_identity':tcp(target,19443,True),
    'other_destination':tcp(target,11434,True),
    'host_other_port':tcp(host,int(host_port),True),
    'udp':udp(target,53,b'neutral-control'),
    'docker_dns_udp':udp('127.0.0.11',53,dns),
    'docker_dns_tcp':tcp('127.0.0.11',53),
    'allowed_database':tcp(host,15433),
    'allowed_identity':tcp(host,19443),
}))
"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker")
    args = parser.parse_args()
    binary = args.docker or shutil.which("docker")
    if not binary:
        raise SystemExit("Docker executable required")

    def docker(*arguments: str) -> str:
        result = subprocess.run(
            [binary, *arguments], cwd=ROOT, capture_output=True, text=True, timeout=45, check=False
        )
        if result.returncode:
            raise RuntimeError("Read egress probe operation failed")
        return result.stdout.strip()

    checks: dict[str, bool] = {}
    report: dict[str, Any] = {
        "phase": "3-read-egress",
        "checks": checks,
        "passed": False,
        "model_invoked": False,
    }
    stage = "deployment-and-authenticated-reads"
    try:
        gate = subprocess.run(
            [sys.executable, str(ROOT / "scripts/check_isolated_reads.py"), "--docker", binary],
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
        if gate.returncode:
            raise RuntimeError("Read isolation gate failed")
        result = json.loads(gate.stdout)
        checks["isolation_and_authenticated_reads"] = result["passed"] is True
        report["isolation_report"] = result["report"]
        if not all(checks.values()):
            raise RuntimeError("Read isolation gate failed")
        restricted = [
            "--pull=never",
            "--read-only",
            "--user=65532:65532",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--memory=128m",
            "--pids-limit=32",
            "--log-driver=none",
        ]
        for service in ("knowledge", "tickets"):
            stage = "network-" + service
            network = "service-desk-phase3-reads_" + service
            service_id = docker(
                "inspect", "-f", "{{.Id}}", "service-desk-phase3-reads-" + service + "-1"
            )
            host_ip = docker(
                "run",
                "--rm",
                "--network",
                network,
                *restricted,
                PYTHON_IMAGE,
                "python",
                "-I",
                "-B",
                "-c",
                "import socket; print(socket.gethostbyname('host.docker.internal'))",
            )
            name = "service-desk-read-control-" + uuid.uuid4().hex[:12]
            target_id = docker(
                "create",
                "--name",
                name,
                "--network",
                network,
                "-p",
                "127.0.0.1::11434",
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
                address = target["NetworkSettings"]["Networks"][network]["IPAddress"]
                host_port = target["NetworkSettings"]["Ports"]["11434/tcp"][0]["HostPort"]

                def probe(
                    namespace: str,
                    address: str = address,
                    host_ip: str = host_ip,
                    name: str = name,
                    host_port: str = host_port,
                ) -> dict[str, bool]:
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
                                address,
                                host_ip,
                                name,
                                host_port,
                            )
                        )
                    )

                before = probe(network)
                denied = probe("container:" + service_id)
                after = probe(network)
                for key in before:
                    checks[service + "_positive_" + key] = (
                        before[key] is True and after[key] is True
                    )
                    checks[service + "_" + key] = denied[key] is key.startswith("allowed_")
            finally:
                docker("rm", "-f", target_id)
        report["passed"] = all(checks.values())
    except Exception as error:
        report["error"] = {"stage": stage, "type": type(error).__name__}
    report["recorded_at"] = datetime.now(UTC).isoformat()
    report["source_sha256"] = {
        name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
        for name in (
            "src/service_desk/read_bootstrap.py",
            "src/service_desk/read_process.py",
            "scripts/read_deployment.py",
            "scripts/check_read_egress.py",
            "scripts/check_phase3_egress.py",
            "infra/compose.phase3-reads.yaml",
            "infra/reads.Dockerfile",
        )
    }
    destination = (
        ROOT / "reports/phase3-deployment/runs" / datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    )
    destination.mkdir(parents=True, exist_ok=True)
    path = destination / "read-egress.json"
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
