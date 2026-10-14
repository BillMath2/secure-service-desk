"""Positive-controlled IPv4 service route, alternate destination and DNS matrix."""

import argparse
import hashlib
import json
import subprocess
import sys
import uuid
from datetime import UTC, datetime
from typing import Any

from check_model_boundary import PYTHON_IMAGE, ROOT
from check_model_boundary import check_boundary as model_boundary
from check_phase3_egress import TARGET
from check_phase4_boundary import check_boundary as app_boundary

from service_desk.phase4_layout import OUTBOUND, PORTS

HOST_PORTS = (15433, 19443, 19482, 19483, 19485, 19487, *PORTS.values())
PROBE = """
import json,socket,sys
target,host,name,host_port,ports=sys.argv[1:]
def tcp(address,port,marker=False):
 try:
  with socket.create_connection((address,port),timeout=1) as c:
   return not marker or c.recv(64)==b'neutral-control'
 except OSError: return False
def udp(address,payload):
 try:
  with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as c:
   c.settimeout(1);c.connect((address,53));c.send(payload);return bool(c.recv(512))
 except OSError: return False
question=b''.join(bytes([len(p)])+p.encode() for p in name.split('.'))
dns=bytes.fromhex('123401000001000000000000')+question+bytes.fromhex('0000010001')
result={
 'other_database':tcp(target,15433,True),'other_identity':tcp(target,19443,True),
 'other_destination':tcp(target,11434,True),'host_other_port':tcp(host,int(host_port),True),
 'udp':udp(target,b'neutral-control'),'dns_udp':udp('127.0.0.11',dns),
 'dns_tcp':tcp('127.0.0.11',53),
}
result.update({str(port):tcp(host,port) for port in json.loads(ports)})
print(json.dumps(result))
"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker", required=True)
    args = parser.parse_args()

    def docker(*argv: str) -> str:
        result = subprocess.run(
            [args.docker, *argv], capture_output=True, text=True, timeout=45, check=False
        )
        if result.returncode:
            raise RuntimeError("Network matrix operation failed")
        return result.stdout.strip()

    checks: dict[str, bool] = {}
    report: dict[str, Any] = {
        "phase": "4-network-matrix",
        "checks": checks,
        "passed": False,
        "model_invoked": False,
        "ipv6": "policy inspection only",
    }
    stage = "deployment"
    try:
        checks["application_gate"] = all(app_boundary(args.docker).values())
        checks["model_gate"] = all(model_boundary(args.docker).values())
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts/check_isolated_reads.py"),
                "--docker",
                args.docker,
            ],
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
        checks["reads_gate"] = result.returncode == 0
        if not all(checks.values()):
            raise RuntimeError("Deployment gate failed")
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
        roles = [(role, "phase4", role, set(OUTBOUND[role])) for role in OUTBOUND]
        roles += [("publisher", "phase3-app", "publisher", {15433, 19443})]
        roles += [(role, "phase3-reads", role, {15433, 19443}) for role in ("knowledge", "tickets")]
        roles += [(role, "phase2-model", "ingress", set()) for role in ("relay", "model")]
        for role, project, network_name, allowed in roles:
            stage = role
            network = "service-desk-" + project + "_" + network_name
            container = "service-desk-" + project + "-" + role + "-1"
            host = docker(
                "run",
                "--rm",
                "--network",
                network,
                *restricted,
                PYTHON_IMAGE,
                "python",
                "-c",
                "import socket; print(socket.gethostbyname('host.docker.internal'))",
            )
            name = "service-desk-matrix-" + uuid.uuid4().hex[:12]
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
                port = target["NetworkSettings"]["Ports"]["11434/tcp"][0]["HostPort"]
                snapshots = []
                for namespace in (network, "container:" + container, network):
                    snapshots.append(
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
                                host,
                                name,
                                port,
                                json.dumps(HOST_PORTS),
                            )
                        )
                    )
                before, restricted_result, after = snapshots
                for key, value in restricted_result.items():
                    checks[role + "_positive_" + key] = before[key] is True and after[key] is True
                    checks[role + "_policy_" + key] = value is (
                        key.isdigit() and int(key) in allowed
                    )
            finally:
                docker("rm", "-f", target_id)
        report["passed"] = all(checks.values())
    except Exception as error:
        report["error"] = {"stage": stage, "type": type(error).__name__}
    report["source_sha256"] = {
        name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
        for name in (
            "scripts/check_phase4_network.py",
            "scripts/check_model_boundary.py",
            "scripts/check_phase4_boundary.py",
            "scripts/check_isolated_reads.py",
            "scripts/check_phase3_egress.py",
            "scripts/model_bootstrap.sh",
            "infra/compose.phase4.yaml",
            "infra/compose.phase3-reads.yaml",
            "infra/compose.phase2-model.yaml",
        )
    }
    folder = ROOT / "reports/phase4/runs" / datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "network-matrix.json").write_text(json.dumps(report, indent=2) + "\n")
    print(
        json.dumps(
            {
                "passed": report["passed"],
                "checks": len(checks),
                "report": str(folder.relative_to(ROOT)),
            }
        )
    )
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
