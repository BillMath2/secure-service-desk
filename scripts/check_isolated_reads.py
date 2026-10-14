"""Inspect scoped read containers, then test real identity, allowed reads and denials."""

import argparse
import hashlib
import json
import shutil
import ssl
import subprocess
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
from check_phase2_identity import LoginForm
from phase2_runtime import LOCAL, ROOT, load_client
from read_deployment import deployment_checks, firewall_matches

from service_desk.core.auth.lab import ISSUER, RESOURCES
from service_desk.core.gateway.dispatch import ReadGateway
from service_desk.core.gateway.store import TaskStore

PROBE = """
import hashlib,json,os,sys
from pathlib import Path
import psycopg
from psycopg.conninfo import make_conninfo
from service_desk.read_process import read_material,FILES
role,host_ip=sys.argv[1:];root=Path('/run/desk')
dsn,identities=read_material(root,role)
dsn=make_conninfo(dsn,hostaddr=host_ip)
lines=Path('/proc/1/status').read_text().splitlines()
status=dict(line.split(':',1) for line in lines if ':' in line)
def inaccessible(path):
 try: Path(path).stat(); return False
 except (FileNotFoundError,PermissionError): return True
checks={
 'own_material_readable': bool(dsn and identities),
 'exact_files': {p.name for p in root.iterdir()}==FILES,
 'unprivileged_process': all(set(status[k].split())=={'65532'} for k in ('Uid','Gid')),
 'no_supplementary_groups': not status['Groups'].strip(),
 'capabilities_empty': all(int(status[k].strip(),16)==0
  for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')),
 'no_new_privileges': status['NoNewPrivs'].strip()=='1',
 'seccomp': status['Seccomp'].strip()=='2',
 'master_and_peer_files_inaccessible': all(inaccessible(p) for p in (
  '/app/.lab','/run/desk/credentials.json','/run/desk/connections.json',
  '/run/desk/publisher.dsn','/run/desk/gateway.dsn','/run/desk/creator.dsn',
  '/run/desk/../knowledge','/run/desk/../tickets','/root/.aws','/var/run/docker.sock')),
 'baseline_absent': not Path('/app/lab_baseline').exists(),
 'entrypoint': Path('/proc/1/cmdline').read_bytes().split(bytes([0]))[:-1]==
  [b'python',b'-I',b'-B',b'-m',b'service_desk.read_process',role.encode(),host_ip.encode()],
}
p=root/'.write-probe'
try:
 with p.open('x') as f: f.write('neutral')
except OSError: checks['secret_mount_read_only']=True
else:
 checks['secret_mount_read_only']=False;p.unlink()
with psycopg.connect(dsn,connect_timeout=3) as db:
 checks['own_login_works']=db.execute('SELECT current_user').fetchone()[0]=='read_'+role
 query="SELECT has_table_privilege(current_user,'service_desk.ticket_comment','INSERT')"
 checks['cannot_insert_comments']=not db.execute(query).fetchone()[0]
tree={str(p.relative_to('/app/src')).replace('\\\\','/'):hashlib.sha256(p.read_bytes()).hexdigest()
 for p in Path('/app/src').rglob('*.py')}
print(json.dumps({'checks':checks,'sources':tree}))
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
            [binary, *arguments], capture_output=True, text=True, timeout=45, check=False
        )
        if result.returncode:
            raise RuntimeError("Container check failed")
        return result.stdout.strip()

    checks: dict[str, bool] = {}
    report: dict[str, Any] = {
        "phase": "3-isolated-reads",
        "checks": checks,
        "passed": False,
        "model_invoked": False,
    }
    stage = "deployment"
    try:
        pin = json.loads((ROOT / "config/isolated-reads.lock.json").read_text())["image_id"]
        image = json.loads(docker("image", "inspect", pin))[0]
        sources = {
            str(p.relative_to(ROOT / "src")).replace("\\", "/"): hashlib.sha256(
                p.read_bytes()
            ).hexdigest()
            for p in (ROOT / "src").rglob("*.py")
        }
        checks["host_admin_material_positive_control"] = all(
            (ROOT / p).is_file() and bool((ROOT / p).read_bytes())
            for p in (
                ".lab/phase2/credentials.json",
                ".lab/phase2-read/connections.json",
                ".lab/phase2/tls/private.key",
            )
        )
        for service in ("knowledge", "tickets"):
            record = json.loads(docker("inspect", "service-desk-phase3-reads-" + service + "-1"))[0]
            checks.update(
                {
                    service + "_" + k: v
                    for k, v in deployment_checks(record, service, image, ROOT).items()
                }
            )
            if not all(checks.values()):
                raise RuntimeError("Deployment gate failed")
            host_ip = docker(
                "run",
                "--rm",
                "--pull=never",
                "--network",
                "service-desk-phase3-reads_" + service,
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--user=65532:65532",
                "--entrypoint=python",
                pin,
                "-I",
                "-B",
                "-c",
                "import socket; print(socket.gethostbyname('host.docker.internal'))",
            )
            checks[service + "_egress_policy_exact"] = firewall_matches(
                json.loads(
                    docker(
                        "exec",
                        record["Id"],
                        "nft",
                        "-j",
                        "list",
                        "table",
                        "inet",
                        "service_desk_read",
                    )
                ),
                service,
                host_ip,
            )
            stage = "filesystem-and-process-" + service
            result = json.loads(
                docker(
                    "exec",
                    "--user",
                    "65532:65532",
                    record["Id"],
                    "python",
                    "-I",
                    "-B",
                    "-c",
                    PROBE,
                    service,
                    host_ip,
                )
            )
            checks.update({service + "_" + k: v for k, v in result["checks"].items()})
            checks[service + "_source_tree_matches"] = result["sources"] == sources
        if not all(checks.values()):
            raise RuntimeError("Isolation checks failed")
        stage = "real-identity-and-reads"
        trust = ssl.create_default_context(cafile=str(LOCAL / "tls/certificate.pem"))
        connections = json.loads((ROOT / ".lab/phase2-read/connections.json").read_text())
        credentials = json.loads((LOCAL / "credentials.json").read_text())
        with httpx.Client(
            verify=trust, trust_env=False, follow_redirects=False, timeout=10
        ) as http:
            oidc = load_client(http, trust)
            oidc.check_discovery()
            gateway = ReadGateway(oidc, TaskStore(connections["gateway"]), http)
            for user in ("erin", "alice"):
                attempt, url = oidc.begin(RESOURCES[0].url)
                with httpx.Client(
                    verify=trust, trust_env=False, follow_redirects=False, timeout=10
                ) as browser:
                    form = LoginForm()
                    form.feed(browser.get(url).text)
                    if not form.action or not form.action.startswith(ISSUER + "/"):
                        raise RuntimeError("Invalid login form")
                    response = browser.post(
                        form.action, data={"username": user, "password": credentials["users"][user]}
                    )
                    if response.status_code != 302:
                        raise RuntimeError("Login failed")
                    query = parse_qs(urlsplit(response.headers["location"]).query)
                login = oidc.finish(attempt, query["state"][0], query["code"][0])
                task = TaskStore(connections["creator"]).create(login.identity, "ticket-alice")
                for name, arguments, allowed in (
                    ("read_document", {"document_id": "doc-public"}, True),
                    ("read_document", {"document_id": "doc-hr"}, False),
                    ("read_ticket", {"ticket_id": "ticket-alice"}, True),
                ):
                    wire = gateway.call(login, task, name, arguments)
                    result = wire if "allowed" in wire else json.loads(wire["content"][0]["text"])
                    checks[user + "_" + next(iter(arguments.values()))] = result.get(
                        "allowed"
                    ) is allowed and (allowed or result.get("reason") == "RESOURCE_DENIED")
                catalog = http.post(
                    RESOURCES[0].url,
                    json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                    headers={"Accept": "application/json, text/event-stream"},
                )
                checks[user + "_unsigned_request_denied"] = catalog.status_code == 401
        report["passed"] = all(checks.values())
    except Exception as error:
        report["error"] = {"stage": stage, "type": type(error).__name__}
    destination = (
        ROOT / "reports/phase3-deployment/runs" / datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    )
    destination.mkdir(parents=True, exist_ok=True)
    report["recorded_at"] = datetime.now(UTC).isoformat()
    report["sources"] = {
        str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in (
            ROOT / "src/service_desk/read_process.py",
            ROOT / "src/service_desk/read_bootstrap.py",
            ROOT / "scripts/read_deployment.py",
            ROOT / "scripts/check_isolated_reads.py",
            ROOT / "infra/compose.phase3-reads.yaml",
            ROOT / "infra/reads.Dockerfile",
        )
    }
    (destination / "isolated-reads.json").write_text(json.dumps(report, indent=2) + "\n")
    print(
        json.dumps(
            {
                "passed": report["passed"],
                "checks": len(checks),
                "report": str(destination.relative_to(ROOT)),
            }
        )
    )
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
