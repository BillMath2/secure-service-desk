"""Inspect actual application credentials, namespaces, privileges, policy and code."""

import argparse
import hashlib
import json
import shutil
import subprocess
from datetime import UTC, datetime
from typing import Any

from check_model_boundary import PYTHON_IMAGE, ROOT
from read_deployment import deployment_checks, firewall_matches

PROBE = """
import hashlib, json, sys
from pathlib import Path
import psycopg
from service_desk.app_process import material, FILES

role, host = sys.argv[1:]
root = Path("/run/desk")
config, identities = material(root, role, host)
status = dict(
    line.split(":", 1) for line in Path("/proc/1/status").read_text().splitlines() if ":" in line
)
checks = {
    "material_valid": bool(config and identities),
    "exact_files": {p.name for p in root.iterdir()} == FILES[role],
    "unprivileged": all(set(status[k].split()) == {"65532"} for k in ("Uid", "Gid")),
    "empty_groups": not status["Groups"].strip(),
    "empty_capabilities": all(
        int(status[k].strip(), 16) == 0 for k in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
    ),
    "no_new_privileges": status["NoNewPrivs"].strip() == "1",
    "seccomp": status["Seccomp"].strip() == "2",
    "command": Path("/proc/1/cmdline").read_bytes().split(bytes([0]))[:-1]
    == [b"python", b"-I", b"-B", b"-m", b"service_desk.app_process", role.encode(), host.encode()],
    "no_host_or_peer_mount": all(
        not Path(p).exists()
        for p in (
            "/app/.lab",
            "/var/run/docker.sock",
            "/app/scripts",
            "/app/lab_baseline",
            "/run/desk/../browser",
            "/run/desk/../agent",
            "/run/desk/../publisher",
            "/run/desk/credentials.json",
            "/run/desk/connections.json",
        )
    ),
}
test = root / ".write-probe"
try:
    with test.open("x") as f:
        f.write("neutral")
except OSError:
    checks["read_only_material"] = True
else:
    checks["read_only_material"] = False
    test.unlink()
for name, value in config.items():
    if name.endswith(".dsn"):
        with psycopg.connect(value, connect_timeout=3) as db:
            checks[name + "_login"] = db.execute("SELECT current_user").fetchone()[0] == {
                "creator.dsn": "read_app", "gateway.dsn": "read_gateway",
                "publisher.dsn": "read_publisher",
            }[name]
            checks[name + "_audit_private"] = not any(
                db.execute(
                    "SELECT has_table_privilege(current_user,'service_desk.read_audit',%s)",
                    (privilege,),
                ).fetchone()[0]
                for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE")
            )
            rows = db.execute(
                "SELECT proname,has_function_privilege(current_user,p.oid,'EXECUTE') "
            "FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace "
            "WHERE n.nspname='service_desk' AND proname IN "
            "('confirm_requester_reply','confirm_internal_comment')"
            ).fetchall()
            checks[name + "_publication_authority"] = len(rows) == 2 and all(
                row[1] is (role == "publisher") for row in rows
            )
if role in ("agent", "browser"):
    checks["real_model_configured"] = json.loads(config["provider.json"]) == {"provider": "local"}
tree = {
    str(p.relative_to("/app/src")): hashlib.sha256(p.read_bytes()).hexdigest()
    for p in Path("/app/src").rglob("*.py")
}
print(json.dumps({"checks": checks, "sources": tree}))

"""


def check_boundary(binary: str) -> dict[str, bool]:
    def docker(*args: str) -> str:
        result = subprocess.run(
            [binary, *args], capture_output=True, text=True, timeout=45, check=False
        )
        if result.returncode:
            raise RuntimeError("Application boundary inspection failed")
        return result.stdout.strip()

    checks: dict[str, bool] = {}
    pin = json.loads((ROOT / "config/isolated-app.lock.json").read_text())["image_id"]
    image = json.loads(docker("image", "inspect", pin))[0]
    sources = {
        p.relative_to(ROOT / "src").as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in (ROOT / "src").rglob("*.py")
    }
    for role in ("browser", "agent", "publisher"):
        record = json.loads(docker("inspect", "service-desk-phase3-app-" + role + "-1"))[0]
        checks.update(
            {
                role + "_" + key: value
                for key, value in deployment_checks(
                    record, role, image, ROOT, application=True
                ).items()
            }
        )
        if not all(checks.values()):
            return checks
        host = docker(
            "run",
            "--rm",
            "--pull=never",
            "--network",
            "service-desk-phase3-app_" + role,
            "--read-only",
            "--cap-drop=ALL",
            "--user=65532:65532",
            "--security-opt=no-new-privileges",
            PYTHON_IMAGE,
            "python",
            "-I",
            "-B",
            "-c",
            "import socket; print(socket.gethostbyname('host.docker.internal'))",
        )
        checks[role + "_policy"] = firewall_matches(
            json.loads(
                docker(
                    "exec", record["Id"], "nft", "-j", "list", "table", "inet", "service_desk_app"
                )
            ),
            role,
            host,
            application=True,
        )
        result = json.loads(
            docker(
                "exec",
                "--user=65532:65532",
                record["Id"],
                "python",
                "-I",
                "-B",
                "-c",
                PROBE,
                role,
                host,
            )
        )
        checks.update({role + "_" + key: value for key, value in result["checks"].items()})
        checks[role + "_source_tree"] = result["sources"] == sources
    return checks


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker")
    args = parser.parse_args()
    binary = args.docker or shutil.which("docker")
    if not binary:
        raise SystemExit("Docker required")
    report: dict[str, Any] = {"passed": False}
    try:
        report["checks"] = check_boundary(binary)
        report["passed"] = all(report["checks"].values())
    except Exception as error:
        report["error"] = type(error).__name__
    report["sources"] = {
        name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
        for name in (
            "scripts/check_app_boundary.py",
            "scripts/read_deployment.py",
            "infra/compose.phase3-app.yaml",
            "src/service_desk/app_process.py",
            "src/service_desk/app_bootstrap.py",
        )
    }
    folder = ROOT / "reports/phase3-deployment/runs" / datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "application.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": report["passed"], "report": str(folder.relative_to(ROOT))}))
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
