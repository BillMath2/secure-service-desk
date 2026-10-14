"""Verify actual role inventories, running privilege, executable code and outbound policies."""

import argparse
import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from check_app_boundary import PROBE as PUBLISHER_PROBE
from check_model_boundary import PYTHON_IMAGE, ROOT, unprivileged
from read_deployment import deployment_checks as publisher_checks
from read_deployment import firewall_matches

from service_desk.phase4_layout import OUTBOUND, PORTS

PROBE = """
import hashlib, json, sys
from pathlib import Path
import psycopg
from service_desk.phase4_process import material
from service_desk.phase4_layout import FILES, LOGINS

role, host = sys.argv[1:]
root = Path("/run/desk")
config, identities = material(root, role, host)
checks = {
    "material": bool(config and identities),
    "files": {p.name for p in root.iterdir()} == FILES[role],
    "no_host_mount": all(
        not Path(p).exists()
        for p in (
            "/app/.lab",
            "/app/scripts",
            "/app/lab_baseline",
            "/var/run/docker.sock",
            "/run/desk/credentials.json",
            "/run/desk/connections.json",
        )
    ),
}
try:
    with (root / ".probe").open("x") as f:
        f.write("neutral")
except OSError:
    checks["read_only"] = True
else:
    checks["read_only"] = False
    (root / ".probe").unlink()
for name, dsn in config.items():
    if not name.endswith(".dsn"):
        continue
    with psycopg.connect(dsn, connect_timeout=3) as db:
        checks[name + "_login"] = (
            db.execute("SELECT current_user").fetchone()[0] == LOGINS[name[:-4]]
        )
        funcs = {
            "access_execute": role == "execution",
            "access_confirm": role == "workflow",
            "access_reconcile": role == "worker",
            "audit_accept": role == "collector",
        }
        for function, expected in funcs.items():
            rows = db.execute(
                "SELECT has_function_privilege(current_user,p.oid,'EXECUTE') FROM pg_proc p "
                "JOIN pg_namespace n ON n.oid=p.pronamespace "
                "WHERE n.nspname='service_desk' AND p.proname=%s",
                (function,),
            ).fetchall()
            checks[name + "_" + function] = len(rows) == 1 and rows[0][0] is expected
        checks[name + "_no_direct_tables"] = not any(
            db.execute(
                "SELECT has_table_privilege(current_user,%s,%s)",
                ("service_desk." + table, privilege),
            ).fetchone()[0]
            for table in (
                "access_request",
                "access_approval",
                "access_grant",
                "collected_audit",
                "audit_outbox",
            )
            for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE")
        )
print(
    json.dumps(
        {
            "checks": checks,
            "status": Path("/proc/1/status").read_text(),
            "command": Path("/proc/1/cmdline").read_bytes().decode().rstrip(chr(0)).split(chr(0)),
            "sources": {
                p.relative_to("/app/src").as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in Path("/app/src").rglob("*.py")
            },
        }
    )
)
"""


def deployment_checks(
    record: dict[str, Any], role: str, image: dict[str, Any], root: Path = ROOT
) -> dict[str, bool]:
    cfg, host = record["Config"], record["HostConfig"]
    expected = str((root / ".lab/phase4" / role).resolve()).replace("\\", "/").lower()
    sources = {expected}
    if len(expected) > 2 and expected[1] == ":":
        sources.add("/run/desktop/mnt/host/" + expected[0] + expected[2:])
    mounts = record["Mounts"]
    port = PORTS[role]
    return {
        "running": record["State"]["Running"] is True,
        "image": cfg["Image"] == record["Image"] == image["Id"],
        "command": cfg["Entrypoint"]
        == ["python", "-I", "-B", "-m", "service_desk.phase4_bootstrap"]
        and cfg["Cmd"] == [role],
        "environment": cfg["Env"] == image["Config"]["Env"],
        "bootstrap": cfg["User"] == "0:0"
        and not host["Privileged"]
        and {c.removeprefix("CAP_") for c in host.get("CapAdd") or []}
        == {"NET_ADMIN", "SETUID", "SETGID", "SETPCAP"}
        and set(host["CapDrop"] or []) == {"ALL"}
        and "no-new-privileges:true" in host["SecurityOpt"],
        "namespace": not host.get("PidMode")
        and host.get("IpcMode") == "private"
        and not host.get("Devices"),
        "root_read_only": host["ReadonlyRootfs"] is True and not host.get("Tmpfs"),
        "limits": host["Memory"] == 256 * 1024 * 1024
        and host["PidsLimit"] == 64
        and host["NanoCpus"] == 1000000000,
        "no_logs": host["LogConfig"]["Type"] == "none",
        "mount": len(mounts) == 1
        and mounts[0]["Type"] == "bind"
        and mounts[0]["Destination"] == "/run/desk"
        and mounts[0]["RW"] is False
        and mounts[0]["Source"].replace("\\", "/").lower() in sources,
        "loopback": host["PortBindings"]
        == {f"{port}/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(port)}]},
        "network": set(record["NetworkSettings"]["Networks"]) == {"service-desk-phase4_" + role},
    }


def check_boundary(binary: str) -> dict[str, bool]:
    def docker(*args: str) -> str:
        result = subprocess.run(
            [binary, *args], capture_output=True, text=True, timeout=45, check=False
        )
        if result.returncode:
            raise RuntimeError("Workflow deployment check unavailable")
        return result.stdout.strip()

    checks: dict[str, bool] = {}
    pin = json.loads((ROOT / "config/phase4.lock.json").read_text())["image_id"]
    image = json.loads(docker("image", "inspect", pin))[0]
    source = {
        p.relative_to(ROOT / "src").as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in (ROOT / "src").rglob("*.py")
    }
    for role in PORTS:
        record = json.loads(docker("inspect", "service-desk-phase4-" + role + "-1"))[0]
        checks.update(
            {role + "_" + k: v for k, v in deployment_checks(record, role, image).items()}
        )
        if not all(checks.values()):
            return checks
        host = docker(
            "run",
            "--rm",
            "--pull=never",
            "--network",
            "service-desk-phase4_" + role,
            "--read-only",
            "--cap-drop=ALL",
            "--user=65532:65532",
            PYTHON_IMAGE,
            "python",
            "-c",
            "import socket;print(socket.gethostbyname('host.docker.internal'))",
        )
        policy = json.loads(
            docker(
                "exec", record["Id"], "nft", "-j", "list", "table", "inet", "service_desk_phase4"
            )
        )
        checks[role + "_policy"] = firewall_matches(
            policy, role, host, profile=("service_desk_phase4", PORTS[role], OUTBOUND[role])
        )
        runtime = json.loads(
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
        checks.update({role + "_" + k: v for k, v in runtime["checks"].items()})
        checks[role + "_unprivileged"] = unprivileged(runtime["status"])
        checks[role + "_runtime_command"] = runtime["command"] == [
            "python",
            "-I",
            "-B",
            "-m",
            "service_desk.phase4_process",
            role,
            host,
        ]
        checks[role + "_sources"] = runtime["sources"] == source
    # The Phase 3 publisher remains separate; browser and agent are replaced, not duplicated.
    publisher = json.loads(docker("inspect", "service-desk-phase3-app-publisher-1"))[0]
    checks.update(
        {
            "publisher_" + k: v
            for k, v in publisher_checks(
                publisher, "publisher", image, ROOT, application=True
            ).items()
        }
    )
    host = docker(
        "run",
        "--rm",
        "--pull=never",
        "--network",
        "service-desk-phase3-app_publisher",
        "--read-only",
        "--cap-drop=ALL",
        PYTHON_IMAGE,
        "python",
        "-c",
        "import socket;print(socket.gethostbyname('host.docker.internal'))",
    )
    runtime = json.loads(
        docker(
            "exec",
            "--user=65532:65532",
            publisher["Id"],
            "python",
            "-I",
            "-B",
            "-c",
            PUBLISHER_PROBE,
            "publisher",
            host,
        )
    )
    checks.update({"publisher_" + k: v for k, v in runtime["checks"].items()})
    checks["publisher_sources"] = runtime["sources"] == source
    checks["publisher_policy"] = firewall_matches(
        json.loads(
            docker(
                "exec", publisher["Id"], "nft", "-j", "list", "table", "inet", "service_desk_app"
            )
        ),
        "publisher",
        host,
        application=True,
    )
    return checks


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker", required=True)
    report: dict[str, Any] = {"passed": False}
    try:
        report["checks"] = check_boundary(parser.parse_args().docker)
        report["passed"] = all(report["checks"].values())
    except Exception as error:
        report["error"] = type(error).__name__
    report["sources"] = {
        p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in [
            Path(__file__),
            ROOT / "scripts/read_deployment.py",
            ROOT / "infra/compose.phase4.yaml",
            *sorted((ROOT / "src").rglob("*.py")),
        ]
    }
    folder = ROOT / "reports/phase4/runs" / datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "boundary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": report["passed"], "report": str(folder.relative_to(ROOT))}))
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
