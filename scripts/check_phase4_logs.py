"""Inspect lab container logging without printing or saving captured log content."""

import argparse
import hashlib
import json
import re
import subprocess
from datetime import UTC, datetime
from typing import Any

from phase2_runtime import LOCAL, ROOT
from psycopg.conninfo import conninfo_to_dict


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker", required=True)
    args = parser.parse_args()
    checks: dict[str, bool] = {}
    report: dict[str, Any] = {"passed": False, "checks": checks}

    def docker(*argv: str) -> str:
        result = subprocess.run(
            [args.docker, *argv], capture_output=True, text=True, timeout=30, check=False
        )
        if result.returncode or len(result.stdout) + len(result.stderr) > 8 * 1024 * 1024:
            raise RuntimeError("Log inspection unavailable")
        return result.stdout + (result.stderr if argv[0] == "logs" else "")

    try:
        fixtures = json.loads((ROOT / "fixtures/company.json").read_text())
        credentials = json.loads((LOCAL / "credentials.json").read_text())
        connections = json.loads((ROOT / ".lab/phase2-read/connections.json").read_text())
        forbidden = [d["canary"] for d in fixtures["documents"] if d.get("canary")]
        forbidden += [*credentials["clients"].values(), *credentials["users"].values()]
        forbidden += [conninfo_to_dict(dsn)["password"] for dsn in connections.values()]
        forbidden += [p.read_text().strip() for p in (ROOT / ".lab/phase4").rglob("*.secret")]
        forbidden += ["Internal support note; never copy into requester context."]
        for project, services in (
            (
                "phase4",
                (
                    "browser",
                    "agent",
                    "workflow",
                    "proposals",
                    "execution",
                    "collector",
                    "worker",
                    "executor",
                    "delivery",
                ),
            ),
            ("phase3-app", ("publisher",)),
            ("phase3-reads", ("knowledge", "tickets")),
            ("phase2-model", ("model", "relay")),
            ("phase2-reads", ("postgres",)),
            ("phase2-identity", ("keycloak",)),
        ):
            for service in services:
                name = "service-desk-" + project + "-" + service + "-1"
                record = json.loads(docker("inspect", name))[0]
                checks[service + "_running"] = record["State"]["Running"] is True
                if service not in ("postgres", "keycloak"):
                    checks[service + "_logs_disabled"] = (
                        record["HostConfig"]["LogConfig"]["Type"] == "none"
                    )
                    continue
                content = docker("logs", name)
                checks[service + "_no_restricted_markers_or_credentials"] = (
                    all(value not in content for value in forbidden)
                    and re.search(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", content)
                    is None
                )
        report["passed"] = all(checks.values())
    except Exception as error:
        report["error"] = type(error).__name__
    report["harness_sha256"] = hashlib.sha256(
        (ROOT / "scripts/check_phase4_logs.py").read_bytes()
    ).hexdigest()
    folder = ROOT / "reports/phase4/runs" / datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "logs.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": report["passed"], "report": str(folder.relative_to(ROOT))}))
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
