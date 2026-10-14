"""Saturate only the disposable read database; record limits/recovery without credentials."""

import hashlib
import json
import select
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from datetime import UTC, datetime
from pathlib import Path

import psycopg
from psycopg.conninfo import conninfo_to_dict

from service_desk.core.database import (
    LOGIN_LIMITS,
    SERVER_SETTINGS,
    SESSION_SETTINGS,
    check_database,
)

ROOT = Path(__file__).resolve().parents[1]
SERVICES = {
    "creator": "read_app",
    "gateway": "read_gateway",
    "knowledge": "read_knowledge",
    "tickets": "read_tickets",
    "publisher": "read_publisher",
}


def capacity_denied(dsn: str) -> bool:
    try:
        with psycopg.connect(dsn, connect_timeout=3):
            return False
    except psycopg.OperationalError as error:
        # libpq may expose only a message during connection establishment. Never save it.
        return error.sqlstate == "53300" or any(
            marker in str(error)
            for marker in ("too many connections", "remaining connection slots are reserved")
        )


def idle_closed(dsn: str, *, transaction: bool) -> bool:
    with psycopg.connect(dsn, autocommit=not transaction, connect_timeout=3) as db:
        assert db.execute("SELECT 1").fetchone() == (1,)
        # Do not poll with SQL: that would refresh the idle timer being measured.
        started = time.monotonic()
        bound = 8 if transaction else 33
        ready, _, _ = select.select([db.fileno()], [], [], bound)
        if not ready:
            return False
        try:
            db.execute("SELECT 1")
            return False
        except psycopg.Error as error:
            expected = "25P03" if transaction else "57P05"
            return error.sqlstate == expected and time.monotonic() - started < bound


def authentication_closed() -> bool:
    with socket.create_connection(("127.0.0.1", 15433), timeout=8) as client:
        started = time.monotonic()
        # Send an incomplete startup length. No username/password or fixture content.
        client.sendall(b"\x00")
        try:
            closed = client.recv(1) == b""
        except ConnectionResetError:
            closed = True
        return closed and time.monotonic() - started < 8


def main() -> None:
    connections = json.loads((ROOT / ".lab/phase2-read/connections.json").read_text())
    for dsn in connections.values():
        options = conninfo_to_dict(dsn)
        if any(
            options.get(k) != v
            for k, v in {
                "host": "127.0.0.1",
                "port": "15433",
                "dbname": "service_desk_read_lab",
            }.items()
        ):
            raise RuntimeError("Refusing to probe a different database")
    checks = {}
    for service, login in SERVICES.items():
        checks.update(
            {service + "_" + k: v for k, v in check_database(connections[service], login).items()}
        )

    # Keep an administrator observer in one of the 40 total slots. The remaining
    # non-reserved capacity is 35: 40 - 4 reserved - 1 observer. No policy is relaxed.
    with psycopg.connect(connections["admin"], autocommit=True, connect_timeout=3) as observer:
        if observer.execute("SELECT current_database()").fetchone() != ("service_desk_read_lab",):
            raise RuntimeError("Refusing to probe a different database")
        with ExitStack() as stack:
            admitted = 0
            for service, count in (("creator", 12), ("gateway", 12), ("knowledge", 11)):
                for _ in range(count):
                    # A short healthcheck connection may briefly occupy the last slot.
                    for attempt in range(5):
                        try:
                            db = psycopg.connect(
                                connections[service], autocommit=True, connect_timeout=3
                            )
                            stack.enter_context(db)
                            admitted += 1
                            break
                        except psycopg.OperationalError:
                            if attempt == 4:
                                raise RuntimeError("Database saturation setup failed") from None
                            time.sleep(0.1)
            checks["shared_normal_capacity_filled"] = admitted == 35
            checks["unused_role_denied_at_shared_ceiling"] = capacity_denied(connections["tickets"])
            checks["admitted_connection_still_usable"] = db.execute("SELECT 1").fetchone() == (1,)
            with psycopg.connect(connections["admin"], autocommit=True, connect_timeout=3) as admin:
                checks["administrator_reserve_available"] = admin.execute(
                    "SELECT 1"
                ).fetchone() == (1,)
        with psycopg.connect(connections["tickets"], connect_timeout=3) as recovered:
            checks["service_recovers_after_release"] = recovered.execute("SELECT 1").fetchone() == (
                1,
            )

    with ThreadPoolExecutor(max_workers=3) as pool:
        idle = pool.submit(idle_closed, connections["knowledge"], transaction=False)
        transaction = pool.submit(idle_closed, connections["tickets"], transaction=True)
        authentication = pool.submit(authentication_closed)
        checks["idle_session_closed"] = idle.result()
        checks["idle_transaction_closed"] = transaction.result()
        checks["incomplete_startup_closed"] = authentication.result()
    checks["service_recovers_after_timeouts"] = all(
        check_database(connections["knowledge"], "read_knowledge").values()
    )
    files = [
        "infra/compose.phase2-reads.yaml",
        "scripts/prepare_read_store.py",
        "scripts/read_runtime.py",
        "scripts/assistant_runtime.py",
        "src/service_desk/core/database.py",
        "scripts/check_phase3_database.py",
    ]
    report = {
        "phase": "3-database-capacity",
        "recorded_at": datetime.now(UTC).isoformat(),
        "checks": checks,
        "passed": all(checks.values()),
        "limits": {
            "server": SERVER_SETTINGS,
            "login_connections": LOGIN_LIMITS,
            "session_defaults": SESSION_SETTINGS,
        },
        "source_sha256": {
            name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in files
        },
        "scope": "Dedicated disposable PostgreSQL only; no model calls or OIDC/MCP trial. "
        "Shared slot exhaustion, administrator reserve, raw incomplete startup, actual default "
        "idle timeouts and recovery. Session timeout defaults are client-changeable; no claim "
        "of query fairness or complete denial-of-service prevention. Host credential separation "
        "and browser/MCP connection bounds remain open.",
    }
    destination = (
        ROOT / "reports/phase3-deployment/runs" / datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    )
    destination.mkdir(parents=True, exist_ok=True)
    path = destination / "database.json"
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
    try:
        main()
    except Exception:
        raise SystemExit("Database capacity probe failed; no credential details emitted") from None
