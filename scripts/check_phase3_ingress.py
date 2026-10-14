"""Direct bounded-ingress checks against the pinned local model; no ticket data sent."""

import argparse
import hashlib
import http.client
import json
import socket
import time
from contextlib import ExitStack, closing
from datetime import UTC, datetime

from check_model_boundary import ROOT, check_boundary


def request(method: str = "GET", path: str = "/api/version") -> tuple[int, bytes]:
    with closing(http.client.HTTPConnection("127.0.0.1", 19485, timeout=2)) as client:
        client.request(method, path, body=b"{}" if method == "POST" else None)
        response = client.getresponse()
        return response.status, response.read(65537)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker")
    args = parser.parse_args()
    checks = check_boundary(args.docker)
    status, body = request()
    checks["host_model_metadata_reachable"] = (
        status == 200 and json.loads(body).get("version") == "0.40.3"
    )
    checks["host_download_route_denied"] = request("POST", "/api/pull")[0] == 404
    with ExitStack() as stack:
        stalled = [
            stack.enter_context(socket.create_connection(("127.0.0.1", 19485), timeout=8))
            for _ in range(2)
        ]
        started = time.monotonic()
        for client in stalled:
            client.sendall(b"GET /api/version HTTP/1.1\r\nX-Slow:")
        time.sleep(0.2)
        try:
            checks["excess_connection_rejected"] = request()[0] == 503
        except (OSError, http.client.RemoteDisconnected):
            checks["excess_connection_rejected"] = True
        closed = True
        for client in stalled:
            try:
                closed = closed and client.recv(4096) == b""
            except ConnectionResetError:
                pass
            except TimeoutError:
                closed = False
        checks["stalled_headers_deadline"] = closed and time.monotonic() - started < 7.5
    checks["relay_recovers_after_stall"] = request()[0] == 200
    files = [
        "scripts/model_relay.py",
        "scripts/relay_bootstrap.py",
        "infra/relay.Dockerfile",
        "scripts/check_model_boundary.py",
        "scripts/check_phase3_ingress.py",
        "infra/compose.phase2-model.yaml",
    ]
    report = {
        "phase": "3-model-ingress",
        "recorded_at": datetime.now(UTC).isoformat(),
        "checks": checks,
        "passed": all(checks.values()),
        "source_sha256": {
            name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in files
        },
        "limits": {
            "active_connections": 2,
            "listen_backlog": 8,
            "input_seconds": 5,
            "upstream_seconds": 45,
            "body_bytes": 65536,
        },
        "scope": "Model metadata and neutral stalled sockets only; "
        "no draft or real-model task trials. "
        "Relay egress policy is inspected; reachable-target trials use check_phase3_egress.py. "
        "Host application credential isolation remains unproven. "
        "Host database/identity ports were not positive-controlled by this probe.",
    }
    destination = (
        ROOT / "reports/phase3-deployment/runs" / datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    )
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "ingress.json").write_text(json.dumps(report, indent=2) + "\n")
    print(
        json.dumps(
            {
                "passed": report["passed"],
                "checks": len(checks),
                "report": str((destination / "ingress.json").relative_to(ROOT)),
            }
        )
    )
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
