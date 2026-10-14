"""Real signed MCP proposals, browser approvals, executor effects, lifecycle and
collector recovery."""

import argparse
import hashlib
import json
import ssl
import subprocess
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qs, urlsplit
from uuid import UUID, uuid4

import httpx
import psycopg
from check_phase2_identity import LoginForm
from check_phase4_boundary import check_boundary
from phase2_runtime import LOCAL, ROOT, load_client

from service_desk.agent.loop import unpack
from service_desk.core.access import AccessStore
from service_desk.core.auth.lab import ISSUER, RESOURCES
from service_desk.core.gateway.dispatch import ReadGateway
from service_desk.core.gateway.store import TaskStore

ORIGIN = "https://127.0.0.1:19481"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker", required=True)
    args = parser.parse_args()
    checks: dict[str, bool] = {}
    trials: list[dict[str, Any]] = []
    report: dict[str, Any] = {
        "phase": 4,
        "passed": False,
        "checks": checks,
        "trials": trials,
        "model_invoked": False,
    }
    credentials = json.loads((LOCAL / "credentials.json").read_text())
    dsns = json.loads((ROOT / ".lab/phase2-read/connections.json").read_text())
    trust = ssl.create_default_context(cafile=str(LOCAL / "tls/certificate.pem"))
    stopped: set[str] = set()
    stage = "deployment"

    def check(name: str, value: bool) -> None:
        checks[name] = bool(value)
        if not value:
            raise RuntimeError("Workflow check failed")

    def docker(action: str, role: str) -> None:
        result = subprocess.run(
            [args.docker, action, "service-desk-phase4-" + role + "-1"],
            capture_output=True,
            timeout=30,
            check=False,
        )
        if result.returncode:
            raise RuntimeError("Container test operation failed")
        if action == "stop":
            stopped.add(role)
        else:
            stopped.discard(role)

    def row(query: str, params: tuple[Any, ...] = ()) -> Any:
        with psycopg.connect(dsns["admin"]) as db:
            return db.execute(query, params).fetchone()

    def wait(predicate: Any, seconds: int = 45) -> bool:
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if predicate():
                return True
            time.sleep(0.5)
        return False

    @contextmanager
    def browser(user: str) -> Any:
        with httpx.Client(
            verify=trust, trust_env=False, follow_redirects=False, timeout=15
        ) as client:
            login = client.get(ORIGIN + "/login")
            form = LoginForm()
            form.feed(client.get(login.headers["location"]).text)
            if not form.action.startswith(ISSUER + "/"):
                raise RuntimeError("Issuer form denied")
            response = client.post(
                form.action, data={"username": user, "password": credentials["users"][user]}
            )
            callback = client.get(response.headers["location"])
            if callback.status_code != 303:
                raise RuntimeError("Session unavailable")
            csrf = client.get(ORIGIN + "/session").json()["csrf"]
            yield client, {"Origin": ORIGIN, "X-CSRF-Token": csrf}

    def confirm(user: str, rid: str, op: str) -> None:
        with browser(user) as (client, headers):
            url = ORIGIN + "/access/requests/" + rid
            review = client.get(
                url + "/review", params={"operation": op}, headers={"Accept": "application/json"}
            )
            check(user + "_" + op + "_" + rid[:8], review.status_code == 200)
            data = review.json()
            action = {
                "confirmation_token": data["confirmation_token"],
                "action_hash": data["action_hash"],
            }
            check(
                user + "_" + op + "_exact_hash_" + rid[:8],
                client.post(
                    url + "/confirm", json={**action, "action_hash": "0" * 64}, headers=headers
                ).status_code
                == 403,
            )
            result = client.post(url + "/confirm", json=action, headers=headers)
            check(user + "_" + op + "_confirmed_" + rid[:8], result.status_code == 200)
            check(
                user + "_" + op + "_replay_" + rid[:8],
                client.post(url + "/confirm", json=action, headers=headers).status_code == 403,
            )

    try:
        check("deployed_boundary", all(check_boundary(args.docker).values()))
        with httpx.Client(
            verify=trust, trust_env=False, follow_redirects=False, timeout=15
        ) as http:
            oidc = load_client(http, trust)
            oidc.check_discovery()
            attempt, location = oidc.begin(RESOURCES[0].url)
            with httpx.Client(
                verify=trust, trust_env=False, follow_redirects=False, timeout=15
            ) as login_browser:
                form = LoginForm()
                form.feed(login_browser.get(location).text)
                if not form.action.startswith(ISSUER + "/"):
                    raise RuntimeError("Issuer form denied")
                response = login_browser.post(
                    form.action, data={"username": "erin", "password": credentials["users"]["erin"]}
                )
                query = parse_qs(urlsplit(response.headers["location"]).query)
            login = oidc.finish(attempt, query["state"][0], query["code"][0])
            check(
                "web_token_cannot_execute",
                http.post(
                    "https://127.0.0.1:19489/mcp",
                    headers={
                        "Authorization": "Bearer " + login.access_token,
                        "Accept": "application/json, text/event-stream",
                    },
                    json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                ).status_code
                == 401,
            )
            delegated = oidc.exchange(login, RESOURCES[2].url)
            check(
                "proposal_token_cannot_execute",
                http.post(
                    "https://127.0.0.1:19489/mcp",
                    headers={
                        "Authorization": "Bearer " + delegated,
                        "Accept": "application/json, text/event-stream",
                    },
                    json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                ).status_code
                == 401,
            )
            for sensitive in (False, True):
                stage = "sensitive" if sensitive else "standard"
                ticket = "ticket-alice-injected" if sensitive else "ticket-alice"
                template = "engineering-admin" if sensitive else "engineering-workspace"
                group = template + "-" + uuid4().hex[:10]
                # A distinct trusted fixture resource prevents older lab grants from
                # satisfying this trial's effective-access check.
                with psycopg.connect(dsns["admin"]) as db:
                    db.execute(
                        "INSERT INTO service_desk.resource_group SELECT %s,risk,owner_id "
                        "FROM service_desk.resource_group WHERE id=%s",
                        (group, template),
                    )
                    db.execute(
                        "INSERT INTO service_desk.resource_department SELECT %s,department "
                        "FROM service_desk.resource_department WHERE resource_id=%s",
                        (group, template),
                    )
                # Refresh real login before each case because the lab bearer expires in two minutes.
                if sensitive:
                    attempt, location = oidc.begin(RESOURCES[0].url)
                    with httpx.Client(
                        verify=trust, trust_env=False, follow_redirects=False, timeout=15
                    ) as lb:
                        form = LoginForm()
                        form.feed(lb.get(location).text)
                        response = lb.post(
                            form.action,
                            data={"username": "erin", "password": credentials["users"]["erin"]},
                        )
                        query = parse_qs(urlsplit(response.headers["location"]).query)
                    login = oidc.finish(attempt, query["state"][0], query["code"][0])
                task = TaskStore(dsns["creator"]).create(login.identity, ticket)
                gateway = ReadGateway(oidc, TaskStore(dsns["gateway"]), http)
                read = unpack(gateway.call(login, task, "read_ticket", {"ticket_id": ticket}))
                check(stage + "_signed_source_read", read.get("allowed") is True)
                draft = unpack(
                    gateway.call(login, task, "propose_access_change", {"resource_id": group})
                )
                check(stage + "_signed_mcp_draft", draft.get("allowed") is True)
                rid = draft["request_id"]
                correlation = draft["correlation_id"]
                trial = {
                    "case": stage,
                    "request_id": rid,
                    "correlation_id": correlation,
                    "passed": False,
                }
                trials.append(trial)
                check(
                    stage + "_no_automatic_request",
                    row("SELECT state FROM service_desk.access_state WHERE request_id=%s", (rid,))[
                        0
                    ]
                    == "draft",
                )
                with browser("erin") as (client, headers):
                    html = client.get(ORIGIN + "/access/requests/" + rid)
                    labels = [
                        "Original ticket",
                        "Source provenance",
                        "Policy results",
                        "Recorded approvals",
                        "Exact proposed change",
                        "Untrusted proposal justification",
                    ]
                    check(
                        stage + "_provenance_first",
                        html.status_code == 200
                        and [html.text.index(x) for x in labels]
                        == sorted(html.text.index(x) for x in labels),
                    )
                    check(
                        stage + "_safe_preview",
                        html.headers.get("content-security-policy", "").startswith(
                            "default-src 'none'"
                        )
                        and all(
                            secret not in html.text
                            for secret in [
                                *credentials["clients"].values(),
                                *credentials["users"].values(),
                            ]
                        ),
                    )
                    check(
                        stage + "_csrf",
                        client.post(
                            ORIGIN + "/access/requests/" + rid + "/confirm", json={}
                        ).status_code
                        == 403,
                    )
                confirm("erin", rid, "submit")
                for user in ("erin", "alice"):
                    with browser(user) as (client, headers):
                        check(
                            stage + "_" + user + "_self_approval_denied",
                            client.get(
                                ORIGIN + "/access/requests/" + rid + "/review",
                                params={"operation": "approve"},
                            ).status_code
                            == 403,
                        )
                if sensitive:
                    with browser("olivia") as (client, headers):
                        check(
                            "sensitive_owner_cannot_skip_manager",
                            client.get(
                                ORIGIN + "/access/requests/" + rid + "/review",
                                params={"operation": "approve"},
                            ).status_code
                            == 403,
                        )
                else:
                    docker("stop", "collector")
                confirm("morgan", rid, "approve")
                if sensitive:
                    check(
                        "manager_stage_does_not_grant",
                        row(
                            "SELECT count(*) FROM service_desk.access_grant WHERE request_id=%s",
                            (rid,),
                        )[0]
                        == 0,
                    )
                    confirm("olivia", rid, "approve")
                check(
                    stage + "_executor_applied",
                    wait(
                        lambda rid=rid: (
                            row(
                                "SELECT count(*) FROM service_desk.access_grant WHERE "
                                "request_id=%s",
                                (rid,),
                            )[0]
                            == 1
                        )
                    ),
                )
                grant = row(
                    "SELECT id,beneficiary,resource_id,expires_at,extract(epoch FROM "
                    "expires_at-created_at) FROM service_desk.access_grant WHERE request_id=%s",
                    (rid,),
                )
                check(
                    stage + "_actual_directory_effect",
                    grant[1:3] == ("alice", group)
                    and row(
                        "SELECT count(*) FROM service_desk.directory_membership WHERE grant_id=%s",
                        (grant[0],),
                    )[0]
                    == 1,
                )
                check(stage + "_bounded_expiry", grant[4] <= (28801 if sensitive else 2592001))
                receipt = AccessStore(dsns["execution"]).execute(UUID(rid), draft["action_hash"])
                check(
                    stage + "_idempotent_effect",
                    str(grant[0]) == receipt["grant_id"]
                    and row(
                        "SELECT count(*) FROM service_desk.access_grant WHERE request_id=%s", (rid,)
                    )[0]
                    == 1,
                )
                if not sensitive:
                    check(
                        "collector_outage_retains_durable_events",
                        row(
                            "SELECT count(*) FROM service_desk.audit_outbox WHERE delivered_at "
                            "IS NULL AND writer='execution' AND payload->>'correlation_id'=%s",
                            (correlation,),
                        )[0]
                        >= 2,
                    )
                    docker("start", "collector")
                    confirm("morgan", rid, "review")
                    check(
                        "review_does_not_extend_expiry",
                        row(
                            "SELECT expires_at FROM service_desk.access_grant WHERE request_id=%s",
                            (rid,),
                        )[0]
                        == grant[3],
                    )
                check(
                    stage + "_collector_recovered",
                    wait(
                        lambda correlation=correlation: (
                            row(
                                "SELECT count(*) FROM service_desk.collected_audit WHERE "
                                "payload->>'correlation_id'=%s AND "
                                "payload->>'operation'='execute' AND payload->>'reason'='ALLOW'",
                                (correlation,),
                            )[0]
                            == 1
                        )
                    ),
                )
                with browser("harper") as (client, headers):
                    audit = client.get(
                        ORIGIN + "/access/audit",
                        params={"correlation_id": correlation},
                        headers={"Accept": "application/json"},
                    )
                    check(
                        stage + "_restricted_auditor_query",
                        audit.status_code == 200 and bool(audit.json()["events"]),
                    )
                    check(
                        stage + "_content_free_audit",
                        all(
                            value not in audit.text
                            for value in [
                                read["ticket"]["body"],
                                *credentials["clients"].values(),
                                *credentials["users"].values(),
                            ]
                        ),
                    )
                with browser("erin") as (client, headers):
                    check(
                        stage + "_analyst_cannot_read_audit",
                        client.get(
                            ORIGIN + "/access/audit", params={"correlation_id": correlation}
                        ).status_code
                        == 403,
                    )
                docker("stop", "worker")
                with psycopg.connect(dsns["admin"]) as db:
                    if sensitive:
                        db.execute(
                            "UPDATE service_desk.access_grant SET expires_at=created_at+interval "
                            "'1 microsecond' WHERE request_id=%s",
                            (rid,),
                        )
                    else:
                        db.execute(
                            "UPDATE service_desk.access_grant SET "
                            "review_due=created_at,review_deadline=created_at WHERE "
                            "request_id=%s",
                            (rid,),
                        )
                check(
                    stage + "_effective_denial_without_worker",
                    not AccessStore(dsns["workflow"]).check(login.identity, "alice", group)[
                        "effective"
                    ],
                )
                check(
                    stage + "_stale_membership_before_cleanup",
                    row(
                        "SELECT count(*) FROM service_desk.directory_membership WHERE grant_id=%s",
                        (grant[0],),
                    )[0]
                    == 1,
                )
                docker("start", "worker")
                check(
                    stage + "_restart_reconciles",
                    wait(
                        lambda grant=grant: (
                            row(
                                "SELECT count(*) FROM service_desk.directory_membership WHERE "
                                "grant_id=%s",
                                (grant[0],),
                            )[0]
                            == 0
                        )
                    ),
                )
                check(
                    stage + "_correlated_read_decision_execution_lifecycle",
                    wait(
                        lambda correlation=correlation: (
                            {"read_ticket", "draft", "submit", "approve", "execute", "revoke"}
                            <= set(
                                row(
                                    "SELECT array_agg(DISTINCT payload->>'operation') "
                                    "FROM service_desk.collected_audit "
                                    "WHERE payload->>'correlation_id'=%s",
                                    (correlation,),
                                )[0]
                                or []
                            )
                        )
                    ),
                )
                check(
                    stage + "_correlated_blocked_confirmation",
                    row(
                        "SELECT count(*) FROM service_desk.collected_audit "
                        "WHERE payload->>'correlation_id'=%s "
                        "AND payload->>'reason'='APPROVAL_DENIED'",
                        (correlation,),
                    )[0]
                    > 0,
                )
                trial["passed"] = True
        report["passed"] = all(checks.values()) and len(trials) == 2
    except Exception as error:
        report["error"] = {"stage": stage, "type": type(error).__name__}
    finally:
        for role in list(stopped):
            try:
                docker("start", role)
            except Exception:
                report["passed"] = False
    report["source_sha256"] = {
        name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
        for name in (
            "scripts/check_phase4_workflows.py",
            "migrations/0012_access_workflow.sql",
            "migrations/0013_access_tools.sql",
            "config/phase4.lock.json",
        )
    }
    folder = ROOT / "reports/phase4/runs" / datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "workflows.json").write_text(json.dumps(report, indent=2, default=str) + "\n")
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
