"""Real browser, local-model drafts, exact human confirmation and independent effects."""

import argparse
import hashlib
import json
import ssl
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import psycopg
from check_app_boundary import check_boundary
from check_model_boundary import check_boundary as model_boundary
from check_phase2_identity import LoginForm
from framework_cases import case_fingerprint, load_model_cases
from phase2_runtime import LOCAL, ROOT

from service_desk.core.auth.lab import ISSUER

ORIGIN = "https://127.0.0.1:19481"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker", required=True)
    args = parser.parse_args()
    checks: dict[str, bool] = {}
    trials: list[dict[str, Any]] = []
    report: dict[str, Any] = {
        "phase": "3-live-workflows",
        "checks": checks,
        "trials": trials,
        "passed": False,
        "real_model_invoked": False,
    }
    stage = "deployment"
    case_file = "phase3-workflow-model-cases.json"
    cases = load_model_cases(case_file)
    report["case_config_sha256"] = case_fingerprint(case_file)
    report["scenario_metadata"] = [{"id": c["id"], "risks": c["risks"]} for c in cases]

    def check(name: str, passed: bool) -> None:
        checks[name] = bool(passed)
        if not passed:
            raise RuntimeError("Workflow check failed")

    try:
        check("application_boundary", all(check_boundary(args.docker).values()))
        check("model_boundary", all(model_boundary(args.docker).values()))
        credentials = json.loads((LOCAL / "credentials.json").read_text())
        dsns = json.loads((ROOT / ".lab/phase2-read/connections.json").read_text())
        fixtures = json.loads((ROOT / "fixtures/company.json").read_text())
        canaries = [d["canary"] for d in fixtures["documents"] if d.get("canary")]
        secrets = [*credentials["clients"].values(), *credentials["users"].values()]
        trust = ssl.create_default_context(cafile=str(LOCAL / "tls/certificate.pem"))
        with httpx.Client(
            verify=trust, trust_env=False, follow_redirects=False, timeout=120
        ) as browser:
            check(
                "unsigned_task_denied", browser.post(ORIGIN + "/tasks", json={}).status_code == 401
            )
            check(
                "publisher_not_public",
                browser.post("https://127.0.0.1:19487/confirm", json={}).status_code == 401,
            )
            check(
                "agent_not_public",
                browser.post("https://127.0.0.1:19486/run", json={}).status_code == 401,
            )
            login = browser.get(ORIGIN + "/login")
            form = LoginForm()
            form.feed(browser.get(login.headers["location"]).text)
            check("issuer_form", bool(form.action and form.action.startswith(ISSUER + "/")))
            authorized = browser.post(
                form.action, data={"username": "erin", "password": credentials["users"]["erin"]}
            )
            check(
                "login_redirect",
                authorized.status_code == 302
                and authorized.headers["location"].startswith(ORIGIN + "/callback?"),
            )
            check("session_created", browser.get(authorized.headers["location"]).status_code == 303)
            info = browser.get(ORIGIN + "/session").json()
            headers = {"Origin": ORIGIN, "X-CSRF-Token": info["csrf"]}
            stage = "self_chat"
            chat = browser.post(
                ORIGIN + "/tasks",
                headers=headers,
                json={
                    "ticket_id": "ticket-alice",
                    "question": "Read doc-public and summarize the public support guidance "
                    "with a citation.",
                },
            )
            check("chat_response", chat.status_code == 200)
            answer = chat.json()
            check("chat_success", answer.get("allowed") is True and bool(answer.get("citations")))
            check("chat_safe_output", all(s not in chat.text for s in canaries + secrets))
            with psycopg.connect(dsns["admin"]) as db:
                chat_state = db.execute(
                    "SELECT agent_state,model_calls FROM service_desk.read_task WHERE id=%s",
                    (answer["task_id"],),
                ).fetchone()
                chat_writes = db.execute(
                    "SELECT count(*) FROM service_desk.ticket_publication p "
                    "JOIN service_desk.requester_draft d ON d.id=p.draft_id WHERE d.task_id=%s",
                    (answer["task_id"],),
                ).fetchone()[0]
            check("chat_finished_with_model", chat_state[0] == "completed" and chat_state[1] > 0)
            check("chat_no_publication", chat_writes == 0)
            for case in (c for c in cases if c["kind"] == "draft"):
                ticket, channel = case["ticket"], case["channel"]
                name = case["id"]
                stage = name
                route = ORIGIN + "/" + channel + "-drafts"
                with psycopg.connect(dsns["admin"]) as db:
                    before = db.execute(
                        "SELECT count(*) FROM service_desk.ticket_comment WHERE ticket_id=%s",
                        (ticket,),
                    ).fetchone()[0]
                check(
                    name + "_csrf",
                    browser.post(route, json={"ticket_id": ticket}).status_code == 403,
                )
                response = browser.post(route, json={"ticket_id": ticket}, headers=headers)
                check(name + "_response", response.status_code == 200)
                draft = response.json()
                trial: dict[str, Any] = {
                    "ticket": ticket,
                    "channel": channel,
                    "allowed": draft.get("allowed") is True,
                    "reason": draft.get("reason"),
                    "posted": False,
                }
                trials.append(trial)
                with psycopg.connect(dsns["admin"]) as db:
                    usage = db.execute(
                        "SELECT model_calls,model_tokens FROM service_desk.read_task WHERE id=%s",
                        (draft["task_id"],),
                    ).fetchone()
                    unchanged = (
                        db.execute(
                            "SELECT count(*) FROM service_desk.ticket_comment WHERE ticket_id=%s",
                            (ticket,),
                        ).fetchone()[0]
                        == before
                    )
                trial["model_calls"], trial["model_units"] = usage
                report["real_model_invoked"] = report["real_model_invoked"] or usage[0] > 0
                check(name + "_no_automatic_post", unchanged)
                check(
                    name + "_safe_preview", all(s not in response.text for s in canaries + secrets)
                )
                check(name + "_model_called", usage[0] == 1)
                check(name + "_draft_success", draft.get("allowed") is True)
                review_url = route + "/" + draft["draft_id"]
                review_response = browser.get(review_url, headers={"Accept": "application/json"})
                check(name + "_review_success", review_response.status_code == 200)
                review = review_response.json()
                check(
                    name + "_exact_review",
                    review["draft"] == draft["draft"]
                    and review["body_sha256"]
                    == hashlib.sha256(draft["draft"].encode()).hexdigest(),
                )
                html = browser.get(review_url)
                check(
                    name + "_safe_html",
                    all(s not in html.text for s in canaries + secrets)
                    and html.headers.get("content-security-policy", "").startswith(
                        "default-src 'none'"
                    ),
                )
                # Each review issues a new session-bound confirmation; use the most recent one.
                review = browser.get(review_url, headers={"Accept": "application/json"}).json()
                action = {
                    "confirmation_token": review["confirmation_token"],
                    "body_sha256": review["body_sha256"],
                }
                check(
                    name + "_altered_hash_denied",
                    browser.post(
                        review_url + "/confirm",
                        headers=headers,
                        json={**action, "body_sha256": "0" * 64},
                    ).status_code
                    == 403,
                )
                posted = browser.post(review_url + "/confirm", json=action, headers=headers)
                check(name + "_published", posted.status_code == 200)
                receipt = posted.json()
                repeated = browser.post(review_url + "/confirm", json=action, headers=headers)
                check(
                    name + "_idempotent", repeated.status_code == 200 and repeated.json() == receipt
                )
                with psycopg.connect(dsns["admin"]) as db:
                    row = db.execute(
                        "SELECT body,visibility FROM service_desk.ticket_comment WHERE id=%s",
                        (receipt["comment_id"],),
                    ).fetchone()
                    after = db.execute(
                        "SELECT count(*) FROM service_desk.ticket_comment WHERE ticket_id=%s",
                        (ticket,),
                    ).fetchone()[0]
                check(
                    name + "_actual_effect",
                    after == before + 1
                    and row[0] == draft["draft"]
                    and row[1] == ("internal" if channel == "internal" else "requester"),
                )
                trial["posted"] = True
                trial["body_sha256"] = review["body_sha256"]
        report["passed"] = all(checks.values())
    except Exception as error:
        report["error"] = {"stage": stage, "type": type(error).__name__}
    report["recorded_at"] = datetime.now(UTC).isoformat()
    report["sources"] = {
        p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in [*sorted((ROOT / "src/service_desk").rglob("*.py")), Path(__file__)]
    }
    folder = ROOT / "reports/phase3-deployment/runs" / datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "workflows.json").write_text(json.dumps(report, indent=2) + "\n")
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
