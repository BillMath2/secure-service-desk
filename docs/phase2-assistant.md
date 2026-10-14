# Phase 2 deterministic read-only assistant

Current hardened deployment: [Phase 3 startup and exit evidence](phase3.md#verification-and-reproduction) supersede the host-process limitations and older commands below. Use `scripts/phase3.ps1` for separate browser/agent/publisher/read containers and checked model/relay egress. Historical results below retain their original scope.

Current isolation option: use the [Phase 3 read containers](phase3.md#read-service-process-and-credential-separation) in place of the two host `read_runtime.py` processes. Rerun `prepare_phase2.py` before browser startup to create the scoped web/gateway client file. The browser/agent/publisher still share a host process; the older interactive instructions below do not establish read-service filesystem isolation.

Current deployment update: [Phase 3 database capacity controls](phase3.md#database-connection-capacity) now apply to the shared read database and runtime entry points. Start the current Compose project and rerun `scripts/prepare_read_store.py --apply` before launching services; the gate rejects older server settings. Historical Phase 2 reports below retain their original scope.

October 13, 2026: authenticated task submission, a browser form, a bounded provider loop and cited answers are implemented. This slice uses an explicitly labelled deterministic provider that reads the task ticket and public support guide. The subsequent [local-model slice](phase2-model.md) adds the pinned Qwen adapter; the stub remains the default. Phase 2 remains open.

The complete checker passes 146 tests with PostgreSQL enabled: 103 default tests and 43 opt-in database cases. The new coverage includes 20 assistant/database cases and eight browser cases. The real browser-login → task → gateway → TLS MCP → PostgreSQL flow passes 27 checks for Erin and Alice. See [selected live evidence](../reports/phase2-assistant/results.json). No token, prompt, source body, password or answer is saved in that report. The first live attempt encountered startup before Keycloak was ready; the probe now waits up to 45 seconds for discovery. Failed and successful run records are retained.

## What is enforced

- `/tasks` requires a live server-side session, exact Origin and CSRF token. Inputs contain only ticket ID and question; identity, recipients and conversation history cannot be supplied. The task creator verifies the signed token again and checks ticket visibility in PostgreSQL. Browser tasks always answer only to the signed-in user. Requester-draft generation is not enabled.
- Each task can be claimed once. The database atomically reserves cumulative model budget (16,000 units) before each provider invocation, across processes and restarts. Reservations are conservative serialized UTF-8 input bytes plus 512 framing units and 512 maximum output units. Failed calls receive no refund. This estimate is tested for the stub; a real adapter must validate its tokenizer/template bound before activation.
- Runs allow at most eight provider calls, use a 45-second provider timeout and 10-second tool timeout, and stop at the task's remaining 120-second deadline or signed-token expiry. Existing shared 12-tool and 32-KiB tool-result limits still apply. There are no automatic retries. Cancellation closes the task; timed-out read work cannot return a late answer or perform a write.
- Model context is constructed anew for every run. It includes business identifiers, question, the pinned read catalog and this task's authorized results. It excludes access tokens, issuer/subject, CSRF tokens and database credentials. No conversation or answer is cached. Providers cannot select URLs, clients, audiences or database roles.
- Citations must come from successful reads. All retrieved sources, including uncited sources and ticket comments, are rechecked before subsequent provider calls and before answer release. Lost permission, changed document/ticket version, stale policy or task expiry blocks the answer. This verifies citation provenance and access, not the factual accuracy of arbitrary model prose.
- The browser renders answers as escaped plain text and citations as text, with no script or external-resource loading. PostgreSQL records admission, reservations, stop/completion and read decisions without prompt or source content. Service roles cannot reset model budgets or claim application runs.

## Reproduce

Use the existing repository environment and Docker Desktop Linux engine. Commands run from the repository root:

```powershell
.\.venv\Scripts\python.exe scripts/prepare_phase2.py
.\.venv\Scripts\python.exe scripts/prepare_read_store.py
docker compose -f infra/compose.phase2-reads.yaml up -d --wait
docker compose -f infra/compose.phase2-identity.yaml up -d
try {
    .\.venv\Scripts\python.exe scripts/prepare_read_store.py --apply
    if ($LASTEXITCODE -ne 0) { throw 'Database preparation failed' }
    $env:DESK_READ_INTEGRATION = '1'
    .\scripts\check.ps1
    .\.venv\Scripts\python.exe scripts/check_phase2_assistant.py
    if ($LASTEXITCODE -ne 0) { throw 'Live assistant checks failed' }
} finally {
    Remove-Item Env:\DESK_READ_INTEGRATION -ErrorAction SilentlyContinue
    docker compose -f infra/compose.phase2-identity.yaml down
    docker compose -f infra/compose.phase2-reads.yaml down
}
```

Use `scripts/check.ps1` for the full suite; it runs pytest through Python so the repository is importable by the separate baseline tests. Without the integration flag, database cases are reported as skipped. Migration 0004 is additive and adds run state, counters and narrowly granted functions. Existing read-only tasks continue to work. The disposable database uses temporary container storage; restarting its project requires applying migrations and fixtures again.

For an interactive demo, keep both Compose projects running after preparation and use three terminals:

```powershell
.\.venv\Scripts\python.exe scripts/read_runtime.py knowledge
.\.venv\Scripts\python.exe scripts/read_runtime.py tickets
.\.venv\Scripts\python.exe scripts/assistant_runtime.py
```

Open `https://127.0.0.1:19481/`, sign in with a synthetic account from the ignored `.lab/phase2/credentials.json`, and submit `ticket-alice`. The lab certificate is locally generated; automated probes trust only that certificate and make no system trust changes. The browser needs an explicit local trust decision. Ports 19481–19483 must be free; do not run identity or live-read probes concurrently with these listeners. Stop the three processes, then bring both Compose projects down when finished.

`POST /tasks` also accepts JSON with `ticket_id` and `question`, using the session cookie and `Origin`/`X-CSRF-Token` headers. Results are returned to that request only. There is no task lookup, resume, shared-chat, posting or access-grant endpoint.

## Remaining exit work

The pinned local-model adapter, real key rotation and selected discovery profile are implemented, and the [Phase 2 read-only exit gate is met](phase2-exit.md). See the [model slice](phase2-model.md) for tokenizer, transport and deployment limits. Authentication sessions remain single-process with no refresh; deployment-grade identity lifecycle/revocation, admission throttling, service isolation and independent audit collection remain later work. No write capability is enabled.
