# Phase 2: shared limits and authorized reads

Current hardened deployment: [Phase 3 startup and exit evidence](phase3.md#verification-and-reproduction) supersede the host-process limitations and older commands below. Use `scripts/phase3.ps1` for separate browser/agent/publisher/read containers and checked model/relay egress. Historical results below retain their original scope.

Current isolation option: the [Phase 3 read deployment](phase3.md#read-service-process-and-credential-separation) runs knowledge and tickets in separate credential-scoped containers with its own live probe. Use that path for filesystem/process isolation; the older host runtime commands below remain compatibility helpers. Rerun `prepare_phase2.py` to create the web/gateway credential export required by the shared client loader.

Current deployment update: [Phase 3 database capacity controls](phase3.md#database-connection-capacity) now apply to the shared read database and runtime entry points. Start the current Compose project and rerun `scripts/prepare_read_store.py --apply` before launching services; the gate rejects older server settings. Historical Phase 2 reports below retain their original scope.

Implemented October 13, 2026 after the [identity foundation](phase2.md). The full checker passes **118 tests** with PostgreSQL enabled: 95 default tests and 23 database integration cases. The separate live Keycloak → gateway → TLS MCP → PostgreSQL probe passes **34 checks**. Its [sanitized report](../reports/phase2-reads/results.json) records source hashes and runtime versions. The model was not invoked. Phase 2's assistant exit gate remains open.

## What is implemented

The approved catalog contains `read_document`, `search_documents`, and `read_ticket`. Definitions include descriptions, strict argument schemas and read-only annotations. A [reviewed snapshot](contracts/read-tools-v1.json) makes local catalog changes visible in tests. The gateway compares the complete remote catalog against its local definitions before dispatch. Changed descriptions, schemas, extra metadata, duplicate tools, unknown tools and unexpected pagination fail closed. Model arguments cannot supply identity, recipients, task state, server URLs or policy overrides.

Migration 0003 adds durable tasks, reservations, audit decisions, ticket/comment ACLs and PostgreSQL full-text indexing. Trusted application code creates tasks from a verified login and a ticket the caller can read. The audience is either the caller (`self`) or that ticket's requester; the database resolves the actual readers. The task stores the issuer/subject, mapped human, ticket, recipients, allowed capabilities, policy version, deadline, correlation ID and limits. The gateway and MCP services cannot create tasks or update counters directly.

Each new gateway attempt reserves one of the task's 12 slots before schema checks or remote discovery. The reservation binds the task, service, reviewed tool name and canonical argument hash. The server independently validates the signed user, atomically consumes the reservation once, checks the task and current policy, then performs its own resource authorization. Direct calls without a reservation reserve their own slot in the same database. Invalid or replayed reservation references also consume a rejected-attempt slot for the verified task owner. A different user cannot spend the owner's budget or consume their reservation. Reservations are never refunded, including failures and timeouts. Calls that cannot authenticate, parse as MCP requests, or identify an owned task are rejected before admission.

Concurrent calls to knowledge and tickets share a single locked counter. Tests show exactly 12 successful reads from 24 concurrent attempts, with the other 12 stopped at the budget. Simultaneous reuse of one reservation returns content once. Unknown tools, schema failures and forged reservation references exhaust the same limit. Reconstructing service instances does not reset task state.

The default active-task lifetime is 120 seconds. Service reads have a ten-second deadline bounded by remaining task time; SQL statements receive the remaining timeout. The gateway bounds its remote request sequence and streams at most 32 KiB without accepting compressed responses. The service measures the escaped MCP text envelope, reserves space for JSON-RPC overhead and checks deadlines again before releasing data. A revoked, expired or stale-policy task cannot return a body even if invalidation occurs during its read. These are read controls; cancellation-safe writes, model-token reservations and provider budgets remain later work.

## Resource enforcement

Document reads require the caller and every recipient to be explicit document readers. Searches first materialize the authorized document set, then apply PostgreSQL `websearch_to_tsquery`, ranking and snippet construction. Restricted titles, IDs, snippets, canaries and global result counts are absent from returned search data. Subsequent document reads recheck current ACLs. PostgreSQL's [text-search controls](https://www.postgresql.org/docs/18/textsearch-controls.html) define the search functions used here; snippet strings are untrusted plain text, not trusted HTML.

Ticket reads are restricted to the task's stored ticket and current reader set. Each comment requires every intended viewer's permission; internal comments are additionally withheld whenever the requester is a viewer. Knowledge reads also verify that the task's ticket remains visible. Restricted and nonexistent document/ticket IDs produce the same resource-unavailable result. Returned documents and tickets have source/version citations; complete document reads also include a body fingerprint. There is no conversation or result cache in this slice.

Live evidence demonstrates Erin's permitted internal read, Alice's denied internal read, HR denial for both, requester-recipient restrictions, permitted cited reads, hidden search metadata, and a common counter for gateway and direct MCP calls. No textual model refusal is used as the security oracle.

## Database and audit boundary

The creator, gateway, knowledge and tickets services use separate LOGIN credentials belonging to narrow group roles. Security-definer functions have a fixed search path and no PUBLIC execution permission. Services can reserve/consume/finish attempts through those functions; they cannot reset task budgets, create tasks, edit content or delete audit rows. Knowledge and tickets have only their service's necessary data reads. The model receives no database credentials.

Reservations and outcomes persist before content is returned. Events contain task/correlation IDs, approved operation labels and stable reasons, not queries, source bodies, guessed resource IDs, tokens or raw exception messages. Audit failure suppresses output. This is a minimal read-audit boundary in the application database; the independent collector, outbox relay and comprehensive unauthenticated-denial audit remain Phase 4 work.

The fixture/admin harness deliberately holds migration credentials. Runtime MCP commands load only their service's `.dsn` file. All local credential files are under ignored `.lab`; separate filesystem/container mounts and final network isolation remain to be built. The database has a loopback binding and disposable storage, but its host connection is not TLS and this Compose project is not an egress-denied attack environment.

## Reproduce

Run from the repository root with Docker Desktop's Linux engine available:

```powershell
.\scripts\bootstrap.ps1
.\.venv\Scripts\python.exe scripts/prepare_phase2.py
.\.venv\Scripts\python.exe scripts/prepare_read_store.py
docker compose -f infra/compose.phase2-reads.yaml up -d --wait
docker compose -f infra/compose.phase2-identity.yaml up -d
try {
    .\.venv\Scripts\python.exe scripts/prepare_read_store.py --apply
    if ($LASTEXITCODE -ne 0) { throw 'Read database preparation failed' }
    $env:DESK_READ_INTEGRATION = '1'
    .\scripts\check.ps1
    .\.venv\Scripts\python.exe scripts/check_phase2_reads.py
    if ($LASTEXITCODE -ne 0) { throw 'Live read checks failed' }
} finally {
    Remove-Item Env:\DESK_READ_INTEGRATION -ErrorAction SilentlyContinue
    docker compose -f infra/compose.phase2-identity.yaml down
    docker compose -f infra/compose.phase2-reads.yaml down
}
```

Without `DESK_READ_INTEGRATION=1`, pytest explicitly skips the 23 database cases; they do not count as passing. The opt-in cases use only the fixed prepared lab database. No live service credentials are accepted from model input. The preparation command refuses a different database name and preserves existing fixtures only when their recorded fingerprint matches. It does not truncate or reset another database. To reset, recreate only `infra/compose.phase2-reads.yaml`; its container storage is disposable.

The live probe starts and stops the two TLS read MCP listeners on 19482/19483. Keycloak runs on 19443 and PostgreSQL on 15433. Do not run the earlier identity probe or persistent MCP commands on the same ports concurrently. The existing identity realm configuration and its seven-day certificate are reused, with certificate verification enabled and no system trust changes.

For persistent read endpoints, use the repository Python with `scripts/read_runtime.py knowledge` and `scripts/read_runtime.py tickets` in separate terminals after preparation. The subsequent [assistant slice](phase2-assistant.md) adds authenticated browser/API tasks and a bounded deterministic provider. The `access` service remains an identity-only probe. No access-check/grant or ticket-write tool has been enabled.

Reports under `reports/runs/phase2-reads/` use unique filenames. The selected successful report under `reports/phase2-reads/` contains no usable credentials or protected content. Both disposable Compose projects were removed after validation.

## Remaining Phase 2 work

The subsequent assistant, local-model and authentication-compatibility slices are complete. The [Phase 2 exit gate is met](phase2-exit.md) for the pinned read-only lab. The final regression includes genuine local-model tasks; small initial trials do not establish later model-quality targets. Phase 3 recipient/confirmation/output controls remain required before writes are enabled.
