# Access approvals, grants, lifecycle and audit

Phase 4 adds a complete temporary-access workflow to the authenticated local lab. Its implementation is in migrations 0012–0013, the `access_*` modules, the executor MCP service, and the Phase 4 container processes. The [exit record](phase4-exit.md) separates deterministic tests, deployed effects and model observations.

## Run the lab

```powershell
.\scripts\phase4.ps1 Start
.\scripts\phase4.ps1 Check
.\scripts\phase4.ps1 Stop
```

Pass `-DockerPath 'C:\Users\Bill\AppData\Local\Programs\DockerDesktop\resources\bin\docker.exe'` when Docker is not on PATH. Prerequisites are the bootstrapped Python environment, Docker Desktop Linux containers, the Phase 2 identity/model material and verified model cache, and the locally built images pinned in `config/phase4.lock.json`, `config/isolated-reads.lock.json` and `config/local-model.lock.json`. The earlier [model setup](phase2-model.md) explains cache preparation. Start never downloads an unpinned replacement runtime image.

Open `https://127.0.0.1:19481/access` after trusting the generated local CA. Synthetic passwords remain in ignored `.lab/phase2/credentials.json`; staging gives each runtime only its own authority. Sign in as Erin to draft and submit a request for Alice's ticket. Morgan is Alice's manager; Olivia owns the engineering resources. Harper is the explicitly assigned audit reader. Sign out before switching identities.

Use `engineering-workspace` for standard access or `engineering-admin` for sensitive access. Every submission and approval requires a separate exact review and confirmation. Refresh the inbox to see the executor's result. The standard grant's continued-access review is available to an eligible manager or owner. Renewal means creating and approving a fresh request.

`Check` stops Phase 4 background services during PostgreSQL tests, then restores them before the live probes. Tests and workflow probes operate on the disposable synthetic database and create or change fixture records. Stop removes this lab's containers/networks and its tmpfs database; it preserves ignored keys, image/model caches and saved reports. It does not stop Docker Desktop or unrelated projects. Run Start again for a fresh fixture database.

## Authority and workflow

The model catalog contains the existing read tools plus `check_access` and `propose_access_change`. These use the access-proposal service and the same shared task budget. A proposal resolves its beneficiary from the authenticated task's ticket requester. It accepts a resource and optional bounded duration, with a fixed server-generated explanation. It has no argument for a beneficiary, approval, executor credential or free-form justification. A privileged chat transcript is never copied into an approver's proposal context.

The human form can supply a justification, which is screened against the proposal audience and displayed as untrusted text. The review shows original ticket, submitter and timestamp; source hashes; policy and state; recorded approvals; exact action; and finally the justification. The canonical action hash binds provenance, beneficiary, resource, duration, triggerer, submitter, manager, owner, policy version and justification hash. Request records and decisions are immutable to runtime roles.

A session-bound, expiring confirmation token authorizes only that exact action. The authenticated browser and workflow service independently verify the signed user. Neither a service secret alone nor a bearer token alone authorizes the workflow RPC. CSRF, origin, byte and time limits apply. The server resolves trusted manager/owner relationships and ticket readership again at confirmation and execution.

Standard access requires one eligible manager **or** owner. Sensitive access requires manager first, then a distinct owner. The requester, triggering analyst and beneficiary cannot approve. Missing or conflicting relationships and nonhuman beneficiaries fail closed. Even standard requests require both trusted, distinct, nonconflicting relationships to exist; this is a conservative lab policy.

The default policy caps standard grants at 30 days, sensitive grants at eight hours, and submitted approval windows at 15 minutes. Drafts expire after ten minutes. Confirmations last at most five minutes and never outlive their bearer or request/review window. An analyst can create at most 20 drafts and submit five requests per hour; pending/approved global admission is capped at 64. Review-token issuance is capped at 20 per minute per person. Policy changes invalidate prior proposals.

The executor runner alone holds the executor OAuth client secret. It obtains a short-lived execution-audience token and calls the separate MCP endpoint. That endpoint accepts only its pinned workload client/audience and exposes a bounded approved queue plus execution by stored request ID/hash. The agent has neither this tool catalog nor network access to that endpoint. Execution rechecks current policy and approvals under locks, creates one unique grant and directory membership, consumes approval, and appends intent/outcome records in the same transaction. A failed transaction creates no grant; lost responses and retries return the original receipt without extending access.

## Lifecycle and audit

Effective access checks evaluate expiry, review deadline and revocation directly, independently of stale directory-membership rows. Standard grants are due for review every seven days, with a one-day review window. Continued-access review moves only the review deadline, never the grant's expiry. Expired or missed-review grants deny access even when the worker is stopped. The worker removes stale memberships and restores missing memberships only for already-valid grants; its role cannot create or extend a grant. A renewed grant needs a fresh request and independent approval.

Each mutation records durable intent and outcome in its database transaction. If that write fails, the mutation rolls back. Collector downtime does not invalidate a committed mutation: service-scoped delivery retries pending events. The collector accepts one immutable event per writer/event ID, accepts identical retries, and rejects changed duplicates. Runtime roles cannot directly read, update, delete or truncate grant/audit tables. Only the workflow query function admits the designated auditor.

A task correlation ID connects source reads, model proposals, denied confirmations, human decisions, execution and lifecycle cleanup. Audit envelopes contain identifiers, operations, policy version, stage, reason and time; they exclude ticket bodies, justifications, bearer tokens and credentials. Runtime container logging is disabled, and the log probe scans the database/identity logs in memory without saving captured text.

## Runtime separation

Every row below is a separate container, bridge, leaf TLS key and exact read-only material mount. Bootstrap installs a default-deny inet outbound policy and drops all capabilities before running as UID/GID 65532. Listeners use the bounded Phase 3 TLS/HTTP server. Only loopback host ports are published.

| Process | Host port | Initiated connections | Private authority |
|---|---:|---|---|
| Browser | 19481 | Identity, agent, publisher, workflow | Web OIDC and three RPC secrets; no database login |
| Agent | 19486 | Database, identity, knowledge, tickets, proposals, model relay | Task-creator/gateway logins, gateway OIDC and agent RPC secret |
| Workflow | 19488 | Database, identity, collector | Human workflow login, RPC and workflow audit secrets |
| Proposals | 19484 | Database, identity | Proposal-only database login |
| Execution MCP | 19489 | Database, identity, collector | Executor database login and execution audit secret |
| Collector | 19490 | Database | Collector login and four writer secrets |
| Lifecycle worker | 19491 | Database, collector | Lifecycle login and lifecycle audit secret |
| Executor runner | 19492 | Identity, execution MCP | Executor OAuth secret; no database login |
| Read-event delivery | 19493 | Database, collector | Outbox-delivery login and reads audit secret |

The publisher, knowledge, tickets, model relay and model containers retain their separate Phase 3 boundaries. The old Phase 3 browser and agent are stopped when Phase 4 starts. Direct positive-controlled IPv4 probes cover all 14 runtime namespaces; inspected inet rules also default-deny IPv6, but this environment has no live IPv6 reachability control.

## Scope and operational limits

### Model task completion

The local adapter uses a final-answer-only response schema after a successful `propose_access_change` result. It rejects a further tool turn even if the provider violates that schema. The transition depends on structured, successful tool history, never on a ticket claiming that a proposal succeeded. A new task starts with fresh history. Preparing another proposal requires another task; human submission, approval and execution remain separate actions.

The proposal catalog tells the model to omit an unspecified duration so the database selects the resource-specific default. Explicit durations still pass the same independent policy checks. MCP denials stop the task with an allowlisted control code; arbitrary error text is never returned. Stable policy and tool definitions precede growing history in each complete model request, reducing repeated prefix processing without increasing the 45-second provider timeout, 120-second task deadline or 16,000-unit reservation budget.

The model probe records content-free failure codes, task/audit timing and image pins. It requires exactly one correctly bound local draft, its actual request ID in the answer, a human review/confirmation explanation, and no approval or grant. These are functional observations; repeated comparative evaluation remains Phase 5.

### Local image updates

When runtime source changes, rebuild both scoped images, inspect their immutable IDs, and update the matching Compose files and `config/phase4.lock.json`, `config/isolated-app.lock.json` and `config/isolated-reads.lock.json` before running the gates:

```powershell
docker build --pull=false -f infra/app.Dockerfile -t service-desk-app:phase4 .
docker build --pull=false -f infra/reads.Dockerfile -t service-desk-read:phase4 .
docker image inspect service-desk-app:phase4 service-desk-read:phase4 --format '{{.Id}}'
```

The deployment gates compare the entire installed Python source inventory with the working tree. Both images therefore need refreshing even if a changed module is unused by a particular service. Dependency versions remain locked; local build IDs may differ with build metadata. Startup uses the reviewed immutable pins, not the mutable build tags.

### Trust and storage limits

The directory is a synthetic PostgreSQL adapter. Grant creation and its audit outbox share a transaction; integrating a real external directory would require an additional idempotent effect/reconciliation protocol. The collector is independently authenticated and credential-scoped but uses a separate protected table in the **same PostgreSQL instance**. This is not protection against the trusted database administrator, host administrator or storage loss. The outbox survives collector, executor and application-container restarts. The database itself uses tmpfs: stopping/recreating the database container or tearing down the lab discards its records. Production backup, replication, retention and physical audit-store separation are outside this lab.

A global source/authorization epoch conservatively invalidates proposals when any protected fixture source, ACL, relationship or access policy changes, even an unrelated one. Recreate and reapprove a proposal after such a change. This also prevents a stale preview from displaying newly restricted material. Screening remains the documented canary/fingerprint boundary, not a general semantic proof. The fixed model proposal explanation avoids introducing privileged generated prose into approval review. Repeated attack/benign comparisons and final clean-checkout delivery belong to Phase 5.
