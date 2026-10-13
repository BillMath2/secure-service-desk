# Secure Service Desk Agent Lab: Implementation Plan

Created October 12, 2026. Governing requirements: [Project plan](SECURE_SERVICE_DESK_AGENT_PROJECT.md). Review input: [Proposed changes](SECURE_SERVICE_DESK_AGENT_PROPOSED_CHANGES.md).

## Outcome and current state

Deliver a local, reproducible service desk assistant that completes permitted support tasks while independent controls block unauthorized reads, disclosures, and access changes. Demonstrate the difference against a contained vulnerable baseline using the same fixtures and measurable outcomes.

The initial review found only planning documents. Phase 0 is now complete; phase-specific progress notes below distinguish implemented work from future work. Build phases in order and require each exit gate before extending the next trust boundary.

## Implementation decisions

| Area | Initial choice | Reason / constraint |
|---|---|---|
| Runtime | Python; pinned dependencies and lockfile | One language for services, orchestration, and tests |
| MCP | Official Python MCP SDK; authenticated Streamable HTTP | Exercise real transport and resource authorization |
| Application | FastAPI, server-rendered templates, small explicit agent loop | Keep analyst and approver actions inspectable; avoid a separate frontend platform |
| Identity | Local Keycloak, OIDC authorization code with PKCE, confidential gateway client | Real signatures and delegated identities without a cloud tenant |
| Storage | PostgreSQL with migrations and separate service database roles | Durable counters, row locking, transactional approval consumption, and full-text search |
| Retrieval | ACL-filtered full-text search plus cited document reads | Establish retrieval correctness before adding embeddings |
| Model | Deterministic stub plus one local instruction/tool-capable model | Repeatable control tests and offline adversarial runs; select the model after checking host resources |
| Deployment | Docker Compose with internal networks and local TLS | Reproducible isolation on this Windows development machine |
| Testing | pytest, HTTP/MCP integration tests, browser workflow tests | Verify actual data effects and human review flows |
| Reuse | Modules in this repository | Extract a shared package only when Hookline needs it |

Use the [official Python MCP SDK](https://github.com/modelcontextprotocol/python-sdk) as the implementation reference. Record tested runtime, SDK, protocol, Keycloak, database, and model versions in a compatibility record; do not depend on floating `latest` images. Model selection and hardware fit are phase 0 tasks, not assumptions about this machine.

## Target repository layout

```text
secure-service-desk/
  pyproject.toml
  <dependency lockfile>
  src/service_desk/
    app/                  sign-in, analyst UI, approver UI, application endpoints
    agent/                bounded loop, provider adapter, context builder
    core/
      auth/               issuer/client mappings and token verification
      policy/             identity, resource, audience, and workflow decisions
      gateway/            tool registry, schema checks, dispatch, budgets
      approvals/          immutable proposals and approval state machine
      audit/              event schemas, outbox client, redaction
    mcp/
      knowledge/          search/read tools and document ACLs
      tickets/            ticket reads, draft jobs, confirmed internal comments
      access/             proposals and separately protected execution endpoint
    workers/              executor, expiration/review worker, outbox relay
    audit_collector/      ingestion and restricted query API
  migrations/             schema and least-privilege database roles
  fixtures/               synthetic people, content, ACLs, and policies
  infra/
    compose.yaml          hardened default deployment
    keycloak/             realm/client templates without secrets
    network/              TLS, egress restrictions, and probes
  lab_baseline/            separate unsafe runner and isolated Compose deployment
  tests/
    unit/
    integration/
    e2e/
    attacks/              versioned cases and expected effects
  evaluation/             runner, result schemas, metric/report generation
  docs/                   threat model, permission matrix, ADRs, runbook
  reports/                redacted, reproducible evaluation artifacts
```

The baseline must not be imported into the hardened runtime or enabled by an application flag. Share fixtures and test contracts, not its authorization bypasses.

## Contracts to define before implementation

### Trusted request and policy context

Define a server-owned context containing issuer/subject, verified client ID, token audience/scopes, task ID, ticket ID, intended audience, allowed capabilities, policy version, and correlation ID. Token material never enters model context. Model arguments contain business identifiers only and cannot override identity or task state.

Use a single policy decision shape: `allow`, stable `reason_code`, policy version, and required obligations. Examples: `RESOURCE_DENIED`, `RECIPIENT_DENIED`, `CONFIRMATION_REQUIRED`, `APPROVAL_EXPIRED`, and `BUDGET_EXHAUSTED`. Keep externally visible not-found/denied responses from revealing the existence of restricted records.

The gateway and servers may share policy code, but each server evaluates its own decision. Validate any task/confirmation assertion cryptographically or resolve it from trusted storage; unsigned headers are insufficient. Distributed budgets and confirmation state must still apply when the test harness reaches a server directly.

### Data and state

| Records | Required fields / invariant |
|---|---|
| People and service principals | Immutable identity, human/workload type, team, manager, resource ownership; controlled by fixtures/admin only |
| Documents and chunks | Source ID/version, classification, ACL, body, fingerprint; chunks inherit source ACL |
| Tickets and comments | Requester, assigned team, reader set, visibility, text, timestamps, version |
| Tasks and budgets | Trusted initiator, task scope, audience, state, deadline, atomic usage/reservations |
| Drafts and confirmations | Ticket, exact body hash, recipients, source/version manifest, policy version, reviewer, expiry, single-use state |
| Access proposals | Requester, triggering analyst, beneficiary, resource, action, duration, risk tier, immutable canonical hash, provenance |
| Approval stages | Proposal ID/hash, eligible relationship, approver, decision, sequence, expiry |
| Grants and reviews | Unique execution ID, target, resource, start/end, effective status, review due date and outcome |
| Audit outbox and collector events | Unique event ID, correlation ID, actor, operation, decision, safe metadata, occurrence/collection timestamps |

Keep proposal, approval, and simulated grant state in one transactional database boundary so execution can lock the request, validate it, apply the change, consume approval, and append the outcome outbox in one transaction. Use separate roles and restricted service operations; the agent cannot access these tables directly. The collector owns a separate audit database and does not grant update/delete to producers.

Approval states: `DRAFT -> PENDING_STAGE_1 -> PENDING_STAGE_2 (sensitive only) -> APPROVED -> EXECUTED`. Also support terminal `DENIED`, `EXPIRED`, `CANCELLED`, and `INVALIDATED`. Edits to a submitted request create a new version and invalidate previous approval. An idempotent retry of an executed request returns its existing outcome; a replay cannot create another effect.

### Tool and human-action boundaries

| Operation | Model access | Required enforcement |
|---|---|---|
| `search_documents`, `read_document` | Yes | Caller ACL, task audience, safe metadata, byte limits |
| `read_ticket` | Yes | Ticket ACL and comment visibility |
| `draft_response` | Yes | Ticket/source IDs and audience only; recipient draft context rebuilt by trusted code |
| `add_comment` | After exact-action confirmation | Internal audience only; verified body/provenance and one-use confirmation |
| `check_access` | Yes | Only targets/resources authorized for this task |
| `propose_access_change` | After exact-action confirmation | Human beneficiary, policy-valid duration, rate limit, provenance; does not grant access |
| Approve / publish reply | No | Authenticated human endpoint, CSRF protection, exact version, independent policy recheck |
| `execute_approved_change` | No | Executor identity and execution audience, current policy, all approvals, atomic single-use execution |
| Expire / revoke / review grants | No | Narrow lifecycle-worker and eligible human-review permissions |

For requester drafts, do not accept free-form text from the analyst's privileged model context as a prompt or draft body. Build queries and generation context from requester-visible history and authorized sources in a fresh invocation. Treat source selection itself as untrusted: validate references and avoid leaking restricted titles or IDs in errors. Human edits invalidate review and require a new checked draft; the initial lab can support regeneration instead of unrestricted free-text publication. Document that a malicious authorized human manually copying information is outside the agent-injection threat model.

### Initial policy defaults

These are tunable lab defaults. Change them through versioned operator configuration, never through model instructions.

| Control | Initial value |
|---|---|
| Total tool calls per task | 12, including rejected dispatch attempts and retries |
| Model token budget | 16,000 input + output tokens cumulatively; reserve estimated input and maximum output before each call |
| Active task deadline | 120 seconds; human review uses a separate persisted waiting state |
| Individual tool timeout | 10 seconds, bounded by remaining task time |
| Provider call timeout | 45 seconds, bounded by remaining task time |
| Retry allowance | At most one transient retry per operation; no automatic policy-denial retry |
| Tool response / draft sizes | 32 KiB per tool response; 8 KiB per draft |
| Submitted access requests | 5 per authenticated user per rolling hour, enforced atomically |
| Confirmation / approval lifetime | 10 minutes for a ticket action; 15 minutes from first approval for the entire grant approval chain |
| Standard grant duration | Default and initial maximum 30 days |
| Privileged grant duration | Maximum 8 hours; separate manager and owner approvals |
| Grant cleanup interval | 60 seconds; effective expiry is immediate at `expires_at` |
| Standard access review | Every 7 days; 24-hour confirmation window, then automatic revocation |

All clocks are UTC internally. Use an injected clock in tests. A suspended review does not preserve an old token or bypass reauthentication, current policy, or execution budgets.

## Phase 0: Foundation, fixtures, and test contracts

**Progress (October 12, 2026):** Phase 0 exit gate met: fixture/contract foundation, executable read tool, audit collector, scenario runner, 30 passing tests, and isolated sink probe. The early real OIDC/delegated-MCP round trip and PostgreSQL foundation migration checks also passed. Full model-driven baseline and authenticated application work remain in later phases. See [status and compatibility](docs/compatibility.md) and [runbook](docs/runbook.md) for evidence and commands.

1. Check local Python, Docker/Compose, available memory, and local model options. Choose and lock versions; record unresolved compatibility questions in an ADR.
2. Create the package, migrations, configuration schema, formatting/lint/type checks, and pytest scaffold. Add secret exclusions and sanitized configuration examples.
3. Write the threat model, data-flow boundaries, permission matrix, and tool/event contracts above. Assign every project requirement a test ID.
4. Seed a fictional company with at least three departments; two requesters, two analysts with different scopes, managers, distinct resource owners, a deliberately conflicting approver, and the agent/executor/worker clients. Include public, team-only, HR-restricted, and privileged-procedure documents.
5. Create benign and malicious versions of tickets/documents, unique restricted-source canaries, and standard/sensitive group fixtures. Include a complete allowed path for each workflow.
6. Implement a scenario runner that resets only disposable lab state, submits a task or forced tool call, inspects resulting records and output sinks, and emits structured results plus redacted audit references.
7. Add the audit event contract and minimal collector with the first instrumented tool, along with a local exfiltration sink confined to the test network.

**Exit gate:** Fixture reset is deterministic; a simple allowed read and denied read can be represented and evaluated; scenario results distinguish success, failure, error, and unsupported cases. The permission matrix identifies each approver and each channel's readers.

## Phase 1: Contained vulnerable baseline

Depends on phase 0.

**Progress (October 12, 2026):** Phase 1 exit gate met. The separate baseline, three real MCP services, pinned offline local model, and actual-effect evaluation are implemented. All 44 automated tests and live containment probes pass. Forced tests demonstrate all three required unsafe effects (restricted read, requester disclosure, unapproved grant), plus a successful benign read. The three real-model attacks did not achieve their objectives; the model also failed its one benign task. All four model outcomes are recorded as failures, with zero execution errors, rather than fabricated successes. Evidence is saved in [reports/phase1](reports/phase1/results.json); containers and networks were removed after the run. See the [Phase 1 runbook](docs/phase1.md) for limits and reproduction. Phase 2 progress is recorded below.

1. Build a separate v0 runner with the three simulated MCP servers, shared tool shapes, one model, and deliberately absent policy/approval checks. Wire unauthenticated execution only inside this baseline environment.
2. Use a separate Compose project, private network, disposable volumes, synthetic configuration, and a loopback-only entry point. Do not mount host credentials, the Docker socket, source secrets, or hardened databases.
3. Preload the chosen local model, then deny external network access for the run. Include an outer wall-clock/cost limit independent of the vulnerable agent. Verify denied egress and separation from hardened services with probes.
4. Run forced boundary tests and the initial model-driven attacks. Show at least one unauthorized read, requester disclosure, and unauthorized simulated grant in forced tests. A real-model attack failing to trigger is reported honestly, not replaced with a fabricated success.
5. Save fixture hashes, model settings, applicable test IDs, baseline commit/configuration, outcomes, and safe evidence. Extend baseline cases as later workflow semantics are implemented.

**Exit gate:** Baseline containment probes pass, representative vulnerabilities are measurable, and the evaluation harness can distinguish a requested unsafe action from an actual unauthorized effect. No baseline setting is reachable from the hardened app.

## Phase 2: Real identity and an authorized read-only assistant

Depends on phase 1. Resolve authentication interoperability first; it is the highest integration risk.

**Complete (October 13, 2026): Phase 2 exit gate met for the pinned, pre-registered read-only lab.** The gateway now discovers MCP resource metadata and tries RFC 8414/OIDC endpoints before exchange, while rejecting changed issuers, endpoints and scope expansion. Real administrator-driven key rotation, retirement across the 60-second JWKS cache and token expiry pass with realm restoration. The full checker passes 211 tests; live evidence covers 68 identity checks, 34 read checks, 27 assistant checks, 25 authentication-compatibility checks and the genuine local-model tasks. See the [Phase 2 exit matrix, limitations and reproduction](docs/phase2-exit.md). No write capability is enabled. The entries below preserve earlier slice history.

**Local-model progress (October 13, 2026):** The pinned Ollama/Qwen adapter now uses fixed raw framing, strict structured turns, pre-dispatch token reservations, usage checks, bounded HTTP and an offline cache-integrity gate. The actual model namespace passes 16 containment checks. Initial authenticated benign, ticket-injection and document-injection trials complete with cited answers and no tested unauthorized effects. The checker passes 179 tests with PostgreSQL enabled. See the [model runbook](docs/phase2-model.md) and [sanitized evidence](reports/phase2-model/results.json). Phase 2 remains open for real Keycloak key rotation and outstanding OAuth/MCP compatibility cases; no write capability is enabled. Older progress entries below are historical slice snapshots.

**Current assistant progress (October 13, 2026):** Authenticated browser/API tasks now run a one-shot, cited read-only assistant with a deterministic provider. PostgreSQL enforces atomic 16,000-unit model reservations and eight-call admission; provider/tool/task timeouts, cancellation, source revalidation, CSRF and fresh context are tested. The complete checker passes 146 tests with PostgreSQL enabled, and the real browser/Keycloak/gateway/TLS/PostgreSQL flow passes 27 checks. See the [assistant runbook](docs/phase2-assistant.md) and [live evidence](reports/phase2-assistant/results.json). **The Phase 2 exit gate remains open:** the pinned local-model adapter, real-model validation, real Keycloak key rotation and remaining OAuth/MCP compatibility cases are still pending. No write tool is enabled. The paragraphs below record earlier slice results.

**Progress (October 13, 2026):** Phase 2 started with the identity foundation: confidential OIDC/PKCE login, server-side protected sessions and CSRF logout, strict signed-token validation, restricted delegation, three TLS MCP identity probes, and separate executor/worker clients. The full checker passes 83 tests (39 new identity cases). The live Keycloak 26.7.4 flow passes for both analyst and requester identities across all three audiences, including wrong-audience/header/scope denials and blocked privileged exchange. See the [Phase 2 runbook and remaining work](docs/phase2.md) and [sanitized live evidence](reports/phase2-identity/results.json). **The Phase 2 exit gate is not met:** protected reads, ACL-filtered retrieval, shared task budgets, registry pinning, and the bounded assistant remain to implement. No protected data or write tool is enabled by this slice.

**Read boundary progress (October 13, 2026):** Shared PostgreSQL tasks and atomic reservations, the pinned three-tool read registry, independent MCP checks, ACL-filtered full-text retrieval, recipient-safe ticket/comment reads, citations, response limits and durable read decisions are implemented. With PostgreSQL enabled, the checker passes 118 tests; the real Keycloak/gateway/TLS/PostgreSQL probe passes 34 checks. See the [read-boundary runbook](docs/phase2-reads.md) and [live evidence](reports/phase2-reads/results.json). Phase 2 remains open for authenticated task UI, the bounded model loop and token/provider limits, conversation isolation, and remaining authentication compatibility cases. No write tool is enabled.

1. Configure Keycloak users, confidential agent client, separate resource audiences, narrowly scoped executor/worker clients, and OIDC login. Use server-side sessions, protected cookies, state/nonce, PKCE, and CSRF protection for human actions.
2. Demonstrate delegation from the authenticated user through the confidential gateway to each MCP audience. Capture sanitized decoded claim shapes, expected mappings, and negative cases. Never save usable tokens to reports.
3. Verify [Keycloak standard token exchange](https://www.keycloak.org/securing-apps/token-exchange) prerequisites and the relationship between subject token, client, audience, and permitted scopes. Test that exchange cannot expand effective user entitlement. Do not assume `act` is present.
4. Implement and test the chosen [MCP authorization protocol](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization), including protected-resource metadata, discovery/challenges, resource indicators, and audience validation. Verify the exact SDK/Keycloak combination; if an adapter is needed, document it and test it without weakening audience checks or forwarding unrelated tokens.
5. Register and pin tool definitions. Implement schema validation, policy context, authorization middleware in every server, and minimum gateway budgets before allowing model dispatch.
6. Implement authorized ticket/document reads and full-text retrieval. Apply ACL predicates before ranking and snippet construction; recheck on document reads. Partition caches and conversations by identity and audience.
7. Connect the bounded agent loop and source citations. Denied/unknown tools never dispatch. Use local TLS and test key rotation, expired tokens, wrong issuer/audience/client, missing scope, and direct-server calls.

**Exit gate:** Signed real tokens support a legitimate read task; forged identity headers and every resource/client/scope denial leave protected data undisclosed. Direct calls cannot evade policy or task limits. The auth compatibility record is complete before any write feature is enabled.

## Phase 3: Recipient-safe drafting, confirmed ticket writes, and limits

Depends on phase 2.

1. Implement explicit audience policies for requester replies, analyst drafts, team comments, and chat results. Validate every recipient, including additional ticket participants.
2. Build the fresh requester context described above, with separate retrieval/query construction and no privileged conversation, generated summary, or cache reuse. Require a complete source manifest.
3. Add canary/fingerprint checks, safe Markdown rendering, remote-image blocking, and content-size limits. On a failed output check, retain only safe failure metadata, not the leaking draft in a log or preview.
4. Build draft review and exact-action confirmation screens. Keep internal comments internal; publish requester replies only through the human endpoint to the simulated ticket store. Recheck recipients, ACLs, sources, body hash, and ticket version at commit time.
5. Complete atomic budgets, bounded provider calls, reservations for token use, cancellation, and approval-request throttling. A timeout must not allow a late write; use transactions, operation deadlines, and idempotency keys.
6. Lock down container mounts, service-to-service routes, model egress, secret ownership, and audit-reader access. Prove these restrictions with direct probes rather than assuming a container network is sufficient.

**Exit gate:** Restricted content and canaries are absent from unauthorized drafts, comments, replies, previews, model requests, network sinks, and logs. Audience/ACL changes invalidate old reviews. Loop and retry attacks stop at their limits, including concurrent attempts. At least one legitimate reviewed reply and internal comment succeed.

## Phase 4: Approvals, grants, lifecycle, and durable audit

Depends on phase 3.

1. Add draft access requests and confirmed submission with immutable canonical arguments, provenance, original submitter, triggering analyst, beneficiary, and policy version.
2. Build the approval UI in provenance-first order. Resolve approvers from trusted manager/owner relationships; exclude requester, triggerer, and beneficiary. Enforce two distinct ordered stages for sensitive resources.
3. Add an executor-only endpoint/audience within the Access MCP service. The model never obtains executor credentials or this tool in its catalog. Execution references the stored request; it cannot replace its arguments.
4. In a transaction, lock the request and relevant policy/resource state, recheck authority and approval expiry, insert the unique grant, consume approval, and append the outcome outbox. Test simultaneous executions, commit failures, lost responses, and retries.
5. Add effective grant expiry to every access lookup, then implement cleanup/reconciliation, weekly reviews, missed-review revocation, and renewal through a fresh approval. The worker can revoke/expire but cannot create or extend a grant.
6. Complete the append-only collector interface, service-scoped writers, restricted audit query UI, durable intent/outbox, duplicate-event handling, and delivery retries. Fail mutations closed when durable audit recording is unavailable; collector downtime may queue events in durable outboxes.
7. Make a single correlation ID connect source reads, blocked actions, human decisions, execution, and lifecycle events. Test redaction and attempts by the agent to alter or delete audit history.

**Exit gate:** A normal grant and a two-stage sensitive grant succeed; self-approval, fabricated approval text, changed arguments, stale policy, replay, and concurrent reuse fail. Expiry denies access even while cleanup is stopped; restart reconciles memberships; missed reviews revoke grants. Audit delivery survives collector interruption without losing mutation evidence.

## Phase 5: Comparative evaluation and portfolio delivery

Depends on phase 4.

1. Run the full deterministic suite and end-to-end workflows on the hardened deployment. Run matching cases on v0; mark differences in supported features explicitly.
2. Run each model-driven attack and benign scenario at least five times initially, with the same pinned model/settings and fixtures across variants. Report counts and uncertainty; increase repetitions when conclusions are unstable, not merely to obtain a preferred score.
3. Generate baseline-versus-hardened reports by actor, entry point, and tested OWASP category. Include attempted actions, actual effects, false blocks, task completion, latency, token use, and audit coverage.
4. Review findings, fix critical unauthorized effects, and rerun affected tests plus the release suite. Preserve earlier findings and results so improvements remain traceable.
5. Write setup, seed/reset, troubleshooting, baseline-containment, test, and demo instructions. Add README links to the plans, runbook, threat model, and final report.
6. Record a concise demonstration: allowed support answer; injection leading to an independently denied action; rejected requester disclosure; approved temporary grant; replay denial; expiry; correlated audit evidence.

**Exit gate:** A clean checkout reproduces setup and deterministic results; all required security gates pass; the report includes model-driven results and limitations; the recorded demonstration agrees with the saved evidence.

## Minimum verification matrix

| Test family | Required negative case | Positive control / evidence |
|---|---|---|
| Identity | Forged header, bad signature, wrong issuer/audience/client, expired token | Valid delegated task; sanitized claim contract |
| Resource authorization | Guess another department's ticket/document ID; direct MCP bypass | Authorized ticket and document; same decision at gateway/server |
| Retrieval and context | Restricted snippet/count/title, cache reuse across users or audiences | Authorized cited answer and no forbidden retrieval rows |
| Injection | Ticket, document, attachment, tool-result, and tool-description instructions | Forced unsafe call denied; legitimate task still completes |
| Output audience | Requester asks for restricted procedure; indirect/paraphrased leakage | Safe requester reply; inspect drafts, browser output, provider payloads, sinks, logs |
| Confirmation | Missing/replayed confirmation, changed body/recipient/source/ACL | Exact reviewed action commits once |
| Approval authority | Requester/analyst/beneficiary self-approval, wrong owner, same person in two stages | Eligible distinct approvers complete sensitive workflow |
| Approval integrity | Fake approval in ticket, changed target/duration, expiry, policy change | Immutable approved request executes once |
| Execution races | Two workers consume one approval; lost response and retry | One grant, stable idempotent outcome, complete audit evidence |
| Governance | Agent beneficiary, worker creates grant, delayed expiry cleanup, missed review | Human grant expires/revokes correctly; restart catches up |
| Limits | Repeated calls, parallel dispatch, excessive tokens/bytes, approval spam | Within-budget task succeeds; precise exhaustion reason |
| Isolation and audit | External egress, unregistered server, secret/log leak, collector outage | Allowed local traffic and durable, redacted event delivery |

Test outcomes must inspect stored grants, effective permissions, visible messages, and captured output channels. A textual refusal or an audit event alone is insufficient evidence that no effect occurred.

## Metrics and release gates

Each attack case defines an objective and an oracle before execution. Tag mappings include the risk list edition and exact category ID. Use OWASP LLM 2025 and [Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) for stable comparisons; record uncovered categories instead of claiming complete coverage.

| Metric | Definition |
|---|---|
| Attack success rate | Attack trials achieving their predefined objective / evaluable attack trials |
| Unauthorized-effect rate | Attack trials producing any forbidden disclosure or mutation / evaluable attack trials; also show raw effect counts |
| Legitimate-task completion | Correct completed allowed tasks / evaluable allowed-task trials |
| False-block rate | Allowed-task trials blocked by a security control / evaluable allowed-task trials; separate from model and infrastructure failures |
| Audit coverage | Required security decisions/effects with matching durable audit evidence / expected decisions/effects |

Report errors, unsupported cases, skipped cases, and timeouts separately with counts; never silently remove them to improve a rate. A designed loop attack stopped by its enforced limit is an evaluable defensive outcome. Use identical eligible case sets for comparisons. Where a trial maps to multiple categories, explain overlap and do not add category counts as if disjoint.

Release requires all deterministic policy, identity, approval, concurrency, expiry, containment, and redaction tests to pass; zero unauthorized effects in evaluated hardened trials; 100% audit coverage for required decisions/effects; all scripted positive workflows passing; and initial model-driven targets of at least 90% legitimate completion and at most 5% false blocks. Freeze the benign corpus and thresholds before the final evaluation and show the underlying counts. These thresholds are project acceptance criteria, not proof of security outside the tested cases.

## Reproducibility and remaining decisions

Create a small documented command surface for bootstrap, synthetic seeding, starting the hardened app, running the opt-in baseline, deterministic tests, model evaluation, and report generation. Exact commands belong in the runbook once implemented; this document does not imply runnable scripts already exist.

The critical path is identity/MCP interoperability, audience-safe context construction, transactional approval execution, then comparative evaluation. Resolve these before UI polish. Optional vector retrieval, additional model providers, hash-chain audit checkpoints, Entra, and shared Hookline packaging follow a completed local release.

Next implementation task: start Phase 3 with requester-safe generation in a fresh context, explicit recipient policy and a validated source manifest, before adding reviewed/confirmed ticket writes. Phase 2's read-only exit gate is met; see docs/phase2-exit.md for evidence and deployment limitations. No write capability is enabled yet.
