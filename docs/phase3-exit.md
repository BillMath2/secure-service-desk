# Phase 3 exit matrix

October 14, 2026. [Machine-readable selected evidence](../reports/phase3-deployment/results.json). Scope: the pinned synthetic lab, fixed ticket/public-guide draft recipe, IPv4 loopback deployment and local Qwen3-4B-Instruct-2507 model. The [implementation/runbook](phase3.md) describes the boundaries and startup/check/stop commands. **The Phase 3 exit gate is met for this scope.** All final records below passed; earlier checkpoint failures remain retained separately.

| Exit requirement | Evidence and actual-effect oracle |
|---|---|
| Every output has an explicit authorized audience | Self-only chat; requester plus every registered participant; all registered internal staff. Recipient and source changes, including revoke/restore, invalidate old reviews. Tests: `test_requester_drafts.py`, `test_internal_drafts.py`, `test_draft_reviews.py`. |
| Fresh requester context and complete provenance | Two server-selected reads, complete independent manifest, no caller prompt/source override or privileged history reuse. Real-model channel trials observe internal-to-requester freshness and injected public-document instructions for Erin and Alice. Only request hashes and safe outcomes are retained. |
| Unauthorized content absent from released answers, drafts and previews | Private database canary/fingerprint screening for chat and both draft channels; forced hostile-provider cases; escaped HTML, no rendered Markdown/images, restrictive CSP. Tests: `test_chat_output.py`, `test_task_ui.py`, `test_draft_reviews.py`. Actual model/browser probes check restricted markers and credentials in responses and previews. |
| Human review binds the exact action | Immutable body/hash, source manifest, recipients, channel, session-bound expiring confirmation and current ticket/policy state. Altered hash, cross-channel reuse, changed ACLs, stale review and concurrent confirmation tests. Actual browser probe confirms the exact stored body and visibility and repeats confirmation with the same receipt and no second comment. |
| Legitimate reviewed reply and internal comment succeed | Real browser login, real local inference, authenticated TLS MCP reads, review and confirmation succeed for both benign and injected tickets. Stored comments are checked independently of model claims. Chat also completes with a citation and no publication. |
| Loops, retries and concurrent work stop at shared limits | Atomic per-person/lab admission; tool/model/token reservations; absolute task/provider/transaction deadlines; bounded TLS, HTTP and relay resources. Publication rolls back on audit failure or timeout. Tests: `test_agent_tasks.py`, `test_task_admission.py`, `test_publication.py`, ingress/relay/database-limit suites. |
| Credentials, mounts and service routes are separated | Browser has no database login; agent cannot publish; publisher has no gateway/model credential. Exact per-role mounts, leaf keys, commands, environments, images and actual unprivileged processes are inspected. Independent RPC service/user authentication is tested. |
| Model/runtime cannot reach forbidden network sinks | Exact default-deny policies plus a seven-namespace IPv4 matrix with neutral reachable before/after TCP/UDP controls, alternate destinations/ports, Docker DNS and actual allowed/denied host services. Model inference still succeeds after its Docker DNS path is closed. |
| Logs and audit do not expose content or authority | Runtime container logging disabled; safe fixed errors and content-free audit fields; all five runtime database logins lack audit-table read/write privileges. Actual model channel trials check audit metadata for canary/credential absence; log inspection checks PostgreSQL/Keycloak output in memory and verifies disabled application/model logging. Audit-failure regressions verify rollback. Operator/admin access is explicitly trusted. |

## Final validation records

- [Deterministic regression record](../reports/phase3-deployment/runs/20261014T105228Z/regression.json): **649 passed**, including **173 PostgreSQL cases**, with zero failures/skips. Lint, formatting and strict typing passed in the same command.
- [Application process/credential gate](../reports/phase3-deployment/runs/20261014T104902Z/application.json): 86 checks passed.
- [Read-service deployment and authenticated reads](../reports/phase3-deployment/runs/20261014T105212Z/isolated-reads.json): 65 checks passed.
- [Model/relay deployment and containment](../reports/phase3-deployment/runs/20261014T104832Z/containment.json): 39 checks passed.
- [Final network matrix](../reports/phase3-deployment/runs/20261014T105350Z/network-matrix.json): **213 checks passed** across seven namespaces, including reachable controls and prerequisite gates.
- [Real-model channel trials](../reports/phase3-deployment/runs/20261014T105509Z/channels.json): **4/4 passed** (two benign, two injected document trials), each with one actual model call and no publication.
- [Real browser/model workflow](../reports/phase3-deployment/runs/20261014T105725Z/workflows.json): **65 checks passed**, including cited self-chat and **4/4 confirmed publications** across benign/injected tickets and requester/internal channels. Altered hashes were denied and repeated confirmations produced no duplicate comments.
- [Post-workflow log inspection](../reports/phase3-deployment/runs/20261014T105746Z/logs.json): **18 checks passed**. Seven runtime log drivers are disabled; PostgreSQL/Keycloak logs contain none of the tested restricted markers, fixture credentials or JWT patterns. Raw logs were neither saved nor displayed.

Counts overlap: the network and workflow probes rerun prerequisite gates. Do not sum checks into a statistical attack denominator. Earlier successful and failed reports remain in `reports/phase3-deployment/runs`; only the linked final records apply to this completion claim.

## Scope and next phase

These are functional and adversarial samples, not a broad model-resistance rate. Fingerprints detect exact normalized overlaps and canaries, not every paraphrase or encoding. IPv6 default denial is inspected in the exact `inet` policies; live positive-controlled IPv6 testing is not claimed. The trusted operator, Docker daemon, database administrator and identity administration plane are outside the runtime model boundary. The model relay is loopback HTTP; identity, application RPC and MCP use verified local TLS. Multi-user host isolation is not claimed.

Phase 4 starts next: immutable access requests, provenance-first approvals, executor-only grants, expiry/review lifecycle and durable audit delivery. Phase 5 retains broader source/attack coverage, repeated baseline comparisons, statistical acceptance targets, clean-checkout release validation and the recorded demonstration. No Phase 4/5 completion is implied by this gate.

The documented startup and teardown commands were exercised. All five service-desk Compose projects and neutral probe containers were removed after verification; unrelated Docker projects were left unchanged. Docker Desktop, local images, ignored credentials and the external model cache remain available.
