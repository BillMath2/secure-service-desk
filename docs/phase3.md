# Phase 3: recipient-safe drafts and confirmed comments

Status: Phase 3 implementation is complete for the pinned synthetic IPv4 lab. The final exit-gate evidence and reproduction commands are below. Phase 4 approval/grant workflows and Phase 5 repeated comparative evaluation remain separate work.

## Review of the other session

Commit `39639ec` added the security-framework crosswalk, AI RMF crosswalk, recommendations, README/requirements links, and `AML.T0051.001` on two fixture scenarios. It changed no runtime authorization code. The mappings correctly separate forced authorization tests from genuine model trials and planned controls from tested ones.

The recommendation to validate taxonomy IDs is still outstanding: `risks` remains a free-form array, and the Phase 2 model-case configuration has no risk tags. A shared risk register and expanded taxonomy coverage are recommendations, not completed evidence. Preserve the existing conservative claims when expanding them.

Adding those fixture tags changed the fixture fingerprint to `902f33e22c275d8bc63fc0ec14eb404103780c67b1736720bf2ae595a933438e`. Historical Phase 2 reports keep their original hashes; they are not rerun results for this revision. The new database tests use the current fixtures.

## Implemented boundary

`POST /requester-drafts` accepts only `ticket_id`, behind the existing signed browser session, exact Origin check, CSRF token and request-size bound. The browser has a separate requester-draft form. It displays an **unreviewed** plain-text preview and explicitly says nothing has been posted. HTML is escaped; Markdown and remote images are not rendered.

The database resolves the requester plus all registered `ticket_reply_participant` rows. Participants must be human ticket readers and able to read the public support guide, as must the caller. The participant table is administered through the trusted fixture/admin plane; the application and model cannot modify it. Existing fixtures have no additional participants; integration tests add and remove them temporarily. This initial policy includes every registered participant, with no browser-selected subset.

The [draft runner](../src/service_desk/agent/requester.py) starts a new context and performs exactly two server-selected reads: requester-visible ticket/history and `doc-public`. It accepts no analyst prompt, selected source IDs, previous answers, summaries or history. The independent read services intersect the caller's ACL with every recipient's ACL. Internal comments are excluded. The model receives only manifest-covered fields, no credentials or recipient controls, and an empty tool list. A proposed tool call stops the draft without dispatching it.

[Migration 0005](../migrations/0005_requester_context.sql) reconstructs the complete expected source manifest independently of the model and browser. It includes ticket/document versions, body hashes, document-title hash, and the IDs, visibility and body hashes of every included comment. Missing comments, changed content without a version bump, changed ACLs, requester/participant changes, and stale policy fail closed before generation or before release. The manifest covers all supplied sources, not just cited sources. Chat and draft task admission are separate, including when the caller is the requester.

Each draft has a single atomic claim and at most one model reservation; it also consumes the shared read-call budget. Failed, timed-out or cancelled generation retains its token reservation. Cancellation closes the task. The returned body hash is **not** a confirmation token or authorization to publish.

## Output screening and immutable review

[Migration 0006](../migrations/0006_draft_reviews.sql) independently screens the generated body before storing or returning it. It compares against documents, document titles, tickets and comments unavailable to the caller or any recipient. It detects restricted synthetic canaries, case/whitespace-normalized 32-character SHA-256 fingerprints, and complete shorter fields of at least eight characters. Protected content and fingerprints stay inside the database. This is a supplemental exact-content check: paraphrases, encodings, Unicode confusables and short fragments can evade it, and overlapping authorized text can cause false blocks. It does not establish answer correctness.

Only a screened draft is inserted into `requester_draft`. The immutable record binds the exact body and hash, citations, complete source manifest, owner, ticket, recipients, policy, security epoch and expiry. A database trigger rejects updates/deletes; application roles have no direct table access. Generation completion, insertion and the durable audit decision share one transaction. A screening failure stores only a safe denial event, with no candidate body. An audit failure rolls back the body and completion. Concurrent saves produce one record for a task.

The draft expires at the earlier of the verified login token's expiry and ten minutes after saving; the current lab token lifetime usually makes this shorter than ten minutes. Opening a review does not extend it. `GET /requester-drafts/{draft_id}` requires the original owner's authenticated session, revalidates all sources/recipients/policy, checks expiry and reruns output screening. HTML shows source references, recipients, exact body, expiry and body fingerprint; `Accept: application/json` returns the same authorized record. Stale or unauthorized requests return only `Draft unavailable`. Browser output remains escaped plain text with `no-store` caching.

A global security epoch advances whenever source, participant, identity, permission or policy tables change. Review/save checks hold a shared epoch lock while validating; those changes must advance the epoch before committing. Any committed change invalidates earlier records, even if later restored. This deliberately conservative first version also invalidates drafts for unrelated changes. It prioritizes reliable invalidation over narrowly targeted reuse.

There is no body-edit endpoint. To change the body, generate a new draft. Expired records remain in the protected lab database until it is disposed; production retention/cleanup is not implemented.

## Human-confirmed requester posting

[Migration 0007](../migrations/0007_confirmed_replies.sql) introduces a dedicated `desk_ticket_publisher` role and the [human publication store](../src/service_desk/app/publication.py). The application startup passes this credential to the human routes only. The agent, gateway and read-service roles cannot execute confirmation/publication functions, and the publisher has no direct business-table access. The MCP registry still exposes only the three read tools. The separate publisher process and mount boundary are now enforced by the application deployment described below.

With the publisher configured, opening a saved review rechecks the immutable record and issues a random confirmation token. Only its hash is stored, bound to the draft and current browser session. The token expires within 60 seconds, capped by the login and draft expiry. Issuance is limited to five tokens per draft and twenty per owner per minute across drafts. The review page shows the exact text, sources, recipients and an explicit **Confirm and post this reply** button. The token travels in a form/JSON body, never a URL or model prompt.

`POST /requester-drafts/{draft_id}/confirm` requires the authenticated original owner, exact Origin and CSRF checks, the confirmation token and exact body hash. It rejects body, audience, recipient or source overrides. The database serializes publication against source/policy changes, rechecks every bound value and the complete source manifest, reruns output screening, then inserts the requester comment, its reader ACL, the ticket-version increment, the unique publication receipt and audit outcome in one transaction. Reader access is the listed recipients plus the author; no extra team audience is inferred.

Repeated use of the **same** successful confirmation returns the original receipt with no additional effect. A different token, draft, session, owner or body hash cannot reuse that confirmation. An expired unused confirmation cannot post. A committed reply can still be acknowledged after its confirmation expires when the same session proof, current authenticated owner and ticket access remain valid; that path returns a receipt only. A network disconnect can make a response uncertain, so retry the identical confirmation to determine the committed outcome rather than generate another reply.

Publication uses a single autocommitted database call, a five-second operation/transaction limit, a two-second lock limit, and deadline checks before and after side effects. Slow-trigger, audit-failure and lock-timeout tests prove rollback rather than a delayed extra reply. The timeout settings follow [PostgreSQL 18's transaction and statement timeout semantics](https://www.postgresql.org/docs/18/runtime-config-client.html). Source-change triggers now take the security-epoch lock before changing rows to match publication's lock order. A successful post invalidates other older reviews under the existing conservative global-epoch policy.

The first posting trial exposed an output-screening false block: a public-guide excerpt copied into a private ticket made subsequent public-guide drafts look restricted. [Migration 0008](../migrations/0008_authorized_output_overlap.sql) excludes exact fingerprint spans already present in the current authorized source manifest. It does not exempt restricted canaries. A regression test checks that a private suffix remains blocked even when attached to an allowed public excerpt.

## Internal staff comments

[Migration 0009](../migrations/0009_internal_comments.sql) adds `ticket_internal_member`, an explicit trusted staff audience. The fixture administrator seeds human analysts, managers and resource owners who can read the ticket, excluding its requester. Seeding runs once, including when upgrading an existing fixture database; rerunning preparation preserves later membership revocations. Neither the browser, model nor application roles can change membership. A ticket with no registered staff fails closed.

`POST /internal-drafts` accepts only a ticket ID. The caller must be a registered member. Every registered member must be a human ticket reader with access to the public support guide; a requester, workload identity or unreadable member invalidates the whole audience. The fresh context includes only ticket comments readable by **every** member, including authorized internal history, plus the public guide. It reuses no chat or requester history. The requester path continues to exclude all internal comments.

The task and immutable draft store their channel explicitly. Separate database entry points enforce requester/internal binding for claim, save, review, confirmation issuance and publication, including receipt retries. Shared implementation functions are private to the database owner. Moving an internal draft ID or confirmation token to a requester endpoint cannot reveal its body or publish it with requester visibility. The legacy `requester_run` and `requester_draft` table names now hold both channels; their names do not determine authority.

The internal form links to `GET /internal-drafts/{draft_id}`, which shows the exact staff recipients, sources and body. Its **Confirm and post this internal comment** action submits to `POST /internal-drafts/{draft_id}/confirm`. The human publisher commits an `internal` comment with precisely the stored reader list, using the same deadlines, immutable confirmation, atomic audit and idempotency checks as requester replies. The author is already a member of that list. Staff membership changes advance the security epoch; revocation followed by restoration cannot revive an old review. Confirmation issuance limits are shared across both channels.

Tests publish a comment containing an authorized staff canary and verify that staff can read it while the requester cannot. They also check cross-channel review/publication denial, concurrent confirmation, incomplete comment ACLs, membership changes during generation, stale reviews, forbidden output, restricted helper privileges, escaped internal previews and browser context overrides. These are deterministic tests against the simulated store, not live-model resistance results.

## Shared task admission

[Migration 0010](../migrations/0010_task_admission.sql) enforces admission before inserting any task. Chat, requester drafts, internal drafts and direct task-creation function calls share the same counters. Limits are keyed to the trusted principal ID, so a new session, application connection or alternate subject bound to the same person cannot reset them.

| Limit | Per person | Entire lab |
|---|---:|---:|
| Active, unexpired tasks | 4 | 32 |
| Accepted task starts in the preceding 60 seconds | 20 | 100 |

Pending tasks consume active slots. Completed/stopped tasks release those slots, and abandoned tasks stop counting when their database deadline expires. Every committed start remains charged for the full rolling minute, including failed or cancelled generation. A rolled-back creation consumes no capacity. Existing per-task read/model reservations and deadlines continue to apply; new task IDs cannot bypass the aggregate start limits.

A private policy row serializes admissions across database connections. Its update also makes a transaction with a stale repeatable-read or serializable snapshot fail closed. Application, gateway, read-service and publisher roles cannot read or modify the policy, change task timestamps, or invoke the trigger helper directly. The trusted administrator may lower limits within the migration's ceilings; changes affect new admissions. Counts survive application restarts because they are derived from stored tasks, not process memory. Existing tasks receive the migration timestamp during an upgrade, conservatively consuming the new rolling window for up to a minute.

The browser/API translates only the named admission denial into HTTP 429 with a generic message and `Retry-After: 60`. This suggests when to retry; long-running active tasks may still occupy slots then. No tool/model request is dispatched for a rejected admission. These limits bound accepted work; they do not yet bound unauthenticated traffic, malformed/denied request volume, database connection attempts or proxy queues. Those ingress/deployment controls remain part of Phase 3.

[Admission tests](../tests/test_task_admission.py) exercise concurrent users/channels, alias subjects, rolling windows, slot release, start-charge retention, transaction rollback, stale snapshots and role privileges. The disposable test fixture starts each case with an empty admission window while retaining the production limit values; cases never disable enforcement. Earlier identity/network reports remain historical and have not been rerun with admission enabled.

## Bounded model ingress and deployment gate

The [model relay](../scripts/model_relay.py) now admits at most two active connections with a listen backlog of eight. It starts a five-second absolute input deadline before reading the request line, headers or body. After accepting the complete bounded input, it applies a 45-second absolute upstream deadline that shuts down both sockets. Continuously trickled bytes cannot extend either phase. Connections are closed after one request; saturation produces a best-effort HTTP 503 or a closed/reset connection. Socket tests verify that capacity becomes available again after stalls.

The relay keeps its four fixed routes and 64 KiB body/response limits. It rejects duplicate/invalid content lengths, transfer/content encodings, unexpected bodies and `Expect` headers. Inbound credentials are never forwarded. Redirects, encoded responses and oversized upstream bodies return a fixed error without upstream text. The relay suppresses request logging and exception tracebacks. This remains a narrow local lab listener, not a replacement for a production ingress proxy; Python documents the [server queue and request-handling hooks](https://docs.python.org/3.13/library/socketserver.html) used here.

The [startup gate](../scripts/check_model_boundary.py) checks exact model/verifier/relay mount inventories, bounded tmpfs, fixed commands and entrypoints, absence of unexpected capabilities/host PID sharing, fixed relay network membership and resource limits, and equality of mounted relay bytes with the reviewed workspace file. An unexpected read-only credential mount is rejected. This checks mounted files, not an attestation of code already loaded in memory: restart the relay after changing its source. The relay's narrow bootstrap capability exception and live privilege checks are described below.

[Current live ingress evidence](../reports/phase3-deployment/runs/20261014T033021Z/ingress.json) records **38 passing checks** with the egress firewall enabled. The probe reaches real model metadata, rejects a model-download route, saturates the relay with two neutral partial headers, observes timely disconnects and verifies recovery. The report contains booleans, limits and source hashes only. No ticket data or draft was sent, and this is not a real-model task evaluation. Host database/identity ports were not positive-controlled in this probe; their unreachable observations alone do not prove service isolation. The earlier 33-check report remains historical evidence for the preceding ingress slice.

Reproduce after provisioning the relay image described below (serving uses cached images/weights only):

```powershell
docker compose -f infra/compose.phase2-model.yaml up -d --pull never
.\.venv\Scripts\python.exe scripts/check_phase3_ingress.py
.\.venv\Scripts\python.exe scripts/check_phase3_egress.py
docker compose -f infra/compose.phase2-model.yaml down
```

The probe accepts `--docker <absolute-path>` when Docker is not on PATH. New containment runs are saved under `reports/phase3-deployment/runs`; historical Phase 2 evidence remains unchanged.

## Relay egress boundary

The [trusted bootstrap](../scripts/relay_bootstrap.py) resolves the Compose model service before starting any listener. It installs an atomic nftables `inet` output policy that defaults to drop for IPv4 and IPv6. Only TCP connections to that exact model IPv4 address on port 11434 and established replies from the relay's port 8080 are allowed. The filter runs after connection tracking and before Docker's output destination translation, including its embedded DNS translation. Runtime TCP/UDP DNS, other destinations on port 11434 and all other new outbound connections are denied. The [nftables reference](https://www.netfilter.org/projects/nftables/manpage.html) defines these hooks, priorities and state matches.

The container starts its bootstrap as root with exactly `NET_ADMIN`, `SETUID`, `SETGID` and `SETPCAP`. No client listener exists then. Failure to resolve the model or install the policy exits without launching the relay. After installation, [setpriv](https://github.com/util-linux/util-linux/blob/master/sys-utils/setpriv.1.adoc) switches to UID/GID 65532, clears supplementary groups and all capability sets including the bounding set, and keeps no-new-privileges enabled before replacing itself with the listener. The listener cannot change the firewall or regain the setup capabilities. The Docker administrator remains trusted: a new administrative `docker exec` process can still use the configured bootstrap capabilities, which are distinct from the running listener's empty capability sets.

The startup gate pins the local image ID, bootstrap bytes, unchanged image environment, exact installed firewall policy and model address. It reads the running listener's command, four UID/GID fields, groups, five capability sets, no-new-privileges and seccomp mode. Model/verifier containers still start unprivileged without added capabilities. No new mount or credential is added to the relay. Recreate the model and relay together when changing model networking; the captured upstream address is deliberately not refreshed through runtime DNS.

[Live egress evidence](../reports/phase3-deployment/runs/20261014T032930Z/egress.json) records **46 passing checks**. A disposable unprivileged responder on the normal ingress bridge serves neutral TCP markers on ports 11434, 15433 and 19443, plus UDP 53. Unfiltered peers reach every responder and the registered Docker DNS name before and after the relay-namespace attempts. The relay namespace cannot reach them or Docker DNS over TCP/UDP, while the allowed model remains reachable. The probe always removes the responder it created. These are synthetic database/identity port controls, not live tests against those services; IPv6 denial is policy-inspected only. This earlier relay-only result is supplemented by the application separation, service ingress tests and final containment matrix below.

The [initial failed run](../reports/phase3-deployment/runs/20261014T032545Z/egress.json) is retained: its Docker UDP DNS positive control queried a service name outside the peer's network and did not respond. All relay denial checks passed, but the report correctly failed overall. The corrected probe queries its own registered neutral responder, and both positive controls pass. No failed control is counted as containment evidence.

The [relay Dockerfile](../infra/relay.Dockerfile) uses the same digest-pinned Python base plus `nftables=1.1.3-1`. Build it separately from serving:

```powershell
docker build --pull=false -f infra/relay.Dockerfile -t service-desk-model-relay:phase3 .
docker image inspect service-desk-model-relay:phase3 --format '{{.Id}}'
```

The reviewed local image ID is `sha256:69f0328dc75aad42c44b9894961d84d6f700ad359ebdc36a0132c5ecdfe22472`, pinned in Compose and the startup gate. Building requires registry/Debian package access; no package install occurs in the serving path. Rebuilds can have a different image ID because build metadata and transitive Debian packages are not fully frozen. Review the resulting image and update both pins before rerunning containment checks; never automatically accept a new tag. This is a local artifact pin, not a published registry artifact or a claim of byte-reproducible builds.

## Database connection capacity

The disposable PostgreSQL project now starts with 40 total connection slots, including four reserved for superusers; ordinary services share the other 36. Each of the creator, gateway, knowledge and ticket logins has a 12-connection limit, and the publisher has six. These role limits apply across service processes and sessions. They do not add independent capacity beyond the shared server ceiling. PostgreSQL documents [reserved slots and authentication timing](https://www.postgresql.org/docs/18/runtime-config-connection.html), and notes that [role limits can reject simultaneous attempts conservatively](https://www.postgresql.org/docs/18/sql-createrole.html). These controls bound connections; they do not guarantee fairness, memory availability or protection against sustained connection floods.

Client authentication, including a stalled initial startup packet, must complete within five seconds. Preparation applies the following defaults to all five service logins on both first setup and upgrade, without rotating their credentials or changing fixture memberships:

| Service default | Limit |
|---|---:|
| Statement | 10 seconds |
| Lock wait | 3 seconds |
| Transaction | 15 seconds |
| Idle within a transaction | 5 seconds |
| Idle outside a transaction | 30 seconds |

Existing publication connections retain their stricter five-second statement/transaction and two-second lock limits. Services open short-lived connections and close them after each operation. PostgreSQL's [session timeout parameters](https://www.postgresql.org/docs/18/runtime-config-client.html) remain client-changeable defaults; a principal capable of arbitrary SQL can disable them. The server ceiling, authentication timeout and login connection limits are separately enforced. No claim is made that these defaults contain a stolen service credential.

The [database gate](../src/service_desk/core/database.py) uses only the intended service credential to inspect the effective settings, exact login/connection limit, privilege flags and lack of reserved-slot access. The assistant checks its creator, gateway and publisher connections before provider initialization; each read runtime checks its own login before opening its listener. Changed settings or unavailable connections stop startup with a generic error. This is a startup snapshot, not continuous monitoring, and direct library/test callers must invoke the gate explicitly when they need deployment validation.

[Database capacity tests](../tests/test_database_limits.py) saturate every role, check another service remains usable, and verify recovery after releasing connections. A saturated read returns a fixed `SERVICE_ERROR` without content. A saturated publisher creates neither a comment nor a publication receipt; the same confirmation succeeds exactly once after capacity recovers. Tests also reject role attempts to remove their limits and verify that rerunning preparation restores settings without rotating credentials. [Gate tests](../tests/test_database_gate.py) reject altered settings, unexpected privileges and credential-bearing error text.

The [live capacity probe](../reports/phase3-deployment/runs/20261014T044213Z/database.json) records **29 passing checks**, including shared saturation with 35 ordinary connections plus one administrator observer, rejection of an unused service login at the shared ceiling, successful use of a reserved administrator slot, and successful new service connections after release. It measures the real five-second idle-transaction/authentication and 30-second idle-session defaults. Reports contain booleans, configured limits and source hashes only. Run it while the disposable database is otherwise idle; do not run it concurrently with tests or active demos because it intentionally fills service slots.

```powershell
docker compose -f infra/compose.phase2-reads.yaml up -d --wait
.\.venv\Scripts\python.exe scripts/prepare_read_store.py --apply
.\.venv\Scripts\python.exe scripts/check_phase3_database.py
```

Changing the Compose server settings requires recreating this disposable database container. Preparation then reapplies its schema, synthetic fixtures and service limits. Applying only the role defaults to an older running server is insufficient: the runtime gate will reject its old server settings. No actual model or OIDC/MCP trial is part of this database probe.

## Browser and MCP HTTP input bounds

The shared [runtime configuration](../scripts/phase2_runtime.py) now selects a [bounded HTTP protocol](../src/service_desk/core/ingress.py) for the browser, assistant, read services and identity probes. Each single-process listener admits up to 16 established HTTP connections and 16 unfinished application tasks, with a listen backlog of 16. Saturation closes the connection with a best-effort empty HTTP 503 response; clients may observe a reset instead. Capacity is local to each listener, while the existing task and database quotas remain shared.

Before authentication or application code runs, the listener buffers a complete request within a five-second absolute deadline. Trickled bytes do not extend it. Headers and decoded bodies are each limited to 16 KiB; the entire wire request, including chunk framing and trailers, is limited to 32 KiB. Existing smaller route-specific limits still apply. Oversized, malformed, compressed, upgrade and `Expect` requests fail without reflecting request data. Bounded chunked requests are supported. Coalesced pipelined requests are rejected, and each accepted connection serves only one request with `Connection: close`. Ordinary browser and stateless MCP clients reconnect for subsequent requests.

An absolute 125-second connection lifetime bounds HTTP transport retention and slow responses. Closing a transport does not prove that already-started work was cancelled or rolled back. Unfinished application tasks retain admission capacity after disconnect, and capacity is checked again immediately before dispatch to cover sockets accepted before other tasks became detached. Existing provider/task deadlines and database transaction checks continue to govern work and effects. There is no automatic retry at this layer.

The implementation uses the lockfile's Uvicorn 0.54.0 H11 protocol and explicitly declares h11 as a dependency. Revalidate the socket tests when upgrading either package. Uvicorn's [concurrency/backlog and keep-alive settings](https://www.uvicorn.org/settings/) alone do not supply the complete-input admission used here.

The HTTP protocol runs after TLS negotiation. The separately bounded TLS acceptor described below now covers the preceding handshake and subsequent TLS shutdown. Directly constructing `uvicorn.Server(server_config(...))` bypasses that acceptor; deployment and live-probe entry points must use the shared `create_server(...)` factory instead. The HTTP-only socket tests intentionally continue to instantiate Uvicorn directly when isolating that layer.

The [18 socket cases](../tests/test_http_ingress.py) verify normal fixed-length/chunked requests, rejected input without application invocation, absolute input deadlines, saturation/recovery, unfinished-work admission and the pending-socket race. They also exercise the shared configuration over verified TLS and real authenticated MCP requests across successive connections. Tests use shortened deadlines and reduced capacity for race cases, temporary test certificates and synthetic signing keys. They do not constitute a live Keycloak, real-model or full output-channel trial. Run them with `.\.venv\Scripts\python.exe -m pytest tests/test_http_ingress.py`.

## TLS admission and shutdown

The [TLS acceptor](../src/service_desk/core/tls_ingress.py) reserves capacity at TCP accept, before creating any TLS task. Browser, assistant, read-service and Phase 2 live-probe entry points now use it through the shared [server factory](../scripts/phase2_runtime.py). Each server instance supports one IPv4 loopback listener and requires TLS, the bounded HTTP protocol, disabled WebSockets and disabled forwarded-header trust. Unsupported startup configuration fails before opening a listener. Existing public startup commands are unchanged.

| Per-listener limit | Value |
|---|---:|
| Admitted sockets across handshake, HTTP and TLS shutdown | 16 |
| New TLS handshakes in a rolling one-second window | 32 |
| Absolute TLS handshake deadline | 5 seconds |
| TLS close-notify deadline | 1 second |
| Requested OS listen backlog | 16 |

An accepted socket that exceeds connection capacity, the handshake-start window or the unfinished-application-task ceiling is closed before TLS parsing. No TLS task, HTTP error response or per-peer log is created for that rejection. Each admitted handshake consumes its rolling-window charge even if it fails, disconnects or completes quickly. A reconnect does not reset the window. The accept loop yields between sockets so a busy queue does not monopolize deadline callbacks.

The acceptor transfers admitted sockets to Python's [documented `connect_accepted_socket` TLS API](https://docs.python.org/3.13/library/asyncio-eventloop.html#asyncio.loop.connect_accepted_socket), with explicit handshake and shutdown deadlines. It does not implement TLS cryptography. Successful connections retain their reservation until transport disconnection; failed handshakes release it without invoking the application. Shutdown stops acceptance, cancels incomplete handshakes and closes remaining transports. The existing HTTP limits and disconnected-task accounting still apply. On Windows, exclusive address use prevents another listener from sharing the port.

The [17 TLS cases](../tests/test_tls_ingress.py) exercise the real default 16-connection/five-second boundary, silent and trickled TLS records, mixed TLS/HTTP capacity, failed and successful handshake rate charging, recovery, disconnected work, server shutdown, and a peer withholding close-notify. Positive controls use verified certificates and authenticated MCP; a separate case runs the shared factory through Uvicorn's complete serving/shutdown lifecycle. Race tests use smaller limits, and certificates/signing keys are temporary synthetic fixtures. Run with `.\.venv\Scripts\python.exe -m pytest tests/test_tls_ingress.py tests/test_http_ingress.py`.

These results cover the pinned Python 3.13.16/Uvicorn 0.54.0 Windows runtime. This is a per-listener admission boundary, not proof of denial-of-service resistance: rejected TCP traffic still costs OS and event-loop work, timers depend on event-loop progress, limits reset on trusted process restart, and no fairness across listeners or users is guaranteed. Production proxy/load-balancer behavior, host credential isolation, IPv6 and actual host-service containment still require separate validation. No real-model or live Keycloak trial is added by these socket tests.

## Read-service process and credential separation

The [read deployment](../infra/compose.phase3-reads.yaml) runs knowledge and tickets in separate containers. Each listener runs as UID/GID 65532 with a read-only root, no capabilities, no-new-privileges, private process namespaces, bounded memory/CPU/process counts and disabled container logging. The trusted firewall bootstrap temporarily starts with the setup privileges described below. Each container mounts exactly its own directory at `/run/desk`, read-only. It contains five files: its database login, public identity mapping, public trust certificate, service leaf certificate and service private key. Neither container receives the master client/user credentials, administrator/creator/gateway/publisher database logins, CA private key, peer credentials, host repository or Docker socket.

The trusted [preparation script](../scripts/prepare_isolated_reads.py) stages these files and issues distinct non-CA, server-authentication-only leaf certificates. Repeated preparation preserves existing keys and database passwords; partial certificate pairs, unexpected files and near-expiry certificates require operator correction. The [container entry point](../src/service_desk/read_process.py) rejects unexpected material, database destinations/roles, issuer mappings and invalid or mismatched certificates before serving. It verifies the database limits and retrieves TLS-verified signing keys before opening its listener. Missing dependencies stop startup; there is no automatic restart/retry policy.

The public issuer, resource URLs, audiences and registry remain unchanged. Inside Docker Desktop, bootstrap resolves `host.docker.internal` once and passes the numeric address to the listener. Database connections use libpq's [hostaddr parameter](https://www.postgresql.org/docs/18/libpq-connect.html#LIBPQ-PARAMKEYWORDS) to avoid runtime DNS; signing-key requests use the numeric address while retaining the original issuer's certificate name through HTTPX's [SNI extension](https://www.python-httpx.org/advanced/extensions/#sni_hostname). Signing-key retrieval rejects redirects, encoded responses and bodies over 64 KiB, with a five-second HTTP I/O timeout and the existing key-cache/cooldown settings. No OIDC client secret is needed by either read service. The container-specific TLS acceptor binds its bridge interface, while Docker publishes only the existing `127.0.0.1:19482/19483` host ports. It retains the bounded TLS/HTTP protocol described above.

Browser startup now loads only web and gateway client secrets from ignored `.lab/phase2/web-client.json`. Rerun `scripts/prepare_phase2.py` to create this scoped export without rotating existing credentials. This removes unused administrator, executor, worker and synthetic-user secrets from the normal client loader, but does not prevent the same host user from opening the master file. The browser, agent, gateway and publisher still share a host process and filesystem authority.

The [deployment probe](../scripts/check_isolated_reads.py) rejects changed image, command, environment, mounts, ports, networks, privileges and limits before executing its in-container checks. It verifies live process privileges, exact readable material, inaccessible host/peer paths, read-only mounts, working own-role database login, absence of comment-insert permission and matching packaged Python source hashes. Host administrator material is positively checked as present/readable without recording its contents. This is an explicit operator verification gate, not continuous enforcement or a prerequisite automatically imposed by the host assistant command.

[Current live evidence](../reports/phase3-deployment/runs/20261014T095523Z/isolated-reads.json) records **65 passing checks**, including real Keycloak login/delegation for Erin and Alice, allowed public-document/ticket reads, explicit `RESOURCE_DENIED` for the HR document, and rejection of unsigned MCP requests. It also checks exact installed outbound policies and empty supplementary groups. Reports contain booleans, source hashes and sanitized error stage/type only; no model was invoked. The earlier 61-check run and its three preceding failed probe runs remain historical evidence. The [material/JWKS tests](../tests/test_read_process.py) and [configuration-gate tests](../tests/test_read_deployment.py) cover the 32-case isolation foundation.

Each read container has its own ordinary Docker bridge plus the enforced outbound policy below. Docker administration and host preparation remain trusted. This live trial covers the read path, not browser draft/publication workflows or the full model/output-channel matrix.

Provision the local image separately from serving:

```powershell
docker build --pull=false -f infra/reads.Dockerfile -t service-desk-read:phase3 .
docker image inspect service-desk-read:phase3 --format '{{.Id}}'
```

The reviewed image ID is `sha256:6fbf8477746ae3b7b08804d9785f4bfd37ad58e0ffad3ed3e51d8ee531e9c3f3`, pinned in Compose and [the lock record](../config/isolated-reads.lock.json). Building installs locked Python dependencies and `nftables=1.1.3-1`, and needs package/registry access. A rebuild may produce a different image ID; review it and update both pins before validation. Do not automatically accept a mutable tag. This is a local artifact pin, not a published image or a byte-reproducibility claim.

Prepare and start the disposable dependencies, then stage the scoped files:

```powershell
.\.venv\Scripts\python.exe scripts/prepare_phase2.py
.\.venv\Scripts\python.exe scripts/prepare_read_store.py
docker compose -f infra/compose.phase2-reads.yaml up -d --wait --pull never
.\.venv\Scripts\python.exe scripts/prepare_read_store.py --apply
docker compose -f infra/compose.phase2-identity.yaml up -d --pull never
.\.venv\Scripts\python.exe scripts/prepare_isolated_reads.py
```

Wait for the identity discovery endpoint to return HTTP 200 using the lab CA before starting the reads. This command verifies readiness without changing system trust; rerun it if Keycloak is still starting:

```powershell
.\.venv\Scripts\python.exe -c "import httpx,ssl; c=ssl.create_default_context(cafile='.lab/phase2/tls/certificate.pem'); r=httpx.get('https://127.0.0.1:19443/realms/service-desk-phase2/.well-known/openid-configuration',verify=c,trust_env=False,timeout=5); r.raise_for_status(); print('Identity ready')"
docker compose -f infra/compose.phase3-reads.yaml up -d --pull never
.\.venv\Scripts\python.exe scripts/check_isolated_reads.py
.\.venv\Scripts\python.exe scripts/check_read_egress.py
```

The probe accepts `--docker <absolute-path>`. Run it separately from database tests, which mutate the synthetic fixtures. For the interactive demo, keep these containers running and launch only `scripts/assistant_runtime.py` on the host; do not also start the older host read listeners on the same ports. Teardown removes only these disposable projects:

```powershell
docker compose -f infra/compose.phase3-reads.yaml down
docker compose -f infra/compose.phase2-identity.yaml down
docker compose -f infra/compose.phase2-reads.yaml down
```

## Read-service outbound policy

The [trusted bootstrap](../src/service_desk/read_bootstrap.py) resolves only `host.docker.internal`, validates the resulting IPv4 address and atomically installs an nftables `inet` output policy with default drop. Before any listener exists, it allows new/established TCP connections only to that exact address on database port 15433 and identity port 19443. It also permits established replies from that service's MCP listener port. The output hook runs after connection tracking and before Docker's DNS destination translation, using the [nftables priority and state semantics](https://www.netfilter.org/projects/nftables/manpage.html). Runtime DNS, UDP, other destinations on the allowed ports and other host ports are denied. IPv6 has no allowed new outbound destination.

Compose grants only `NET_ADMIN`, `SETUID`, `SETGID` and `SETPCAP` to the root bootstrap. Once the policy is installed, `setpriv` changes to UID/GID 65532, clears supplementary groups and every capability set, retains no-new-privileges and replaces bootstrap with the read listener. Resolution or policy-installation failure prevents listener launch. The gate checks both configured bootstrap authority and the live listener's reduced authority, plus the full policy table and destination resolved by a separate unfiltered helper. Docker administrators can still launch privileged administrative processes and remain outside this boundary. Recreate the read containers if the trusted host address changes; listeners do not refresh it through DNS.

The [live outbound probe](../scripts/check_read_egress.py) first runs the complete isolation/authenticated-read gate. For each read service it then starts a disposable neutral responder on that service's ordinary bridge, including an ephemeral loopback-published host port. Unfiltered peers must reach all controls before and after attempts from the actual service network namespace. The [37-check result](../reports/phase3-deployment/runs/20261014T095542Z/read-egress.json) passes: different destinations on ports 15433/19443/11434, a different port on the allowed host address, UDP 53 and Docker DNS over TCP/UDP are unreachable from both restricted namespaces. The actual host PostgreSQL and Keycloak ports remain reachable, and the prerequisite [65-check result](../reports/phase3-deployment/runs/20261014T095523Z/isolated-reads.json) proves real authenticated reads. The 37 checks include the prerequisite's overall result; do not sum these counts as independent cases. The responders and helper containers are removed after the run.

[Twenty-eight policy/bootstrap cases](../tests/test_read_egress.py) reject altered destinations, ports, rule sets, priorities, reply conditions and default policies for both service roles. They also check invalid addresses, setup failures before launch and complete privilege dropping. IPv6 denial is policy-inspected only; no new real-model or draft/publication trial is claimed. The firewall limits network destinations, not protocol paths or queries on allowed database/identity connections. Authorization within those services remains necessary. The application separation and final network matrix below supersede the host-process limitation of this earlier slice.

## Browser, agent and human publisher separation

The hardened entry point is now [compose.phase3-app.yaml](../infra/compose.phase3-app.yaml), alongside the separate read containers. It runs three processes with distinct leaf TLS keys, service credentials, read-only material mounts, network namespaces and bounded resources. No runtime container mounts the repository, master credential file, Docker socket or another service's material. The image contains application code but excludes the baseline and operator scripts. [The live gate](../scripts/check_app_boundary.py) compares the complete image, command, environment, mount, process, source-hash and firewall inventories; it checks actual database privileges too.

| Process | Private material | Permitted new host connections |
|---|---|---|
| Browser, HTTPS 19481 | Web OIDC client and two distinct RPC secrets; no database login | Identity 19443, agent 19486, publisher 19487 |
| Agent, HTTPS 19486 | Gateway OIDC client, task-creator and gateway database logins, agent RPC secret | Database 15433, identity 19443, knowledge 19482, tickets 19483, model relay 19485 |
| Publisher, HTTPS 19487 | Publisher database login and publisher RPC secret | Database 15433, identity 19443 |
| Knowledge / tickets, HTTPS 19482 / 19483 | Only their respective read login and leaf key | Database 15433, identity 19443 |

The browser forwards the signed user's access token, not user-supplied identity fields. The agent and publisher each require their own service secret **and** independently validate the signed token's issuer, client, audience and expiry. Strict schemas reject extra authority, recipient, source and body fields. Only the publisher implements review/confirmation endpoints; the agent cannot execute publication functions. Runtime database roles cannot select, insert, update, delete or truncate the audit table. Security-definer functions write content-free decisions transactionally; the trusted lab administrator remains the audit reader. Phase 4 will add durable collector delivery and its query UI.

Each trusted bootstrap resolves the host address once, installs an exact default-deny IPv4/IPv6 policy, and drops user/group IDs, supplementary groups and all capabilities before starting its listener. Startup fails before serving if policy installation fails. Runtime DNS is blocked. Destination routing retains the original verified TLS identity and Host header while using the resolved numeric address. Browser and MCP traffic retain the established TLS/HTTP admission limits. All published ports bind only to IPv4 loopback.

## Model outbound boundary and chat release

The direct containment review found that an internal Docker network still allowed Docker DNS traffic. The [model bootstrap](../scripts/model_bootstrap.sh) now installs its own outbound policy before dropping all privileges. It permits replies from Ollama port 11434 and TCP to **127.0.0.1** on the loopback interface for Ollama's inference runner. It does not permit Docker DNS at 127.0.0.11, new relay connections, host services or other destinations. Real inference succeeded with this policy enabled.

The model image is built with [model.Dockerfile](../infra/model.Dockerfile), pinned by immutable local image ID in Compose and the deployment gate. The gate checks the actual process, bootstrap bytes, exact policy and environment, read-only cache, absence of cache writers and bounded memory/CPU/processes. The relay retains its separate exact model-only outbound policy. No cloud API or credential is involved.

[Migration 0011](../migrations/0011_chat_output.sql) applies the protected-canary and normalized-fingerprint screen to self-audience chat answers before release. It checks the task owner, channel, complete source list and current permissions under the security-epoch lock. A rejected body is not persisted; the task stops with a fixed audit reason. Drafts use the same private screening helper. Tests force validly cited hostile answers containing unauthorized titles, bodies and internal comments and verify no answer or leaking log is returned. This supplements recipient-filtered retrieval; it does not claim to detect every paraphrase or encoding.

## Verification and reproduction

Final evidence and exact counts are recorded in the [Phase 3 exit matrix](phase3-exit.md). Deterministic tests cover concurrency, immutable reviews, revocation/restoration, cancellation, audit rollback, deadlines, duplicate confirmation, admission limits, strict RPC authentication, credential inventory and policy mutation. The real browser workflow logs in through Keycloak, invokes the local model, reads through TLS MCP, reviews exact drafts, rejects altered hashes, confirms requester replies/internal comments and independently checks stored bodies, visibility and exactly-once effects.

The separate channel evaluator observes actual model requests in memory, persists only hashes/booleans, and checks fresh internal-to-requester context plus hostile document instructions for Erin and Alice. It is a trusted host evaluator, not a claim that prompts were extracted from runtime containers. Browser publication is exercised by the separate deployed workflow probe. The network matrix uses reachable before/after neutral TCP/UDP responders for all seven runtime namespaces; a failed positive control fails the whole report. Application logs are disabled, audit metadata is checked for content/credential absence, and the runtime audit-reader privileges are denied.

Prerequisites: Docker Desktop in Linux-container mode, the locked Python environment, generated synthetic identity/database configuration, and the verified offline model cache described in [the model runbook](phase2-model.md). Build the four local artifacts before serving:

```powershell
docker build --pull=false -f infra/relay.Dockerfile -t service-desk-model-relay:phase3 .
docker build --pull=false -f infra/model.Dockerfile -t service-desk-model:phase3 .
docker build --pull=false -f infra/reads.Dockerfile -t service-desk-read:phase3 .
docker build --pull=false -f infra/app.Dockerfile -t service-desk-app:phase3 .
docker image inspect service-desk-model-relay:phase3 service-desk-model:phase3 service-desk-read:phase3 service-desk-app:phase3 --format '{{.Id}}'
```

Local build IDs can change with build metadata or transitive packages. Review the resulting artifacts and update the corresponding Compose IDs, `config/isolated-reads.lock.json`, `config/isolated-app.lock.json` and model/relay constants in `scripts/check_model_boundary.py` together. Startup never accepts a mutable tag automatically. Build-time package access is separate from the serving boundary.

```powershell
# Supply an absolute Docker executable with -DockerPath when it is absent from PATH.
.\scripts\phase3.ps1 -Action Start
.\scripts\phase3.ps1 -Action Check
.\scripts\phase3.ps1 -Action Stop
```

`Start` applies migrations through 0011, preserves existing credentials, stages only per-role files, starts the five Compose projects and runs deployment gates. It uses the real local model. Open `https://127.0.0.1:19481` with the generated local CA trusted and use the synthetic lab credentials stored in ignored `.lab/phase2`. Use the saved-review link and exact confirmation button to publish. The old host `assistant_runtime.py` remains a compatibility/development runner; it does not establish the hardened process boundary.

`Check` runs lint, formatting, typing and the full PostgreSQL-enabled regression, then the deployment/network matrix, real-model channels, real browser workflows and a content-free log inspection. Do not run another database-mutating evaluator concurrently. Successful live workflows intentionally leave simulated comments; the tests tolerate these legitimate effects. Evidence is retained under `reports/phase3-deployment/runs`. Test scratch files stay under ignored `.lab`, avoiding machine-specific temporary-directory permissions. `Stop` removes only these projects' containers/networks and preserves local credentials, reports and the external model cache. The database is backed by temporary memory storage: stopping disposes synthetic tasks/comments, and the next start reapplies the fixtures.

An old fixture fingerprint is deliberately refused. Follow the disposable-database reset instructions in [the read runbook](phase2-reads.md); never overwrite its fingerprint to bypass validation. Startup/gate failures must be investigated before proceeding. All publications affect only the simulated local ticket store.

## Framework evidence carried forward

These rows use the flow/threat identifiers proposed in the [framework recommendations](../SECURE_SERVICE_DESK_AGENT_FRAMEWORK_RECOMMENDATIONS.md). They are implementation traceability, not additional framework coverage claims.

| Threat / flow | Project risk tags | Current evidence and remaining work |
|---|---|---|
| `T-F4-I-01`: restricted source content reaches requester output | `LLM02:2025`, `LLM05:2025` | Fresh context, complete manifest, recipient tests and independent restricted-output canary/fingerprint screening implemented; deterministic output denial and actual model input/preview/publication/audit checks pass in the final matrix |
| `T-F5-T-01`: draft changed after confirmation | `LLM06:2025` | Immutable binding, session-bound human confirmation, expiry, stale-state denial, atomic publication and idempotent replay tests implemented for requester replies and internal staff comments; cross-channel reuse denied |
| `T-F10-I-01`: model network disclosure | `LLM02:2025` | Exact relay egress policy, live privilege checks and reachable TCP/UDP controls; separate service authority and the positive-controlled seven-namespace IPv4 matrix pass |

No new ATLAS technique IDs are introduced by this slice. Continue using the existing indirect-injection mapping for the existing ticket/document injection cases; verify new technique IDs against the pinned catalog before adding them. The full shared risk register and machine-checked taxonomy remain follow-up work.

## Next phase and scope limits

Proceed to Phase 4: immutable access requests, provenance-first approval, executor separation, grant lifecycle and durable audit delivery. Broader authorized retrieval recipes, attachment/tool-description adversarial trials and repeated baseline-versus-hardened model statistics belong to the later evaluation work. Phase 3 uses the fixed, complete ticket/public-guide draft recipe; it does not expose arbitrary retrieval or model-selected audiences.

The tested runtime uses IPv4 loopback. IPv6 default denial is inspected in the exact `inet` policies but does not have live positive-controlled IPv6 trials. The trusted operator, Docker daemon and identity/database administration plane remain outside the model/container threat boundary. Local image pins are integrity checks, not byte-reproducible public artifacts. The model trials are small functional/attack samples, not statistical security guarantees.

Source hashes protect integrity and provenance, not truthfulness or all paraphrased disclosure. An unreviewed draft is never published automatically. Human confirmation permits only its exact stored action; it does not unlock future model actions or grant privileged access.
