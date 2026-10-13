# Status and compatibility

## Current status: Phase 2 exit gate met

October 13, 2026: the pinned, pre-registered read-only lab passes 211 tests (167 default, 44 PostgreSQL integration), lint, formatting and strict type checks. Final live probes pass 68 identity, 34 read, 27 browser-assistant and 25 authentication-compatibility checks, plus the local-model tasks. Real Keycloak rotation/retirement/expiry and RFC 8414 discovery are verified; the fallback branches and hostile metadata have 31 deterministic tests. Cached retired keys remain accepted for at most the configured 60-second JWKS lifetime. See the [exit matrix and reproduction](phase2-exit.md). Phase 3 recipient-safe drafts/confirmed writes and full deployment isolation remain unimplemented. No write capability is enabled. All records below are historical slice snapshots.

Phase 1 exit gate met October 12, 2026: three separate unauthenticated MCP services, containment probes in all six attack-network namespaces, three forced unsafe effects, one forced benign success, and four completed local-model trials. The model's three attacks and one benign task all missed their objectives; none is presented as a successful task or security guarantee. See [Phase 1 evidence and reproduction](phase1.md). The Phase 1 checker passed 44 tests. Ollama 0.40.3 and Qwen3-4B-Instruct-2507 Q4_K_M are pinned by image/model hashes; inference used CPU despite requested GPU passthrough. Phase 2 started October 13, 2026; see the current record below.

## Phase 2 local-model record

October 13, 2026: 179 tests pass with PostgreSQL enabled (136 default, 43 opt-in). The pinned Ollama 0.40.3 / Qwen3-4B-Instruct-2507 Q4_K_M adapter passes 16 live model-deployment checks, and the three frozen authenticated benign/injection cases initially completed with valid citations and no tested unauthorized effects. The hardened adapter uses CPU inference, raw structured turns and an 8,192-token context; these differ from the earlier baseline settings. The observed API digest is the pinned final metadata-layer digest, while the offline gate separately verifies the manifest and all blobs. See [provider details and limits](phase2-model.md) and [trial evidence](../reports/phase2-model/results.json). Real Keycloak rotation and remaining discovery cases are still required. Records below describe earlier slices.

## Phase 2 deterministic-assistant record

October 13, 2026: the full checker passes 146 tests with PostgreSQL enabled (103 default, 43 opt-in). The authenticated browser/API task flow passes 27 live checks against the existing Keycloak 26.7.4, PostgreSQL 18.3 and MCP 2.3.0 stack. A deterministic provider exercises the bounded loop, durable model reservations, source citations and isolated contexts. The [assistant runbook](phase2-assistant.md) and [sanitized evidence](../reports/phase2-assistant/results.json) record reproduction and limits. Real-model integration, real provider key rotation and remaining discovery checks are still required. No write tool is enabled. Earlier records below are historical snapshots.

## Phase 2 authorized-read record

October 13, 2026: 118 tests pass with the disposable PostgreSQL integration enabled (95 default, 23 opt-in). All 34 real Keycloak ? pinned gateway ? TLS MCP ? PostgreSQL read checks pass. PostgreSQL 18.3 enforces shared reservations across service roles; MCP 2.3.0 serves the reviewed read catalog. Evidence and limits are in the [read runbook](phase2-reads.md) and [sanitized report](../reports/phase2-reads/results.json). The bounded model assistant remains unimplemented; no write tool is enabled. Earlier reports remain historical snapshots and their source hashes need not match newer changes.

## Phase 2 identity record

October 13, 2026: the full checker passes 83 tests, including 39 new signature, key rotation, HTTP/MCP boundary, session and exchange tests. Real confidential OIDC login, TLS, delegated tokens for knowledge/tickets/access, scope denials, privileged exchange denials, workload isolation, and protected browser sessions passed against Keycloak 26.7.4 / MCP 2.3.0 / PyJWT 2.15.1 / HTTPX 0.28.1 with protocol 2025-11-25. Sanitized claim shapes and source hashes are in [the live report](../reports/phase2-identity/results.json).

The minimum realm required an explicit subject mapper; the verifier rejected missing `sub` until the configuration was corrected. The tested adapter maps exact signed audience names to pinned resource URLs and rejects scope expansion; it does not establish general OAuth discovery or per-resource user entitlement. The [Phase 2 runbook](phase2.md) records these limits, sessions, commands and remaining work. The Phase 2 read-only assistant exit gate is still open.

## Phase 0 record

Recorded October 12, 2026. The Phase 0 fixture/contract exit gate is implemented. The early real OIDC/delegated-MCP round trip and PostgreSQL foundation migration/role checks also passed. This proves the selected integration path, not the complete phase 2 authenticated application.

| Component | Observed / pinned version | Evidence and status |
|---|---|---|
| Python | 3.13.16 | Repository-local runtime; fixture suite runs |
| uv | 0.13.0 | Local bootstrap; `uv.lock` records full dependency resolution |
| Pydantic | 2.14.1 | Executable contracts and generated JSON Schema |
| FastAPI / Uvicorn | 0.143.0 / 0.54.0 | Test capture API and built Linux sink container |
| pytest / Ruff / mypy | 9.1.1 / 0.17.0 / 2.4.0 | Local automated checks |
| Official MCP SDK | 2.3.0 | Real authenticated Streamable HTTP tool request passed |
| Keycloak | 26.7.4 | OIDC code/PKCE, ID-token nonce verification, standard token exchange passed |
| PostgreSQL | 18.3 | Foundation/role migrations and read-only knowledge-role assertions passed |
| Docker / Compose | 29.8.1 / 5.5.1 | Engine started; both Compose configurations used |
| MCP protocol | 2025-11-25 | Requested and negotiated in the real tool round trip |
| Model (Phase 0) | Deterministic forced-call driver | Superseded for baseline inference by the Phase 1 model record above |

The workstation has about 31.6 GiB physical RAM, four CPU cores, and a Quadro RTX 3000 with 6 GiB VRAM. The current environment initially hid Docker and reported no global Python; the working toolchain is kept in this repository. No system PATH or trust store changes were made.

## Verified foundation

- Validated company fixtures cover three human departments, two requester/analyst paths, managers, distinct resource owners, a conflicting approver, and three workload identities.
- Benign/malicious document and ticket variants, unique canaries, standard/sensitive group paths, and future workflow scenarios are present.
- Disposable reset, allowed/denied reads, caller AND recipient ACLs, output limits, safe errors, and minimal durable audit evidence are executable.
- Scenario results distinguish success, failure, execution error, and unsupported features. The [final saved run](../reports/phase0-final/results.json) has 10 successful oracles, zero failures/errors, and three explicitly unsupported future workflows.
- The sink image built and ran on an internal network with no published port. Its probe passed local capture, no response echo, and denied external TCP. See [sink evidence](../reports/phase0-sink.json).
- The threat model, permission matrix, tool/event contracts, requirement mapping, configuration, migration scaffold, lockfile, and runbook are present.
- The checker passes 30 tests, Ruff lint/format, and strict mypy checks. These include pre-body authorization and an ACL-change race. Test outcomes are independent of the optional Docker probes.
- The identity spike preserves the authenticated user's subject through delegation, identifies `gateway` as the client, limits the audience to `knowledge`, and supplies `knowledge:read`. Missing-token, wrong-audience, and forged-header probes return 401. See [identity evidence](../reports/phase0-identity-spike.json).

## Integration findings and remaining boundaries

1. Docker's internal network did not expose the spike's published ports to the Windows runner. The trusted identity/database spike now uses a regular bridge with explicit loopback bindings. The adversarial capture sink remains on an internal network.
2. Keycloak emitted Secure login cookies over the original HTTP endpoint. The probe correctly refused to send those cookies over HTTP. Keycloak was reconfigured for locally trusted TLS instead of weakening cookie protection.
3. The initial TLS attempt ended before the endpoint was ready. An explicit readiness check and a certificate with key-usage/identifier extensions were added. The completed probe verifies the generated certificate; no TLS-verification or cookie-protection bypass is used.
4. The observed exchange has the same user `sub`, `azp=gateway`, `aud=knowledge`, scope `knowledge:read`, and no `act` claim. The verifier explicitly maps the validated `knowledge` audience to the configured MCP resource URI. This does not establish automatic OAuth client discovery or provider-native resource-URI binding; verify those, scope escalation limits, JWKS rotation, and all server audiences in phase 2.
5. PostgreSQL migrations and knowledge SELECT/no-INSERT privileges were checked against the real disposable database. These are foundation roles, not the final grant transaction and outbox schema. The default domain-tool tests still use SQLite and fixture identities.
6. The real model artifact/runtime/digest were subsequently pinned and measured in Phase 1. No hosted provider received fixture data.

The spike uses synthetic local credentials, a seven-day generated certificate, and disposable container state. All containers and networks created by these two Compose projects were removed after validation; downloaded images, the repository-local toolchain, and ignored generated credentials remain for reuse. Docker Desktop itself was left running. The runbook includes project-scoped `down` commands for future cleanup; do not remove unrelated Docker resources. An automatic approval-review service limit briefly interrupted diagnostics; work resumed when review became available, and it did not leave the identity result unverified.
