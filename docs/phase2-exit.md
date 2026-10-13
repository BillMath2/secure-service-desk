# Phase 2 exit record

October 13, 2026: **Phase 2's read-only assistant exit gate is met for the pinned, pre-registered lab deployment.** The authenticated browser/API assistant can complete a cited read task with the local model. Independent gateway and MCP checks enforce identity, scope, resource access and durable task limits. No write capability is enabled.

## Acceptance evidence

The complete checker passes **211 tests**, including 44 opt-in PostgreSQL cases and 167 default cases. Ruff lint/format and strict mypy checks pass. The final live regression uses the same pinned runtime described in the [compatibility record](compatibility.md).

| Exit requirement | Evidence |
|---|---|
| Signed real tokens support legitimate reads | [34 protected-read checks](../reports/phase2-reads/results.json), [27 browser-assistant checks](../reports/phase2-assistant/results.json), and [three genuine local-model tasks](../reports/phase2-model/results.json) |
| Confidential login, preserved delegation, separate client/audience/scope boundaries | [68 live identity checks](../reports/phase2-identity/results.json) and 39 deterministic identity cases |
| Direct calls cannot bypass ACLs or shared limits | 24 PostgreSQL read cases, 20 assistant cases, 12 registry cases and the live read probe |
| MCP metadata, challenges and authorization-server discovery work within the pinned trust policy | 31 discovery cases plus [25 live compatibility checks](../reports/phase2-auth-compat/results.json); the gateway performs discovery before exchanging or sending a token |
| Signing-key rotation, retirement and expiry work against the actual issuer | New-key protected reads succeed without restarting validators; retired keys leave the real JWKS; fresh verifiers reject immediately, and warm verifiers reject after their 60-second cache expires; real expired tokens fail |
| The model remains bounded and cannot select destinations or capabilities | 23 provider cases, ten cache/relay cases, 16 model-containment checks and the final local-model trials |

Reports contain safe claim shapes, checks, counters, hashes and timing. They do not contain usable tokens, passwords, private keys, prompts or protected source bodies. Older timestamped failures remain available; they are not included as successful evidence.

The [exit evidence index](../reports/phase2-exit/results.json) records the verified report hashes, test counts, scope and remaining limitations.

## Authentication compatibility contract

The selected MCP authorization version is 2025-11-25, implemented with SDK 2.3.0, Keycloak 26.7.4 and PyJWT 2.15.1. The gateway first makes a credential-free request to the registered resource. It uses the Bearer challenge's metadata URL when present, otherwise trying the path-specific and root protected-resource metadata locations. It validates the exact resource and pinned authorization server before exchanging a token. Discovery failures consume the existing tool reservation and never forward credentials or dispatch the requested tool.

Authorization-server discovery tries RFC 8414 path insertion, OIDC path insertion, then OIDC path appending. Keycloak 26.7.4 supports the first and third locations; the second returns 404. Deterministic tests cover successful fallback through each location. A missing location permits fallback; a redirect, invalid successful document, outage, changed issuer/endpoint, unsupported PKCE or malformed capabilities causes denial. Responses and elapsed time are bounded. Requests strip Authorization, Cookie and Proxy-Authorization, even if the HTTP pool has defaults.

This order and the registration choices follow the [MCP authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization). The trust policy deliberately permits only the configured issuer and standard metadata locations on each registered resource. A scope challenge cannot expand the configured read capability. The deployment uses pre-registered confidential clients; optional Dynamic Client Registration and Client ID Metadata Documents are not enabled. This is a tested application adapter, not a general-purpose client for arbitrary MCP servers.

Keycloak's signed audience names remain mapped to canonical MCP resource URLs only after signature, issuer, client and exact single-audience validation. The adapter sends `resource` during authorization, redemption and exchange and validates the returned audience/scopes itself. It does not assume Keycloak natively enforces arbitrary resource-URI requests, and it never forwards the original web token to an MCP server. Scopes limit capabilities; PostgreSQL ACLs separately determine entitlement to specific resources.

## Real signing-key rotation

The probe creates one additional generated RSA signing-key component at higher priority, preserving the old key during overlap. It then disables the old component and tests both a fresh verifier and the already-running MCP verifier. Old-token rejection occurs before token expiry, demonstrating key retirement rather than merely expiration. The final run observed approximately 60.6 seconds of remaining warm-cache acceptance. This is the documented cache bound, not immediate revocation. A new key can also be denied briefly during the five-second unknown-key refresh cooldown.

The same probe temporarily reduces token lifetime, proves acceptance followed by expiry rejection, and restores the original lifetime/key configuration. Component creation, priority and disabling follow the [Keycloak administration guide](https://www.keycloak.org/docs/latest/server_admin/index.html#rotating-keys) and its [Admin REST API](https://www.keycloak.org/docs-api/latest/rest-api/index.html). Administrator credentials exist only in the separate ignored rotation directory and optional Compose override. Application runtimes do not load them.

Two harness findings were corrected before the successful run: the first probe expected OIDC fallback even though this Keycloak supports RFC 8414 directly; the next probe's temporary admin token expired during the deliberate cache wait. The latter run could not restore the realm, so its disposable container was removed and recreated from the unchanged import. The final harness renews its admin token and confirms restoration. Failed reports retain their failed status.

## Reproduce the final matrix

Start from stopped Phase 2 projects so the optional administrator is bootstrapped into a fresh disposable identity container. The read database is temporary; the model uses the previously verified immutable cache.

```powershell
.\.venv\Scripts\python.exe scripts/prepare_phase2.py
.\.venv\Scripts\python.exe scripts/prepare_read_store.py
.\.venv\Scripts\python.exe scripts/prepare_rotation.py
docker compose -f infra/compose.phase2-reads.yaml up -d --wait
docker compose -f infra/compose.phase2-identity.yaml -f infra/compose.phase2-rotation.yaml up -d
docker compose -f infra/compose.phase2-model.yaml up -d --pull never
try {
    .\.venv\Scripts\python.exe scripts/prepare_read_store.py --apply
    if ($LASTEXITCODE -ne 0) { throw 'Database preparation failed' }
    $env:DESK_READ_INTEGRATION = '1'
    .\scripts\check.ps1
    foreach ($probe in @('check_phase2_auth_compat', 'check_phase2_identity',
                        'check_phase2_reads', 'check_phase2_assistant', 'check_phase2_model')) {
        .\.venv\Scripts\python.exe "scripts/$probe.py"
        if ($LASTEXITCODE -ne 0) { throw "Probe failed: $probe" }
    }
} finally {
    Remove-Item Env:\DESK_READ_INTEGRATION -ErrorAction SilentlyContinue
    docker compose -f infra/compose.phase2-model.yaml down
    docker compose -f infra/compose.phase2-identity.yaml -f infra/compose.phase2-rotation.yaml down
    docker compose -f infra/compose.phase2-reads.yaml down
}
```

The model probe accepts `--docker <absolute-path>` if Docker is not in PATH. Run probes sequentially because they use the same local TLS ports. The rotation probe needs about a minute for the real cache-expiry test. If restoration fails, remove only this disposable identity project and recreate it before further use. The scripts do not change an external realm.

## Scope of completion and next work

Phase 2 completion is limited to this lab's authenticated, read-only deployment. The real model's small fixed-seed trials do not establish the Phase 5 success-rate targets. A warm JWKS cache is not immediate revocation, sessions remain single-process with no refresh, and the entire host application/relay does not yet have proven egress and credential isolation. Those limits are explicit in the [model runbook](phase2-model.md).

Phase 3 begins with requester-safe generation in a fresh context, an explicit source manifest and recipient policy, followed by reviewed/confirmed ticket writes. It also covers stronger output controls, admission throttling and deployment isolation. Phase 4 owns privileged execution and full independent audit collection. Phase 2 completion does not enable any of these capabilities automatically.
