# Phase 2: identity foundation

**Current status:** the full Phase 2 read-only exit gate is now met. See the [final compatibility and exit record](phase2-exit.md) for discovery, real key rotation, current evidence and limitations. This page preserves the earlier identity-slice snapshot below.

Started October 13, 2026. **Phase 2 is in progress; its read-only assistant exit gate is not met.** The first slice resolves confidential login and delegated identity before enabling protected data tools. The full checker passes 83 tests, including 39 new identity cases. The live Keycloak/TLS probe passes; sanitized evidence is in [reports/phase2-identity/results.json](../reports/phase2-identity/results.json).

The next slice is now implemented: see [shared limits and authorized reads](phase2-reads.md) for the current 118-test status, 34 live checks, and remaining assistant work. This page preserves the initial identity-slice evidence.

## Review and implementation boundary

Phase 1's saved results support proceeding: the forced unsafe effects and containment checks passed, while its model-driven failures remain reported as failures. Its isolated runtime remains separate from the authenticated package. The Phase 0 identity spike was useful evidence but had a public login client, only one resource audience, and no application session boundary.

The new slice implements:

- Confidential `web` sign-in using authorization code, S256 PKCE, one-use state bound to the browser, signed ID-token validation, and nonce/subject checks. No password grant is enabled.
- Bounded, locked, server-side sessions. Cookies carry random handles, use `__Host-`, Secure, HttpOnly and SameSite=Lax, and never contain tokens. Callback responses are not cacheable. Logout requires both an exact Origin and session CSRF token. Successful sign-in replaces the previous session; callback replay fails.
- A separate confidential `gateway` exchanges a validated user token for exactly one registered audience. The adapter checks the original scope, preserved subject, returned client/audience, and that the returned scopes do not expand the original or target capability.
- Real RS256 signature verification, fixed issuer/JWKS, exact single audience, allowed `azp`, required time claims, and an operator-owned `(issuer, sub)` to fixture-principal mapping. Usernames and model/header identity assertions are not authentication.
- Three authenticated MCP identity probes with protected-resource metadata, challenges, required scopes, and local TLS. Their only tool is `identity_status`; no fixture data or mutation tool is exposed.
- Separate executor and lifecycle clients. Live service-account tokens have only their own audience/capability and cannot invoke the three human-facing MCP endpoints. The gateway cannot exchange into either privileged audience.

JWT validation is a reusable component; the browser shell and identity probe are deliberately not an assistant deployment. The Phase 0 fixture `RequestContext` remains explicitly unauthenticated and is not relabeled as real identity.

## Tested claim and resource contract

Keycloak 26.7.4, MCP SDK 2.3.0, PyJWT 2.15.1, HTTPX 0.28.1, and MCP protocol 2025-11-25 were exercised. Python and the remaining dependencies are pinned in `uv.lock` and the [compatibility record](compatibility.md).

| Token / destination | Validated client | Signed audience | Capability |
|---|---|---|---|
| Web ID token | `web` | `web` | Nonce-bound sign-in only |
| Web access token held server-side | `web` | `gateway` | Requested read scopes plus `openid` |
| Knowledge: `https://127.0.0.1:19482/mcp` | `gateway` | `knowledge` | `knowledge:read` |
| Tickets: `https://127.0.0.1:19483/mcp` | `gateway` | `tickets` | `tickets:read` |
| Access: `https://127.0.0.1:19484/mcp` | `gateway` | `access` | `access:read` |
| Executor (no execution endpoint yet) | `executor` | `execution` | `access:execute` |
| Lifecycle worker (no lifecycle endpoint yet) | `worker` | `lifecycle` | `access:lifecycle` |

The live tests preserve both Erin's and Alice's subjects through all three exchanges. No `act` claim was emitted, and none is assumed. The validated client claim identifies the issued client; bearer tokens are not proof of possession.

The adapter sends `resource` on authorization, code redemption and exchange. Keycloak uses its configured audience names; only after exact signed audience validation does the server map that audience to its fixed canonical MCP URL. Multi-audience tokens and another server's token fail. The original web token also fails at every MCP server. This explicit adapter follows the audience requirement in the [MCP authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization); it is not a claim that Keycloak natively enforces resource-URI binding.

The gateway is pre-registered, validates pinned OIDC discovery, and does not accept arbitrary authorization servers or redirect destinations. Generic MCP OAuth client discovery, including RFC 8414 fallback and client registration, is not implemented. The live probe verifies the SDK's resource metadata and challenges without claiming a general-purpose discovery client.

Keycloak standard exchange can add optional scopes; audience filtering alone does not prevent that. The adapter rejects a missing original scope and checks returned scopes independently. Privileged scopes/audiences are not assigned to the gateway. Read scopes are capability ceilings shared by the fixture humans, not their document or ticket entitlements. The resource-policy intersection and its non-expansion proof remain required before protected reads are enabled. See [Keycloak's exchange prerequisites and scope behavior](https://www.keycloak.org/securing-apps/token-exchange).

JWKS sets have a 60-second cache lifetime, a five-second unknown-key refresh cooldown, and no permanent per-key cache. Tests exercise a new signing key, removal of an old key after refresh, and failure on an unavailable uncached key source. Rotation may temporarily deny a new key during the cooldown; cached keys remain acceptable until refresh/expiry. Real Keycloak administrator-driven rotation remains a later integration check.

## Live findings

The first probe reached Keycloak before startup completed. A bounded readiness check now handles startup. The next probe rejected an access token without `sub`: the minimal custom realm scopes had omitted the subject mapper. Explicit `oidc-sub-mapper` configuration fixed the issuer contract without weakening validation. The [official mapper reference](https://www.keycloak.org/admin-api/protocol-mappers) describes this mapper. Neither failed run counted as a pass; subsequent complete runs passed. No usable token, password, code, session cookie, or client secret is saved in the report.

## Reproduce

From the repository root, with Docker Desktop's Linux engine running:

```powershell
.\scripts\bootstrap.ps1
.\scripts\check.ps1
.\.venv\Scripts\python.exe scripts/prepare_phase2.py
docker compose -f infra/compose.phase2-identity.yaml up -d
try {
    .\.venv\Scripts\python.exe scripts/check_phase2_identity.py
    if ($LASTEXITCODE -ne 0) { throw 'Phase 2 identity probe failed' }
} finally {
    docker compose -f infra/compose.phase2-identity.yaml down
}
```

The probe starts and stops four loopback TLS listeners itself: web on 19481 and MCP on 19482–19484. Keycloak uses 19443. Certificates are explicitly trusted by the clients; system trust is unchanged. The probe performs real form login, code redemption, exchange, and MCP HTTP calls. Browser-session checks use an HTTP client with a cookie jar, not browser UI automation. Results are written under ignored `reports/runs/phase2-identity/` with unique filenames; selected sanitized evidence is checked into `reports/phase2-identity/`.

If Docker is installed per-user but absent from PATH, its executable on this workstation is `C:\Users\Bill\AppData\Local\Programs\DockerDesktop\resources\bin\docker.exe`. Use that explicit path for the Compose commands if needed.

`prepare_phase2.py` keeps credentials in ignored `.lab/phase2` and preserves complete existing configuration. It refuses partial or expired configurations. After stopping this Compose project, `prepare_phase2.py --refresh-realm` updates the realm template while retaining generated credentials. Certificates last seven days. Rotating the full configuration requires explicitly removing or archiving only `.lab/phase2` while its services are stopped, then preparing again. Never regenerate a live realm's credentials.

For a persistent identity shell, start Keycloak and run `scripts/phase2_runtime.py web` with the repository Python. Separate terminals can run `knowledge`, `tickets`, and `access`. All listeners use the generated certificate. MCP processes load public subject mappings and verification keys, without loading client credentials. Human credentials are synthetic entries in the ignored local credential file. This shell exposes JSON `/session`, login/callback and logout endpoints; analyst workflow screens are still pending. Do not disable TLS verification to try the shell in a browser.

Sessions are in memory for one process, capped at 256, and expire at the earlier of 15 minutes or the original access token's expiry (120 seconds in this realm). Restart requires signing in again. There is no refresh-token flow or IdP-wide logout. Persisted multi-process sessions, task suspension and reauthentication belong to the next application work. The trusted identity Compose bridge has loopback bindings but does not deny egress; it is not an attack network or the final hardened deployment.

## Follow-on work

Items 1?3 below were subsequently implemented in the [read boundary slice](phase2-reads.md). Item 4 remains open.

1. Persist a server-owned task context and atomic shared tool-call budgets, usable by every MCP service even on direct calls. Keep identity and audience outside model arguments.
2. Add the reviewed tool registry and schema/version pinning. Bind dispatch to current task scope and audience; count rejected attempts as well as accepted calls.
3. Implement PostgreSQL ticket/document ACL checks and full-text retrieval with ACL filtering before ranking/snippets. Test guessing, recipient restrictions and scope non-expansion through actual data effects.
4. Connect cited, bounded read-only agent tasks, isolated conversation/cache state, and audit decisions. Complete generic discovery coverage where needed, real provider rotation checks, and the Phase 2 exit matrix before enabling writes.
