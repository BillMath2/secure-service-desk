# Phase 0 status and compatibility

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
| Model | Deterministic forced-call driver | No downloaded model or measured inference; first candidate in ADR 0001 |

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
6. The real model artifact/runtime/digest and hardware benchmark belong to the next baseline build. No hosted provider received fixture data.

The spike uses synthetic local credentials, a seven-day generated certificate, and disposable container state. All containers and networks created by these two Compose projects were removed after validation; downloaded images, the repository-local toolchain, and ignored generated credentials remain for reuse. Docker Desktop itself was left running. The runbook includes project-scoped `down` commands for future cleanup; do not remove unrelated Docker resources. An automatic approval-review service limit briefly interrupted diagnostics; work resumed when review became available, and it did not leave the identity result unverified.
