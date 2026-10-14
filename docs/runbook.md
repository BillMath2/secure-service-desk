# Foundation runbook

For the current hardened lab, use the [Phase 4 startup/check/stop runbook](phase4.md) and [completed exit matrix](phase4-exit.md). The [Phase 2 exit record](phase2-exit.md) preserves the historical read-only regression matrix, administrator setup for real key rotation and authentication compatibility limits.

For the separate contained vulnerable baseline, see the [Phase 1 runbook](phase1.md). For confidential login and the three TLS identity probes, see the [Phase 2 identity runbook](phase2.md). For the PostgreSQL task limits and authorized read tools, see the [read-boundary runbook](phase2-reads.md). For authenticated browser tasks and the bounded deterministic provider, see the [assistant runbook](phase2-assistant.md).

Run commands from the repository root. The default harness uses synthetic fixture identities and opens no network listener. It does not require Docker, a model, or a cloud account.

For the optional pinned local-model provider, offline checksum gate and genuine model trials, see the [Phase 2 model runbook](phase2-model.md). It reuses immutable cached weights and requires no cloud API key.

## Local setup and checks (Windows PowerShell)

```powershell
.\scripts\bootstrap.ps1
.\scripts\check.ps1
.\.venv\Scripts\service-desk.exe validate
.\.venv\Scripts\service-desk.exe evaluate --output reports/runs/my-first-run
```

Bootstrap downloads pinned uv and a Python 3.13.16 runtime under ignored `.tools`, then installs the locked dependencies into `.venv`. It does not edit system PATH or install Python globally. Internet access is needed for initial setup. The checker runs lint, formatting, strict type checks, and pytest. Evaluation output must be a new directory; use a new name for each run. Results include a fixture hash, configuration, outcomes, and safe audit evidence.

On another platform with uv 0.13.x installed, use `uv sync --locked --group baseline`, `uv run --group baseline ruff check .`, `uv run --group baseline ruff format --check .`, `uv run --group baseline mypy`, and `uv run --group baseline pytest`. Linux container execution is exercised by the sink and baseline builds; a complete Linux development checkout is not yet a tested target.

Fixture resets occur inside a temporary directory allocated by the harness. They replace only the disposable adapter's known tables and check database ownership. They do not reset PostgreSQL or remove arbitrary directories. Edit `fixtures/company.json` intentionally, validate it, and record the new hash when changing scenarios. Allowed document scenarios pin an expected body hash, so a fixture edit must update that oracle deliberately.

## Real identity and database spike

This is an optional Phase 0 compatibility test, separate from the default test suite. Its complete flow passed with the versions in the compatibility record. Docker Desktop must be running with Linux containers. It uses only synthetic credentials and loopback ports 18443 (Keycloak TLS), 18082 (temporary MCP server), and 15432 (PostgreSQL). Port 18081 is a redirect URI parsed by the test client; no callback server is needed.

```powershell
$env:UV_PYTHON_INSTALL_DIR = Join-Path $PWD '.tools/python'
$env:UV_CACHE_DIR = Join-Path $PWD '.tools/uv-cache'
.\.tools\uv\uv.exe sync --locked --group spike
.\.venv\Scripts\python.exe scripts/prepare_spike.py
docker compose -f infra/compose.spike.yaml up -d
docker compose -f infra/compose.spike.yaml logs --tail 10 keycloak
# Wait until Keycloak reports that startup and realm import are complete.
.\.venv\Scripts\python.exe scripts/run_identity_spike.py
docker compose -f infra/compose.spike.yaml down
```

The spike signs in the synthetic user through OIDC authorization code with PKCE, verifies the ID token and nonce, exchanges the user access token through the confidential gateway client, and makes an authenticated MCP tool request. It checks missing tokens, wrong-audience tokens, and forged username headers. It also applies the PostgreSQL foundation/role migrations and checks knowledge read/write privileges. Output contains booleans and safe claim shapes, never usable tokens or passwords.

`.lab` holds generated throwaway credentials and is excluded from Git and Docker build contexts. Preparation preserves a complete existing configuration. To rotate it, first bring down only this Compose project and remove its generated files explicitly before preparing again. Do not regenerate credentials while containers using the old values are running. Database state is disposable; `down` removes the PostgreSQL container and its temporary data.

Keycloak runs in development mode with a generated local TLS certificate trusted only by the probe, without changing the system trust store. Generated certificates expire after seven days; stop the spike before rerunning preparation, which refreshes expired or nearly expired certificates. The MCP endpoint still uses loopback HTTP. The bridge network permits the loopback published ports and is not an egress-denied attack environment. End-to-end TLS, OAuth client discovery automation, per-tool resource ACLs, refresh/session handling, and production identity checks remain phase 2 work. An unexpected login form or failed token exchange must fail the probe rather than fall back to password grants or forged identities.

## Test capture sink

```powershell
docker compose -f infra/compose.phase0.yaml up -d --build
.\scripts\check_sink.ps1
docker compose -f infra/compose.phase0.yaml down
```

The sink is accessible only on its internal test network; it has no published ports, no credentials, no host mounts, a read-only filesystem, and capped memory/processes. The probe confirms local capture, no payload echo, network configuration, and denied outbound TCP. The API accepts at most 8 KiB per capture and 100 captures per container lifetime. Restart the disposable sink for a new test run; never use it as an application logging destination.

## Troubleshooting

If `py` reports no installed Python, use bootstrap and the `.venv` paths above. If Docker reports a missing Linux engine pipe, start Docker Desktop and rerun its health check. If port 18443 refuses connections or TLS ends before a handshake completes, inspect the spike logs and confirm startup completed. Do not disable certificate verification or strip Secure flags from cookies. A Docker internal network can suppress published host access; only the sink uses that mode, while the trusted identity spike uses explicit loopback bindings.

Do not change policy to turn a failing test green. `failure` means an oracle mismatch, `error` means the test could not complete, and `unsupported` means the feature is not implemented. None of these counts as a passing security test. Preserve safe evidence and fix the corresponding boundary.
