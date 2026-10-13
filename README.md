# Secure Service Desk Agent Lab

A synthetic AI security lab where the model proposes actions and independent code enforces permissions.

Phase 0 provides a Python scaffold, validated fictional company fixtures, an instrumented document-read tool, a durable minimal audit collector, actual-effect scenario evaluation, PostgreSQL foundation migrations, and isolated compatibility probes. The full assistant and vulnerable baseline are later phases.

```powershell
.\scripts\bootstrap.ps1
.\scripts\check.ps1
.\.venv\Scripts\service-desk.exe evaluate --output reports/runs/first-run
```

See the [runbook](docs/runbook.md) for setup, evidence, the optional real OIDC/MCP spike, and test-sink probes.

- [Project plan](SECURE_SERVICE_DESK_AGENT_PROJECT.md)
- [Implementation plan](SECURE_SERVICE_DESK_AGENT_IMPLEMENTATION_PLAN.md)
- [Phase 0 status and compatibility](docs/compatibility.md)
- [Threat model](docs/threat-model.md)
- [Permission matrix](docs/permission-matrix.md)
- [Tool and event contracts](docs/contracts.md)
- [Requirement-to-test mapping](docs/requirements.md)
- [Foundation design decision](docs/adr/0001-phase0-foundation.md)

The default fixture harness is not an authenticated production service. Its controlled test identities, SQLite adapter, and forced tool calls must not be mistaken for a deployed MCP agent or a model-driven security evaluation.
