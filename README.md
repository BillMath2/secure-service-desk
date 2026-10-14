# Secure Service Desk Agent Lab

A synthetic AI security lab where the model proposes actions and independent code enforces permissions.

Phases 0–2 are complete for the pinned synthetic lab. The read-only assistant includes confidential sign-in, protected sessions, verified delegation, shared PostgreSQL limits, pinned tools, ACL-filtered reads and cited answers using either a deterministic provider or the local Qwen model. Real signing-key rotation and the selected MCP/OAuth discovery paths are tested. Phase 3 will add recipient-safe drafting and confirmed writes; no write capability is currently enabled.

```powershell
.\scripts\bootstrap.ps1
.\scripts\check.ps1
.\.venv\Scripts\service-desk.exe evaluate --output reports/runs/first-run
```

See the [runbook](docs/runbook.md) for setup, evidence, the optional real OIDC/MCP spike, and test-sink probes.

- [Project plan](SECURE_SERVICE_DESK_AGENT_PROJECT.md)
- [Implementation plan](SECURE_SERVICE_DESK_AGENT_IMPLEMENTATION_PLAN.md)
- [Phase 0 status and compatibility](docs/compatibility.md)
- [Phase 1 baseline and runbook](docs/phase1.md)
- [Phase 2 identity foundation](docs/phase2.md)
- [Phase 2 authorized reads, shared limits and next steps](docs/phase2-reads.md)
- [Phase 2 authenticated assistant demo and limits](docs/phase2-assistant.md)
- [Phase 2 local model, containment and initial trials](docs/phase2-model.md)
- [Phase 2 exit matrix and remaining deployment limits](docs/phase2-exit.md)
- [Threat model](docs/threat-model.md)
- [Permission matrix](docs/permission-matrix.md)
- [Tool and event contracts](docs/contracts.md)
- [Requirement-to-test mapping](docs/requirements.md)
- [OWASP, MITRE ATLAS and initial STRIDE mapping](docs/security-framework-mapping.md)
- [NIST AI RMF and Generative AI Profile mapping](docs/ai-rmf-mapping.md)
- [Foundation design decision](docs/adr/0001-phase0-foundation.md)

The default fixture harness is not an authenticated production service. Its controlled test identities, SQLite adapter, and forced tool calls must not be mistaken for a deployed MCP agent or a model-driven security evaluation.
