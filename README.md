# Secure Service Desk Agent Lab

A synthetic AI security lab where the model proposes actions and independent code enforces permissions.

Phases 0?3 are complete for the pinned synthetic lab. The assistant has signed-user authentication, independently authorized read tools, bounded tasks, fresh recipient-safe contexts, screened chat/draft output, immutable reviews and exact human-confirmed requester replies/internal comments. Browser, agent, publisher and read services now have separate credentials and containers; all seven application/model runtime namespaces have checked outbound policies. The [Phase 3 exit matrix](docs/phase3-exit.md) records deterministic tests, real-model/browser workflows and direct containment evidence. Phase 4 access approvals, grants, lifecycle and durable audit delivery are next.

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
- [Phase 3 implementation and hardened startup/check/stop commands](docs/phase3.md)
- [Threat model](docs/threat-model.md)
- [Permission matrix](docs/permission-matrix.md)
- [Tool and event contracts](docs/contracts.md)
- [Requirement-to-test mapping](docs/requirements.md)
- [OWASP, MITRE ATLAS and initial STRIDE mapping](docs/security-framework-mapping.md)
- [NIST AI RMF and Generative AI Profile mapping](docs/ai-rmf-mapping.md)
- [Foundation design decision](docs/adr/0001-phase0-foundation.md)

The default fixture harness is not an authenticated production service. Its controlled test identities, SQLite adapter, and forced tool calls must not be mistaken for a deployed MCP agent or a model-driven security evaluation.
