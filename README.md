# Secure Service Desk Agent Lab

A synthetic AI security lab where the model proposes actions and independent code enforces permissions.

Phases 0 through 4 are complete for the pinned synthetic lab. Phase 4 passes 759 tests and the final deployed containment, grant-workflow, model-completion and log checks. The authenticated assistant supports authorized reads, fresh recipient-safe drafts and exact human-confirmed ticket writes. Access proposals now require independent human approval; a separate executor creates temporary grants, and expiry/review checks deny access independently of cleanup. Service-scoped outboxes deliver correlated events to a protected audit collector. The [Phase 4 exit matrix](docs/phase4-exit.md) records the tests, deployed grant workflows, containment evidence and scope limits. Phase 5 covers repeated comparative evaluation and final delivery.

```powershell
.\scripts\bootstrap.ps1
.\scripts\check.ps1
.\.venv\Scripts\service-desk.exe evaluate --output reports/runs/first-run
```

See the [runbook](docs/runbook.md) for setup, evidence, the optional real OIDC/MCP spike, and test-sink probes.

[Phase 5 evaluation](docs/phase5-report.md) now records five repetitions of four matched read cases per variant, plus a separate hardened confirmation cohort. Neither variant produced an unsafe model-driven effect; forced baseline tests reproduced all three intended vulnerabilities. The initial hardened cohort retained one provider timeout; the confirmation completed all 20 tasks. The release regression passes 792 tests, and fresh-checkout setup/tests and exact runtime bytes are verified. The [3:58 recorded evidence walkthrough](docs/demo/README.md) uses a female British English voice. All five deployed release gates passed. Technical delivery is complete; explicit [owner risk acceptance](docs/phase5-owner-review.md) remains pending in the [Phase 5 runbook](docs/phase5.md).

- [Project plan](SECURE_SERVICE_DESK_AGENT_PROJECT.md)
- [Implementation plan](SECURE_SERVICE_DESK_AGENT_IMPLEMENTATION_PLAN.md)
- [Phase 0 status and compatibility](docs/compatibility.md)
- [Phase 1 baseline and runbook](docs/phase1.md)
- [Phase 2 identity foundation](docs/phase2.md)
- [Phase 2 authorized reads, shared limits and next steps](docs/phase2-reads.md)
- [Phase 2 authenticated assistant demo and limits](docs/phase2-assistant.md)
- [Phase 2 local model, containment and initial trials](docs/phase2-model.md)
- [Phase 2 exit matrix and remaining deployment limits](docs/phase2-exit.md)
- [Phase 3 implementation and historical exit evidence](docs/phase3.md)
- [Phase 4 approvals, lifecycle, audit and startup/check/stop commands](docs/phase4.md)
- [Threat model](docs/threat-model.md)
- [Permission matrix](docs/permission-matrix.md)
- [Tool and event contracts](docs/contracts.md)
- [Requirement-to-test mapping](docs/requirements.md)
- [Shared risk register and scenario index](docs/risk-register.md)
- [Lab governance and risk-review procedure](docs/lab-governance.md)
- [Phase 5 evaluation and delivery status](docs/phase5.md)
- [Repeated evaluation report and limitations](docs/phase5-report.md)
- [Frozen comparison method and reproduction](docs/phase5-evaluation.md)
- [Demo capture and female UK narration](docs/demo/README.md)
- [Owner residual-risk review](docs/phase5-owner-review.md)
- [OWASP, MITRE ATLAS and per-flow STRIDE mapping](docs/security-framework-mapping.md)
- [NIST AI RMF and Generative AI Profile mapping](docs/ai-rmf-mapping.md)
- [Foundation design decision](docs/adr/0001-phase0-foundation.md)

The default fixture harness is not an authenticated production service. Its controlled test identities, SQLite adapter, and forced tool calls must not be mistaken for a deployed MCP agent or a model-driven security evaluation.
