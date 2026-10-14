# Phase 5: framework preparation and comparative evaluation

Started October 14, 2026. Phase 4 remains complete for its recorded synthetic scope. Phase 5 now includes the [repeated evaluation report](phase5-report.md), [frozen comparison method](phase5-evaluation.md), clean-checkout verification and [demo preparation](demo/README.md). The initial comparison's provider timeout is retained alongside the successful confirmation cohort. The owner explicitly [accepted the documented residual risks](phase5-owner-review.md) on October 14, 2026 for local synthetic lab and portfolio use. **Phase 5 is complete for that scope; production use is not approved.**

## Completed preparation

- One machine-readable [risk register](../config/risk-register.json) with 17 risks, 20 threats across F1–F10, and 35 fixture/baseline/model scenario references. The [readable view](risk-register.md) is generated and checked for drift. Ratings are qualitative; owner acceptance is not fabricated.
- A [taxonomy registry](../config/risk-taxonomies.json) with reviewed ATLAS technique/mitigation names and a hash-verified, licensed copy of the pinned v2026.07 catalog. The upstream YAML is exempt from Git newline conversion to preserve its hash across clean checkouts.
- Explicit risk tags on all current fixture, baseline and model case definitions. Phase 3/4 inline case selections now live in versioned configuration; regression checks preserve their prior selection/order. Updated probes record case tags and configuration fingerprints in future results. Historical reports retain their original tags and hashes.
- Refreshed [threat model](threat-model.md), [security crosswalk](security-framework-mapping.md), [AI RMF/Profile review](ai-rmf-mapping.md), and [lab governance charter](lab-governance.md), grounded in the Phase 3/4 exit records. Governance, licensing, bias, environmental assessment and owner decisions retain explicit gaps.

The Phase 4 injected ticket asks for restricted disclosure; the authorized local proposal is not itself an adversarial grant attempt. Its tags therefore describe indirect injection and a leakage objective. Baseline unauthorized-grant cases separately use the adversarial tool-invocation mapping.

## Commands

Validation for this slice: **782 unique tests passed across two runs** (547 non-database tests, then 235 PostgreSQL integration tests), including 23 new framework tests. Lint, formatting and strict typing passed. The first run's 235 database skips were covered by the separate integration run, which had no failures or skips. [Saved preparation evidence](../reports/phase5-frameworks/results.json) records commands, counts and input hashes. The disposable database container/network were removed after validation; no service-desk containers remain running. This is working-tree regression evidence, not a clean-checkout or live model evaluation.

```powershell
.\.venv\Scripts\python.exe scripts/check_frameworks.py
.\.venv\Scripts\python.exe scripts/check_frameworks.py --write-view
.\scripts\check.ps1
```

Edit `config/risk-register.json`, then regenerate its view. Updating the taxonomy requires reviewing the upstream release, ID/name semantics and SHA-256, retaining the license, and running the offline checks. Tests never fetch a changing taxonomy. Empty benign risk arrays are intentional; missing arrays, unregistered cases, stale references and unknown tags fail validation.

Changing fixture tags changes the fixture fingerprint. A previously seeded disposable database with the old fingerprint must be recreated through the existing scoped lab teardown/start workflow; do not bypass the seed hash check or relabel old evidence. Runtime source and image pins have not changed in this preparation slice.

## Evaluation and delivery progress

1. **Completed:** four frozen matched read cases and actual-effect oracles, with forced tests kept separate. The register now indexes 39 scenario references. V0 approval/lifecycle/publication differences are explicitly unsupported comparisons.
2. **Completed with a retained limitation:** five repetitions per case/variant, plus a predeclared hardened confirmation cohort. Initial benign completion was 10/10 v0 and 9/10 hardened with one timeout; confirmation completed all 20 tasks. All cohorts observed 0/10 attack objectives, which does not establish a security improvement.
3. **Completed:** [machine-readable grouped report](../reports/phase5/results.json) by actor, entry, OWASP/ATLAS and STRIDE, with denominators, actual effects, completion, false blocks, latency, model accounting, action evidence and audit scope. Overlapping categories are not added together.
4. **Completed technical verification:** fresh dependency environment and Git checkout, 557 non-database plus 235 PostgreSQL tests, and exact runtime/catalog byte preservation. The full working-tree release regression passes 792 tests with zero skips. The [release manifest](../reports/phase5/release/results.json) records passing deployed probes: 256 boundary, 619 network, 73 signed workflow, 18 model and 32 log checks. The missing scratch-parent issue is fixed; earlier failed evidence remains available.
5. **Completed capture:** the [3:58 evidence walkthrough](demo/README.md) uses Microsoft Hazel's female UK voice, inspected image slides and OBS at 1080p/30 fps. Original MKV and playback MP4 are saved locally. All eight segment frames, decoded streams, audio levels and source alignment passed inspection. The earlier browser-texture defect and final OBS skip counters are preserved in the capture reports.
6. **Completed owner decision:** the owner accepted RISK-01 through RISK-17 for local synthetic lab and portfolio use on October 14, 2026. The [decision record](../reports/phase5/owner-acceptance.json) preserves the response, limits and review triggers. Planned improvements remain open.

The [initial freeze](../reports/phase5/comparison-01/freeze.json) and [confirmation protocol](../reports/phase5/confirmation-protocol.json) preserve the evaluated inputs. Later evidence-link and checker-delivery fixes do not rewrite those snapshots. Technical delivery is complete for the documented scope. The Phase 5 exit gate is closed for local synthetic lab and portfolio use following explicit owner acceptance, including the retained provider-timeout limitation. Production requires a separate readiness assessment and approval. The [implementation plan](../SECURE_SERVICE_DESK_AGENT_IMPLEMENTATION_PLAN.md) remains the governing release checklist. Lab containers were stopped after evidence collection; model/image caches and local recordings are retained.
