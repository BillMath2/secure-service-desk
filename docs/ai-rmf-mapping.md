# NIST AI RMF mapping

Reviewed October 13, 2026. Scope: the synthetic, read-only Secure Service Desk lab through Phase 2. This is an evidence crosswalk and improvement plan, not certification, a compliance assessment, or proof of an operational enterprise governance program.

The [NIST AI RMF 1.0 Core](https://airc.nist.gov/airmf-resources/airmf/5-sec-core/) defines Govern, Map, Measure, and Manage as interacting functions. Govern applies across the other functions. The source notes that a revised framework is in progress; this document explicitly uses AI RMF 1.0.

## Project mapping

| Function | Existing project evidence | Remaining work |
|---|---|---|
| **Map** | The [threat model](threat-model.md) identifies assets, actors, trust boundaries, assumptions, and excluded threats. The [permission matrix](permission-matrix.md) defines human/workload roles and data audiences. The [framework mapping](security-framework-mapping.md) classifies selected attack scenarios. | Refresh the Phase 0 threat model for the deployed Phase 2 architecture; add a data-flow diagram, affected-party analysis, prioritized risk register, and residual-risk decisions. |
| **Measure** | [Requirements traceability](requirements.md), deterministic boundary tests, PostgreSQL integration cases, recorded live identity/read/assistant checks, and initial real-model injection tasks. The [Phase 2 exit record](phase2-exit.md) separates successful evidence from failed historical runs and documents limitations. | Expand attack diversity and repeated runs; measure benign task completion, false blocks, disclosure/action effects, and uncertainty. Current small fixed-seed trials do not establish population-level attack-success rates or a controlled improvement over the baseline. |
| **Manage** | Independent authorization, scoped delegation, permission-filtered retrieval, pinned tools, bounded resource use, container restrictions, and artifact verification constrain selected risks. The read-only milestone limits enabled capabilities. | Complete recipient-safe output, confirmed writes, privileged execution controls, stronger host/relay isolation, and operational incident/recovery procedures before expanding deployment scope. |
| **Govern** | Design decisions, versioned requirements, explicit milestone gates, permission/approval contracts, and durable read-decision records establish lab-level accountability. | Assign accountable owners and risk-acceptance authority; define change approval and review cadence, evidence retention, and escalation. Approval contracts are design artifacts: live human approval, approval-bound privileged execution, and full independent audit collection remain planned. |

Mappings above are the project's interpretation of the framework, not NIST validation. Audit records also support Measure and Manage; approval contracts alone do not complete Govern.

## Generative AI Profile: NIST AI 600-1

[NIST AI 600-1, Artificial Intelligence Risk Management Framework: Generative Artificial Intelligence Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence) is a companion to AI RMF 1.0. Use it to extend this initial security-focused mapping into a broader generative-AI risk review.

Useful project starting points are unauthorized disclosure and prompt-driven tool misuse, answer/source reliability, model/tool provenance, and the boundary between human authority and automated action. Existing artifacts provide evidence for parts of that review; they do not address every profile risk or recommended action. Add explicit profile action mappings only after reviewing the relevant actions and documenting applicability, evidence, gaps, an owner, and a review date.

## Next review record

For each material risk, record: affected users/assets, scenario and source IDs, likelihood/impact rationale, implemented mitigation, test evidence, residual risk, accountable owner, acceptance or remediation decision, and next review trigger. Retain the distinction between a control that is designed, implemented, tested deterministically, and evaluated with a real model.

The existing lab is a useful portfolio application of the framework. Familiarity with NIST SP 800-53 does not by itself establish AI RMF experience; this documented mapping is a concrete first step.
