# NIST AI RMF and Generative AI Profile mapping

Reviewed October 14, 2026 against the Phase 3/4 exit evidence and the [risk register](risk-register.md). Uses **AI RMF 1.0**; the official Core notes a revision in progress. This is our lab-scoped interpretation, not NIST validation, certification, a compliance assessment or enterprise governance assurance. Earlier Phase 2 mappings remain in repository history.

## Applicable Core subcategories

The evidence level on each risk is scoped to the cited control. Documentation of a practice is not proof that its full organizational outcome has been achieved.

| Subcategory | Risk IDs and lab contribution | Evidence / remaining gap |
|---|---|---|
| GOVERN 1.5, 2.1 | RISK-14: owner, review cadence, evidence retention | [Lab charter](lab-governance.md) established; final owner residual-risk decisions pending |
| GOVERN 3.2 | RISK-05/06: human/model/executor roles | Exact review and independent approvals tested in [Phase 4](phase4-exit.md); no organizational training/oversight assessment |
| GOVERN 6.1 | RISK-12/15: component stewardship | Pins and integrity checks implemented; licensing/supplier review incomplete |
| MAP 1.1 | RISK-01/03/14: purpose, actors, context | [Threat model](threat-model.md), synthetic fixtures and permission matrix; external stakeholder consultation not performed |
| MAP 4.1 | RISK-09/12/15: component risks | Model, identity and MCP pins; no comprehensive legal or vendor assessment |
| MAP 5.1 | All material risks: potential impact | Qualitative likelihood/impact rationales; not empirical population estimates |
| MEASURE 1.1, 2.1 | RISK-14: methods and metrics | Frozen actual-effect oracles, source hashes, repeated cohorts and explicit error/timeout/unsupported denominators |
| MEASURE 2.3, 2.5 | RISK-13: task quality and reliability | Initial benign model observations and documented failures; no broad reliability claim |
| MEASURE 2.7 | RISK-01 through RISK-12: security/resilience | Deterministic, database and live containment/workflow checks; scenario-specific model samples |
| MEASURE 2.8 | RISK-08/14: accountability evidence | Correlated, redacted audit; reporting and organizational accountability review remain partial |
| MEASURE 2.10 | RISK-02/04/10: audience confidentiality | Fresh requester context and disclosure tests; synthetic data is not a full privacy assessment |
| MEASURE 2.11, 2.12 | RISK-16/17: bias and environmental effects | Explicitly unassessed; policy-driven grants and local inference do not remove these risks |
| MEASURE 3.1 | RISK-14: recurring risk review | Register and review triggers established; sustained monitoring history not yet available |
| MANAGE 1.3 | RISK-07/14: treatments and priorities | Control decisions recorded; residual acceptance and final release decision remain with owner |
| MANAGE 2.4 | RISK-11: stopping unsafe work | Cancellation, deadlines and scoped teardown tested; not a complete enterprise deactivation process |
| MANAGE 3.1 | RISK-12: component changes | Catalog quarantine and artifact pins; periodic vendor-risk monitoring incomplete |
| MANAGE 4.1 | RISK-08/14: monitoring/recovery | Durable outbox/recovery tests and lab procedure; user appeals, incident communications and production operations not implemented |

Workforce diversity, organization-wide training/culture, legal/regulatory governance and affected-community consultation are not demonstrated by this single-owner lab. They are outside the present evidence scope, not automatically inapplicable to any future deployment. MEASURE 1.3 independent assessment is likewise a gap. Human fixture roles do not stand in for real organizational accountability.

## NIST AI 600-1 risk review

All rows are owned by the **project owner**, reviewed October 14, 2026, and due again at Phase 5 exit or a change in model, data, audience or deployment. Unsupported areas are reported explicitly; no risk is marked absent merely because it was not tested.

| Profile risk | Applicability and register | Evidence / residual decision |
|---|---|---|
| CBRN Information or Capabilities | Outside intended support use; RISK-16 | No domain evaluation; do not claim the base model lacks these capabilities |
| Confabulation | Applies; RISK-13 | Citation/source checks and initial tasks; semantic claim verification remains incomplete |
| Dangerous, Violent, or Hateful Content | Outside intended use; RISK-16 | No harmful-content benchmark; synthetic scope limits exposure only |
| Data Privacy | Applies to modeled confidentiality; RISK-02/04/10 | Audience ACLs and redaction tested; real-person privacy assessment not performed |
| Environmental Impacts | Unassessed; RISK-17 | Runtime/tokens available as workload measures, not energy or lifecycle measurements |
| Harmful Bias and Homogenization | Relevant but unassessed; RISK-16 | Policy-based grants limit model discretion; answer quality and language disparities remain untested |
| Human-AI Configuration | Applies; RISK-05/06/14 | Separate human confirmation/approval tested; usability and overreliance studies not performed |
| Information Integrity | Partially evaluated; RISK-12/13/14 | Provenance, source revalidation and honest reports; not misinformation-at-scale assurance |
| Information Security | Primary; RISK-01 through RISK-12 | Scoped controls and repeated selected read/injection cases; limited attack diversity and no measured model-driven attack-rate reduction |
| Intellectual Property | Relevant, review pending; RISK-15 | Synthetic fixtures do not resolve model/dependency licensing or generated-output rights |
| Obscene, Degrading, and/or Abusive Content | Outside intended use; RISK-16 | No dedicated output-safety benchmark; no general safety claim |
| Value Chain and Component Integration | Applies; RISK-09/12/15 | Pinned model/SDK/identity/images and separate authority; broader supplier review remains open |

## Selected Profile actions

These narrowly mapped actions were checked against AI 600-1. The short labels below summarize their relevance; consult the source for their full scope.

| Action | Evidence / risk | Status and limit |
|---|---|---|
| GV-1.5-003: retain evaluation history | RISK-14; versioned successful/failed run records and charter | Implemented retention practice for sanitized repository artifacts; not production backup |
| MS-2.7-004: security-effectiveness metrics | RISK-03/14; actual effects, false blocks, completion and audit definitions | [Repeated cohorts](phase5-report.md) retain denominators, timeout and comparison limits; no measured attack-rate reduction established |
| MS-2.7-007: adversarial evaluation | RISK-03; forced tests plus initial real-model injection cases | Partial security evaluation; no claim of all attack families listed by the Profile |
| MS-2.10-001: disclosure evaluation | RISK-04; recipient-context and output tests | Covers synthetic restricted-source disclosures, not training-data extraction or membership inference |

Sources: [AI RMF 1.0 Core](https://airc.nist.gov/airmf-resources/airmf/5-sec-core/) and [NIST AI 600-1](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf), especially the selected action tables on printed pages 16, 33–34 and 35. The [implementation plan](../SECURE_SERVICE_DESK_AGENT_IMPLEMENTATION_PLAN.md) tracks the evaluated corpus, final risk decisions, clean-checkout evidence and evidence-matched demo. Framework mapping does not change a historical run's evidence level or denominator.
