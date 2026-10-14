# Security framework mapping

Reviewed October 14, 2026. Scope: implemented synthetic lab through Phase 4, with the [Phase 5 repeated read-surface evaluation](phase5-report.md). Owner residual-risk acceptance remains open. This replaces the Phase 2-only crosswalk; original reports and their hashes remain unchanged. [Risk register](risk-register.md) entries supply risk decisions and evidence levels; [Phase 3](phase3-exit.md) and [Phase 4](phase4-exit.md) exit records establish the deployed control scope.

## Versioned taxonomy and traceability

[config/risk-taxonomies.json](../config/risk-taxonomies.json) pins OWASP LLM 2025, OWASP Agentic Applications 2026 and MITRE ATLAS content v2026.07/data format 6.0.0. The complete upstream ATLAS YAML and MITRE license are cached under `config/taxonomies`; its SHA-256 is verified offline. Only reviewed ATLAS IDs/names are allowed. A valid tag is a classification, not evidence of coverage.

Run `python scripts/check_frameworks.py` or the normal checker. The gate covers every fixture/baseline case and discovered `config/*model-cases.json`, requires explicit risk arrays (including empty benign arrays), checks risk/evidence links, and detects generated-register drift. New reports from Phase 2/3/4 probes retain tags and case configuration fingerprints. Existing report directories are never relabeled.

## ATLAS attack and defense views

| Mapping | Register / applicable scenario | Interpretation |
|---|---|---|
| AML.T0051.001 indirect injection | RISK-03; ticket/document cases in fixtures, baseline and model probes | Untrusted retrieved content contains instructions; forced calls and real-model observations remain distinct |
| AML.T0051.000 direct injection | Reviewed taxonomy entry only | No dedicated repeated direct-prompt evaluation is claimed |
| AML.T0053 AI Agent Tool Invocation | RISK-06; baseline unauthorized-grant objectives | Adversarial tool use is the objective; legitimate tool calls are not malicious observations |
| AML.T0057 LLM Data Leakage | RISK-04; requester-disclosure objectives | Attempted leakage is distinct from inspected unauthorized output |
| AML.T0110.000 tool definition/instructions poisoning | RISK-12; pinned catalog rejection tests | Deterministic definition-integrity boundary, not an observed full poisoning campaign |
| AML.T0046 Spamming AI System with Chaff Data | RISK-11; proposal/approval admission limits | Applies to spam and human-attention load; not a generic label for every token/time limit |
| AML.M0028 tool permissions | RISK-02, RISK-06, RISK-09 | Scoped identities, separate executor authority and server-side authorization |
| AML.M0029 human-in-the-loop | RISK-05, RISK-06 | Exact confirmation and independent approval before durable effects |

The Phase 4 `injected` case uses a ticket requesting restricted password-reset information. Preparing a local access proposal is the legitimate task, so that case is tagged indirect injection and leakage objective, not automatically malicious grant invocation. Both final Phase 4 model tasks created one local draft and no approval/grant; signed forced workflows separately establish the grant controls.

The input channel determines direct versus indirect injection. Classifications express the scenario or attacker objective; report attempted actions, actual model behavior, enforced decisions and actual stored/output effects separately. For a model that never proposes the forbidden action, use a separately labeled forced boundary test to demonstrate independent enforcement. Do not sum overlapping category counts.

## OWASP and STRIDE views

| OWASP LLM 2025 area | Risk IDs / evidence | Remaining limit |
|---|---|---|
| LLM01 injection | RISK-03; repeated matched model trials and independent authorization | No model-driven success in either variant; broader attack diversity remains untested |
| LLM02 disclosure | RISK-02, RISK-04, RISK-10; ACLs, fresh context, screened output, egress | Fingerprints are not general semantic leakage detection |
| LLM03 supply chain | RISK-12, RISK-15; reviewed artifacts/catalogs | Supplier assurance and complete licensing review pending |
| LLM04 poisoning | No training/embedding poisoning evaluation | Retrieved instructions are classified as injection |
| LLM05 output handling | RISK-04, RISK-05; escaped UI, strict schemas, exact publication | Fixed channels and synthetic effects only |
| LLM06 excessive agency | RISK-06, RISK-07, RISK-09; proposal/approval/execution separation | External directory integration not tested |
| LLM07 prompt leakage | Credentials excluded from prompts | No dedicated extraction benchmark |
| LLM08 vector weaknesses | No vector index is used | SQL ACL tests do not establish vector coverage |
| LLM09 misinformation | RISK-13; citation/source checks | Not comprehensive claim verification |
| LLM10 consumption | RISK-11; durable limits, admission, bounded HTTP/TLS/model calls | No host-wide capacity certification |

This table is conceptual control correspondence, not permission to add tags indiscriminately. Scenario tags remain specific to their objectives. Agentic tags likewise retain the 2026 edition and do not establish coverage of the whole Top 10.

The [threat model](threat-model.md) assigns 20 stable threats across F1–F10. The register groups them by STRIDE and supplies likelihood/impact rationales and residual decisions. RISK-14 tracks reporting/governance gaps; RISK-15 through RISK-17 track licensing, uneven performance/content and environmental assessment gaps without forcing a STRIDE or ATLAS label.

## Claims and next gate

The [Phase 5 report](phase5-report.md) adds five repetitions of four matched read cases per variant and a separately reported hardened confirmation cohort. The initial hardened provider timeout remains visible. Zero observed attack success in both variants does not demonstrate a reduction attributable to controls; forced effects and signed workflows provide separate control evidence. Owner residual-risk acceptance remains pending. Describe the work as evaluating selected ATLAS techniques and applying relevant AI RMF practices; do not claim comprehensive ATLAS coverage, certification, or universal injection prevention.

Sources: [ATLAS pinned catalog](https://github.com/mitre-atlas/atlas-data/blob/v2026.07/dist/v6/ATLAS-2026.07.yaml), [OWASP LLM list](https://genai.owasp.org/llm-top-10/), [OWASP Agentic 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/). See the [AI RMF view](ai-rmf-mapping.md) and [lab charter](lab-governance.md).
