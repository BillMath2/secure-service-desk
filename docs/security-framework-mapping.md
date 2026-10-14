# Security framework mapping

Reviewed October 13, 2026. Scope: the pinned, synthetic, read-only Phase 2 lab. These are project mappings, not claims of comprehensive framework coverage. See the [exit record](phase2-exit.md) for implementation status and recorded results.

The subsequent [Phase 3 drafting and publication slices](phase3.md) record F4 source-to-audience tests and F5 confirmed requester/internal publication separately; F10 now includes relay egress policy and reachable neutral controls, while host isolation and the full containment matrix remain open. The Phase 2 mappings and historical model evidence below retain their original scope.

## Versioned references

- [OWASP LLM Top 10, 2025](https://genai.owasp.org/llm-top-10/): preserve the existing `LLMxx:2025` comparison baseline.
- [OWASP Agentic Applications, 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/): preserve existing `ASIxx:2026` tags; this review does not expand their coverage.
- [MITRE ATLAS content v2026.07](https://github.com/mitre-atlas/atlas-data/blob/v2026.07/dist/v6/ATLAS-2026.07.yaml), data format 6.0.0. The official catalog was checked for the technique IDs below. Do not use the deprecated unversioned `dist/ATLAS.yaml` as the current catalog.

The following ATLAS names/IDs were checked: `AML.T0051` (LLM Prompt Injection), `AML.T0051.000` (Direct), `AML.T0051.001` (Indirect), `AML.T0053` (AI Agent Tool Invocation), and `AML.T0057` (LLM Data Leakage). An ID classifies a scenario or attacker objective; it is not a coverage score.

## Injection scenario tags

The `risks` arrays in [company.json](../fixtures/company.json) now place `AML.T0051.001` beside the OWASP tags for these two scenarios. The existing evaluator copies those tags into newly generated scenario results without changing authorization behavior.

| Scenario | ATLAS mapping | Execution and interpretation |
|---|---|---|
| `deny-requester-leak` | `AML.T0051.001` under `AML.T0051` | An attacker-controlled ticket attempts to move privileged content into a requester's context. The fixture driver forces the resulting forbidden call; this tests recipient policy, not whether a model follows the injection. |
| `deny-hr-after-injection` | `AML.T0051.001` under `AML.T0051` | An attacker-controlled document suggests a forbidden HR read. The fixture driver tests the downstream authorization boundary. |
| `ticket-injection`, `document-injection` in [model cases](../config/phase2-model-cases.json) | `AML.T0051.001` | These are genuine model-driven trials of indirect inputs, recorded separately from the fixture tests. The three-case model suite contains two injection tasks and one benign task. This document adds the mapping; existing historical reports are unchanged. |
| Future malicious user prompt | `AML.T0051.000` | Direct injection is a candidate for expanded evaluation. It is not established by the two indirect model tasks. |

The channel determines the sub-technique: ticket/document content retrieved during another user's legitimate task is indirect input even if the attacker typed it directly into the ticket. A malicious instruction submitted as the active model user's prompt is direct input.

Unauthorized tool use and disclosure objectives also relate to `AML.T0053` and `AML.T0057`. Do not add those as successful attack observations merely because a scenario seeks those outcomes. Preserve the distinction between attempted action, model behavior, enforced denial, and actual effect.

## OWASP controls crosswalk

These are mappings from the reviewed implementation to risk categories, not proof that an entire category is mitigated.

| OWASP 2025 risk | Implemented evidence | Limit |
|---|---|---|
| LLM01 Prompt Injection | Independent [gateway](../src/service_desk/core/gateway/dispatch.py) and [read-service](../src/service_desk/reads.py) checks; initial injection trials | Controls limit selected effects even if a model follows malicious content; no universal prevention claim |
| LLM02 Sensitive Information Disclosure | ACL filtering before retrieval output, caller/recipient intersection, fresh task context | Limited to modeled resources/channels; canaries do not detect every paraphrased leak |
| LLM03 Supply Chain | Exact tool catalog validation, pinned images, offline model manifest/blob checks | Integrity relative to reviewed artifacts; no claim of complete supplier assurance or malicious-model detection |
| LLM04 Data and Model Poisoning | No demonstrated training/embedding poisoning assessment | Malicious retrieved instructions are classified separately as indirect injection |
| LLM05 Improper Output Handling | Strict tool argument schemas, bounded responses, escaped browser output | Recipient-safe generation and confirmed ticket writes remain Phase 3 |
| LLM06 Excessive Agency | Read-only capability registry, resource scopes, delegated identity, independent ACLs | Privileged execution and approval-bound writes are not implemented |
| LLM07 System Prompt Leakage | Credentials and authority are kept outside model context | No dedicated system-prompt extraction evaluation established |
| LLM08 Vector and Embedding Weaknesses | No vector/embedding security evaluation established | SQL ACL filtering is useful retrieval authorization, not proof of vector-specific coverage |
| LLM09 Misinformation | Citation validation and source revalidation | Citation validity does not establish that all answer claims are correct |
| LLM10 Unbounded Consumption | Shared tool/model reservations, time and byte limits | Broader admission throttling and full deployment isolation remain incomplete |

## Initial STRIDE crosswalk

This is a new design review using [Microsoft's STRIDE categories](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats). The existing [threat model](threat-model.md) supplies assets, actors, and boundaries; follow up with a data-flow diagram, per-flow threat IDs, prioritization, and explicit residual-risk decisions.

| Category | Project example | Control or remaining work |
|---|---|---|
| Spoofing | Forged identity or wrong-audience token | Signed issuer/client/audience validation, PKCE, state/nonce and delegation checks |
| Tampering | Changed tool description/schema or cached model artifact | Catalog equality and artifact integrity gates |
| Repudiation | Disputed tool access or missing decision record | Durable structured read decisions; independent collector and stronger administrative isolation remain planned |
| Information disclosure | Cross-department reads or data returned to the wrong recipient | ACL filtering and audience intersection; broader output-channel protection remains planned |
| Denial of service | Repeated calls, oversized output, or runaway generation | Durable reservations and bounded time/bytes; request admission limits remain incomplete |
| Elevation of privilege | Model requests broader scope, a new identity, or an unregistered tool | Preserved signed subject, constrained token exchange, fixed capabilities; grant execution remains unimplemented |

## Next evaluation work

Keep deterministic authorization tests separate from model-driven attack trials. Expand direct/indirect cases and record attacker-controlled surface, intended objective, source version, model/configuration, technique IDs, benign task success, false blocks, errors, and actual unauthorized effects. Use synthetic data and the existing contained sink. Record repeat counts and denominators; do not infer an attack-success rate from the current fixed-seed examples. A model refusal alone is not evidence that a side effect was prevented.

See [NIST AI RMF mapping](ai-rmf-mapping.md) for risk-management context. Historical reports remain tied to their original fixture/configuration hashes; adding risk tags changes the fixture fingerprint for future runs.
