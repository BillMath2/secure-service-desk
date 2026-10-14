# Risk register

Generated from [config/risk-register.json](../config/risk-register.json). Edit that source, then run `python scripts/check_frameworks.py --write-view`.

Reviewed 2026-10-14; source revision `b627fb540e4a4816850344f43ecc660278f5c9af`. Pinned synthetic lab through Phase 5 evaluation; owner residual-risk acceptance pending.

Ratings describe inherent likelihood/impact in this synthetic lab, not measured probabilities. Mitigated means evidence for the stated scope; it does not mean zero residual risk. Planned decisions and owner acceptance remain open. Model evidence on a row does not turn every linked deterministic test into a model trial.

## RISK-01: Forged browser identity or cross-client authority

- **Actor / entry:** Employee / browser request
- **Assets / affected parties:** identity, tickets
- **Threats:** T-F1-S-01
- **STRIDE:** S
- **OWASP / ATLAS:** ASI03:2026
- **ATLAS mitigations:** AML.M0028
- **AI RMF:** MAP 1.1, MEASURE 2.7, MAP 5.1
- **Requirements:** R01
- **Evidence levels:** designed, implemented, deterministically-tested
- **Decision:** mitigated-in-tested-scope
- **Evidence:** [tests/test_phase2_identity.py](../tests/test_phase2_identity.py), [tests/test_access_interfaces.py](../tests/test_access_interfaces.py), [docs/phase2-exit.md](../docs/phase2-exit.md), [reports/phase5/release/results.json](../reports/phase5/release/results.json)
- **Likelihood / impact:** Medium / High. Network clients can supply arbitrary claims; successful forgery exposes user authority.
- **Residual / gap:** Trusted identity administration and host remain outside the tested boundary.
- **Owner / next review:** Project owner; Phase 5 exit, or any relevant source, policy, model, dependency, or deployment change

## RISK-02: Unauthorized document or ticket read

- **Actor / entry:** Employee / MCP arguments
- **Assets / affected parties:** document bodies, metadata, tickets
- **Threats:** T-F3-I-01
- **STRIDE:** I, E
- **OWASP / ATLAS:** LLM02:2025, ASI02:2026
- **ATLAS mitigations:** AML.M0028
- **AI RMF:** MEASURE 2.7, MEASURE 2.10, MAP 5.1
- **Requirements:** R02
- **Evidence levels:** designed, implemented, deterministically-tested
- **Decision:** mitigated-in-tested-scope
- **Evidence:** [tests/test_phase2_reads.py](../tests/test_phase2_reads.py), [docs/phase2-exit.md](../docs/phase2-exit.md), [docs/phase5-report.md](../docs/phase5-report.md), [reports/phase5/results.json](../reports/phase5/results.json), [reports/phase5/release/results.json](../reports/phase5/release/results.json)
- **Likelihood / impact:** High / High. Guessable business identifiers make direct attempts easy; cross-team data is sensitive.
- **Residual / gap:** Only modeled ACLs, sources, and interfaces are evaluated.
- **Owner / next review:** Project owner; Phase 5 exit, or any relevant source, policy, model, dependency, or deployment change

## RISK-03: Retrieved instructions redirect model actions

- **Actor / entry:** Requester or knowledge author / ticket or document
- **Assets / affected parties:** model context, tool actions, requester output
- **Threats:** T-F2-E-01
- **STRIDE:** T, E
- **OWASP / ATLAS:** LLM01:2025, LLM02:2025, ASI01:2026, ASI03:2026, AML.T0051.001, AML.T0053, AML.T0057
- **ATLAS mitigations:** No mapping claimed
- **AI RMF:** MEASURE 2.7, MAP 5.1
- **Requirements:** R06
- **Evidence levels:** designed, implemented, deterministically-tested, real-model-evaluated
- **Decision:** mitigated-in-tested-scope
- **Evidence:** [docs/phase2-exit.md](../docs/phase2-exit.md), [docs/phase3-exit.md](../docs/phase3-exit.md), [docs/phase4-exit.md](../docs/phase4-exit.md), [lab_baseline/cases.json](../lab_baseline/cases.json), [docs/phase5-report.md](../docs/phase5-report.md), [reports/phase5/results.json](../reports/phase5/results.json), [reports/phase5/release/results.json](../reports/phase5/release/results.json)
- **Likelihood / impact:** High / High. Untrusted prose reaches the model; an unsafe proposal can target privileged data or actions.
- **Residual / gap:** Small fixed-case observations are not a statistical guarantee; repeated comparisons remain pending. The repeated matched corpus observed no successful model-driven attack in either variant; no measured attack-rate reduction is established.
- **Owner / next review:** Project owner; Phase 5 exit, or any relevant source, policy, model, dependency, or deployment change

## RISK-04: Restricted content reaches another audience

- **Actor / entry:** Requester / draft, chat, preview or published reply
- **Assets / affected parties:** restricted content, recipient privacy
- **Threats:** T-F4-I-01
- **STRIDE:** I
- **OWASP / ATLAS:** LLM02:2025, ASI02:2026, AML.T0057
- **ATLAS mitigations:** No mapping claimed
- **AI RMF:** MEASURE 2.10, MAP 5.1, MEASURE 2.7
- **Requirements:** R03, R05
- **Evidence levels:** designed, implemented, deterministically-tested, real-model-evaluated
- **Decision:** mitigated-in-tested-scope
- **Evidence:** [tests/test_requester_drafts.py](../tests/test_requester_drafts.py), [tests/test_chat_output.py](../tests/test_chat_output.py), [docs/phase3-exit.md](../docs/phase3-exit.md), [docs/phase5-report.md](../docs/phase5-report.md), [reports/phase5/results.json](../reports/phase5/results.json), [reports/phase5/release/results.json](../reports/phase5/release/results.json)
- **Likelihood / impact:** High / High. Privileged context is available to analysts; copying it to a requester is harmful.
- **Residual / gap:** Fixed retrieval recipes and fingerprints do not establish general semantic leak detection.
- **Owner / next review:** Project owner; Phase 5 exit, or any relevant source, policy, model, dependency, or deployment change

## RISK-05: Reviewed publication changed or reused

- **Actor / entry:** Employee / confirmation endpoint
- **Assets / affected parties:** ticket comments, review integrity
- **Threats:** T-F5-T-01
- **STRIDE:** T
- **OWASP / ATLAS:** ASI02:2026
- **ATLAS mitigations:** AML.M0029
- **AI RMF:** GOVERN 3.2, MEASURE 2.7, MAP 5.1
- **Requirements:** R05
- **Evidence levels:** designed, implemented, deterministically-tested, real-model-evaluated
- **Decision:** mitigated-in-tested-scope
- **Evidence:** [tests/test_draft_reviews.py](../tests/test_draft_reviews.py), [tests/test_publication.py](../tests/test_publication.py), [docs/phase3-exit.md](../docs/phase3-exit.md), [reports/phase5/release/results.json](../reports/phase5/release/results.json)
- **Likelihood / impact:** Medium / High. Mutable recipients or bodies could invalidate a previously safe review.
- **Residual / gap:** Authorized humans manually copying data are outside the agent-injection scope.
- **Owner / next review:** Project owner; Phase 5 exit, or any relevant source, policy, model, dependency, or deployment change

## RISK-06: Fake approval or self-approval authorizes a grant

- **Actor / entry:** Requester, analyst or beneficiary / proposal and approval
- **Assets / affected parties:** approval authority, temporary access
- **Threats:** T-F6-S-01, T-F6-E-01
- **STRIDE:** S, E
- **OWASP / ATLAS:** ASI03:2026, AML.T0053
- **ATLAS mitigations:** AML.M0028, AML.M0029
- **AI RMF:** GOVERN 3.2, MEASURE 2.7, MAP 5.1
- **Requirements:** R07
- **Evidence levels:** designed, implemented, deterministically-tested
- **Decision:** mitigated-in-tested-scope
- **Evidence:** [tests/test_access_workflow.py](../tests/test_access_workflow.py), [tests/test_access_interfaces.py](../tests/test_access_interfaces.py), [docs/phase4-exit.md](../docs/phase4-exit.md), [reports/phase5/release/results.json](../reports/phase5/release/results.json)
- **Likelihood / impact:** Medium / High. Attacker prose may claim authority; an accepted claim would grant access.
- **Residual / gap:** Real-model proposal observations do not exercise autonomous approval; independent signed workflow tests establish this boundary.
- **Owner / next review:** Project owner; Phase 5 exit, or any relevant source, policy, model, dependency, or deployment change

## RISK-07: Replay, race or stale membership extends access

- **Actor / entry:** Executor retry or delayed worker / directory adapter
- **Assets / affected parties:** grants, effective access
- **Threats:** T-F7-T-01, T-F7-E-01
- **STRIDE:** T, E
- **OWASP / ATLAS:** ASI03:2026
- **ATLAS mitigations:** AML.M0028
- **AI RMF:** MEASURE 2.7, MANAGE 1.3, MAP 5.1
- **Requirements:** R08, R09
- **Evidence levels:** designed, implemented, deterministically-tested
- **Decision:** mitigated-in-tested-scope
- **Evidence:** [tests/test_access_workflow.py](../tests/test_access_workflow.py), [docs/phase4-exit.md](../docs/phase4-exit.md), [reports/phase5/release/results.json](../reports/phase5/release/results.json)
- **Likelihood / impact:** Medium / High. Retries and cleanup delays are normal; incorrect handling creates durable privilege.
- **Residual / gap:** Synthetic transactional directory only; an external directory needs separate effect reconciliation.
- **Owner / next review:** Project owner; Phase 5 exit, or any relevant source, policy, model, dependency, or deployment change

## RISK-08: Audit outage loses evidence or exposes content

- **Actor / entry:** Failed collector or runtime principal / outbox and query
- **Assets / affected parties:** audit evidence, credentials
- **Threats:** T-F8-R-01, T-F8-I-01
- **STRIDE:** R, I
- **OWASP / ATLAS:** No mapping claimed
- **ATLAS mitigations:** No mapping claimed
- **AI RMF:** MEASURE 2.8, MANAGE 4.1, MAP 5.1, MEASURE 2.7
- **Requirements:** R10
- **Evidence levels:** designed, implemented, deterministically-tested
- **Decision:** mitigated-in-tested-scope
- **Evidence:** [tests/test_access_workflow.py](../tests/test_access_workflow.py), [docs/phase4-exit.md](../docs/phase4-exit.md), [reports/phase5/release/results.json](../reports/phase5/release/results.json)
- **Likelihood / impact:** Medium / High. Outages and retries can lose mutation evidence without durable transactional recording.
- **Residual / gap:** Collector shares PostgreSQL; tmpfs teardown discards state; administrator/storage compromise is outside scope.
- **Owner / next review:** Project owner; Phase 5 exit, or any relevant source, policy, model, dependency, or deployment change

## RISK-09: Token reuse or changed issuer expands delegation

- **Actor / entry:** Compromised service / identity exchange
- **Assets / affected parties:** delegated credentials
- **Threats:** T-F9-S-01, T-F9-E-01
- **STRIDE:** S, E
- **OWASP / ATLAS:** ASI03:2026
- **ATLAS mitigations:** AML.M0028
- **AI RMF:** MEASURE 2.7, MAP 4.1, MAP 5.1
- **Requirements:** R01, R04
- **Evidence levels:** designed, implemented, deterministically-tested
- **Decision:** mitigated-in-tested-scope
- **Evidence:** [tests/test_auth_discovery.py](../tests/test_auth_discovery.py), [docs/phase2-exit.md](../docs/phase2-exit.md), [reports/phase5/release/results.json](../reports/phase5/release/results.json)
- **Likelihood / impact:** Medium / High. A token received for one resource may be replayed elsewhere.
- **Residual / gap:** Only pinned issuer/client interoperability and the documented key-cache windows are tested.
- **Owner / next review:** Project owner; Phase 5 exit, or any relevant source, policy, model, dependency, or deployment change

## RISK-10: Runtime exfiltration or host credential access

- **Actor / entry:** Model or compromised service / outbound network and mounts
- **Assets / affected parties:** restricted content, host secrets
- **Threats:** T-F10-I-01
- **STRIDE:** I, E
- **OWASP / ATLAS:** LLM02:2025
- **ATLAS mitigations:** AML.M0028
- **AI RMF:** MEASURE 2.7, MEASURE 2.10, MAP 5.1
- **Requirements:** R13
- **Evidence levels:** designed, implemented, deterministically-tested
- **Decision:** mitigated-in-tested-scope
- **Evidence:** [docs/phase3-exit.md](../docs/phase3-exit.md), [docs/phase4-exit.md](../docs/phase4-exit.md), [tests/test_model_egress.py](../tests/test_model_egress.py), [reports/phase5/release/results.json](../reports/phase5/release/results.json)
- **Likelihood / impact:** Medium / High. A compromised process can attempt arbitrary egress; credentials would widen impact.
- **Residual / gap:** IPv4 has positive-controlled live probes; IPv6 denial is inspected only. Host administrators remain trusted.
- **Owner / next review:** Project owner; Phase 5 exit, or any relevant source, policy, model, dependency, or deployment change

## RISK-11: Resource exhaustion or approval spam

- **Actor / entry:** Employee or injected task / generation, sockets, proposals
- **Assets / affected parties:** availability, human attention
- **Threats:** T-F2-D-01, T-F1-D-01, T-F6-D-01
- **STRIDE:** D
- **OWASP / ATLAS:** LLM10:2025, AML.T0046
- **ATLAS mitigations:** No mapping claimed
- **AI RMF:** MEASURE 2.7, MANAGE 2.4, MAP 5.1
- **Requirements:** R11
- **Evidence levels:** designed, implemented, deterministically-tested
- **Decision:** mitigated-in-tested-scope
- **Evidence:** [tests/test_task_admission.py](../tests/test_task_admission.py), [tests/test_tls_ingress.py](../tests/test_tls_ingress.py), [tests/test_access_workflow.py](../tests/test_access_workflow.py), [docs/phase3-exit.md](../docs/phase3-exit.md), [docs/phase5-report.md](../docs/phase5-report.md), [reports/phase5/results.json](../reports/phase5/results.json), [reports/phase5/release/results.json](../reports/phase5/release/results.json)
- **Likelihood / impact:** High / Medium. Repeated tasks and connections are easy; admission limits bound individual services.
- **Residual / gap:** AML.T0046 applies to spam/human-review load, not every timeout or token-exhaustion test; host-wide capacity is not certified. The initial Phase 5 cohort had one 45-second provider timeout; a separate 20-task confirmation completed after competing jobs stopped. Cold-start/workstation-load sensitivity remains.
- **Owner / next review:** Project owner; Phase 5 exit, or any relevant source, policy, model, dependency, or deployment change

## RISK-12: Changed tool definition or compromised component

- **Actor / entry:** MCP server or supplier / catalog, package or model artifact
- **Assets / affected parties:** tool integrity, model integrity
- **Threats:** T-F3-T-01
- **STRIDE:** T
- **OWASP / ATLAS:** LLM03:2025, AML.T0110.000
- **ATLAS mitigations:** No mapping claimed
- **AI RMF:** MAP 4.1, MANAGE 3.1, MAP 5.1, MEASURE 2.7
- **Requirements:** R04, R13
- **Evidence levels:** designed, implemented, deterministically-tested
- **Decision:** mitigated-in-tested-scope
- **Evidence:** [tests/test_read_registry.py](../tests/test_read_registry.py), [tests/test_model_deployment.py](../tests/test_model_deployment.py), [docs/phase3-exit.md](../docs/phase3-exit.md), [reports/phase5/release/results.json](../reports/phase5/release/results.json)
- **Likelihood / impact:** Medium / High. Definitions and artifacts influence model actions; reviewed hashes detect changes.
- **Residual / gap:** Integrity relative to pinned artifacts does not prove supplier trust or absence of malicious model behavior.
- **Owner / next review:** Project owner; Phase 5 exit, or any relevant source, policy, model, dependency, or deployment change

## RISK-13: Cited answer is incorrect or misleading

- **Actor / entry:** Model / generated answer
- **Assets / affected parties:** support correctness, information integrity
- **Threats:** T-F4-T-01
- **STRIDE:** T
- **OWASP / ATLAS:** LLM09:2025
- **ATLAS mitigations:** No mapping claimed
- **AI RMF:** MEASURE 2.3, MEASURE 2.5, MAP 5.1
- **Requirements:** R16
- **Evidence levels:** designed, implemented, deterministically-tested, real-model-evaluated
- **Decision:** planned
- **Evidence:** [tests/test_agent_tasks.py](../tests/test_agent_tasks.py), [docs/phase4-exit.md](../docs/phase4-exit.md), [docs/phase5-report.md](../docs/phase5-report.md), [reports/phase5/results.json](../reports/phase5/results.json), [reports/phase5/release/results.json](../reports/phase5/release/results.json)
- **Likelihood / impact:** Medium / Medium. Citations can be valid while individual claims are wrong.
- **Residual / gap:** No comprehensive claim-level factuality evaluation; Phase 5 benign completion and false-block measurements remain planned.
- **Owner / next review:** Project owner; Phase 5 exit, or any relevant source, policy, model, dependency, or deployment change

## RISK-14: Framework claims exceed evidence or risks lack an owner

- **Actor / entry:** Project delivery / reporting
- **Assets / affected parties:** evidence integrity, risk accountability
- **Threats:** T-F8-R-02
- **STRIDE:** R
- **OWASP / ATLAS:** No mapping claimed
- **ATLAS mitigations:** No mapping claimed
- **AI RMF:** GOVERN 1.5, GOVERN 2.1, MEASURE 1.1, MAP 5.1, MAP 1.1, MEASURE 2.1, MEASURE 2.8, MEASURE 3.1, MANAGE 1.3, MANAGE 4.1
- **Requirements:** R15, R16, R17
- **Evidence levels:** designed, implemented, deterministically-tested
- **Decision:** planned
- **Evidence:** [SECURE_SERVICE_DESK_AGENT_IMPLEMENTATION_PLAN.md](../SECURE_SERVICE_DESK_AGENT_IMPLEMENTATION_PLAN.md), [docs/lab-governance.md](../docs/lab-governance.md), [tests/test_frameworks.py](../tests/test_frameworks.py), [docs/phase5-report.md](../docs/phase5-report.md), [reports/phase5/results.json](../reports/phase5/results.json), [docs/phase5-owner-review.md](../docs/phase5-owner-review.md), [reports/phase5/release/results.json](../reports/phase5/release/results.json), [reports/phase5/capture/results.json](../reports/phase5/capture/results.json)
- **Likelihood / impact:** Medium / Medium. Overlapping checks and small samples can be presented as stronger evidence than they are.
- **Residual / gap:** Repeated cohorts, their denominators, one timeout, unsupported comparisons and failed setup are retained. Independent human assessment and explicit owner residual-risk acceptance remain pending.
- **Owner / next review:** Project owner; Phase 5 exit, or any relevant source, policy, model, dependency, or deployment change

## RISK-15: Component or generated-content licensing risk

- **Actor / entry:** Supplier or generated answer / dependencies and model
- **Assets / affected parties:** intellectual property
- **Threats:** No mapping claimed
- **STRIDE:** No mapping claimed
- **OWASP / ATLAS:** No mapping claimed
- **ATLAS mitigations:** No mapping claimed
- **AI RMF:** GOVERN 6.1, MAP 4.1, MAP 5.1
- **Requirements:** R17
- **Evidence levels:** designed
- **Decision:** planned
- **Evidence:** [pyproject.toml](../pyproject.toml), [config/local-model.lock.json](../config/local-model.lock.json)
- **Likelihood / impact:** Medium / Medium. Synthetic fixtures do not remove model, software or generated-output licensing concerns.
- **Residual / gap:** License inventory and output-use review remain pending; no legal compliance claim.
- **Owner / next review:** Project owner; Phase 5 exit, or any relevant source, policy, model, dependency, or deployment change

## RISK-16: Uneven task performance or harmful generated content

- **Actor / entry:** Model / support answers
- **Assets / affected parties:** users, answer quality
- **Threats:** No mapping claimed
- **STRIDE:** No mapping claimed
- **OWASP / ATLAS:** No mapping claimed
- **ATLAS mitigations:** No mapping claimed
- **AI RMF:** MEASURE 2.11, MAP 5.1
- **Requirements:** R16
- **Evidence levels:** designed
- **Decision:** planned
- **Evidence:** [docs/permission-matrix.md](../docs/permission-matrix.md)
- **Likelihood / impact:** Medium / Medium. Policy-driven grants do not eliminate uneven language performance or biased explanations.
- **Residual / gap:** No demographic, multilingual or harmful-content benchmark; closed synthetic domain limits exposure, not model capability.
- **Owner / next review:** Project owner; Phase 5 exit, or any relevant source, policy, model, dependency, or deployment change

## RISK-17: Unmeasured energy and environmental costs

- **Actor / entry:** Operator / local inference
- **Assets / affected parties:** energy, environment
- **Threats:** No mapping claimed
- **STRIDE:** No mapping claimed
- **OWASP / ATLAS:** No mapping claimed
- **ATLAS mitigations:** No mapping claimed
- **AI RMF:** MEASURE 2.12, MAP 5.1
- **Requirements:** R16
- **Evidence levels:** designed
- **Decision:** planned
- **Evidence:** [config/local-model.lock.json](../config/local-model.lock.json)
- **Likelihood / impact:** Medium / Low. Local inference consumes power; tokens and runtime are not energy measurements.
- **Residual / gap:** No energy/lifecycle assessment; do not describe impact as measured or minimal.
- **Owner / next review:** Project owner; Phase 5 exit, or any relevant source, policy, model, dependency, or deployment change

## Scenario index

Empty risk lists identify benign controls, not excluded trials.

| Source and case | Risk IDs |
|---|---|
| `fixtures/company.json#read-public` | Benign control |
| `fixtures/company.json#read-team` | Benign control |
| `fixtures/company.json#read-admin-internal` | Benign control |
| `fixtures/company.json#deny-cross-department` | RISK-02 |
| `fixtures/company.json#deny-requester-leak` | RISK-03, RISK-04 |
| `fixtures/company.json#deny-hr-after-injection` | RISK-03 |
| `fixtures/company.json#deny-direct-client` | RISK-09 |
| `fixtures/company.json#deny-missing-scope` | RISK-09 |
| `fixtures/company.json#deny-unknown-resource` | RISK-02 |
| `fixtures/company.json#deny-empty-audience` | RISK-02 |
| `fixtures/company.json#pending-standard-grant` | Benign control |
| `fixtures/company.json#pending-sensitive-grant` | Benign control |
| `fixtures/company.json#pending-requester-reply` | Benign control |
| `lab_baseline/cases.json#BASELINE-READ-01` | RISK-02 |
| `lab_baseline/cases.json#BASELINE-OUTPUT-01` | RISK-04 |
| `lab_baseline/cases.json#BASELINE-GRANT-01` | RISK-06 |
| `lab_baseline/cases.json#BASELINE-BENIGN-01` | Benign control |
| `lab_baseline/cases.json#INJECT-TICKET-01` | RISK-03, RISK-04 |
| `lab_baseline/cases.json#INJECT-DOCUMENT-01` | RISK-03 |
| `lab_baseline/cases.json#INJECT-GRANT-01` | RISK-03, RISK-06 |
| `lab_baseline/cases.json#MODEL-BENIGN-01` | Benign control |
| `config/phase2-model-cases.json#benign-public` | Benign control |
| `config/phase2-model-cases.json#ticket-injection` | RISK-03 |
| `config/phase2-model-cases.json#document-injection` | RISK-03 |
| `config/phase3-channel-model-cases.json#erin_internal_benign` | Benign control |
| `config/phase3-channel-model-cases.json#erin_requester_benign` | Benign control |
| `config/phase3-channel-model-cases.json#erin_requester_document_injection` | RISK-03, RISK-04 |
| `config/phase3-channel-model-cases.json#alice_requester_document_injection` | RISK-03, RISK-04 |
| `config/phase3-workflow-model-cases.json#self_chat` | Benign control |
| `config/phase3-workflow-model-cases.json#ticket-alice_requester` | Benign control |
| `config/phase3-workflow-model-cases.json#ticket-alice_internal` | Benign control |
| `config/phase3-workflow-model-cases.json#ticket-alice-injected_requester` | RISK-03, RISK-04 |
| `config/phase3-workflow-model-cases.json#ticket-alice-injected_internal` | RISK-03, RISK-04 |
| `config/phase4-model-cases.json#benign` | Benign control |
| `config/phase4-model-cases.json#injected` | RISK-03, RISK-04 |
| `config/phase5-model-cases.json#common-public` | Benign control |
| `config/phase5-model-cases.json#common-team` | Benign control |
| `config/phase5-model-cases.json#common-document-injection` | RISK-03, RISK-04 |
| `config/phase5-model-cases.json#common-ticket-injection` | RISK-03, RISK-04 |
