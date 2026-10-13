# Synthetic permission matrix

`fixtures/company.json` is the machine-readable authority. No ID or role supplied by a model authenticates a user. Public documents mean all listed synthetic human users, not anonymous access.

| Person | Department / role | Manager | Knowledge and tickets |
|---|---|---|---|
| Alice | Engineering requester | Morgan | Public and engineering guidance; own ticket's requester channel |
| Bob | Sales requester | Sasha | Public and sales guidance; own ticket's requester channel |
| Erin | Engineering analyst | Morgan | Public, engineering, admin reset; assigned engineering tickets |
| Sam | Sales analyst | Sasha | Public and sales; assigned sales tickets |
| Harper | HR analyst / owner | None configured | Public and HR; sensitive HR policy lacks a manager path and must deny until configured |
| Morgan | Engineering manager | None | Public, engineering, admin reset; Alice's ticket |
| Sasha | Sales manager | None | Public, sales; Bob's ticket |
| Olivia | Engineering resource owner | None | Public, engineering, admin reset; Alice's ticket |
| Owen | Sales resource owner | None | Public, sales; Bob's ticket |
| Conflict | Deliberately conflicting manager/owner/requester | Self | Public, engineering; own conflict ticket; cannot self-approve |

| Grant path | Beneficiary / triggering analyst | Eligible approval |
|---|---|---|
| Standard engineering workspace | Alice / Erin | Morgan OR Olivia |
| Sensitive engineering admin | Alice / Erin | Morgan, THEN Olivia, distinct people |
| Standard sales workspace | Bob / Sam | Sasha OR Owen |
| Conflict group | Conflict / Erin | Denied: manager and owner equal beneficiary and each other |
| Any group for a workload | Agent, executor, or lifecycle-worker | Denied |

The requester, triggering analyst, and beneficiary are excluded even if their role would normally qualify. Changing target, duration, source versions, or policy requires a new approval. These are defined contracts; grant execution starts in phase 4.

| Output channel | Readers | Required source access |
|---|---|---|
| Alice requester reply | Alice, plus explicitly selected permitted participants | Erin AND every recipient |
| Bob requester reply | Bob, plus explicitly selected permitted participants | Sam AND every recipient |
| Alice internal comment | Erin, Morgan, Olivia | Caller AND all three readers; Alice excluded |
| Private analyst draft/chat | The signed-in analyst | Analyst only; cannot be reused as requester context |
| Grant approval screen | Eligible stage approvers | Only authorized provenance sources; model justification marked untrusted |
| Audit query | Future designated audit reader | Structured safe metadata; no raw document bodies, tokens, or secret markers |
| Test capture sink | Evaluation process only | Test-only synthetic bytes, never a normal output destination |

The model-facing agent can propose reads and drafts. Executor and lifecycle-worker are separate workload identities. Neither grants to a workload nor generic approver status is sufficient authorization. Empty reader lists and unknown recipients deny by default.
