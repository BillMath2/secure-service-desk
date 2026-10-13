# Tool, identity, and event contracts

Executable Phase 0 schemas live in `src/service_desk/contracts.py`; generated JSON Schemas are in `docs/contracts/`. Regenerate with `service-desk schemas --output docs/contracts`. Unknown fields are rejected. Tuple/frozen models discourage accidental mutation of policy inputs.

| Operation | Model arguments | Trusted state / enforcement | Phase |
|---|---|---|---|
| `read_document` | `document_id` only | User/client, scopes, capabilities, readers, policy version, correlation; safe denial | Domain adapter in 0; authenticated MCP in 2 |
| `search_documents` | Query, bounded count | ACL filter before ranking/snippets/counts | 2 |
| `read_ticket` | Ticket ID | Ticket ACL and comment reader sets | 2 |
| `draft_response` | Ticket ID, checked source refs, audience selector | Trusted audience resolution; fresh requester-only context, no privileged free text | 3 |
| `add_comment` | Stored reviewed draft ID | Internal-only readers; exact single-use confirmation | 3 |
| `check_access` | Human target, resource | Caller/task/resource authorization | 4 |
| `propose_access_change` | Target, resource, action, duration, source refs | Exact confirmation; immutable proposal; rate limit | 4 |
| `execute_approved_change` | Stored approval request ID | Executor-only audience/client; atomic consume/apply/audit | 4 |

Human approve/publish/review actions and lifecycle operations are not model tools. The underscore spelling is the future MCP tool name; fixture scenario dispatch currently uses `read-document` as a local test operation ID.

`Decision` carries allow/deny, stable reason code, policy version, and obligations. Current denial reasons are identity, client, scope, resource, recipient, stale policy, and output limit. Unavailable and forbidden documents return the same public response with no ID, version, or body. Only restricted audit evidence distinguishes the reasons.

`AuditEvent` has a unique event ID, shared correlation/task UUIDs, timestamp, producer, actor/client IDs, known resource reference, operation, decision, and outcome. It has no free-form token, body, prompt, exception, or arbitrary metadata field. Exact duplicate delivery is idempotent; a reused ID with different content fails. The first tool persists an event before returning content. Full transactional outboxes and service isolation are phase 4 work.

`Scenario` defines actor, entry point, controlled content, objective, forced operation, trusted fixture identity, intended recipients, expected decision, expected allowed-body hash, forbidden markers, requirement IDs, and versioned risk tags. The runner checks output bytes, audit payloads, and stored effects. Source content and usable credentials never enter its published results.

`ScenarioResult` uses `success` when the oracle matches (including an expected denial), `failure` for mismatched effects/evidence, `error` for execution/storage exceptions, and `unsupported` for unimplemented tools. Unsupported cases do not count as passing. Error messages are fixed codes, not exception text. Each suite run creates a fresh output directory and refuses to overwrite an earlier report.

The SQLite fixture adapter is disposable and owns only document, mutation-observation, and fixture metadata tables. The tool loads access metadata before any document body, then repeats caller/recipient ACL predicates in the content query to prevent a stale metadata check from releasing content after an ACL change. Reset requires its application marker and never recursively deletes caller-selected paths. PostgreSQL migration 0001 creates the service's foundation schema; 0002 creates NOLOGIN role groups and gives only the knowledge role read access. No agent database role is created. End-user ACL enforcement is still required above the service's SQL privileges.
