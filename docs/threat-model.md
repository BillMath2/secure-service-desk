# Threat model: Phase 0

The protected assets are document bodies and metadata, ticket visibility, effective directory grants, human approval records, workload credentials, and security evidence. All business data is synthetic. The host, identity provider, policy administrator, and approval service are trusted for this lab.

| Actor | Control / entry point | Objective | Independent control |
|---|---|---|---|
| External requester | Own ticket and plain-text attachment | Receive restricted instructions or gain access | Caller AND recipient ACLs, separate reply context, exact review |
| Compromised employee | Own account, tickets, permitted comments | Read another department or approve own grant | Resource authorization, trusted relationships, separation of duties |
| Knowledge author | Editable document content | Cause later unsafe tool calls | Untrusted source provenance; downstream policy |
| Compromised MCP server | Its descriptions, schemas, results | Redirect actions or reuse credentials | Pinned registry, per-resource token audiences, egress boundaries |

Data crosses these boundaries: user to application; application to model; gateway to each MCP server; source content to output audience; analyst confirmation to durable action; human approval to executor; executor to simulated directory; producers to audit collector. Credentials and authenticated context stay outside the model. A server is still responsible for its own authorization when the gateway is bypassed.

Phase 0 implements only a fixture-backed document tool and output oracle. `RequestContext` is constructed by trusted test setup; it is NOT verified identity and must not become a production HTTP request schema. The separate identity spike establishes a real token flow without turning the fixture harness into an authenticated application. The fixture read tool uses a SQLite adapter; the application will use PostgreSQL.

The runner forces the forbidden call that an injected source might induce. It does not currently feed that source through an LLM. Accordingly, passing these cases demonstrates the local policy function and oracle, not resistance of a complete agent to prompt injection.

The minimal collector persists safe structured events before returning document content. SQLite triggers reject ordinary event updates/deletes, but a process with database ownership can bypass them. Collector process and database-role separation, durable outboxes, and production log access controls remain later work.

The test sink stores bounded synthetic payloads in memory without forwarding or echoing them. Its container uses an internal network, has no host port, and mounts no host secrets. The separate Keycloak/PostgreSQL spike publishes loopback ports. Keycloak is configured for local certificate-verified TLS; the temporary MCP endpoint uses loopback HTTP. This is not the hardened deployment's end-to-end transport configuration.

Out of scope: host compromise, hostile policy administrators, malicious authorized humans manually copying data, real identity/directory integrations, live email, executable attachments, and confidentiality of data already entrusted to a fully compromised source server. Canaries help detect selected leaks; they cannot prove absence of paraphrased disclosure.
