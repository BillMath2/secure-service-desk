# ADR 0001: Small executable foundation before the full agent

Status: accepted for Phase 0, October 12, 2026.

The lab starts with strict Python contracts, deterministic fixtures, a single instrumented domain tool, and actual-effect evaluation. Avoid adding the entire agent/UI framework before the data and security oracles are testable. The SQLite adapter is confined to disposable tests; PostgreSQL remains the application store. Foundation SQL and least-privilege role groups are supplied separately.

Use uv with a checked-in lockfile. The implementation's Python and package versions are recorded in the compatibility record, not assumed from a global workstation installation. Keep the official MCP SDK and database/crypto clients in an optional spike dependency group until the authenticated services are built.

The workstation has approximately 31.6 GiB physical memory and a Quadro RTX 3000 with 6 GiB VRAM (confirmed with `nvidia-smi`; WMI's AdapterRAM field underreported it). That supports evaluating a small quantized local model, but does not establish inference latency or tool-call quality. Phase 0 uses the deterministic forced-call driver; no model weights have been downloaded or benchmarked.

Select [Qwen3-4B-Instruct-2507](https://huggingface.co/Qwen/Qwen3-4B-Instruct-2507) as the first Phase 1 model candidate with a four-bit GGUF build and a modest context window. This is a candidate, not a validated deployment: pin a trusted conversion artifact, SHA-256, runtime, and prompt template only after checking its tool-call behavior and memory usage. The final model/runtime decision remains open until that benchmark. Do not claim the 16,000-token cumulative task budget requires a 16,000-token resident context.

The identity spike uses real OIDC authorization code + PKCE and Keycloak standard token exchange, then tests issued claims against the official MCP SDK. The complete round trip passed. It deliberately does not simulate authentication with a username header. Local identity-provider TLS, a loopback HTTP MCP endpoint, and explicit resource-URI-to-client-audience mapping are preliminary integration choices; the authenticated application must implement the hardened transport and end-to-end authorization requirements separately. See the compatibility record for observed claims and remaining checks.

Deferred decisions: full MCP authorization discovery/resource-indicator behavior with the selected provider; local TLS naming/certificates; production JWKS rotation and token caching; approved task assertions; model runtime and digest; and transactional grant/outbox schema. Record findings in `compatibility.md` and do not silently weaken requirements to accommodate an SDK or provider.
