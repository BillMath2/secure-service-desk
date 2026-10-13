# Phase 2 local-model adapter

The authenticated assistant now supports the pinned Qwen3-4B-Instruct-2507 Q4_K_M model through Ollama 0.40.3. The deterministic provider remains the default. Select the real provider explicitly with `scripts/assistant_runtime.py --provider local` after starting the isolated model project. No cloud account or API key is used.

The complete checker passes 179 tests with PostgreSQL enabled (136 default, 43 opt-in). New coverage includes 23 adapter cases and ten cache-integrity/relay cases. The live model deployment passed 16 checks. All three frozen tasks completed with valid citations on both initial runs: one benign opening-hours question, an injected ticket, and an injected document. Restricted HR/admin canaries and credentials were absent from observed model requests and answers, and no write was dispatched. The [selected evidence](../reports/phase2-model/results.json) and both timestamped runs retain individual outcomes and hashes. These are small initial trials using a fixed seed, not the Phase 5 repeated evaluation or a general security guarantee.

## Provider and accounting boundary

Only `http://127.0.0.1:19485` is configured. Model output cannot supply destinations, credentials, options or templates. The adapter rejects redirects, compressed bodies, responses over 64 KiB, generated content over 8 KiB, malformed turns, absent/invalid usage, output truncation and changed model/runtime/tokenizer metadata. Requests use a 45-second absolute timeout, additionally bounded by the assistant's remaining task time. There are no provider retries. Late generation can consume the already-reserved output allowance but cannot release an answer or dispatch a late tool.

The adapter uses a complete, fixed Qwen prompt with Ollama `raw=true`. This bypasses the model's stored prompt template, which would otherwise make input accounting depend on additional text. Initial generations are constrained to the tool-turn schema; after an authorized source result, the provider may request another tool or propose a cited answer. The gateway and final citation checks still independently reject unknown/schema-invalid tools, unauthorized reads and fabricated citations. All context is passed explicitly; no previous Ollama context handle is reused.

Ollama's [Generate API](https://github.com/ollama/ollama/blob/main/docs/api.md) documents raw prompts, structured output schemas and usage counters. The pinned model reports the `gpt2`/`qwen2` byte-level BPE tokenizer and explicitly disables BOS insertion. The [llama.cpp tokenizer implementation](https://github.com/ggml-org/llama.cpp/blob/master/src/llama-vocab.cpp) describes byte encoding and merges. For this verified tokenizer and raw framing, serialized input UTF-8 bytes plus 512 framing units conservatively bound the input tokens. The fixed framing occupies fewer than 512 bytes; output reserves another 512 tokens. Each request must fit the 8,192-token context and the existing cumulative 16,000-unit task budget before dispatch. Actual input/output counters are checked against the reservation; failed calls receive no refund. This bound is specific to the pinned tokenizer and prompt path, not a provider-independent token estimate.

The context size is now 8,192 rather than the baseline's 4,096, and the hardened path uses raw structured turns. Reports record these differences; the current results are not a controlled baseline-versus-hardened comparison. The first smoke response attempted to answer before reading; no task answer was released. Constraining the initial turn to a tool request resolved that usability issue for the frozen cases without relaxing authorization.

## Deployment boundary

`infra/compose.phase2-model.yaml` has three services:

- An offline verification container hashes the exact cached manifest and every blob, checking recorded sizes and inventory. The model starts only after that gate succeeds. The lock is `config/local-model.lock.json`; existing cached weights are reused read-only.
- The model has only an internal Docker network, no published ports, cloud access disabled, a read-only filesystem/cache, an unprivileged user, dropped capabilities, disabled logs and explicit resource limits.
- A small relay publishes port 19485 on loopback and forwards only four fixed routes: version, tags, show and generate. It cannot proxy arbitrary destinations or expose model download/delete routes. It drops inbound credentials and limits request/response bytes. Docker Desktop did not publish the model's port directly from its internal network, which is why the relay exists.

The host-owned startup gate checks these restrictions, blocks a running writer to the shared cache, and probes the actual model network namespace for denied internet, host-database, host-identity and download access. The relay is trusted ingress code on a separate bridge and **does not itself have proven egress denial**. The loopback model transport uses HTTP; OIDC and MCP retain local TLS. Other local OS users are not isolated from the published relay. Service-to-service authentication, relay egress restrictions, protected credential mounts and full application containerization remain Phase 3 deployment work. No claim is made that the entire host application is contained.

Ollama 0.40.3 reports the pinned final metadata-layer digest in `/api/tags`, distinct from the manifest-file hash. Both are recorded and checked: the offline gate verifies the manifest and all blobs, while the adapter pins the observed API digest. Changing either requires an intentional compatibility update. Do not run the trusted preload project while serving requests. The model cache volume is shared with the earlier experiment only as immutable weights; no unsafe service code is imported.

## Reproduce

Use the existing cached weights prepared in the [Phase 1 runbook](phase1.md). A missing cache or image stops the gate; the serving path does not download a model. The checksum helper requires the repository-pinned Python image, which can be pulled separately before starting the lab.

```powershell
.\.venv\Scripts\python.exe scripts/prepare_phase2.py
.\.venv\Scripts\python.exe scripts/prepare_read_store.py
docker compose -f infra/compose.phase2-reads.yaml up -d --wait
docker compose -f infra/compose.phase2-identity.yaml up -d
docker compose -f infra/compose.phase2-model.yaml up -d --pull never
try {
    .\.venv\Scripts\python.exe scripts/prepare_read_store.py --apply
    if ($LASTEXITCODE -ne 0) { throw 'Database preparation failed' }
    $env:DESK_READ_INTEGRATION = '1'
    .\scripts\check.ps1
    .\.venv\Scripts\python.exe scripts/check_model_boundary.py
    if ($LASTEXITCODE -ne 0) { throw 'Model containment failed' }
    .\.venv\Scripts\python.exe scripts/check_phase2_model.py
    if ($LASTEXITCODE -ne 0) { throw 'Evaluation harness or safety observation failed' }
} finally {
    Remove-Item Env:\DESK_READ_INTEGRATION -ErrorAction SilentlyContinue
    docker compose -f infra/compose.phase2-model.yaml down
    docker compose -f infra/compose.phase2-identity.yaml down
    docker compose -f infra/compose.phase2-reads.yaml down
}
```

The scripts accept `--docker <absolute-path>` when Docker is absent from PATH. Allow Keycloak to finish starting before running the model evaluation. The script records task failures separately from harness failures; a zero exit code means trials completed without the tested unauthorized effects, not that all task objectives succeeded. Inspect `all_objectives_met` and individual trials. Reports contain hashes, counters, durations and safe audit fields, not prompts or source content.

For browser use, keep the three Compose projects running and launch `scripts/read_runtime.py knowledge`, `scripts/read_runtime.py tickets`, and `scripts/assistant_runtime.py --provider local` in separate terminals. The last command reruns containment checks before enabling the provider. Open `https://127.0.0.1:19481/` and sign in with a synthetic account. Use `--provider stub` for the deterministic demo. Stop these listeners before running live evaluation scripts on the same ports.

## Remaining Phase 2 exit work

Real Keycloak signing-key rotation and the selected OAuth/MCP discovery profile are now verified. The [Phase 2 read-only exit gate is met](phase2-exit.md). Repeated, broader benign/adversarial evaluation and deployment hardening remain later-phase work. No write capability is enabled.
