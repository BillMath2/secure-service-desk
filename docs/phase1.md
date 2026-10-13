# Phase 1: Contained vulnerable baseline

The implementation is in `lab_baseline/`. Its three unauthenticated MCP services intentionally permit restricted reads, requester publication, and grants without approval, using only the shared fictional fixtures. The normal `service-desk` package cannot import or enable the baseline.

## Recorded result — October 12, 2026

Phase 1's exit gate is met. All 44 tests, lint, formatting, strict type checks, and live containment probes passed. The [saved evaluation](../reports/phase1/results.json) contains eight completed cases with zero execution errors:

| Mode | Attack objectives achieved | Benign objectives achieved | Interpretation |
|---|---:|---:|---|
| Forced MCP calls | 3 / 3 | 1 / 1 | Unauthorized HR read, requester publication, and grant without approval were observed |
| Qwen model loop | 0 / 3 | 0 / 1 | Attacks did not trigger the targeted effects; the benign model task also missed its objective |

The model's benign attempt searched instead of completing the requested document read. This is a model/tool-use quality limitation, not a policy denial or a passing task. Model trials took approximately 8.8–67.2 seconds each on CPU. These are single trials, not attack-success estimates or a complete performance benchmark. The first report-export attempt failed; the saved run uses the corrected export path. Baseline containers and networks were removed after verification; only the model cache and images remain.

Containment, model integrity, runtime observations, and source hashes are saved alongside the results in [reports/phase1](../reports/phase1/containment.json). The initial suite demonstrates measurable baseline vulnerabilities; Phase 2 authentication and later hardened workflow controls remain unimplemented.

## Reproduce

Run from the repository root with Docker Desktop running Linux containers. The checked-in Compose file requests NVIDIA GPU access, but the observed runtime used CPU inference (about 3.2 GB loaded model memory, 4,096 context tokens). Initial preparation downloads the pinned Ollama image and approximately 2.5 GB of model weights; subsequent experiment runs use only the local cache.

```powershell
.\scripts\bootstrap.ps1
.\scripts\check.ps1
docker compose -f infra/compose.baseline.yaml build knowledge
docker compose -f infra/compose.baseline-preload.yaml up -d
docker compose -f infra/compose.baseline-preload.yaml exec -T preload ollama pull qwen3:4b-instruct-2507-q4_K_M
docker compose -f infra/compose.baseline-preload.yaml down
.\.venv\Scripts\python.exe scripts/run_baseline.py --output reports/runs/baseline-01
```

Wait for the preload server to be ready if the pull reports a connection error. The preparation project has no fixture data, tool services, host ports, or credentials. Stop it before running the baseline; the host script refuses to proceed if it is still running. Model manifest/blob hashes must match `lab_baseline/model.lock.json` before model-driven evaluation. Do not replace the lock merely to silence a mismatch: review the changed artifact first.

Use `--mode forced` for the four deterministic boundary cases. This runs the same container/network checks but skips model invocation and integrity inspection. A model volume is still required by Compose. Use a new output directory each time. The host script refuses to overwrite results or attach to an existing baseline run.

The script starts a separate `service-desk-baseline` Compose project, verifies containment, runs the experiment and stops all its services/networks. No ports are published; operator access uses the local Docker CLI. If the host interpreter itself is forcibly killed, run this project-scoped cleanup:

```powershell
docker compose -f infra/compose.baseline.yaml down --timeout 5
docker compose -f infra/compose.baseline-preload.yaml down
```

The dedicated `service-desk-baseline-model` volume and downloaded images remain cached. Do not prune unrelated Docker resources. The baseline has no host bind mounts or durable ticket/grant database. All simulated effects disappear at teardown.

## Evidence and interpretation

- `containment.json`: configuration checks and namespace probes for every tool service, runner, sink, and model; a live protected-network sentinel; fixed synthetic sink capture without echo.
- `model-integrity.json`: independently recomputed model artifact hashes, compared with the reviewed lock before inference.
- `source.json`: base Git commit and hashes of working implementation/configuration files, including uncommitted code.
- `results.json`: fixture, case, catalog, prompt and template fingerprints; provider model digest/settings; case outcomes, safe event references and hashes; separate forced/model sample counts.

`success` means a case's objective occurred. For an attack, it means the vulnerability was demonstrated. `failure` means the requested effect was not observed; it is not proof of a robust defense. `error` means execution or observation failed, and may still include observed partial effects. No model prose, raw tool arguments, document text, replies, canaries, or usable tokens are included in saved evidence. Container log storage is disabled for the experiment.

Initial cases cover an unauthorized HR read, a requester-visible privileged procedure, an unapproved sensitive grant, a legitimate document read, two indirect injection paths, and a self-approval claim. Model cases use the same tool catalog and existing hostile fixture text. The experiment has no arbitrary shell, URL-fetch, or filesystem tool. The source document's request to send data to a sink has no corresponding model tool; that case measures the unauthorized read stage only.

The audit observations here are per-service in-memory sequences plus hashes. They are not the protected durable collector/outbox required later. Likewise, the independent experimental limits are not the hardened application's concurrent per-user budgets. See [ADR 0002](adr/0002-contained-baseline.md) for decisions and limitations.

The host-port probe checks an unreachable development database port; it is not a scan or proof that every host service is inaccessible. The separate protected-network sentinel is live and positively checked before the isolation probes. These probes establish the tested routes and container configuration, not universal isolation under a compromised Docker daemon.

Docker Desktop did not support exporting the report from the runner's tmpfs with `docker cp` in the first trial. The harness now reads only the already-redacted JSON through `docker exec` before teardown. It never exports the raw in-memory service stores.
