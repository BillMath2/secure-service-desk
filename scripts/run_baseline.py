"""Host-owned containment gate and watchdog. No shell interpolation or raw evidence logs."""

import argparse
import hashlib
import json
import shutil
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ["compose", "-f", "infra/compose.baseline.yaml"]
DOCKER = shutil.which("docker") or "docker"
SERVICES = ("knowledge", "tickets", "access", "runner", "sink", "model")


def docker(*args: str, timeout: int = 90) -> str:
    result = subprocess.run(
        [DOCKER, *args], cwd=ROOT, capture_output=True, text=True, timeout=timeout, check=False
    )
    if result.returncode:
        # Only command names in exceptions; tool/model exception text stays out of reports.
        raise RuntimeError(f"Docker operation failed: {args[0]}")
    return result.stdout.strip()


def source_manifest() -> dict[str, str]:
    files = [
        p
        for folder in ("src", "lab_baseline", "infra", "scripts")
        for p in (ROOT / folder).rglob("*")
        if p.is_file() and p.suffix in (".py", ".json", ".yaml", ".Dockerfile")
    ]
    files.extend(ROOT / name for name in ("pyproject.toml", "uv.lock", "fixtures/company.json"))
    return {
        p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(files)
    }


def run(output: Path, mode: str) -> None:
    output.mkdir(parents=True, exist_ok=False)
    # Preload must be gone before the vulnerable environment starts.
    if docker(
        "ps", "-q", "--filter", "label=com.docker.compose.project=service-desk-baseline-preload"
    ):
        raise RuntimeError("Stop the trusted preload project before running the baseline")
    if docker(*COMPOSE, "ps", "-q"):
        raise RuntimeError("Baseline already running; stop it before creating a fresh run")
    evidence: dict[str, object] = {"passed": False, "namespace_probes": {}}
    try:
        docker(*COMPOSE, "up", "-d", "--no-build", timeout=180)
        ids = {s: docker(*COMPOSE, "ps", "-q", s) for s in (*SERVICES, "protected-sentinel")}
        inspections = {s: json.loads(docker("inspect", cid))[0] for s, cid in ids.items()}
        attack_network = "service-desk-baseline_attack"
        protected_network = "service-desk-baseline_protected"
        network = json.loads(docker("network", "inspect", attack_network))[0]
        assert network["Internal"]
        assert set(network["Containers"]) == {ids[s] for s in SERVICES}
        for service in SERVICES:
            container = inspections[service]
            config = container["HostConfig"]
            assert set(container["NetworkSettings"]["Networks"]) == {attack_network}
            assert not config["Privileged"] and config["ReadonlyRootfs"]
            assert not config["PortBindings"]
            assert not config["CapAdd"] and "ALL" in config["CapDrop"]
            assert "no-new-privileges:true" in config["SecurityOpt"]
            assert config["Memory"] > 0 and config["PidsLimit"] > 0
            assert config["LogConfig"]["Type"] == "none"
            assert container["Config"]["User"] == "65532:65532"
            for mount in container["Mounts"]:
                assert mount["Type"] in ("tmpfs", "volume")
                if mount["Type"] == "volume":
                    assert service == "model" and mount["Name"] == "service-desk-baseline-model"
                    assert not mount["RW"] and mount["Destination"] == "/models"
        sentinel = inspections["protected-sentinel"]
        assert set(sentinel["NetworkSettings"]["Networks"]) == {protected_network}
        sentinel_ip = sentinel["NetworkSettings"]["Networks"][protected_network]["IPAddress"]
        ready = (
            "import urllib.request; "
            "assert urllib.request.urlopen('http://127.0.0.1:8080',timeout=2).status==200"
        )
        deadline = time.monotonic() + 30
        while True:
            try:
                docker("exec", ids["protected-sentinel"], "python", "-c", ready)
                for service in ("knowledge", "tickets", "access"):
                    docker(
                        "exec", ids[service], "python", "-c", ready.replace("8080'", "8080/health'")
                    )
                break
            except RuntimeError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(1)
        probes = {}
        for service in SERVICES:
            # Python probe shares each target's actual network namespace, including Ollama.
            raw = docker(
                "run",
                "--rm",
                "--network",
                f"container:{ids[service]}",
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--memory=128m",
                "--pids-limit=32",
                "--log-driver=none",
                "service-desk-baseline:phase1",
                "python",
                "-m",
                "lab_baseline.probe",
                sentinel_ip,
                timeout=30,
            )
            probes[service] = json.loads(raw)
            assert all(probes[service].values())
        # Fixed synthetic sink capture; no arbitrary URLs are offered to the model.
        sink_test = (
            "import urllib.request; "
            "r=urllib.request.urlopen(urllib.request.Request('http://sink:8080/capture',"
            "data=b'baseline-containment-probe',method='POST')); "
            "assert r.status==204 and r.read()==b''"
        )
        docker("exec", ids["runner"], "python", "-c", sink_test)
        evidence.update(
            {
                "passed": True,
                "namespace_probes": probes,
                "protected_sentinel_positive_control": True,
                "no_host_ports_or_binds": True,
                "sink_capture_no_echo": True,
                "images": {s: i["Image"] for s, i in inspections.items()},
            }
        )
        (output / "containment.json").write_text(json.dumps(evidence, indent=2) + "\n")
        manifest = source_manifest()
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True
        ).stdout.strip()
        (output / "source.json").write_text(
            json.dumps(
                {
                    "base_commit": revision,
                    "working_tree_file_sha256": manifest,
                },
                indent=2,
            )
            + "\n"
        )
        if mode == "all":
            integrity = json.loads(
                docker(
                    "run",
                    "--rm",
                    "--network=none",
                    "--read-only",
                    "--cap-drop=ALL",
                    "--security-opt=no-new-privileges",
                    "--memory=128m",
                    "--pids-limit=32",
                    "--mount",
                    "type=volume,src=service-desk-baseline-model,dst=/models,readonly",
                    "service-desk-baseline:phase1",
                    "python",
                    "-m",
                    "lab_baseline.model_integrity",
                )
            )
            pin = json.loads((ROOT / "lab_baseline/model.lock.json").read_text())
            assert integrity == pin, "local model differs from reviewed lock"
            (output / "model-integrity.json").write_text(json.dumps(integrity, indent=2) + "\n")
        # Independent 660s host deadline, plus the 600s in-container child supervisor.
        docker(
            "exec",
            ids["runner"],
            "python",
            "-m",
            "lab_baseline.supervisor",
            "--mode",
            mode,
            timeout=660,
        )
        # docker cp cannot reliably export from a container tmpfs on Docker Desktop.
        # Read only the already-redacted report through exec, never the raw service stores.
        report = json.loads(docker("exec", ids["runner"], "cat", "/results/run/results.json"))
        (output / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    except Exception:
        (output / "run-error.json").write_text(
            '{"status":"error","reason":"baseline-run-failed"}\n'
        )
        raise
    finally:
        # Stops provider and tools too; no late model call can mutate after this run ends.
        docker(*COMPOSE, "down", "--timeout", "5", timeout=90)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mode", choices=("all", "forced"), default="all")
    arguments = parser.parse_args()
    run(arguments.output.resolve(), arguments.mode)
