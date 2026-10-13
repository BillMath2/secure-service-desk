"""Verify every local model blob offline; never mount this cache writable in an attack."""

import hashlib
import json
from pathlib import Path


def inventory(root: Path) -> dict[str, object]:
    manifest_path = root / "manifests/registry.ollama.ai/library/qwen3/4b-instruct-2507-q4_K_M"
    raw = manifest_path.read_bytes()
    manifest = json.loads(raw)
    blobs = []
    for blob in [manifest["config"], *manifest["layers"]]:
        algorithm, expected = blob["digest"].split(":")
        if algorithm != "sha256" or len(expected) != 64:
            raise ValueError("invalid digest")
        with (root / "blobs" / f"sha256-{expected}").open("rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        if actual != expected:
            raise ValueError("model blob checksum mismatch")
        blobs.append({"digest": blob["digest"], "size": blob["size"]})
    return {"manifest_sha256": hashlib.sha256(raw).hexdigest(), "blobs": blobs}


if __name__ == "__main__":
    print(json.dumps(inventory(Path("/models"))))
