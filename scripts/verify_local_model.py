"""Offline cache gate: exact manifest, every blob checksum and size; prints no content."""

import hashlib
import json
from pathlib import Path


def verify(root: Path, lock_file: Path) -> None:
    lock = json.loads(lock_file.read_text())
    manifest = root / "manifests/registry.ollama.ai/library/qwen3/4b-instruct-2507-q4_K_M"
    raw = manifest.read_bytes()
    if hashlib.sha256(raw).hexdigest() != lock["manifest_sha256"]:
        raise ValueError("Manifest mismatch")
    data = json.loads(raw)
    records = [data["config"], *data["layers"]]
    if [{"digest": b["digest"], "size": b["size"]} for b in records] != lock["blobs"]:
        raise ValueError("Blob inventory mismatch")
    for blob in lock["blobs"]:
        algorithm, digest = blob["digest"].split(":")
        if (
            algorithm != "sha256"
            or len(digest) != 64
            or any(c not in "0123456789abcdef" for c in digest)
        ):
            raise ValueError("Invalid digest")
        path = root / "blobs" / ("sha256-" + digest)
        if path.stat().st_size != blob["size"]:
            raise ValueError("Blob size mismatch")
        with path.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != digest:
                raise ValueError("Blob checksum mismatch")


if __name__ == "__main__":
    try:
        verify(Path("/models"), Path("/model.lock.json"))
    except Exception:
        raise SystemExit("Local model integrity gate failed") from None
    print('{"model_integrity":true}')
