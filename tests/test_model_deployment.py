"""Offline integrity gate and fixed-route relay behavior."""

import hashlib
import http.client
import json
import threading
from contextlib import closing
from http.server import HTTPServer
from pathlib import Path

import pytest

from scripts.model_relay import Relay
from scripts.verify_local_model import verify


@pytest.mark.parametrize("tamper", ["none", "manifest", "blob", "size", "inventory"])
def test_offline_gate_verifies_every_byte(tmp_path: Path, tamper: str) -> None:
    root = tmp_path / "models"
    blob = b"synthetic-model-test"
    digest = hashlib.sha256(blob).hexdigest()
    entry = {"digest": "sha256:" + digest, "size": len(blob)}
    manifest = root / "manifests/registry.ollama.ai/library/qwen3/4b-instruct-2507-q4_K_M"
    manifest.parent.mkdir(parents=True)
    raw = json.dumps({"config": entry, "layers": []}).encode()
    manifest.write_bytes(raw)
    target = root / "blobs" / ("sha256-" + digest)
    target.parent.mkdir()
    target.write_bytes(blob)
    lock = {"manifest_sha256": hashlib.sha256(raw).hexdigest(), "blobs": [entry]}
    if tamper == "manifest":
        manifest.write_bytes(raw + b" ")
    elif tamper == "blob":
        target.write_bytes(b"x" * len(blob))
    elif tamper == "size":
        target.write_bytes(blob + b"x")
    elif tamper == "inventory":
        lock["blobs"] = []
    lock_file = tmp_path / "lock.json"
    lock_file.write_text(json.dumps(lock))
    if tamper == "none":
        verify(root, lock_file)
    else:
        with pytest.raises(ValueError):
            verify(root, lock_file)


@pytest.mark.parametrize(
    "method,path,headers,status",
    [
        ("POST", "/api/pull", {}, 404),
        ("POST", "/api/delete", {}, 404),
        ("GET", "https://evil.invalid/", {}, 404),
        ("POST", "/api/generate", {"Transfer-Encoding": "chunked"}, 400),
        ("POST", "/api/generate", {"Content-Length": "65537"}, 413),
    ],
)
def test_relay_rejects_unregistered_routes_and_unbounded_bodies(
    method: str,
    path: str,
    headers: dict[str, str],
    status: int,
) -> None:
    server = HTTPServer(("127.0.0.1", 0), Relay)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with closing(
            http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
        ) as client:
            client.request(method, path, headers=headers)
            assert client.getresponse().status == status
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)
