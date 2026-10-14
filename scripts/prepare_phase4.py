"""Trusted staging only: preserve existing keys and expose exact per-role material."""

import json
import secrets
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from psycopg.conninfo import conninfo_to_dict, make_conninfo

from scripts.prepare_isolated_reads import issue_leaf
from service_desk.phase4_layout import BASE, FILES, WRITERS
from service_desk.phase4_process import material

ROOT = Path(__file__).resolve().parents[1]


def prepare(root: Path = ROOT) -> None:
    identity, database = root / ".lab/phase2", root / ".lab/phase2-read"
    destination = root / ".lab/phase4"
    ca = x509.load_pem_x509_certificate((identity / "tls/certificate.pem").read_bytes())
    key = serialization.load_pem_private_key((identity / "tls/private.key").read_bytes(), None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("Unsupported lab CA")
    credentials = json.loads((identity / "credentials.json").read_text())["clients"]
    for role, names in FILES.items():
        target = destination / role
        target.mkdir(parents=True, exist_ok=True)
        if {p.name for p in target.iterdir()} - names:
            raise ValueError("Unexpected workflow material")
        issue_leaf(target, role, ca, key)
        for name in ("trust.pem", "identities.json"):
            (target / name).write_bytes(
                (identity / ("tls/certificate.pem" if name == "trust.pem" else name)).read_bytes()
            )
        for name in names - BASE:
            if name.endswith(".dsn"):
                options = conninfo_to_dict((database / name).read_text())
                options["host"] = "host.docker.internal"
                (target / name).write_text(make_conninfo("", **options))
            elif name in {"web.secret", "gateway.secret", "executor.secret"}:
                (target / name).write_text(credentials[name[:-7]])
            elif name == "provider.json":
                (target / name).write_text(json.dumps({"provider": "local"}))
    pairs = [
        (destination / "browser/agent.secret", destination / "agent/service.secret"),
        (destination / "browser/workflow.secret", destination / "workflow/service.secret"),
    ]
    pairs += [
        (destination / role / "audit.secret", destination / "collector" / (writer + ".secret"))
        for role, writer in WRITERS.items()
    ]
    for left, right in pairs:
        if left.exists() != right.exists():
            raise ValueError("Partial workflow credential pair")
        if not left.exists():
            secret = secrets.token_urlsafe(32)
            left.write_text(secret)
            right.write_text(secret)
        if left.read_bytes() != right.read_bytes():
            raise ValueError("Workflow credential pair mismatch")
    (destination / "browser/publisher.secret").write_bytes(
        (root / ".lab/phase3-app/browser/publisher.secret").read_bytes()
    )
    for role in FILES:
        material(destination / role, role, "192.0.2.10")


if __name__ == "__main__":
    try:
        prepare()
    except Exception:
        raise SystemExit(
            "Workflow preparation failed; inspect trusted local configuration"
        ) from None
    print("Prepared exact per-role workflow material; existing credentials preserved.")
