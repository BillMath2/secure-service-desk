"""Trusted operator staging for separate browser, agent and publisher containers."""

import argparse
import json
import secrets
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from psycopg.conninfo import conninfo_to_dict, make_conninfo

from scripts.prepare_isolated_reads import issue_leaf
from service_desk.app_process import FILES, material

ROOT = Path(__file__).resolve().parents[1]


def prepare(root: Path = ROOT, provider: str = "local") -> None:
    if provider not in {"stub", "local"}:
        raise ValueError("Invalid provider")
    identity = root / ".lab/phase2"
    source = root / ".lab/phase2-read"
    destination = root / ".lab/phase3-app"
    ca = x509.load_pem_x509_certificate((identity / "tls/certificate.pem").read_bytes())
    ca_key = serialization.load_pem_private_key((identity / "tls/private.key").read_bytes(), None)
    if not isinstance(ca_key, rsa.RSAPrivateKey):
        raise ValueError("Unsupported lab CA")
    clients = json.loads((identity / "credentials.json").read_text())["clients"]
    for role in FILES:
        target = destination / role
        target.mkdir(parents=True, exist_ok=True)
        if {p.name for p in target.iterdir()} - FILES[role]:
            raise ValueError("Unexpected application material")
        issue_leaf(target, role, ca, ca_key)
        (target / "trust.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        (target / "identities.json").write_bytes((identity / "identities.json").read_bytes())
        for name in FILES[role]:
            if name.endswith(".dsn"):
                options = conninfo_to_dict((source / name).read_text())
                options["host"] = "host.docker.internal"
                (target / name).write_text(make_conninfo("", **options), encoding="utf-8")
        if role in {"browser", "agent"}:
            name = "web" if role == "browser" else "gateway"
            (target / (name + ".secret")).write_text(clients[name], encoding="utf-8")
            (target / "provider.json").write_text(
                json.dumps({"provider": provider}), encoding="utf-8"
            )
    for role in ("agent", "publisher"):
        service = destination / role / "service.secret"
        browser = destination / "browser" / (role + ".secret")
        if service.exists() != browser.exists():
            raise ValueError("Partial service credential; inspect before retrying")
        if not service.exists():
            value = secrets.token_urlsafe(32)
            service.write_text(value, encoding="utf-8")
            browser.write_text(value, encoding="utf-8")
        if service.read_bytes() != browser.read_bytes():
            raise ValueError("Service credential mismatch")
    for role in FILES:
        material(destination / role, role, "192.0.2.10")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", choices=("local", "stub"), default="local")
    args = parser.parse_args()
    try:
        prepare(provider=args.provider)
    except Exception:
        raise SystemExit("Application preparation failed; inspect local configuration") from None
    print("Prepared scoped application material; existing credentials and keys preserved.")
