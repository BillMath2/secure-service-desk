"""Container-only read service: one database login, one leaf key, no client secrets."""

import argparse
import json
import ssl
import time
from datetime import UTC, datetime
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
import jwt
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from psycopg.conninfo import conninfo_to_dict, make_conninfo

from service_desk.core.auth.lab import ISSUER, RESOURCES
from service_desk.core.auth.tokens import TokenValidator
from service_desk.core.database import check_database
from service_desk.core.gateway.store import TaskStore
from service_desk.core.ingress import BoundedHTTPProtocol
from service_desk.core.tls_ingress import BoundedTLSServer
from service_desk.mcp.reads import create_read_mcp
from service_desk.read_bootstrap import destination
from service_desk.reads import ReadService

FILES = {"database.dsn", "identities.json", "trust.pem", "certificate.pem", "private.key"}
JWKS_PATH = "/realms/service-desk-phase2/protocol/openid-connect/certs"


def validate_leaf(root: Path, service: str) -> None:
    ca = x509.load_pem_x509_certificate((root / "trust.pem").read_bytes())
    leaf = x509.load_pem_x509_certificate((root / "certificate.pem").read_bytes())
    key = serialization.load_pem_private_key((root / "private.key").read_bytes(), None)
    leaf.verify_directly_issued_by(ca)
    now = datetime.now(UTC)
    if (
        leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        or leaf.subject != x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "desk-" + service)])
        or list(leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)
        != [ExtendedKeyUsageOID.SERVER_AUTH]
        or list(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value)
        != [x509.IPAddress(IPv4Address("127.0.0.1"))]
        or not leaf.not_valid_before_utc <= now < leaf.not_valid_after_utc
        or leaf.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        != key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ):
        raise ValueError("Invalid service leaf certificate")


class DesktopKeys(jwt.PyJWKClient):
    """Route to Docker Desktop's host, retaining the issuer's TLS name and key cache."""

    def __init__(self, http: httpx.Client, host_ip: str) -> None:
        super().__init__(
            ISSUER + "/protocol/openid-connect/certs",
            lifespan=60,
            cooldown_duration=5,
            cache_keys=False,
        )
        self.http = http
        self.host_ip = destination(host_ip)

    def fetch_data(self) -> dict[str, Any]:
        try:
            with self.http.stream(
                "GET",
                "https://" + self.host_ip + ":19443" + JWKS_PATH,
                headers={"Host": "127.0.0.1:19443", "Accept-Encoding": "identity"},
                extensions={"sni_hostname": "127.0.0.1"},
            ) as response:
                if response.status_code != 200 or response.headers.get("content-encoding"):
                    raise ValueError()
                body = bytearray()
                for part in response.iter_raw():
                    if len(body) + len(part) > 65536:
                        raise ValueError()
                    body.extend(part)
                result = json.loads(body)
                if not isinstance(result, dict) or not isinstance(result.get("keys"), list):
                    raise ValueError()
        except (httpx.HTTPError, ValueError):
            raise jwt.PyJWKClientConnectionError("Identity keys unavailable") from None
        if self.jwk_set_cache is not None:
            self.jwk_set_cache.put(result)
        self._last_successful_fetch = time.monotonic()
        return result


def read_material(root: Path, service: str) -> tuple[str, dict[tuple[str, str], str]]:
    try:
        if service not in {"knowledge", "tickets"} or {p.name for p in root.iterdir()} != FILES:
            raise ValueError()
        if any(
            p.is_symlink() or not p.is_file() or p.stat().st_size > 65536 for p in root.iterdir()
        ):
            raise ValueError()
        dsn = (root / "database.dsn").read_text()
        values = conninfo_to_dict(dsn)
        if set(values) != {"host", "port", "dbname", "user", "password"} or any(
            values.get(k) != v
            for k, v in {
                "host": "host.docker.internal",
                "port": "15433",
                "dbname": "service_desk_read_lab",
                "user": "read_" + service,
            }.items()
        ):
            raise ValueError()
        rows = json.loads((root / "identities.json").read_text())
        identities = {(r["issuer"], r["subject"]): r["principal_id"] for r in rows}
        if not identities or any(issuer != ISSUER for issuer, _ in identities):
            raise ValueError()
        validate_leaf(root, service)
        return dsn, identities
    except Exception:
        raise ValueError("Invalid read-service material") from None


class ReadTLSServer(BoundedTLSServer):
    # Docker publishes only loopback host ports; its bridge requires this bind.
    BIND_HOST = "0.0.0.0"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("service", choices=("knowledge", "tickets"))
    parser.add_argument("host_ip", type=destination)
    args = parser.parse_args()
    root = Path("/run/desk")
    try:
        dsn, identities = read_material(root, args.service)
        dsn = make_conninfo(dsn, hostaddr=args.host_ip)
        check_database(dsn, "read_" + args.service)
        trust = ssl.create_default_context(cafile=str(root / "trust.pem"))
        binding = next(r for r in RESOURCES if r.audience == args.service)
        with httpx.Client(verify=trust, trust_env=False, follow_redirects=False, timeout=5) as http:
            validator = TokenValidator(ISSUER, DesktopKeys(http, args.host_ip), identities)
            validator.keys.get_jwk_set()  # Prove TLS-verified identity connectivity before serving.
            app = create_read_mcp(validator, binding, ReadService(args.service, TaskStore(dsn)))
            port = urlsplit(binding.url).port
            assert port is not None
            config = uvicorn.Config(
                app,
                host="0.0.0.0",
                port=port,
                http=BoundedHTTPProtocol,
                ws="none",
                workers=1,
                proxy_headers=False,
                access_log=False,
                log_level="critical",
                backlog=16,
                timeout_keep_alive=0,
                timeout_graceful_shutdown=5,
                h11_max_incomplete_event_size=BoundedHTTPProtocol.MAX_HEADERS,
                headers=[("Connection", "close")],
                ssl_certfile=str(root / "certificate.pem"),
                ssl_keyfile=str(root / "private.key"),
            )
            ReadTLSServer(config).run()
    except Exception:
        raise SystemExit("Read service startup or runtime failed") from None


if __name__ == "__main__":
    main()
