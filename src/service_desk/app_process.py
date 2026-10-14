"""Credential-scoped browser, generation and human-publication container entry points."""

import argparse
import asyncio
import json
import re
import ssl
from pathlib import Path

import httpx
import uvicorn
from psycopg.conninfo import conninfo_to_dict, make_conninfo

from service_desk.agent.local_model import LocalModelProvider
from service_desk.agent.loop import Assistant
from service_desk.agent.provider import DeterministicProvider, Provider
from service_desk.agent.store import AgentStore
from service_desk.app.backend import LocalTaskBackend
from service_desk.app.identity import create_identity_app
from service_desk.app.publication import PublicationStore
from service_desk.app.rpc import RemoteTaskBackend, service_app
from service_desk.app_network import OUTBOUND, PORTS, RoutedAsyncTransport, RoutedTransport
from service_desk.core.auth.lab import ISSUER, REDIRECT, RESOURCES
from service_desk.core.auth.oidc import OIDCClient
from service_desk.core.auth.tokens import TokenValidator
from service_desk.core.database import check_database
from service_desk.core.gateway.dispatch import ReadGateway
from service_desk.core.gateway.store import TaskStore
from service_desk.core.ingress import BoundedHTTPProtocol
from service_desk.read_bootstrap import destination
from service_desk.read_process import DesktopKeys, ReadTLSServer, validate_leaf

BASE = {"trust.pem", "certificate.pem", "private.key", "identities.json"}
FILES = {
    "browser": BASE | {"web.secret", "agent.secret", "publisher.secret", "provider.json"},
    "agent": BASE
    | {"gateway.secret", "service.secret", "creator.dsn", "gateway.dsn", "provider.json"},
    "publisher": BASE | {"service.secret", "publisher.dsn"},
}
LOGINS = {"creator": "read_app", "gateway": "read_gateway", "publisher": "read_publisher"}


def material(
    root: Path, role: str, host_ip: str
) -> tuple[dict[str, str], dict[tuple[str, str], str]]:
    try:
        host_ip = destination(host_ip)
        if {p.name for p in root.iterdir()} != FILES[role]:
            raise ValueError()
        if any(
            p.is_symlink() or not p.is_file() or p.stat().st_size > 65536 for p in root.iterdir()
        ):
            raise ValueError()
        validate_leaf(root, role)
        rows = json.loads((root / "identities.json").read_text())
        identities = {(r["issuer"], r["subject"]): r["principal_id"] for r in rows}
        if not identities or any(issuer != ISSUER for issuer, _ in identities):
            raise ValueError()
        config = {}
        for name in FILES[role] - BASE:
            value = (root / name).read_text().strip()
            if name.endswith(".secret") and not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", value):
                raise ValueError()
            if name.endswith(".dsn"):
                options = conninfo_to_dict(value)
                if set(options) != {"host", "port", "dbname", "user", "password"} or any(
                    options[k] != v
                    for k, v in {
                        "host": "host.docker.internal",
                        "port": "15433",
                        "dbname": "service_desk_read_lab",
                        "user": LOGINS[name[:-4]],
                    }.items()
                ):
                    raise ValueError()
                value = make_conninfo(value, hostaddr=host_ip)
            if name == "provider.json" and json.loads(value) not in (
                {"provider": "local"},
                {"provider": "stub"},
            ):
                raise ValueError()
            config[name] = value
        return config, identities
    except Exception:
        raise ValueError("Invalid application material") from None


async def serve(role: str, host_ip: str, root: Path = Path("/run/desk")) -> None:
    config, identities = material(root, role, host_ip)
    for key in config:
        if key.endswith(".dsn"):
            check_database(config[key], LOGINS[key[:-4]])
    trust = ssl.create_default_context(cafile=str(root / "trust.pem"))
    with (
        httpx.Client(verify=trust, trust_env=False, follow_redirects=False, timeout=5) as keys_http,
        httpx.Client(
            transport=RoutedTransport(host_ip, OUTBOUND[role], trust),
            trust_env=False,
            follow_redirects=False,
            timeout=10,
        ) as http,
    ):
        keys = DesktopKeys(keys_http, host_ip)
        keys.get_jwk_set()
        validator = TokenValidator(ISSUER, keys, identities, "web")
        delegated = TokenValidator(ISSUER, keys, identities, "gateway")
        oidc = OIDCClient(
            validator,
            config.get("web.secret", ""),
            REDIRECT,
            RESOURCES,
            http,
            delegated,
            config.get("gateway.secret", ""),
        )
        oidc.check_discovery()
        async with httpx.AsyncClient(
            transport=RoutedAsyncTransport(host_ip, OUTBOUND[role], trust),
            trust_env=False,
            follow_redirects=False,
            timeout=120,
        ) as rpc_http:
            provider_name = json.loads(config.get("provider.json", '{"provider":"local"}'))[
                "provider"
            ]
            label = (
                "Local Qwen3 model: check cited sources."
                if provider_name == "local"
                else "Deterministic test provider."
            )
            if role == "browser":
                app = create_identity_app(
                    oidc,
                    backend=RemoteTaskBackend(
                        rpc_http,
                        config["agent.secret"],
                        config["publisher.secret"],
                        provider_label=label,
                    ),
                )
            elif role == "agent":
                provider: Provider = DeterministicProvider()
                if provider_name == "local":
                    local = LocalModelProvider(
                        transport=RoutedAsyncTransport(host_ip, (19485,), trust)
                    )
                    await local.prepare()
                    provider = local
                assistant = Assistant(
                    validator,
                    AgentStore(config["creator.dsn"]),
                    ReadGateway(oidc, TaskStore(config["gateway.dsn"]), http),
                    provider,
                    provider_label=label,
                )
                app = service_app(
                    "agent", validator, config["service.secret"], agent=LocalTaskBackend(assistant)
                )
            else:
                app = service_app(
                    "publisher",
                    validator,
                    config["service.secret"],
                    publisher=PublicationStore(config["publisher.dsn"]),
                )
            server_config = uvicorn.Config(
                app,
                host="0.0.0.0",
                port=PORTS[role],
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
            await ReadTLSServer(server_config).serve()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=tuple(PORTS))
    parser.add_argument("host_ip", type=destination)
    args = parser.parse_args()
    try:
        asyncio.run(serve(args.role, args.host_ip))
    except Exception:
        raise SystemExit("Application startup or runtime failed") from None


if __name__ == "__main__":
    main()
