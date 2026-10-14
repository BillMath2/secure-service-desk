"""Shared trusted bootstrap for the identity shell and optional live probe."""

import argparse
import json
import ssl
from collections.abc import Awaitable, Callable
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import uvicorn
from starlette.applications import Starlette

from service_desk.app.identity import create_identity_app
from service_desk.core.auth.lab import ISSUER, REDIRECT, RESOURCES
from service_desk.core.auth.oidc import OIDCClient
from service_desk.core.auth.tokens import TokenValidator, key_client
from service_desk.core.ingress import BoundedHTTPProtocol
from service_desk.core.tls_ingress import BoundedTLSServer
from service_desk.mcp.identity import create_identity_mcp

ROOT = Path(__file__).resolve().parents[1]
LOCAL = ROOT / ".lab/phase2"


def load_validator(trust: ssl.SSLContext, client_id: str = "gateway") -> TokenValidator:
    identities = {
        (row["issuer"], row["subject"]): row["principal_id"]
        for row in json.loads((LOCAL / "identities.json").read_text())
    }
    keys = key_client(ISSUER + "/protocol/openid-connect/certs", trust)
    return TokenValidator(ISSUER, keys, identities, client_id)


def load_client(http: httpx.Client, trust: ssl.SSLContext) -> OIDCClient:
    credentials = json.loads((LOCAL / "web-client.json").read_text())
    if set(credentials) != {"clients"} or set(credentials["clients"]) != {"web", "gateway"}:
        raise ValueError("Invalid browser client credential scope")
    return OIDCClient(
        load_validator(trust, "web"),
        credentials["clients"]["web"],
        REDIRECT,
        RESOURCES,
        http,
        load_validator(trust),
        credentials["clients"]["gateway"],
    )


def server_config(app: Callable[..., Awaitable[None]], port: int | None) -> uvicorn.Config:
    if port is None:
        raise ValueError("A fixed local listener port is required")
    return uvicorn.Config(
        app,
        host="127.0.0.1",
        port=port,
        http=BoundedHTTPProtocol,
        ws="none",
        workers=1,
        backlog=16,
        timeout_keep_alive=0,
        timeout_graceful_shutdown=5,
        h11_max_incomplete_event_size=BoundedHTTPProtocol.MAX_HEADERS,
        headers=[("Connection", "close")],
        proxy_headers=False,
        access_log=False,
        log_level="critical",
        ssl_certfile=str(LOCAL / "tls/certificate.pem"),
        ssl_keyfile=str(LOCAL / "tls/private.key"),
    )


def create_server(app: Callable[..., Awaitable[None]], port: int | None) -> BoundedTLSServer:
    return BoundedTLSServer(server_config(app, port))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("service", choices=["web", *(r.audience for r in RESOURCES)])
    args = parser.parse_args()
    trust = ssl.create_default_context(cafile=str(LOCAL / "tls/certificate.pem"))
    app: Starlette
    port: int | None
    with httpx.Client(verify=trust, trust_env=False, timeout=10, follow_redirects=False) as http:
        if args.service == "web":
            oidc = load_client(http, trust)
            oidc.check_discovery()
            app, port = create_identity_app(oidc), 19481
        else:
            binding = next(r for r in RESOURCES if r.audience == args.service)
            app = create_identity_mcp(load_validator(trust), binding)
            port = urlsplit(binding.url).port
        create_server(app, port).run()


if __name__ == "__main__":
    main()
