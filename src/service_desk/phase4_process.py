"""Separate browser, proposal, approval, execution, worker and collector runtimes."""

import argparse
import asyncio
import json
import re
import ssl
from collections.abc import Awaitable, Callable
from contextlib import suppress
from pathlib import Path
from typing import Any

import httpx
import uvicorn
from fastapi import FastAPI
from psycopg.conninfo import conninfo_to_dict, make_conninfo

from service_desk.access_service import AccessProposalService
from service_desk.agent.local_model import LocalModelProvider
from service_desk.agent.loop import Assistant
from service_desk.agent.store import AgentStore
from service_desk.app.access_api import (
    LocalAccessBackend,
    RemoteAccessBackend,
    create_collector_app,
    create_workflow_app,
)
from service_desk.app.backend import LocalTaskBackend
from service_desk.app.identity import create_identity_app
from service_desk.app.rpc import RemoteTaskBackend, service_app
from service_desk.app_network import RoutedAsyncTransport, RoutedTransport
from service_desk.core.access import AccessStore
from service_desk.core.access_runtime import deliver_once, execute_once
from service_desk.core.auth.lab import ISSUER, REDIRECT, RESOURCES
from service_desk.core.auth.oidc import OIDCClient
from service_desk.core.auth.tokens import TokenValidator
from service_desk.core.database import check_database
from service_desk.core.gateway.dispatch import ReadGateway
from service_desk.core.gateway.store import TaskStore
from service_desk.core.ingress import BoundedHTTPProtocol
from service_desk.mcp.execution import WorkloadValidator, create_execution_mcp
from service_desk.mcp.reads import create_read_mcp
from service_desk.phase4_layout import BASE, FILES, LOGINS, OUTBOUND, PORTS, WRITERS
from service_desk.read_bootstrap import destination
from service_desk.read_process import DesktopKeys, ReadTLSServer, validate_leaf


def material(
    root: Path, role: str, host_ip: str
) -> tuple[dict[str, str], dict[tuple[str, str], str]]:
    try:
        host_ip = destination(host_ip)
        if {p.name for p in root.iterdir()} != FILES[role] or any(
            p.is_symlink() or not p.is_file() or p.stat().st_size > 65536 for p in root.iterdir()
        ):
            raise ValueError()
        validate_leaf(root, role)
        identities = {
            (r["issuer"], r["subject"]): r["principal_id"]
            for r in json.loads((root / "identities.json").read_text())
        }
        if not identities or any(i != ISSUER for i, _ in identities):
            raise ValueError()
        values = {}
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
            if name == "provider.json" and json.loads(value) != {"provider": "local"}:
                raise ValueError()
            values[name] = value
        return values, identities
    except Exception:
        raise ValueError("Invalid workflow material") from None


async def periodic(action: Callable[[], Awaitable[Any]]) -> None:
    while True:
        with suppress(Exception):
            await action()
        # Failed delivery retains the durable row; no exception text is logged.
        await asyncio.sleep(2)


async def serve(role: str, host_ip: str, root: Path = Path("/run/desk")) -> None:
    config, identities = material(root, role, host_ip)
    for name in config:
        if name.endswith(".dsn"):
            check_database(config[name], LOGINS[name[:-4]])
    trust = ssl.create_default_context(cafile=str(root / "trust.pem"))
    with (
        httpx.Client(verify=trust, trust_env=False, timeout=5) as keys_http,
        httpx.Client(
            transport=RoutedTransport(host_ip, OUTBOUND[role], trust),
            trust_env=False,
            follow_redirects=False,
            timeout=10,
        ) as http,
    ):
        async with httpx.AsyncClient(
            transport=RoutedAsyncTransport(host_ip, OUTBOUND[role], trust),
            trust_env=False,
            follow_redirects=False,
            timeout=120 if role == "browser" else 10,
        ) as async_http:
            jobs: list[asyncio.Task[None]] = []
            app: Any
            keys = DesktopKeys(keys_http, host_ip)
            validator = TokenValidator(ISSUER, keys, identities, "web")
            if role in {"browser", "agent", "workflow", "proposals", "execution"}:
                keys.get_jwk_set()
            if role in {"browser", "agent"}:
                oidc = OIDCClient(
                    validator,
                    config.get("web.secret", ""),
                    REDIRECT,
                    RESOURCES,
                    http,
                    TokenValidator(ISSUER, keys, identities, "gateway"),
                    config.get("gateway.secret", ""),
                )
                oidc.check_discovery()
                if role == "browser":
                    app = create_identity_app(
                        oidc,
                        backend=RemoteTaskBackend(
                            async_http,
                            config["agent.secret"],
                            config["publisher.secret"],
                            provider_label="Local Qwen3 model; proposals require "
                            "independent human approval.",
                        ),
                        access_backend=RemoteAccessBackend(async_http, config["workflow.secret"]),
                    )
                else:
                    provider = LocalModelProvider(
                        transport=RoutedAsyncTransport(host_ip, (19485,), trust)
                    )
                    await provider.prepare()
                    assistant = Assistant(
                        validator,
                        AgentStore(config["creator.dsn"]),
                        ReadGateway(oidc, TaskStore(config["gateway.dsn"]), http),
                        provider,
                        proposal_tools=True,
                    )
                    app = service_app(
                        "agent",
                        validator,
                        config["service.secret"],
                        agent=LocalTaskBackend(assistant),
                    )
            elif role == "workflow":
                app = create_workflow_app(
                    LocalAccessBackend(validator, AccessStore(config["workflow.dsn"])),
                    config["service.secret"],
                )
            elif role == "proposals":
                app = create_read_mcp(
                    TokenValidator(ISSUER, keys, identities, "gateway"),
                    RESOURCES[2],
                    AccessProposalService(AccessStore(config["proposals.dsn"])),
                )
            elif role == "execution":
                app = create_execution_mcp(
                    WorkloadValidator(ISSUER, keys, {}, "executor"),
                    AccessStore(config["execution.dsn"]),
                )
            elif role == "collector":
                app = create_collector_app(
                    AccessStore(config["collector.dsn"]),
                    {w: config[w + ".secret"] for w in WRITERS.values()},
                )
            else:
                health_app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
                app = health_app

                @health_app.get("/health")
                def health() -> dict[str, bool]:
                    return {"ready": True}

                if role == "worker":

                    async def cleanup() -> None:
                        await asyncio.to_thread(AccessStore(config["lifecycle.dsn"]).reconcile)

                    jobs.append(asyncio.create_task(periodic(cleanup)))
                elif role == "executor":

                    async def execute() -> None:
                        await execute_once(async_http, config["executor.secret"])

                    jobs.append(asyncio.create_task(periodic(execute)))
            if role in WRITERS:
                dsn_name = {"worker": "lifecycle", "delivery": "delivery"}.get(role, role) + ".dsn"

                async def deliver() -> None:
                    await deliver_once(
                        AccessStore(config[dsn_name]),
                        async_http,
                        WRITERS[role],
                        config["audit.secret"],
                    )

                jobs.append(asyncio.create_task(periodic(deliver)))
            try:
                cfg = uvicorn.Config(
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
                await ReadTLSServer(cfg).serve()
            finally:
                for job in jobs:
                    job.cancel()
                await asyncio.gather(*jobs, return_exceptions=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=tuple(PORTS))
    parser.add_argument("host_ip", type=destination)
    args = parser.parse_args()
    try:
        asyncio.run(serve(args.role, args.host_ip))
    except Exception:
        raise SystemExit("Workflow startup or runtime failed") from None


if __name__ == "__main__":
    main()
