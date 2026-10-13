"""Run the authenticated read-only assistant with a stub or verified local model."""

import argparse
import asyncio
import ssl

import httpx
import uvicorn
from check_model_boundary import check_boundary
from phase2_runtime import LOCAL, ROOT, load_client, server_config

from service_desk.agent.local_model import LocalModelProvider
from service_desk.agent.loop import Assistant
from service_desk.agent.provider import DeterministicProvider, Provider
from service_desk.agent.store import AgentStore
from service_desk.app.identity import create_identity_app
from service_desk.core.gateway.dispatch import ReadGateway
from service_desk.core.gateway.store import TaskStore


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", choices=("stub", "local"), default="stub")
    parser.add_argument("--docker", help="Docker executable for local-model containment checks")
    args = parser.parse_args()
    provider: Provider = DeterministicProvider()
    label = "Deterministic demo: reads your ticket and the public support guide."
    if args.provider == "local":
        check_boundary(args.docker)
        local = LocalModelProvider()
        asyncio.run(local.prepare())
        provider = local
        label = "Local Qwen3 model: answers may be incomplete; check the cited sources."
    trust = ssl.create_default_context(cafile=str(LOCAL / "tls/certificate.pem"))
    with httpx.Client(verify=trust, trust_env=False, timeout=10, follow_redirects=False) as http:
        oidc = load_client(http, trust)
        oidc.check_discovery()
        store = AgentStore((ROOT / ".lab/phase2-read/creator.dsn").read_text())
        gateway = ReadGateway(
            oidc, TaskStore((ROOT / ".lab/phase2-read/gateway.dsn").read_text()), http
        )
        assistant = Assistant(oidc.validator, store, gateway, provider, provider_label=label)
        app = create_identity_app(oidc, assistant=assistant)
        uvicorn.Server(server_config(app, 19481)).run()


if __name__ == "__main__":
    main()
