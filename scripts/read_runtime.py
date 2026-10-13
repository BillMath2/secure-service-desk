"""Serve an authenticated read MCP endpoint against the prepared disposable read database."""

import argparse
import ssl
from urllib.parse import urlsplit

import uvicorn
from phase2_runtime import LOCAL, ROOT, load_validator, server_config

from service_desk.core.auth.lab import RESOURCES
from service_desk.core.gateway.store import TaskStore
from service_desk.mcp.reads import create_read_mcp
from service_desk.reads import ReadService


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("service", choices=("knowledge", "tickets"))
    args = parser.parse_args()
    dsn = (ROOT / ".lab/phase2-read" / (args.service + ".dsn")).read_text()
    trust = ssl.create_default_context(cafile=str(LOCAL / "tls/certificate.pem"))
    binding = next(r for r in RESOURCES if r.audience == args.service)
    app = create_read_mcp(
        load_validator(trust),
        binding,
        ReadService(args.service, TaskStore(dsn)),
    )
    uvicorn.Server(server_config(app, urlsplit(binding.url).port)).run()


if __name__ == "__main__":
    main()
