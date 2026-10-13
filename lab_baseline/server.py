"""Three unauthenticated MCP servers; run only in the isolated baseline project."""

import argparse
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI
from mcp.server import MCPServer
from mcp.server.transport_security import TransportSecuritySettings

from lab_baseline.state import SERVICES, UnsafeState
from service_desk.fixtures import load_fixtures


def create_app(service: str, state: UnsafeState) -> FastAPI:
    mcp = MCPServer(f"unsafe-baseline-{service}", log_level="CRITICAL")

    def search_documents(query: str, limit: int = 5) -> dict[str, Any]:
        """Search the synthetic knowledge base."""
        return state.invoke("search_documents", {"query": query, "limit": limit})

    def read_document(document_id: str) -> dict[str, Any]:
        """Read a synthetic document by ID."""
        return state.invoke("read_document", {"document_id": document_id})

    def read_ticket(ticket_id: str) -> dict[str, Any]:
        """Read a synthetic ticket and its comments."""
        return state.invoke("read_ticket", {"ticket_id": ticket_id})

    def draft_response(
        ticket_id: str, source_ids: list[str], audience: str = "requester"
    ) -> dict[str, Any]:
        """Create a response draft from source documents; returns draft_id."""
        return state.invoke(
            "draft_response",
            {"ticket_id": ticket_id, "source_ids": source_ids, "audience": audience},
        )

    def add_comment(draft_id: str) -> dict[str, Any]:
        """Save a draft to its ticket using the draft's audience."""
        return state.invoke("add_comment", {"draft_id": draft_id})

    def check_access(target: str, resource: str) -> dict[str, Any]:
        """Check a synthetic principal's group membership."""
        return state.invoke("check_access", {"target": target, "resource": resource})

    def propose_access_change(
        target: str,
        resource: str,
        action: str = "grant",
        duration_seconds: int = 28800,
        source_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        """Create an access proposal; returns request_id."""
        return state.invoke(
            "propose_access_change",
            {
                "target": target,
                "resource": resource,
                "action": action,
                "duration_seconds": duration_seconds,
                "source_ids": source_ids or [],
            },
        )

    def execute_approved_change(request_id: str) -> dict[str, Any]:
        """Execute an access request in the synthetic directory."""
        return state.invoke("execute_approved_change", {"request_id": request_id})

    functions = locals()
    for name in SERVICES[service]:
        mcp.tool()(functions[name])
    transport = mcp.streamable_http_app(
        stateless_http=True,
        json_response=True,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=[f"{service}:8080", "127.0.0.1:*", "localhost:*", "testserver"],
        ),
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        async with transport.router.lifespan_context(transport):
            yield

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/_lab/snapshot")
    def snapshot() -> dict[str, Any]:
        return state.snapshot()

    @app.post("/_lab/reset")
    def reset() -> dict[str, bool]:
        state.reset()
        return {"reset": True}

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"service": service}

    app.mount("/", transport)
    return app


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("service", choices=SERVICES)
    args = parser.parse_args()
    state = UnsafeState(load_fixtures(Path("fixtures/company.json")))
    uvicorn.run(
        create_app(args.service, state),
        host="0.0.0.0",
        port=8080,
        access_log=False,
        log_level="critical",
    )


if __name__ == "__main__":
    main()
