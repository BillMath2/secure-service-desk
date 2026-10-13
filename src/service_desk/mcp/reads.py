"""Authenticated read MCP transport, with admission before tool/schema dispatch."""

import asyncio
from typing import Any
from uuid import UUID

from mcp import types
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import AuthSettings
from mcp.server.context import ServerRequestContext
from mcp.server.lowlevel import Server
from pydantic import AnyHttpUrl
from starlette.applications import Starlette

from service_desk.core.auth.tokens import (
    AuthenticationDenied,
    MCPTokenVerifier,
    ResourceBinding,
    TokenValidator,
)
from service_desk.core.gateway.registry import canonical, catalog
from service_desk.reads import ReadService, denied


def create_read_mcp(
    validator: TokenValidator, binding: ResourceBinding, service: ReadService
) -> Starlette:
    if binding.audience != service.service:
        raise ValueError("Service and signed audience must agree")

    async def list_tools(
        ctx: ServerRequestContext[Any], params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        return types.ListToolsResult(
            tools=[types.Tool.model_validate(t) for t in catalog(service.service)]
        )

    async def call_tool(
        ctx: ServerRequestContext[Any], params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        token = get_access_token()
        try:
            if token is None or ctx.request is None:
                raise ValueError("Missing trusted request")
            if len(canonical(ctx.request_id).encode()) > 128:
                raise ValueError("Oversized protocol identifier")
            task_id = UUID(ctx.request.headers.get("x-desk-task", ""))
            attempt_header = ctx.request.headers.get("x-desk-attempt")
            attempt = UUID(attempt_header) if attempt_header else None
            # Identity comes solely from the validated bearer, never X-User or tool arguments.
            identity = await asyncio.to_thread(validator.access, token.token, binding.audience)
            result = await asyncio.to_thread(
                service.invoke, identity, task_id, params.name, params.arguments or {}, attempt
            )
        except (ValueError, AuthenticationDenied):
            result = denied("TASK_DENIED")
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=canonical(result))],
            is_error=not result["allowed"],
        )

    server: Server[Any] = Server(
        "desk-read-" + service.service,
        version="read-tools-v1",
        on_list_tools=list_tools,
        on_call_tool=call_tool,
    )
    return server.streamable_http_app(
        stateless_http=True,
        json_response=True,
        max_request_body_size=16384,
        token_verifier=MCPTokenVerifier(validator, binding),
        auth=AuthSettings(
            issuer_url=AnyHttpUrl(validator.issuer),
            resource_server_url=AnyHttpUrl(binding.url),
            required_scopes=[binding.scope],
            validate_token_resource=True,
        ),
    )
