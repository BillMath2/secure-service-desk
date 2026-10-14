"""Privileged MCP has a distinct signed audience and client, never in the model catalog."""

import asyncio
from typing import Annotated, Any
from uuid import UUID

import jwt
import psycopg
from mcp import types
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import AuthSettings
from mcp.server.context import ServerRequestContext
from mcp.server.lowlevel import Server
from pydantic import AnyHttpUrl, Field, ValidationError
from starlette.applications import Starlette

from service_desk.contracts import Contract
from service_desk.core.access import AccessStore
from service_desk.core.auth.tokens import (
    AuthenticationDenied,
    MCPTokenVerifier,
    ResourceBinding,
    TokenValidator,
    VerifiedIdentity,
)
from service_desk.core.gateway.registry import BoundaryDenied, canonical

EXECUTION = ResourceBinding("execution", "https://127.0.0.1:19489/mcp", "access:execute")


class WorkloadValidator(TokenValidator):
    def access(self, token: str, audience: str) -> VerifiedIdentity:
        try:
            if len(token) > 16384 or audience != EXECUTION.audience or self.client_id != "executor":
                raise AuthenticationDenied()
            # This only obtains a candidate subject. The second pass verifies signature,
            # issuer, exact client/audience, lifetime and scope before assigning workload authority.
            subject = jwt.decode(token, options={"verify_signature": False})["sub"]
            if not isinstance(subject, str) or not subject:
                raise AuthenticationDenied()
            validator = TokenValidator(
                self.issuer, self.keys, {(self.issuer, subject): "executor"}, "executor"
            )
            who = validator.access(token, audience)
            if EXECUTION.scope not in who.scopes:
                raise AuthenticationDenied()
            return who
        except (jwt.PyJWTError, KeyError, ValueError, TypeError):
            raise AuthenticationDenied() from None


class ExecuteInput(Contract):
    request_id: UUID
    action_hash: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]


class PendingInput(Contract):
    pass


def execution_catalog() -> list[dict[str, Any]]:
    return [
        {
            "name": name,
            "description": description,
            "inputSchema": schema.model_json_schema(),
            "annotations": {
                "readOnlyHint": name == "pending_approved_changes",
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False,
            },
        }
        for name, description, schema in (
            (
                "pending_approved_changes",
                "List a bounded batch of currently approved immutable requests.",
                PendingInput,
            ),
            (
                "execute_approved_change",
                "Consume current approval and apply its exact stored grant once.",
                ExecuteInput,
            ),
        )
    ]


def create_execution_mcp(validator: WorkloadValidator, store: AccessStore) -> Starlette:
    async def listed(
        ctx: ServerRequestContext[Any], params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        return types.ListToolsResult(
            tools=[types.Tool.model_validate(t) for t in execution_catalog()]
        )

    async def called(
        ctx: ServerRequestContext[Any], params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        try:
            token = get_access_token()
            if token is None:
                raise AuthenticationDenied()
            who = await asyncio.to_thread(validator.access, token.token, EXECUTION.audience)
            if params.name == "execute_approved_change":
                value = ExecuteInput.model_validate_json(
                    canonical(params.arguments or {}), strict=True
                )
                result = await asyncio.to_thread(
                    store.execute, value.request_id, value.action_hash, who
                )
            elif params.name == "pending_approved_changes":
                PendingInput.model_validate(params.arguments or {}, strict=True)
                result = {
                    "reason": "ALLOW",
                    "requests": await asyncio.to_thread(store.call, "access_queue"),
                }
            else:
                raise BoundaryDenied("TOOL_DENIED")
        except (AuthenticationDenied, ValidationError, ValueError, psycopg.Error, BoundaryDenied):
            result = {"reason": "EXECUTION_DENIED"}
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=canonical(result))],
            is_error=result["reason"] != "ALLOW",
        )

    server: Server[Any] = Server(
        "desk-access-execution",
        version="access-execution-v1",
        on_list_tools=listed,
        on_call_tool=called,
    )
    return server.streamable_http_app(
        stateless_http=True,
        json_response=True,
        max_request_body_size=8192,
        token_verifier=MCPTokenVerifier(validator, EXECUTION),
        auth=AuthSettings(
            issuer_url=AnyHttpUrl(validator.issuer),
            resource_server_url=AnyHttpUrl(EXECUTION.url),
            required_scopes=[EXECUTION.scope],
            validate_token_resource=True,
        ),
    )
