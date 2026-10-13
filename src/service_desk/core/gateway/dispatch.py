"""Restricted MCP gateway. A reservation is charged before remote discovery or dispatch."""

import json
import time
from contextlib import suppress
from dataclasses import replace
from typing import Any
from uuid import UUID

import httpx
import psycopg

from service_desk.core.auth.oidc import LoginResult, OIDCClient
from service_desk.core.auth.tokens import AuthenticationDenied
from service_desk.core.gateway.registry import (
    BoundaryDenied,
    definition,
    validate_arguments,
    validate_catalog,
)
from service_desk.core.gateway.store import TaskStore
from service_desk.reads import denied


class ReadGateway:
    def __init__(self, oidc: OIDCClient, store: TaskStore, http: httpx.Client) -> None:
        self.oidc, self.store, self.http = oidc, store, http

    def call(
        self, login: LoginResult, task_id: UUID, name: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        attempt: UUID | None = None
        deadline = time.monotonic() + 10
        try:
            # Verify the original user token before reserving; preserve its signed identity.
            original = self.oidc.validator.access(login.access_token, "gateway")
            if original != login.identity:
                raise BoundaryDenied("TASK_DENIED")
            gateway_identity = replace(original, client_id="gateway")
            try:
                tool = definition(name)
                route = tool.service
            except BoundaryDenied:
                route = "gateway"
            attempt = self.store.reserve(gateway_identity, task_id, route, name, arguments)
            tool = definition(name)
            validate_arguments(name, arguments)
            binding = next((r for r in self.oidc.resources.values() if r.audience == route), None)
            if binding is None:
                raise BoundaryDenied("TOOL_DENIED")
            # Validate MCP resource metadata before exchanging or sending a bearer token.
            self.oidc.discover_resource(binding.url, deadline=deadline)
            token = self.oidc.exchange(login, binding.url)
            headers = {
                "Accept": "application/json, text/event-stream",
                "Accept-Encoding": "identity",
                "Authorization": "Bearer " + token,
                "X-Desk-Task": str(task_id),
                "X-Desk-Attempt": str(attempt),
            }

            def request(method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise BoundaryDenied("TIMEOUT")
                with self.http.stream(
                    "POST",
                    binding.url,
                    headers=headers,
                    timeout=remaining,
                    follow_redirects=False,
                    json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}},
                ) as response:
                    response.raise_for_status()
                    if response.headers.get("content-encoding", "identity") != "identity":
                        raise BoundaryDenied("OUTPUT_LIMIT")
                    body = bytearray()
                    for chunk in response.iter_bytes(chunk_size=4096):
                        if time.monotonic() >= deadline:
                            raise BoundaryDenied("TIMEOUT")
                        if len(body) + len(chunk) > 32768:
                            raise BoundaryDenied("OUTPUT_LIMIT")
                        body.extend(chunk)
                data: dict[str, Any] = json.loads(body)["result"]
                return data

            initialized = request(
                "initialize",
                {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "desk-gateway", "version": "1"},
                },
            )
            if initialized.get("protocolVersion") != "2025-11-25":
                raise BoundaryDenied("CATALOG_DENIED")
            listed = request("tools/list")
            if listed.get("nextCursor"):
                raise BoundaryDenied("CATALOG_DENIED")
            validate_catalog(route, listed["tools"])
            result = request("tools/call", {"name": name, "arguments": arguments})
            # Return only this authenticated, task-scoped tool result. No shared conversation/cache.
            return result
        except BoundaryDenied as error:
            reason = error.reason
        except AuthenticationDenied:
            reason = "SCOPE_DENIED"
        except (httpx.HTTPError, psycopg.Error, ValueError, TypeError, KeyError, AttributeError):
            reason = "SERVICE_ERROR"
        if attempt is not None:
            with suppress(psycopg.Error):
                self.store.finish(attempt, reason)
        return denied(reason)
