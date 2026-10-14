"""Bounded outbox delivery and executor polling, with no raw content in errors or logs."""

import asyncio
import json
from typing import Any
from uuid import UUID

import httpx

from service_desk.core.access import AccessStore
from service_desk.core.auth.lab import ISSUER
from service_desk.core.gateway.registry import canonical
from service_desk.mcp.execution import EXECUTION, execution_catalog


async def bounded_post(http: httpx.AsyncClient, url: str, **kwargs: Any) -> dict[str, Any]:
    async with asyncio.timeout(10), http.stream("POST", url, **kwargs) as response:
        if response.status_code != 200 or response.headers.get("content-encoding"):
            raise RuntimeError("Service unavailable")
        data = bytearray()
        async for part in response.aiter_raw():
            data.extend(part)
            if len(data) > 131072:
                raise RuntimeError("Service output exceeded limit")
        value = json.loads(data)
        if not isinstance(value, dict):
            raise ValueError("Invalid service response")
        return value


async def deliver_once(
    store: AccessStore, http: httpx.AsyncClient, writer: str, secret: str
) -> int:
    sent = 0
    async with asyncio.timeout(30):
        batch = await asyncio.to_thread(store.call, "audit_batch")
        for event in batch:
            result = await bounded_post(
                http,
                "https://127.0.0.1:19490/events/" + writer,
                json=event,
                headers={"X-Desk-Service": secret, "Accept-Encoding": "identity"},
            )
            if result != {"accepted": True}:
                raise RuntimeError("Collector rejected event")
            await asyncio.to_thread(store.call, "audit_ack", UUID(event["event_id"]))
            sent += 1
    return sent


async def execute_once(http: httpx.AsyncClient, secret: str) -> int:
    async with asyncio.timeout(90):
        token = await bounded_post(
            http,
            ISSUER + "/protocol/openid-connect/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "executor",
                "client_secret": secret,
            },
            headers={"Accept-Encoding": "identity"},
        )
        headers = {
            "Authorization": "Bearer " + token["access_token"],
            "Accept": "application/json, text/event-stream",
            "Accept-Encoding": "identity",
        }

        async def rpc(method: str, params: dict[str, Any]) -> dict[str, Any]:
            result = await bounded_post(
                http,
                EXECUTION.url,
                headers=headers,
                json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
            )
            data: dict[str, Any] = result["result"]
            return data

        initialized = await rpc(
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "desk-executor", "version": "1"},
            },
        )
        if initialized.get("protocolVersion") != "2025-11-25":
            raise RuntimeError("Protocol denied")
        listed = await rpc("tools/list", {})
        if listed.get("nextCursor") or canonical(
            sorted(listed["tools"], key=lambda t: t["name"])
        ) != canonical(sorted(execution_catalog(), key=lambda t: t["name"])):
            raise RuntimeError("Execution catalog denied")

        async def call(name: str, args: dict[str, Any]) -> dict[str, Any]:
            value = await rpc("tools/call", {"name": name, "arguments": args})
            if (
                value.get("isError")
                or len(value["content"]) != 1
                or value["content"][0]["type"] != "text"
            ):
                raise RuntimeError("Execution denied")
            result: dict[str, Any] = json.loads(value["content"][0]["text"])
            if result.get("reason") != "ALLOW":
                raise RuntimeError("Execution denied")
            return result

        queue = await call("pending_approved_changes", {})
        completed = 0
        for request in queue["requests"][:16]:
            await call("execute_approved_change", request)
            completed += 1
        return completed
