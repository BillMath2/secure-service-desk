"""Real sockets prove incomplete input never invokes the browser/MCP application."""

import asyncio
import ssl
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager, suppress
from pathlib import Path

import httpx
import pytest
import uvicorn
from starlette.applications import Starlette
from test_phase2_identity import IDENTITIES, ISSUER, RESOURCES, RotatingKeys
from uvicorn._types import ASGIReceiveCallable, ASGISendCallable, Scope

from scripts.phase2_runtime import server_config
from service_desk.core.auth.tokens import TokenValidator
from service_desk.core.ingress import BoundedHTTPProtocol
from service_desk.core.tls_ingress import BoundedTLSServer
from service_desk.mcp.identity import create_identity_mcp


@asynccontextmanager
async def running(
    *,
    blocked: asyncio.Event | None = None,
    tls: Path | None = None,
    target: Starlette | None = None,
) -> AsyncIterator[tuple[int, list[bytes], uvicorn.Server]]:
    seen: list[bytes] = []

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        body = bytearray()
        while True:
            message = await receive()
            assert message["type"] == "http.request"
            body.extend(message["body"])
            if not message["more_body"]:
                break
        seen.append(bytes(body))
        if blocked is not None:
            await blocked.wait()
        await send(
            {"type": "http.response.start", "status": 200, "headers": [(b"content-length", b"2")]}
        )
        await send({"type": "http.response.body", "body": b"OK"})

    config = server_config(app if target is None else target, 0)
    config.lifespan = "off" if target is None else "on"
    config.ssl_certfile = str(tls / "certificate.pem") if tls else None
    config.ssl_keyfile = str(tls / "private.key") if tls else None
    config.load()
    server = BoundedTLSServer(config) if tls else uvicorn.Server(config)
    server.lifespan = config.lifespan_class(config)
    await server.startup()
    await server.on_tick(0)
    try:
        if isinstance(server, BoundedTLSServer):
            assert server.listener is not None
            port = server.listener.getsockname()[1]
        else:
            port = server.servers[0].sockets[0].getsockname()[1]
        yield port, seen, server
    finally:
        if blocked is not None:
            blocked.set()
        for connection in tuple(server.server_state.connections):
            connection.transport.abort()
        await server.shutdown()


async def until(predicate: Callable[[], bool]) -> None:
    async with asyncio.timeout(2):
        while not predicate():
            await asyncio.sleep(0.005)


async def request(port: int, wire: bytes, *, allow_reset: bool = False) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        try:
            writer.write(wire)
            await writer.drain()
            return await asyncio.wait_for(reader.read(), 2)
        except ConnectionResetError:
            if not allow_reset:
                raise
            return b""
    finally:
        writer.close()
        with suppress(OSError):
            await writer.wait_closed()


GET = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"


@pytest.mark.parametrize(
    "wire,body",
    [
        (GET, b""),
        (b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\ntest", b"test"),
        (
            b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"4\r\ntest\r\n0\r\n\r\n",
            b"test",
        ),
    ],
)
def test_complete_request_reaches_application_once(wire: bytes, body: bytes) -> None:
    async def run() -> None:
        async with running() as (port, seen, _):
            response = await request(port, wire)
            assert response.startswith(b"HTTP/1.1 200")
            assert b"connection: close" in response.lower()
            assert response.endswith(b"OK")
            assert seen == [body]

    asyncio.run(run())


def test_shared_runtime_over_verified_tls(tls_files: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    trust = ssl.create_default_context(cafile=str(tls_files / "certificate.pem"))
    monkeypatch.setattr(BoundedHTTPProtocol, "INPUT_SECONDS", 0.2)

    async def run() -> None:
        async with running(tls=tls_files) as (port, seen, server):
            for wire in (b"GET / HTTP/1.1\r\n", GET):
                reader, writer = await asyncio.open_connection("127.0.0.1", port, ssl=trust)
                try:
                    writer.write(wire)
                    await writer.drain()
                    response = await asyncio.wait_for(reader.read(), 2)
                    if wire == GET:
                        assert response.startswith(b"HTTP/1.1 200")
                        assert response.endswith(b"OK")
                        assert seen == [b""]
                    else:
                        assert response == b""
                        assert seen == []
                finally:
                    writer.close()
                    with suppress(OSError):
                        await writer.wait_closed()
                await until(lambda: not server.server_state.connections)

    asyncio.run(run())


@pytest.mark.parametrize(
    "wire,status",
    [
        (GET + GET, 400),
        (b"GET / HTTP/1.1\r\nHost: localhost\r\nX: " + b"a" * 16384 + b"\r\n\r\n", 431),
        (b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 16385\r\n\r\n", 413),
        (
            b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"4001\r\n" + b"a" * 16385 + b"\r\n0\r\n\r\n",
            413,
        ),
        (b"GET / HTTP/1.1\r\nHost: localhost\r\nExpect: 100-continue\r\n\r\n", 400),
        (b"GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n\r\n", 400),
        (b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Encoding: gzip\r\n\r\n", 400),
        (
            b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\n"
            b"Content-Length: 2\r\n\r\nx",
            400,
        ),
    ],
)
def test_bad_input_never_reaches_application(wire: bytes, status: int) -> None:
    async def run() -> None:
        async with running() as (port, seen, _):
            response = await request(port, wire)
            assert response.startswith(f"HTTP/1.1 {status}".encode())
            assert response.endswith(b"\r\n\r\n")
            assert seen == []
            assert (await request(port, GET)).endswith(b"OK")

    asyncio.run(run())


@pytest.mark.parametrize(
    "partial",
    [b"", b"GET / HTTP/1.1\r\nX: ", b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 99\r\n\r\n"],
)
def test_absolute_input_deadline_and_capacity_recovery(
    monkeypatch: pytest.MonkeyPatch, partial: bytes
) -> None:
    monkeypatch.setattr(BoundedHTTPProtocol, "INPUT_SECONDS", 0.3)
    monkeypatch.setattr(BoundedHTTPProtocol, "MAX_CONNECTIONS", 2)

    async def run() -> None:
        async with running() as (port, seen, server):
            streams = [await asyncio.open_connection("127.0.0.1", port) for _ in range(2)]
            try:
                for _, writer in streams:
                    writer.write(partial)
                    await writer.drain()
                await until(lambda: len(server.server_state.connections) == 2)
                rejected = await request(port, GET, allow_reset=True)
                assert rejected == b"" or rejected.startswith(b"HTTP/1.1 503")
                for _ in range(4):
                    await asyncio.sleep(0.05)
                    for _, writer in streams:
                        writer.write(b"x")
                        await writer.drain()
                for reader, _ in streams:
                    with suppress(ConnectionResetError):
                        assert await asyncio.wait_for(reader.read(), 1) == b""
                assert seen == []
                await until(lambda: not server.server_state.connections)
                assert (await request(port, GET)).endswith(b"OK")
            finally:
                for _, writer in streams:
                    writer.close()
                    with suppress(OSError):
                        await writer.wait_closed()

    asyncio.run(run())


def test_disconnected_inflight_work_still_consumes_capacity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(BoundedHTTPProtocol, "MAX_CONNECTIONS", 1)
    monkeypatch.setattr(BoundedHTTPProtocol, "CONNECTION_SECONDS", 0.2)

    async def run() -> None:
        release = asyncio.Event()
        async with running(blocked=release) as (port, seen, server):
            assert await request(port, GET, allow_reset=True) == b""
            assert seen == [b""]
            await until(lambda: not server.server_state.connections)
            assert len(server.server_state.tasks) == 1
            rejected = await request(port, GET, allow_reset=True)
            assert rejected == b"" or rejected.startswith(b"HTTP/1.1 503")
            assert seen == [b""]
            release.set()
            await until(lambda: not server.server_state.tasks)
            assert (await request(port, GET)).endswith(b"OK")

    asyncio.run(run())


def test_pending_socket_rechecks_inflight_capacity(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(BoundedHTTPProtocol, "MAX_CONNECTIONS", 2)

    async def run() -> None:
        release = asyncio.Event()
        async with running(blocked=release) as (port, seen, server):
            streams = []
            try:
                # One running task loses its socket, then two sockets are accepted.
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                streams.append((reader, writer))
                writer.write(GET)
                await writer.drain()
                await until(lambda: len(seen) == 1)
                writer.close()
                await writer.wait_closed()
                await until(lambda: not server.server_state.connections)
                for _ in range(2):
                    streams.append(await asyncio.open_connection("127.0.0.1", port))
                streams[1][1].write(GET)
                await streams[1][1].drain()
                await until(lambda: len(seen) == 2)
                streams[2][1].write(GET)
                await streams[2][1].drain()
                assert (await asyncio.wait_for(streams[2][0].read(), 2)).startswith(b"HTTP/1.1 503")
                assert len(seen) == 2
                assert len(server.server_state.tasks) == 2
            finally:
                release.set()
                for _, writer in streams:
                    writer.close()
                    with suppress(OSError):
                        await writer.wait_closed()

    asyncio.run(run())


def test_real_mcp_authentication_and_successive_requests() -> None:
    keys = RotatingKeys()
    app = create_identity_mcp(TokenValidator(ISSUER, keys, IDENTITIES), RESOURCES[0])

    async def run() -> None:
        async with (
            running(target=app) as (port, _, _),
            httpx.AsyncClient(
                base_url=f"http://127.0.0.1:{port}", trust_env=False, timeout=2
            ) as client,
        ):
            headers = {"Accept": "application/json, text/event-stream"}
            message = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
            assert (await client.post("/mcp", json=message, headers=headers)).status_code == 401
            headers["Authorization"] = "Bearer " + keys.sign()
            response = await client.post("/mcp", json=message, headers=headers)
            assert response.status_code == 200
            assert response.headers["connection"] == "close"
            assert response.json()["result"]["tools"][0]["name"] == "identity_status"
            result = await client.post(
                "/mcp",
                headers=headers,
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "identity_status", "arguments": {}},
                },
            )
            assert result.status_code == 200
            assert result.json()["result"]["structuredContent"] == {
                "subject": "subject-erin",
                "client_id": "gateway",
            }

    asyncio.run(run())
