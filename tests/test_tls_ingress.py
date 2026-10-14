"""Real TCP/TLS clients exercise admission before any HTTP/application work."""

import asyncio
import ssl
from contextlib import suppress
from pathlib import Path

import httpx
import pytest
from test_http_ingress import GET, running, until
from test_phase2_identity import IDENTITIES, ISSUER, RESOURCES, RotatingKeys

from scripts.phase2_runtime import create_server, server_config
from service_desk.core.auth.tokens import TokenValidator
from service_desk.core.ingress import BoundedHTTPProtocol
from service_desk.core.tls_ingress import BoundedTLSServer
from service_desk.mcp.identity import create_identity_mcp


def trust(files: Path) -> ssl.SSLContext:
    return ssl.create_default_context(cafile=str(files / "certificate.pem"))


async def close(writer: asyncio.StreamWriter) -> None:
    writer.close()
    with suppress(OSError):
        await writer.wait_closed()


async def closed(reader: asyncio.StreamReader, timeout: float = 2) -> None:
    with suppress(ConnectionResetError):
        assert await asyncio.wait_for(reader.read(), timeout) == b""


async def good_request(port: int, files: Path) -> None:
    reader, writer = await asyncio.open_connection("127.0.0.1", port, ssl=trust(files))
    try:
        writer.write(GET)
        await writer.drain()
        result = await asyncio.wait_for(reader.read(), 2)
        assert result.startswith(b"HTTP/1.1 200")
        assert result.endswith(b"OK")
    finally:
        await close(writer)


def test_default_capacity_and_handshake_deadline(tls_files: Path) -> None:
    async def run() -> None:
        async with running(tls=tls_files) as (port, seen, server):
            assert isinstance(server, BoundedTLSServer)
            clients = []
            start = asyncio.get_running_loop().time()
            try:
                for _ in range(16):
                    clients.append(await asyncio.open_connection("127.0.0.1", port))
                await until(lambda: len(server.admitted) == 16)
                assert len(server.handshakes) == 16
                assert not server.server_state.connections and not seen
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                try:
                    await closed(reader)
                finally:
                    await close(writer)
                assert len(server.admitted) == 16
                assert len(server._starts) == 16
                await asyncio.gather(*(closed(reader, 7) for reader, _ in clients))
                elapsed = asyncio.get_running_loop().time() - start
                assert 4.5 <= elapsed < 7
                await until(lambda: not server.admitted and not server.handshakes)
                assert not seen
                await good_request(port, tls_files)
                assert seen == [b""]
            finally:
                for _, writer in clients:
                    await close(writer)

    asyncio.run(run())


@pytest.mark.parametrize("partial", [b"", b"\x16\x03\x03\x00\x40"])
def test_trickle_does_not_extend_handshake(
    tls_files: Path, monkeypatch: pytest.MonkeyPatch, partial: bytes
) -> None:
    monkeypatch.setattr(BoundedTLSServer, "HANDSHAKE_SECONDS", 0.3)

    async def run() -> None:
        async with running(tls=tls_files) as (port, seen, server):
            assert isinstance(server, BoundedTLSServer)
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            try:
                writer.write(partial)
                await writer.drain()
                for _ in range(4):
                    await asyncio.sleep(0.05)
                    if partial:
                        writer.write(b"x")
                        await writer.drain()
                await closed(reader, 0.3)
                await until(lambda: not server.admitted and not server.handshakes)
                assert not server.server_state.connections and not seen
                await good_request(port, tls_files)
            finally:
                await close(writer)

    asyncio.run(run())


def test_tls_and_http_share_capacity(tls_files: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(BoundedTLSServer, "MAX_CONNECTIONS", 2)

    async def run() -> None:
        async with running(tls=tls_files) as (port, seen, server):
            assert isinstance(server, BoundedTLSServer)
            raw_reader, raw_writer = await asyncio.open_connection("127.0.0.1", port)
            _, tls_writer = await asyncio.open_connection("127.0.0.1", port, ssl=trust(tls_files))
            try:
                await until(lambda: len(server.server_state.connections) == 1)
                assert len(server.admitted) == 2
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                try:
                    await closed(reader)
                finally:
                    await close(writer)
                assert not seen
                await close(tls_writer)
                await until(lambda: len(server.admitted) == 1)
                await good_request(port, tls_files)
                assert seen == [b""]
            finally:
                await close(raw_writer)
                await close(tls_writer)
            await closed(raw_reader)

    asyncio.run(run())


@pytest.mark.parametrize("bad_tls", [False, True])
def test_rolling_handshake_starts_cannot_be_reset_by_reconnect(
    tls_files: Path, monkeypatch: pytest.MonkeyPatch, bad_tls: bool
) -> None:
    monkeypatch.setattr(BoundedTLSServer, "MAX_HANDSHAKE_STARTS", 2)

    async def run() -> None:
        async with running(tls=tls_files) as (port, seen, server):
            assert isinstance(server, BoundedTLSServer)
            for _ in range(2):
                if bad_tls:
                    reader, writer = await asyncio.open_connection("127.0.0.1", port)
                    writer.write(b"invalid plaintext credential=synthetic-secret\r\n")
                    await writer.drain()
                    await closed(reader)
                    await close(writer)
                else:
                    await good_request(port, tls_files)
                await until(lambda: not server.admitted and not server.handshakes)
            assert len(server._starts) == 2
            assert len(seen) == (0 if bad_tls else 2)
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            try:
                await closed(reader)
                assert not server.admitted and not server.handshakes
                assert len(server._starts) == 2
            finally:
                await close(writer)
            remaining = server._starts[-1] + 1.01 - asyncio.get_running_loop().time()
            await asyncio.sleep(max(0, remaining))
            await good_request(port, tls_files)

    asyncio.run(run())


def test_shutdown_cleans_up_incomplete_handshakes(tls_files: Path) -> None:
    async def run() -> None:
        clients = []
        async with running(tls=tls_files) as (port, seen, server):
            assert isinstance(server, BoundedTLSServer)
            for _ in range(3):
                clients.append(await asyncio.open_connection("127.0.0.1", port))
            await until(lambda: len(server.handshakes) == 3)
            assert not seen
        assert server.listener is not None and server.listener.fileno() == -1
        assert not server.admitted and not server.handshakes
        for reader, writer in clients:
            await closed(reader)
            await close(writer)

    asyncio.run(run())


def test_detached_work_blocks_new_tls_handshakes(
    tls_files: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(BoundedHTTPProtocol, "MAX_CONNECTIONS", 1)
    monkeypatch.setattr(BoundedHTTPProtocol, "CONNECTION_SECONDS", 0.2)

    async def run() -> None:
        release = asyncio.Event()
        async with running(tls=tls_files, blocked=release) as (port, seen, server):
            assert isinstance(server, BoundedTLSServer)
            reader, writer = await asyncio.open_connection("127.0.0.1", port, ssl=trust(tls_files))
            writer.write(GET)
            await writer.drain()
            await closed(reader)
            await close(writer)
            await until(lambda: not server.admitted)
            assert seen == [b""] and len(server.server_state.tasks) == 1
            assert len(server._starts) == 1
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            await closed(reader)
            await close(writer)
            assert len(server._starts) == 1  # No TLS work started on the rejected socket.
            release.set()
            await until(lambda: not server.server_state.tasks)
            await good_request(port, tls_files)

    asyncio.run(run())


def test_peer_cannot_hold_capacity_by_withholding_tls_close_notify(tls_files: Path) -> None:
    async def run() -> None:
        async with running(tls=tls_files) as (port, seen, server):
            assert isinstance(server, BoundedTLSServer)
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
            client = trust(tls_files).wrap_bio(
                incoming, outgoing, server_side=False, server_hostname="127.0.0.1"
            )
            try:
                async with asyncio.timeout(2):
                    while True:
                        try:
                            client.do_handshake()
                            break
                        except ssl.SSLWantReadError:
                            writer.write(outgoing.read())
                            await writer.drain()
                            packet = await reader.read(65536)
                            assert packet
                            incoming.write(packet)
                client.write(GET)
                writer.write(outgoing.read())
                await writer.drain()
                await until(lambda: len(seen) == 1)
                assert len(server.admitted) == 1
                started = asyncio.get_running_loop().time()
                # Read encrypted output, but deliberately never reply to the
                # server's close_notify with SSLObject.unwrap().
                assert await asyncio.wait_for(reader.read(), 2.5)
                assert 0.7 < asyncio.get_running_loop().time() - started < 2.5
                await until(lambda: not server.admitted)
                await good_request(port, tls_files)
            finally:
                await close(writer)

    asyncio.run(run())


@pytest.mark.parametrize(
    "change", ["plaintext", "workers", "host", "proxy", "websocket", "protocol"]
)
def test_tls_startup_rejects_unsupported_configuration(tls_files: Path, change: str) -> None:
    app = create_identity_mcp(TokenValidator(ISSUER, RotatingKeys(), IDENTITIES), RESOURCES[0])
    config = server_config(app, 0)
    config.ssl_certfile = str(tls_files / "certificate.pem")
    config.ssl_keyfile = str(tls_files / "private.key")
    if change == "plaintext":
        config.ssl_certfile = config.ssl_keyfile = None
    elif change == "workers":
        config.workers = 2
    elif change == "host":
        config.host = "0.0.0.0"
    elif change == "proxy":
        config.proxy_headers = True
    elif change == "websocket":
        config.ws = "auto"
    else:
        config.http = "h11"
    config.load()
    server = BoundedTLSServer(config)
    server.lifespan = config.lifespan_class(config)
    with pytest.raises(ValueError, match="Unsupported TLS listener configuration"):
        asyncio.run(server.startup())
    assert server.listener is None and not server.started
    assert isinstance(create_server(app, 0), BoundedTLSServer)


def test_authenticated_mcp_still_works_over_bounded_tls(tls_files: Path) -> None:
    keys = RotatingKeys()
    app = create_identity_mcp(TokenValidator(ISSUER, keys, IDENTITIES), RESOURCES[0])

    async def run() -> None:
        async with (
            running(tls=tls_files, target=app) as (port, _, _),
            httpx.AsyncClient(
                base_url=f"https://127.0.0.1:{port}",
                verify=trust(tls_files),
                trust_env=False,
                timeout=2,
            ) as client,
        ):
            message = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
            headers = {"Accept": "application/json, text/event-stream"}
            assert (await client.post("/mcp", json=message, headers=headers)).status_code == 401
            headers["Authorization"] = "Bearer " + keys.sign()
            result = await client.post("/mcp", json=message, headers=headers)
            assert result.status_code == 200
            assert result.headers["connection"] == "close"
            assert result.json()["result"]["tools"][0]["name"] == "identity_status"

    asyncio.run(run())


def test_runtime_factory_serves_and_shuts_down_through_uvicorn_lifecycle(tls_files: Path) -> None:
    app = create_identity_mcp(TokenValidator(ISSUER, RotatingKeys(), IDENTITIES), RESOURCES[0])
    server = create_server(app, 0)
    server.config.ssl_certfile = str(tls_files / "certificate.pem")
    server.config.ssl_keyfile = str(tls_files / "private.key")

    async def run() -> None:
        task = asyncio.create_task(server.serve())
        try:
            await until(lambda: server.started or task.done())
            assert server.started and server.listener is not None
            port = server.listener.getsockname()[1]
            async with httpx.AsyncClient(
                verify=trust(tls_files), trust_env=False, timeout=2
            ) as client:
                response = await client.get(
                    f"https://127.0.0.1:{port}/.well-known/oauth-protected-resource/mcp"
                )
                assert response.status_code == 200
                assert response.json()["resource"] == RESOURCES[0].url
        finally:
            server.should_exit = True
            await asyncio.wait_for(task, 2)
        assert server.listener is not None and server.listener.fileno() == -1
        assert not server.handshakes and not server.admitted

    asyncio.run(run())
