"""Admit raw sockets before starting TLS in the single-process loopback lab.

Use asyncio's TLS implementation, but explicitly accept and reserve capacity
before handing it an accepted socket. Never create an unbounded task per accept.
"""

import asyncio
import socket
from collections import deque
from contextlib import suppress
from functools import partial

import uvicorn

from service_desk.core.ingress import BoundedHTTPProtocol


class BoundedTLSServer(uvicorn.Server):
    BIND_HOST = "127.0.0.1"
    MAX_CONNECTIONS = 16
    MAX_HANDSHAKE_STARTS = 32
    START_WINDOW_SECONDS = 1.0
    HANDSHAKE_SECONDS = 5.0
    SHUTDOWN_SECONDS = 1.0
    BACKLOG = 16

    def __init__(self, config: uvicorn.Config) -> None:
        super().__init__(config)
        self.listener: socket.socket | None = None
        self.admitted: dict[socket.socket, BoundedHTTPProtocol] = {}
        self.handshakes: set[asyncio.Task[None]] = set()
        self._starts: deque[float] = deque()
        self._accept_task: asyncio.Task[None] | None = None

    async def startup(self, sockets: list[socket.socket] | None = None) -> None:
        config = self.config
        if (
            sockets is not None
            or config.host != self.BIND_HOST
            or config.fd is not None
            or config.uds is not None
            or config.workers != 1
            or not config.is_ssl
            or config.ssl is None
            or config.http is not BoundedHTTPProtocol
            or config.ws != "none"
            or config.proxy_headers
        ):
            raise ValueError("Unsupported TLS listener configuration")
        await self.lifespan.startup()
        if self.lifespan.should_exit:
            self.should_exit = True
            return
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            # Do not enable SO_REUSEADDR on Windows: another listener could share
            # the port. The trusted local process owns this listener exclusively.
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            listener.setblocking(False)
            listener.bind((config.host, config.port))
            listener.listen(self.BACKLOG)
        except BaseException:
            listener.close()
            await self.lifespan.shutdown()
            raise
        self.listener = listener
        # Uvicorn still manages application tasks and lifespan, but must not
        # create a second automatic acceptor that bypasses socket admission.
        self.servers = []
        self._accept_task = asyncio.create_task(self._accept())
        self.started = True

    def _can_admit(self, now: float) -> bool:
        while self._starts and self._starts[0] <= now - self.START_WINDOW_SECONDS:
            self._starts.popleft()
        return (
            len(self.admitted) < self.MAX_CONNECTIONS
            and len(self.server_state.tasks) < BoundedHTTPProtocol.MAX_CONNECTIONS
            and len(self._starts) < self.MAX_HANDSHAKE_STARTS
        )

    def _release(self, accepted: socket.socket) -> None:
        self.admitted.pop(accepted, None)

    async def _accept(self) -> None:
        assert self.listener is not None
        loop = asyncio.get_running_loop()
        try:
            while True:
                accepted, _ = await loop.sock_accept(self.listener)
                now = loop.time()
                if not self._can_admit(now):
                    # No TLS parsing, response, credentials or per-peer log.
                    accepted.close()
                else:
                    self._starts.append(now)
                    try:
                        protocol = BoundedHTTPProtocol(
                            self.config,
                            self.server_state,
                            self.lifespan.state,
                            on_disconnect=partial(self._release, accepted),
                        )
                        self.admitted[accepted] = protocol
                        task = asyncio.create_task(self._handshake(accepted, protocol))
                    except BaseException:
                        accepted.close()
                        self._release(accepted)
                        raise
                    self.handshakes.add(task)
                    task.add_done_callback(self.handshakes.discard)
                # A full OS accept queue must not starve deadline callbacks.
                await asyncio.sleep(0)
        except asyncio.CancelledError:
            raise
        except Exception:
            # Unexpected acceptor failure stops serving, without exception data.
            self.should_exit = True
            self.listener.close()

    async def _handshake(self, accepted: socket.socket, protocol: BoundedHTTPProtocol) -> None:
        connected = False
        try:
            # This transfers socket ownership to asyncio. Its TLS handshake and
            # close-notify deadlines are absolute, not reset by incoming bytes.
            await asyncio.get_running_loop().connect_accepted_socket(
                lambda: protocol,
                accepted,
                ssl=self.config.ssl,
                ssl_handshake_timeout=self.HANDSHAKE_SECONDS,
                ssl_shutdown_timeout=self.SHUTDOWN_SECONDS,
            )
            connected = True
        except (OSError, TimeoutError):
            pass
        except asyncio.CancelledError:
            raise
        except Exception:
            self.should_exit = True
            if self.listener is not None:
                self.listener.close()
        finally:
            if not connected:
                # Failed/cancelled connect_accepted_socket closes its transport;
                # no application connection_lost callback is guaranteed then.
                self.admitted.pop(accepted, None)

    async def shutdown(self, sockets: list[socket.socket] | None = None) -> None:
        if self.listener is not None:
            self.listener.close()
        if self._accept_task is not None:
            self._accept_task.cancel()
            with suppress(asyncio.CancelledError):
                await self._accept_task
        handshakes = tuple(self.handshakes)
        for task in handshakes:
            task.cancel()
        await asyncio.gather(*handshakes, return_exceptions=True)
        try:
            await super().shutdown(sockets)
        finally:
            for accepted, protocol in tuple(self.admitted.items()):
                if protocol.transport is None:
                    # Also covers a handshake task cancelled before it started.
                    accepted.close()
                    self.admitted.pop(accepted, None)
                else:
                    protocol.transport.abort()
