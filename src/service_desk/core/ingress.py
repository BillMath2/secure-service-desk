"""Bounded, one-request HTTP ingress for the pinned single-process lab runtimes.

The deployment's BoundedTLSServer admits sockets before TLS reaches this protocol.
Buffer the complete bounded request before invoking authentication or application
code. Uvicorn's concurrency option alone does not bound partial HTTP headers.
"""

import asyncio
from collections.abc import Callable
from typing import Any

import h11
from uvicorn import Config
from uvicorn.protocols.http.h11_impl import H11Protocol
from uvicorn.server import ServerState


class BoundedHTTPProtocol(H11Protocol):
    MAX_CONNECTIONS = 16
    MAX_HEADERS = 16384
    MAX_BODY = 16384
    MAX_WIRE = 32768
    INPUT_SECONDS = 5.0
    CONNECTION_SECONDS = 125.0

    def __init__(
        self,
        config: Config,
        server_state: ServerState,
        app_state: dict[str, Any],
        _loop: asyncio.AbstractEventLoop | None = None,
        *,
        on_disconnect: Callable[[], None] | None = None,
    ) -> None:
        super().__init__(config, server_state, app_state, _loop)
        self._parser = h11.Connection(h11.SERVER, max_incomplete_event_size=self.MAX_HEADERS)
        self._pending = bytearray()
        self._body_size = 0
        self._headers_complete = False
        self._dispatched = False
        self._rejected = False
        self._input_timer: asyncio.TimerHandle | None = None
        self._connection_timer: asyncio.TimerHandle | None = None
        self._on_disconnect = on_disconnect

    def connection_made(self, transport: asyncio.Transport) -> None:  # type: ignore[override]
        saturated = (
            len(self.connections) >= self.MAX_CONNECTIONS or len(self.tasks) >= self.MAX_CONNECTIONS
        )
        super().connection_made(transport)
        if saturated:
            self._reject(503)
            return
        self._input_timer = self.loop.call_later(self.INPUT_SECONDS, self._expire)
        self._connection_timer = self.loop.call_later(self.CONNECTION_SECONDS, self._expire)

    def _expire(self) -> None:
        self._rejected = True
        self._pending.clear()
        self.transport.abort()

    def _reject(self, status: int) -> None:
        self._rejected = True
        self._pending.clear()
        # Never reflect request bytes, paths, credentials or parser exceptions.
        self.transport.write(
            f"HTTP/1.1 {status} Rejected\r\nContent-Length: 0\r\n"
            "Connection: close\r\nCache-Control: no-store\r\n\r\n".encode("ascii")
        )
        self.transport.close()

    def data_received(self, data: bytes) -> None:
        if self._rejected:
            return
        if self._dispatched:
            # No keep-alive, pipelined second action or protocol upgrade.
            self._expire()
            return
        if len(self._pending) + len(data) > self.MAX_WIRE:
            self._reject(413)
            return
        self._pending.extend(data)
        if not self._headers_complete:
            end = self._pending.find(b"\r\n\r\n")
            if (end < 0 and len(self._pending) > self.MAX_HEADERS) or (
                end >= 0 and end + 4 > self.MAX_HEADERS
            ):
                self._reject(431)
                return
            self._headers_complete = end >= 0
        try:
            self._parser.receive_data(data)
            while True:
                event = self._parser.next_event()
                if event is h11.NEED_DATA:
                    return
                if isinstance(event, h11.Request):
                    for name, value in event.headers:
                        if name in (b"upgrade", b"expect", b"content-encoding"):
                            self._reject(400)
                            return
                        if name == b"content-length" and int(value) > self.MAX_BODY:
                            self._reject(413)
                            return
                elif isinstance(event, h11.Data):
                    self._body_size += len(event.data)
                    if self._body_size > self.MAX_BODY:
                        self._reject(413)
                        return
                elif isinstance(event, h11.EndOfMessage):
                    if self._parser.trailing_data[0]:
                        self._reject(400)
                        return
                    # Pending sockets may have been admitted before other work
                    # became detached from its connection. Recheck at dispatch.
                    if len(self.tasks) >= self.MAX_CONNECTIONS:
                        self._reject(503)
                        return
                    self._dispatched = True
                    if self._input_timer is not None:
                        self._input_timer.cancel()
                    request = bytes(self._pending)
                    self._pending.clear()
                    super().data_received(request)
                    return
                else:
                    self._reject(400)
                    return
        except (h11.RemoteProtocolError, ValueError):
            self._reject(400)

    def on_response_complete(self) -> None:
        self.server_state.total_requests += 1
        self.transport.close()

    def connection_lost(self, exc: Exception | None) -> None:
        for timer in (self._input_timer, self._connection_timer):
            if timer is not None:
                timer.cancel()
        self._pending.clear()
        try:
            super().connection_lost(exc)
        finally:
            if self._on_disconnect is not None:
                self._on_disconnect()
                self._on_disconnect = None
