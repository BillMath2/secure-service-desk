"""Bounded local model ingress; fixed routes, deadlines, no credentials or content logging."""

import http.client
import ipaddress
import socket
import sys
import threading
import time
from contextlib import suppress
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

LIMIT = 65536
INPUT_TIMEOUT = 5.0
UPSTREAM_TIMEOUT = 45.0
MAX_CONNECTIONS = 2


class Deadline:
    """Close both sides at an absolute deadline, including continuously trickled bytes."""

    def __init__(self, incoming: socket.socket) -> None:
        self.lock = threading.Lock()
        self.sockets = [incoming]
        self.expired = False
        self.expires_at = float("inf")
        self.generation = 0
        self.timer: threading.Timer | None = None
        self.reset(INPUT_TIMEOUT)

    def reset(self, seconds: float) -> None:
        with self.lock:
            if self.overdue():
                raise TimeoutError()
            self.expires_at = time.monotonic() + seconds
            self.generation += 1
            if self.timer:
                self.timer.cancel()
            self.timer = threading.Timer(seconds, self.expire, (self.generation,))
            self.timer.daemon = True
            self.timer.start()

    def overdue(self) -> bool:
        return self.expired or time.monotonic() >= self.expires_at

    def track(self, connection: socket.socket) -> None:
        with self.lock:
            if self.overdue():
                connection.close()
                raise TimeoutError()
            self.sockets.append(connection)

    def expire(self, generation: int) -> None:
        with self.lock:
            if generation != self.generation:
                return
            self.expired = True
            for connection in self.sockets:
                with suppress(OSError):
                    connection.shutdown(socket.SHUT_RDWR)

    def close(self) -> None:
        with self.lock:
            self.generation += 1
            if self.timer:
                self.timer.cancel()


class RelayServer(HTTPServer):
    request_queue_size = 8

    def __init__(self, address: tuple[str, int], upstream: tuple[str, int]) -> None:
        # The trusted launcher resolves the fixed model name once, before accepting input.
        self.upstream = upstream
        self.slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        super().__init__(address, Relay)

    def process_request(
        self, request: socket.socket | tuple[bytes, socket.socket], client_address: Any
    ) -> None:
        assert isinstance(request, socket.socket)
        if not self.slots.acquire(blocking=False):
            request.settimeout(0.1)
            with suppress(OSError):
                request.sendall(
                    b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n"
                    b"Connection: close\r\nRetry-After: 1\r\n\r\n"
                )
            self.shutdown_request(request)
            return

        def serve() -> None:
            try:
                self.finish_request(request, client_address)
            except Exception:
                pass  # No tracebacks containing request lines or source text.
            finally:
                self.shutdown_request(request)
                self.slots.release()

        try:
            threading.Thread(target=serve, daemon=True).start()
        except Exception:
            self.shutdown_request(request)
            self.slots.release()
            raise

    def handle_error(self, request: Any, client_address: Any) -> None:
        pass


class Relay(BaseHTTPRequestHandler):
    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(INPUT_TIMEOUT)
        self.deadline = Deadline(self.connection)

    def finish(self) -> None:
        try:
            super().finish()
        finally:
            self.deadline.close()

    def log_message(self, format: str, *args: object) -> None:
        pass

    def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
        # Never echo a hostile method, path, upstream error or parser exception.
        self.close_connection = True
        body = b'{"error":"Relay unavailable"}'
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self) -> None:
        self.forward()

    def do_POST(self) -> None:
        self.forward()

    def forward(self) -> None:
        self.close_connection = True
        upstream: http.client.HTTPConnection | None = None
        try:
            allowed = {
                ("GET", "/api/version"),
                ("GET", "/api/tags"),
                ("POST", "/api/show"),
                ("POST", "/api/generate"),
            }
            if (self.command, self.path) not in allowed:
                self.send_error(404)
                return
            lengths = self.headers.get_all("Content-Length", [])
            if (
                len(lengths) > 1
                or self.headers.get("Transfer-Encoding") is not None
                or self.headers.get("Content-Encoding") is not None
                or self.headers.get("Expect") is not None
                or (self.command == "POST" and len(lengths) != 1)
            ):
                self.send_error(400)
                return
            raw_length = lengths[0] if lengths else "0"
            if not raw_length.isascii() or not raw_length.isdecimal():
                self.send_error(400)
                return
            if len(raw_length) > 8 or int(raw_length) > LIMIT:
                self.send_error(413)
                return
            length = int(raw_length)
            if self.command == "GET" and length:
                self.send_error(400)
                return
            body = self.rfile.read(length)
            if len(body) != length:
                self.send_error(400)
                return
            self.deadline.reset(UPSTREAM_TIMEOUT)
            self.connection.settimeout(UPSTREAM_TIMEOUT)
            assert isinstance(self.server, RelayServer)
            host, port = self.server.upstream
            upstream = http.client.HTTPConnection(host, port, timeout=3)
            upstream.connect()
            assert upstream.sock is not None
            self.deadline.track(upstream.sock)
            upstream.sock.settimeout(UPSTREAM_TIMEOUT)
            upstream.request(
                self.command,
                self.path,
                body=body,
                headers={"Content-Type": "application/json", "Accept-Encoding": "identity"},
            )
            response = upstream.getresponse()
            result = response.read(LIMIT + 1)
            if (
                response.status != 200
                or len(result) > LIMIT
                or response.getheader("Content-Encoding", "identity") != "identity"
                or self.deadline.overdue()
            ):
                self.send_error(502)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(result)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(result)
        except Exception:
            self.close_connection = True
        finally:
            if upstream:
                upstream.close()


if __name__ == "__main__":
    # Supplied by the trusted firewall bootstrap; runtime DNS is deliberately blocked.
    model_ip = str(ipaddress.IPv4Address(sys.argv[1]))
    RelayServer(("0.0.0.0", 8080), (model_ip, 11434)).serve_forever()
