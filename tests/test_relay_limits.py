"""Real socket probes of relay deadlines, concurrency and content-free failures."""

import http.client
import socket
import threading
import time
from collections.abc import Iterator
from contextlib import closing, contextmanager, suppress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from scripts.model_relay import Deadline, Relay, RelayServer


@contextmanager
def running(behavior: str = "normal") -> Iterator[tuple[RelayServer, list[dict[str, str]]]]:
    seen: list[dict[str, str]] = []

    class Upstream(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            pass

        def do_GET(self) -> None:
            self.respond()

        def do_POST(self) -> None:
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            self.respond()

        def respond(self) -> None:
            seen.append(dict(self.headers.items()))
            body = b'{"version":"test"}' if behavior == "normal" else b"PRIVATE UPSTREAM ERROR"
            if behavior == "large":
                body *= 4096
            self.send_response(302 if behavior == "redirect" else 200)
            self.send_header("Content-Length", str(len(body)))
            if behavior == "compressed":
                self.send_header("Content-Encoding", "gzip")
            self.end_headers()
            with suppress(OSError):
                if behavior == "trickle":
                    for byte in body:
                        self.wfile.write(bytes([byte]))
                        self.wfile.flush()
                        time.sleep(0.08)
                else:
                    self.wfile.write(body)

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    relay = RelayServer(("127.0.0.1", 0), ("127.0.0.1", upstream.server_port))
    threads = [
        threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        for server in (upstream, relay)
    ]
    for thread in threads:
        thread.start()
    try:
        yield relay, seen
    finally:
        for server in (relay, upstream):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(2)


def get(relay: RelayServer) -> tuple[int, bytes]:
    with closing(http.client.HTTPConnection("127.0.0.1", relay.server_port, timeout=2)) as client:
        client.request("GET", "/api/version")
        response = client.getresponse()
        return response.status, response.read()


def test_relay_forwards_only_fixed_headers_and_closes_connection() -> None:
    with running() as (relay, seen):
        with closing(
            http.client.HTTPConnection("127.0.0.1", relay.server_port, timeout=2)
        ) as client:
            client.request(
                "POST",
                "/api/show",
                b"{}",
                {
                    "Authorization": "Bearer SECRET",
                    "Cookie": "session=SECRET",
                    "X-User": "administrator",
                    "Content-Type": "application/json",
                },
            )
            response = client.getresponse()
            assert response.status == 200 and response.getheader("Connection") == "close"
            assert response.read() == b'{"version":"test"}'
        assert len(seen) == 1
        assert set(seen[0]) == {"Host", "Content-Length", "Content-Type", "Accept-Encoding"}
        assert "SECRET" not in str(seen)


@pytest.mark.parametrize(
    "partial",
    [
        b"GET /api/version",
        b"GET /api/version HTTP/1.1\r\nHost: local\r\nX-Slow:",
        b"POST /api/generate HTTP/1.1\r\nContent-Length: 100\r\n\r\npartial",
    ],
)
def test_stalled_input_closes_without_upstream_dispatch(
    monkeypatch: pytest.MonkeyPatch, partial: bytes
) -> None:
    monkeypatch.setattr("scripts.model_relay.INPUT_TIMEOUT", 0.3)
    with running() as (relay, seen):
        with socket.create_connection(("127.0.0.1", relay.server_port), timeout=2) as client:
            started = time.monotonic()
            client.sendall(partial)
            with suppress(ConnectionResetError):
                assert client.recv(4096) == b""
            assert time.monotonic() - started < 1.5
        assert seen == []
        assert get(relay)[0] == 200


def test_trickled_headers_cannot_extend_input_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("scripts.model_relay.INPUT_TIMEOUT", 0.3)
    with running() as (relay, seen):
        with socket.create_connection(("127.0.0.1", relay.server_port), timeout=2) as client:
            client.sendall(b"GET /api/version HTTP/1.1\r\nX-Slow:")
            finished = threading.Event()

            def trickle() -> None:
                with suppress(OSError):
                    while not finished.wait(0.04):
                        client.sendall(b"a")

            writer = threading.Thread(target=trickle, daemon=True)
            writer.start()
            try:
                with suppress(ConnectionResetError):
                    assert client.recv(4096) == b""
            finally:
                finished.set()
                writer.join(2)
        assert seen == []


def test_trickled_upstream_cannot_extend_deadline_or_release_partial_content(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("scripts.model_relay.UPSTREAM_TIMEOUT", 0.25)
    with running("trickle") as (relay, seen):
        with socket.create_connection(("127.0.0.1", relay.server_port), timeout=2) as client:
            started = time.monotonic()
            client.sendall(b"GET /api/version HTTP/1.1\r\nHost: local\r\n\r\n")
            with suppress(ConnectionResetError):
                assert client.recv(4096) == b""
            assert time.monotonic() - started < 1.5
        assert len(seen) == 1


def test_saturated_relay_rejects_then_recovers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("scripts.model_relay.MAX_CONNECTIONS", 1)
    accepted = threading.Event()
    original_setup = Relay.setup

    def setup(self: Relay) -> None:
        original_setup(self)
        accepted.set()

    monkeypatch.setattr(Relay, "setup", setup)
    with running() as (relay, seen):
        with socket.create_connection(("127.0.0.1", relay.server_port), timeout=2) as stalled:
            stalled.sendall(b"GET /api/version HTTP/1.1\r\nX-Slow:")
            assert accepted.wait(1)
            # TCP may reset an overloaded connection before its 503 is received.
            with suppress(OSError, http.client.RemoteDisconnected):
                assert get(relay)[0] == 503
            assert seen == []
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                if get(relay)[0] == 200:
                    break
            except (OSError, http.client.RemoteDisconnected):
                pass
        else:
            pytest.fail("Relay did not release the closed connection's slot")


@pytest.mark.parametrize(
    "headers",
    [
        b"Content-Length: 0\r\nContent-Length: 0",
        b"Content-Length: -1",
        b"Content-Length: nope",
        b"Content-Length: 0\r\nTransfer-Encoding: chunked",
        b"Content-Length: 0\r\nContent-Encoding: gzip",
        b"Content-Length: 0\r\nExpect: 100-continue",
    ],
)
def test_ambiguous_input_is_denied_without_dispatch(headers: bytes) -> None:
    with running() as (relay, seen):
        with socket.create_connection(("127.0.0.1", relay.server_port), timeout=2) as client:
            client.sendall(b"POST /api/generate HTTP/1.1\r\n" + headers + b"\r\n\r\n")
            assert b"400" in client.recv(4096).split(b"\r\n")[0]
        assert seen == []


@pytest.mark.parametrize("behavior", ["redirect", "compressed", "large"])
def test_upstream_failures_do_not_echo_content(behavior: str, capsys: Any) -> None:
    with running(behavior) as (relay, _):
        status, body = get(relay)
        assert status == 502 and body == b'{"error":"Relay unavailable"}'
    captured = capsys.readouterr()
    assert not captured.out and not captured.err


@pytest.mark.parametrize("action", ["reset", "track"])
def test_overdue_phase_is_denied_even_before_timer_callback(
    monkeypatch: pytest.MonkeyPatch, action: str
) -> None:
    monkeypatch.setattr("scripts.model_relay.time.monotonic", lambda: 0.0)
    with socket.socket() as incoming, socket.socket() as upstream:
        deadline = Deadline(incoming)
        try:
            monkeypatch.setattr("scripts.model_relay.time.monotonic", lambda: 100.0)
            assert deadline.overdue()
            with pytest.raises(TimeoutError):
                if action == "reset":
                    deadline.reset(45)
                else:
                    deadline.track(upstream)
        finally:
            deadline.close()
