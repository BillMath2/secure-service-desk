"""Test-only exfiltration receiver: no forwarding, no response echo, no payload logging."""

import hashlib

from fastapi import FastAPI, Request, Response


class CaptureSink:
    """In-memory observation channel; raw payloads never enter evaluation reports."""

    def __init__(self) -> None:
        self.payloads: list[bytes] = []

    def capture(self, payload: bytes) -> None:
        self.payloads.append(payload)

    def hashes(self) -> tuple[str, ...]:
        return tuple(hashlib.sha256(p).hexdigest() for p in self.payloads)


def create_sink(sink: CaptureSink | None = None) -> FastAPI:
    capture = sink if sink is not None else CaptureSink()
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "test-sink"}

    @app.post("/capture", status_code=204)
    async def receive(request: Request) -> Response:
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 8192:
                return Response(status_code=413)
        if len(capture.payloads) >= 100:
            return Response(status_code=429)
        capture.capture(bytes(body))
        return Response(status_code=204)

    return app
