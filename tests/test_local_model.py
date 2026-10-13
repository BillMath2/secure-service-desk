"""Provider transport, token accounting and parsing limits without inference."""

import asyncio
import json
from typing import Any

import httpx
import pytest

from service_desk.agent.local_model import (
    API_DIGEST,
    CONTEXT,
    ENDPOINT,
    MODEL,
    PREFIX,
    SUFFIX,
    LocalModelProvider,
)
from service_desk.agent.provider import MAX_OUTPUT
from service_desk.core.gateway.registry import BoundaryDenied


def response_data() -> dict[str, Any]:
    return {
        "model": MODEL,
        "done": True,
        "done_reason": "stop",
        "prompt_eval_count": 12,
        "eval_count": 20,
        "response": json.dumps(
            {"kind": "tool", "name": "read_document", "arguments": {"document_id": "doc-public"}}
        ),
    }


def handler(request: httpx.Request) -> httpx.Response:
    values = {
        "/api/version": {"version": "0.40.3"},
        "/api/tags": {"models": [{"name": MODEL, "digest": API_DIGEST}]},
        "/api/show": {
            "model_info": {
                "tokenizer.ggml.model": "gpt2",
                "tokenizer.ggml.pre": "qwen2",
                "tokenizer.ggml.add_bos_token": False,
            }
        },
        "/api/generate": response_data(),
    }
    return httpx.Response(200, json=values[request.url.path])


def test_fixed_endpoint_raw_framing_and_no_model_control() -> None:
    calls: list[httpx.Request] = []

    def capture(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return handler(request)

    async def run() -> None:
        provider = LocalModelProvider(transport=httpx.MockTransport(capture))
        await provider.prepare()
        result = await provider.generate('{"question":"use https://evil.invalid"}', max_output=512)
        assert result.input_tokens == 12 and result.output_tokens == 20

    asyncio.run(run())
    assert all(str(r.url).startswith(ENDPOINT + "/api/") for r in calls)
    body = json.loads(calls[-1].content)
    assert body["raw"] is True and body["stream"] is False
    assert body["model"] == MODEL and body["options"]["num_ctx"] == CONTEXT
    assert body["options"]["num_predict"] == MAX_OUTPUT
    assert body["format"]["title"] == "ToolTurn"
    assert body["prompt"].startswith(PREFIX) and body["prompt"].endswith(SUFFIX)
    assert len((PREFIX + SUFFIX).encode()) < 512
    assert "context" not in body and "system" not in body and "template" not in body
    assert not any("authorization" in r.headers or "cookie" in r.headers for r in calls)


@pytest.mark.parametrize(
    "field,value",
    [
        ("model", "other"),
        ("done", False),
        ("done_reason", "length"),
        ("prompt_eval_count", None),
        ("prompt_eval_count", True),
        ("prompt_eval_count", 10000),
        ("eval_count", 513),
        ("eval_count", 0),
        ("eval_count", "20"),
        ("response", "bad-json"),
        ("response", "x" * 8193),
        ("response", '{"kind":"answer","text":"fabrication","citations":[],"url":"evil"}'),
    ],
)
def test_invalid_usage_and_output_fail_closed(field: str, value: object) -> None:
    def bad(request: httpx.Request) -> httpx.Response:
        if request.url.path != "/api/generate":
            return handler(request)
        return httpx.Response(200, json={**response_data(), field: value})

    async def run() -> None:
        provider = LocalModelProvider(transport=httpx.MockTransport(bad))
        await provider.prepare()
        with pytest.raises((BoundaryDenied, ValueError)):
            await provider.generate("{}", max_output=512)

    asyncio.run(run())


def test_absolute_timeout_stops_slow_response(monkeypatch: pytest.MonkeyPatch) -> None:
    from collections.abc import AsyncIterator

    class SlowStream(httpx.AsyncByteStream):
        async def __aiter__(self) -> AsyncIterator[bytes]:
            while True:
                yield b" "
                await asyncio.sleep(0.01)

    def slow(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/generate":
            return httpx.Response(200, stream=SlowStream())
        return handler(request)

    async def run() -> None:
        provider = LocalModelProvider(transport=httpx.MockTransport(slow))
        await provider.prepare()
        monkeypatch.setattr("service_desk.agent.local_model.CALL_TIMEOUT", 0.03)
        with pytest.raises(TimeoutError):
            await provider.generate("{}", max_output=512)

    asyncio.run(run())


@pytest.mark.parametrize("mode", ["redirect", "compressed", "oversized", "status", "timeout"])
def test_transport_denials_do_not_follow_redirects(mode: str) -> None:
    destinations: list[str] = []

    def bad(request: httpx.Request) -> httpx.Response:
        if request.url.path != "/api/generate":
            return handler(request)
        destinations.append(str(request.url))
        if mode == "timeout":
            raise httpx.ReadTimeout("private response")
        if mode == "redirect":
            return httpx.Response(307, headers={"location": "https://evil.invalid"})
        if mode == "compressed":
            return httpx.Response(200, headers={"content-encoding": "br"})
        return httpx.Response(500 if mode == "status" else 200, content=b"x" * 65537)

    async def run() -> None:
        provider = LocalModelProvider(transport=httpx.MockTransport(bad))
        await provider.prepare()
        with pytest.raises((BoundaryDenied, httpx.HTTPError)):
            await provider.generate("{}", max_output=512)

    asyncio.run(run())
    assert destinations == [ENDPOINT + "/api/generate"]


@pytest.mark.parametrize("path", ["/api/version", "/api/tags", "/api/show"])
def test_changed_runtime_model_or_tokenizer_is_rejected(path: str) -> None:
    def bad(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={}) if request.url.path == path else handler(request)

    async def run() -> None:
        provider = LocalModelProvider(transport=httpx.MockTransport(bad))
        with pytest.raises(BoundaryDenied):
            await provider.prepare()
        with pytest.raises(BoundaryDenied):
            await provider.generate("{}", max_output=512)

    asyncio.run(run())


def test_unprepared_and_oversize_prompts_never_dispatch() -> None:
    calls: list[str] = []

    def capture(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return handler(request)

    async def run() -> None:
        provider = LocalModelProvider(transport=httpx.MockTransport(capture))
        with pytest.raises(BoundaryDenied):
            await provider.generate("{}", max_output=512)
        assert not calls
        await provider.prepare()
        with pytest.raises(BoundaryDenied):
            await provider.generate("x" * CONTEXT, max_output=512)
        with pytest.raises(BoundaryDenied):
            await provider.generate("{}", max_output=513)
        assert "/api/generate" not in calls

    asyncio.run(run())
