"""Typed provider boundary and deterministic control fixture; no remote model access."""

import json
from typing import Any, Literal, Protocol

from pydantic import Field

from service_desk.contracts import Contract
from service_desk.core.gateway.registry import canonical

MAX_OUTPUT = 512


class ToolTurn(Contract):
    kind: Literal["tool"] = "tool"
    name: str = Field(min_length=1, max_length=128)
    arguments: dict[str, Any]


class AnswerTurn(Contract):
    kind: Literal["answer"] = "answer"
    text: str = Field(min_length=1, max_length=2048)
    citations: list[str] = Field(min_length=1, max_length=16)


class ProviderReply(Contract):
    turn: ToolTurn | AnswerTurn
    input_tokens: int = Field(ge=1)
    output_tokens: int = Field(ge=1, le=MAX_OUTPUT)


class Provider(Protocol):
    async def generate(self, request: str, *, max_output: int) -> ProviderReply: ...


def input_reservation(request: str) -> int:
    # Conservative byte estimate plus framing allowance, not a universal tokenizer.
    # Any future real adapter must validate its tokenizer/template against this bound.
    return len(request.encode("utf-8")) + 512


class DeterministicProvider:
    """Exercise ticket + public-document reads, then return a cited excerpt.

    This is an explicitly labelled test provider, not a natural-language model.
    It has no mutable per-user state and never interprets source text as instructions.
    """

    async def generate(self, request: str, *, max_output: int) -> ProviderReply:
        data = json.loads(request)
        history = data["history"]
        turn: ToolTurn | AnswerTurn
        if not history:
            turn = ToolTurn(name="read_ticket", arguments={"ticket_id": data["ticket_id"]})
        elif len(history) == 1:
            turn = ToolTurn(name="read_document", arguments={"document_id": "doc-public"})
        else:
            doc = history[-1]["result"].get("document")
            if doc is None:
                raise ValueError("Required source unavailable")
            turn = AnswerTurn(text=doc["body"][:160], citations=[doc["citation"]])
        size = len(canonical(turn.model_dump()).encode())
        if size > max_output:
            raise ValueError("Provider output limit")
        return ProviderReply(turn=turn, input_tokens=input_reservation(request), output_tokens=size)
