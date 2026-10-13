"""Exact, versioned read-tool contracts. Remote descriptions never define policy."""

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from service_desk.contracts import Contract, ReadDocumentArgs
from service_desk.tool_args import ReadTicketArgs, SearchDocumentsArgs


class BoundaryDenied(Exception):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def canonical(value: object) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def argument_hash(arguments: object) -> str:
    return hashlib.sha256(canonical(arguments).encode()).hexdigest()


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    service: str
    scope: str
    description: str
    arguments: type[Contract]

    def wire(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.arguments.model_json_schema(),
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False,
            },
        }


TOOLS = (
    ToolDefinition(
        "read_document",
        "knowledge",
        "knowledge:read",
        "Read a permitted document with a versioned citation.",
        ReadDocumentArgs,
    ),
    ToolDefinition(
        "search_documents",
        "knowledge",
        "knowledge:read",
        "Search permitted documents; return cited plain-text snippets.",
        SearchDocumentsArgs,
    ),
    ToolDefinition(
        "read_ticket",
        "tickets",
        "tickets:read",
        "Read the task ticket and comments permitted for every recipient.",
        ReadTicketArgs,
    ),
)
REGISTRY_VERSION = "read-tools-v1"


def catalog(service: str) -> list[dict[str, Any]]:
    return [t.wire() for t in TOOLS if t.service == service]


def validate_catalog(service: str, remote: list[dict[str, Any]]) -> None:
    # Full wire equality, including unknown metadata; order does not confer authority.
    expected = sorted(catalog(service), key=lambda t: t["name"])
    if not expected or canonical(sorted(remote, key=lambda t: t.get("name", ""))) != canonical(
        expected
    ):
        raise BoundaryDenied("CATALOG_DENIED")


def definition(name: str) -> ToolDefinition:
    for tool in TOOLS:
        if tool.name == name:
            return tool
    raise BoundaryDenied("TOOL_DENIED")


def validate_arguments(name: str, arguments: dict[str, Any]) -> Contract:
    try:
        return definition(name).arguments.model_validate(arguments, strict=True)
    except ValidationError:
        raise BoundaryDenied("SCHEMA_DENIED") from None


def safe_operation(name: str) -> str:
    return name if any(t.name == name for t in TOOLS) else "unregistered"
