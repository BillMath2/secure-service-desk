"""Business argument shapes; authorization always belongs outside these schemas."""

from typing import Annotated, Literal

from pydantic import Field

from service_desk.contracts import Contract, Identifier


class SearchDocumentsArgs(Contract):
    query: Annotated[str, Field(max_length=512)]
    limit: Annotated[int, Field(ge=1, le=10)] = 5


class ReadTicketArgs(Contract):
    ticket_id: Identifier


class DraftResponseArgs(ReadTicketArgs):
    source_ids: tuple[Identifier, ...]
    audience: Literal["requester", "internal"] = "requester"


class AddCommentArgs(Contract):
    draft_id: Identifier


class CheckAccessArgs(Contract):
    target: Identifier
    resource: Identifier


class ProposeAccessChangeArgs(CheckAccessArgs):
    action: Literal["grant"] = "grant"
    duration_seconds: Annotated[int, Field(gt=0, le=2592000)] = 28800
    source_ids: tuple[Identifier, ...] = ()


class ExecuteApprovedChangeArgs(Contract):
    request_id: Identifier
