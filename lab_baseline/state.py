"""Disposable in-memory stores. All policy/confirmation checks intentionally absent."""

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any

from service_desk.contracts import Contract, FixtureSet, ReadDocumentArgs
from service_desk.tool_args import (
    AddCommentArgs,
    CheckAccessArgs,
    DraftResponseArgs,
    ExecuteApprovedChangeArgs,
    ProposeAccessChangeArgs,
    ReadTicketArgs,
    SearchDocumentsArgs,
)

SHAPES: dict[str, type[Contract]] = {
    "search_documents": SearchDocumentsArgs,
    "read_document": ReadDocumentArgs,
    "read_ticket": ReadTicketArgs,
    "draft_response": DraftResponseArgs,
    "add_comment": AddCommentArgs,
    "check_access": CheckAccessArgs,
    "propose_access_change": ProposeAccessChangeArgs,
    "execute_approved_change": ExecuteApprovedChangeArgs,
}
SERVICES = {
    "knowledge": ("search_documents", "read_document"),
    "tickets": ("read_ticket", "draft_response", "add_comment"),
    "access": ("check_access", "propose_access_change", "execute_approved_change"),
}


class UnsafeState:
    def __init__(self, fixtures: FixtureSet) -> None:
        self.fixtures = fixtures
        self.reset()

    def reset(self) -> None:
        self.drafts: dict[str, dict[str, Any]] = {}
        self.comments: list[dict[str, Any]] = []
        self.proposals: dict[str, dict[str, Any]] = {}
        self.grants: list[dict[str, Any]] = []
        self.events: list[dict[str, Any]] = []

    def snapshot(self) -> dict[str, Any]:
        return {
            "drafts": self.drafts,
            "comments": self.comments,
            "proposals": self.proposals,
            "grants": self.grants,
            "events": self.events,
        }

    def invoke(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        args = SHAPES[name].model_validate(arguments).model_dump()
        # Instrumentation is observation, deliberately not an authorization decision.
        event: dict[str, Any] = {
            "sequence": len(self.events) + 1,
            "operation": name,
            "arguments_sha256": hashlib.sha256(
                json.dumps(args, sort_keys=True).encode()
            ).hexdigest(),
            "outcome": "error",
        }
        self.events.append(event)
        result = self._dispatch(name, args)
        event["outcome"] = "returned"
        event["output_sha256"] = hashlib.sha256(
            json.dumps(result, sort_keys=True).encode()
        ).hexdigest()
        return result

    def _dispatch(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        documents = {d.id: d for d in self.fixtures.documents}
        tickets = {t.id: t for t in self.fixtures.tickets}
        if name == "search_documents":
            query = args["query"].casefold()
            return {
                "documents": [
                    {"document_id": d.id, "title": d.title, "snippet": d.body[:256]}
                    for d in documents.values()
                    if query in (d.title + " " + d.body).casefold()
                ][: args["limit"]]
            }
        if name == "read_document":
            doc = documents[args["document_id"]]
            return {"document_id": doc.id, "version": doc.version, "body": doc.body}
        if name == "read_ticket":
            return tickets[args["ticket_id"]].model_dump(mode="json")
        if name == "draft_response":
            ticket = tickets[args["ticket_id"]]
            body = "\n".join(documents[source].body for source in args["source_ids"])
            draft_id = f"draft-{len(self.drafts) + 1}"
            self.drafts[draft_id] = {
                **args,
                "body": body,
                "requester": ticket.requester,
                "draft_id": draft_id,
            }
            return self.drafts[draft_id]
        if name == "add_comment":
            draft = self.drafts[args["draft_id"]]
            comment = {**draft, "comment_id": f"comment-{len(self.comments) + 1}"}
            # Deliberately publishes requester drafts without confirmation or a human review.
            self.comments.append(comment)
            return {"comment_id": comment["comment_id"], "stored": True}
        if name == "check_access":
            return {
                "granted": any(
                    g["target"] == args["target"] and g["resource"] == args["resource"]
                    for g in self.grants
                )
            }
        if name == "propose_access_change":
            if args["target"] not in {p.id for p in self.fixtures.principals}:
                raise ValueError("unknown synthetic target")
            if args["resource"] not in {g.id for g in self.fixtures.groups}:
                raise ValueError("unknown synthetic group")
            request_id = f"request-{len(self.proposals) + 1}"
            self.proposals[request_id] = {**args, "request_id": request_id, "approvals": []}
            return {"request_id": request_id}
        if name == "execute_approved_change":
            proposal = self.proposals[args["request_id"]]
            now = datetime.now(UTC)
            grant = {
                **proposal,
                "grant_id": f"grant-{len(self.grants) + 1}",
                "starts_at": now.isoformat(),
                "expires_at": (now + timedelta(seconds=proposal["duration_seconds"])).isoformat(),
            }
            self.grants.append(grant)
            return {"grant_id": grant["grant_id"], "applied": True}
        raise ValueError("unknown tool")
