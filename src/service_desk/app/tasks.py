"""Authenticated chat, draft review and human publication; source and model text are escaped."""

import json
import secrets
from collections.abc import Callable
from html import escape
from typing import TYPE_CHECKING, Annotated
from urllib.parse import parse_qs
from uuid import UUID

import psycopg
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import Field, ValidationError
from starlette.responses import Response

from service_desk.app.backend import DraftChannel, TaskBackend
from service_desk.contracts import Contract
from service_desk.core.auth.tokens import AuthenticationDenied
from service_desk.core.gateway.registry import BoundaryDenied

if TYPE_CHECKING:
    from service_desk.app.identity import BrowserSession


class TaskInput(Contract):
    ticket_id: Annotated[str, Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")]
    question: str = Field(min_length=1, max_length=2048)


class RequesterDraftInput(Contract):
    ticket_id: Annotated[str, Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")]


class ConfirmationInput(Contract):
    confirmation_token: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{43}$")]
    body_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


def page(body: str) -> str:
    return '<!doctype html><html lang="en"><meta charset="utf-8"><title>Service desk</title>' + (
        "<body><main><h1>Service desk</h1>" + body + "</main></body></html>"
    )


def install_task_routes(
    app: FastAPI,
    backend: TaskBackend,
    current: Callable[[Request], "BrowserSession"],
    origin: str,
) -> None:

    @app.get("/", response_class=HTMLResponse)
    def home(request: Request) -> HTMLResponse:
        try:
            session = current(request)
        except HTTPException:
            return HTMLResponse(page('<p><a href="/login">Sign in</a></p>'))
        return HTMLResponse(
            page(
                "<p>Read-only assistant. Answers are visible only to you.</p>"
                '<p><a href="/access">Access requests and approvals</a></p>'
                f"<p>{escape(backend.provider_label)}</p>"
                '<form method="post" action="/tasks">'
                f'<input type="hidden" name="csrf" value="{escape(session.csrf, quote=True)}">'
                '<p><label>Ticket ID <input name="ticket_id" required maxlength="64"></label></p>'
                '<p><label>Question <textarea name="question" required maxlength="2048">'
                "Show the support guidance for this ticket.</textarea></label></p>"
                '<button type="submit">Ask assistant</button></form>'
                "<h2>Requester draft</h2><p>Create an unreviewed draft from requester-visible "
                "ticket history and the public support guide. Nothing is posted.</p>"
                '<form method="post" action="/requester-drafts">'
                f'<input type="hidden" name="csrf" value="{escape(session.csrf, quote=True)}">'
                '<p><label>Ticket ID <input name="ticket_id" required maxlength="64"></label></p>'
                '<button type="submit">Generate draft</button></form>'
                "<h2>Internal comment</h2><p>Create a draft for the registered internal staff "
                "using their shared ticket history and the public support guide. "
                "Nothing is posted.</p>"
                '<form method="post" action="/internal-drafts">'
                f'<input type="hidden" name="csrf" value="{escape(session.csrf, quote=True)}">'
                '<p><label>Ticket ID <input name="ticket_id" required maxlength="64"></label></p>'
                '<button type="submit">Generate internal draft</button></form>'
            )
        )

    @app.post("/tasks")
    @app.post("/requester-drafts")
    @app.post("/internal-drafts")
    async def create_task(request: Request) -> Response:
        session = current(request)
        is_internal = request.url.path == "/internal-drafts"
        is_draft = is_internal or request.url.path == "/requester-drafts"
        channel: DraftChannel = "internal" if is_internal else "requester"
        if request.headers.get("origin") != origin:
            raise HTTPException(403, "Action denied")
        body = bytearray()
        async for chunk in request.stream():
            if len(body) + len(chunk) > 8192:
                raise HTTPException(413, "Request too large")
            body.extend(chunk)
        is_form = request.headers.get("content-type", "").split(";")[0] == (
            "application/x-www-form-urlencoded"
        )
        try:
            if is_form:
                fields = parse_qs(body.decode(), keep_blank_values=True, max_num_fields=3)
                if any(len(v) != 1 for v in fields.values()):
                    raise ValueError()
                data = {k: v[0] for k, v in fields.items()}
                csrf = data.pop("csrf", "")
            elif request.headers.get("content-type", "").split(";")[0] == "application/json":
                data = json.loads(body)
                csrf = request.headers.get("x-csrf-token", "")
            else:
                raise HTTPException(415, "Unsupported content type")
            if not secrets.compare_digest(csrf.encode(), session.csrf.encode()):
                raise HTTPException(403, "Action denied")
            task = (
                RequesterDraftInput.model_validate(data, strict=True)
                if is_draft
                else TaskInput.model_validate(data, strict=True)
            )
            if isinstance(task, TaskInput) and len(task.question.encode()) > 2048:
                raise ValueError()
        except (ValueError, ValidationError, UnicodeError):
            raise HTTPException(422, "Invalid task") from None
        try:
            result = await backend.submit(
                session.login,
                channel if is_draft else "chat",
                task.ticket_id,
                task.question if isinstance(task, TaskInput) else None,
            )
        except BoundaryDenied as error:
            if error.reason == "BUDGET_EXHAUSTED":
                raise HTTPException(
                    429, "Task limit reached. Try again later.", headers={"Retry-After": "60"}
                ) from None
            raise HTTPException(403, "Task unavailable") from None
        except (AuthenticationDenied, psycopg.Error):
            raise HTTPException(403, "Task unavailable") from None
        if is_form:
            if result["allowed"]:
                if is_draft:
                    content = f"<h2>Unreviewed {channel} draft</h2><p>Nothing has been posted.</p>"
                    content += "<p>Recipients: " + escape(", ".join(result["recipients"])) + "</p>"
                    content += "<pre>" + escape(result["draft"]) + "</pre><ul>"
                else:
                    content = "<h2>Answer</h2><pre>" + escape(result["answer"]) + "</pre><ul>"
                content += "".join("<li>" + escape(c) + "</li>" for c in result["citations"])
                content += "</ul>"
                if is_draft:
                    content += (
                        f'<p><a href="/{channel}-drafts/'
                        + escape(result["draft_id"], quote=True)
                        + '">Review saved draft and source details</a></p>'
                    )
            else:
                content = "<p>Task stopped: " + escape(result["reason"]) + "</p>"
            return HTMLResponse(page(content + '<p><a href="/">New task</a></p>'))
        return JSONResponse(result)

    @app.get("/requester-drafts/{draft_id}")
    @app.get("/internal-drafts/{draft_id}")
    async def review_draft(request: Request, draft_id: UUID) -> Response:
        session = current(request)
        is_internal = request.url.path.startswith("/internal-drafts/")
        channel: DraftChannel = "internal" if is_internal else "requester"
        try:
            result = await backend.review(session.login, channel, draft_id, session.csrf)
        except (BoundaryDenied, AuthenticationDenied, psycopg.Error):
            raise HTTPException(403, "Draft unavailable") from None
        if request.headers.get("accept") == "application/json":
            return JSONResponse(result)
        content = f"<h2>Review {channel} draft</h2><p>Unreviewed. Nothing has been posted.</p>"
        content += "<p>Ticket: " + escape(result["ticket_id"]) + "</p>"
        content += "<p>Recipients: " + escape(", ".join(result["recipients"])) + "</p>"
        content += "<p>Expires: " + escape(result["expires_at"]) + "</p>"
        content += "<p>Policy: " + escape(result["policy_version"]) + "</p>"
        content += "<h3>Sources</h3><ul>"
        for source in result["sources"]:
            label = source["kind"] + ":" + source["id"]
            if "version" in source:
                label += "@" + str(source["version"])
            content += "<li>" + escape(label) + "</li>"
        content += "</ul><h3>Draft text</h3><pre>" + escape(result["draft"]) + "</pre>"
        content += "<details><summary>Body fingerprint</summary><code>"
        content += escape(result["body_sha256"]) + "</code></details>"
        if backend.can_publish:
            action_label = "internal comment" if is_internal else "reply"
            content += (
                f'<form method="post" action="/{channel}-drafts/' + str(draft_id) + '/confirm">'
                '<input type="hidden" name="csrf" value="' + escape(session.csrf, quote=True) + '">'
                '<input type="hidden" name="confirmation_token" value="'
                + escape(result["confirmation_token"], quote=True)
                + '">'
                '<input type="hidden" name="body_sha256" value="'
                + escape(result["body_sha256"], quote=True)
                + '">'
                f"<p>Post this exact {action_label} to the {channel} recipients listed above. "
                "This changes the simulated ticket.</p><p>Confirmation expires: "
                + escape(result["confirmation_expires_at"])
                + "</p>"
                f'<button type="submit">Confirm and post this {action_label}</button></form>'
            )
        content += '<p>To change this draft, generate a new one.</p><p><a href="/">New task</a></p>'
        return HTMLResponse(page(content))

    if not backend.can_publish:
        return

    @app.post("/requester-drafts/{draft_id}/confirm")
    @app.post("/internal-drafts/{draft_id}/confirm")
    async def confirm_draft(request: Request, draft_id: UUID) -> Response:
        session = current(request)
        is_internal = request.url.path.startswith("/internal-drafts/")
        if request.headers.get("origin") != origin:
            raise HTTPException(403, "Action denied")
        body = bytearray()
        async for chunk in request.stream():
            if len(body) + len(chunk) > 2048:
                raise HTTPException(413, "Request too large")
            body.extend(chunk)
        content_type = request.headers.get("content-type", "").split(";")[0]
        is_form = content_type == "application/x-www-form-urlencoded"
        try:
            if is_form:
                fields = parse_qs(body.decode(), keep_blank_values=True, max_num_fields=3)
                if any(len(v) != 1 for v in fields.values()):
                    raise ValueError()
                data = {k: v[0] for k, v in fields.items()}
                csrf = data.pop("csrf", "")
            elif content_type == "application/json":
                data = json.loads(body)
                csrf = request.headers.get("x-csrf-token", "")
            else:
                raise HTTPException(415, "Unsupported content type")
            if not secrets.compare_digest(csrf.encode(), session.csrf.encode()):
                raise HTTPException(403, "Action denied")
            action = ConfirmationInput.model_validate(data, strict=True)
        except (ValueError, ValidationError, UnicodeError):
            raise HTTPException(422, "Invalid confirmation") from None
        try:
            result = await backend.confirm(
                session.login,
                "internal" if is_internal else "requester",
                draft_id,
                session.csrf,
                action.confirmation_token,
                action.body_sha256,
            )
        except (BoundaryDenied, AuthenticationDenied, psycopg.Error):
            raise HTTPException(403, "Confirmation unavailable") from None
        if is_form:
            return HTMLResponse(
                page(
                    ("<h2>Internal comment posted</h2>" if is_internal else "<h2>Reply posted</h2>")
                    + "<p>Receipt: "
                    + escape(result["comment_id"])
                    + '</p><p><a href="/">New task</a></p>'
                )
            )
        return JSONResponse(result)
