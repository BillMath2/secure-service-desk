"""Authenticated self-audience task form/API; source and model text are escaped."""

import asyncio
import json
import secrets
from collections.abc import Callable
from html import escape
from typing import TYPE_CHECKING, Annotated
from urllib.parse import parse_qs

import psycopg
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import Field, ValidationError
from starlette.responses import Response

from service_desk.agent.loop import Assistant
from service_desk.contracts import Contract
from service_desk.core.auth.tokens import AuthenticationDenied
from service_desk.core.gateway.registry import BoundaryDenied

if TYPE_CHECKING:
    from service_desk.app.identity import BrowserSession


class TaskInput(Contract):
    ticket_id: Annotated[str, Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")]
    question: str = Field(min_length=1, max_length=2048)


def page(body: str) -> str:
    return '<!doctype html><html lang="en"><meta charset="utf-8"><title>Service desk</title>' + (
        "<body><main><h1>Service desk</h1>" + body + "</main></body></html>"
    )


def install_task_routes(
    app: FastAPI,
    assistant: Assistant,
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
                f"<p>{escape(assistant.provider_label)}</p>"
                '<form method="post" action="/tasks">'
                f'<input type="hidden" name="csrf" value="{escape(session.csrf, quote=True)}">'
                '<p><label>Ticket ID <input name="ticket_id" required maxlength="64"></label></p>'
                '<p><label>Question <textarea name="question" required maxlength="2048">'
                "Show the support guidance for this ticket.</textarea></label></p>"
                '<button type="submit">Ask assistant</button></form>'
            )
        )

    @app.post("/tasks")
    async def create_task(request: Request) -> Response:
        session = current(request)
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
            task = TaskInput.model_validate(data, strict=True)
            if len(task.question.encode()) > 2048:
                raise ValueError()
        except (ValueError, ValidationError, UnicodeError):
            raise HTTPException(422, "Invalid task") from None
        try:
            identity = await asyncio.to_thread(
                assistant.validator.access, session.login.access_token, "gateway"
            )
            if identity != session.login.identity:
                raise AuthenticationDenied()
            task_id = await asyncio.to_thread(assistant.store.create, identity, task.ticket_id)
            result = await assistant.run(session.login, task_id, task.question)
        except (BoundaryDenied, AuthenticationDenied, psycopg.Error):
            raise HTTPException(403, "Task unavailable") from None
        if is_form:
            if result["allowed"]:
                content = "<h2>Answer</h2><pre>" + escape(result["answer"]) + "</pre><ul>"
                content += "".join("<li>" + escape(c) + "</li>" for c in result["citations"])
                content += "</ul>"
            else:
                content = "<p>Task stopped: " + escape(result["reason"]) + "</p>"
            return HTMLResponse(page(content + '<p><a href="/">New task</a></p>'))
        return JSONResponse({"task_id": str(task_id), **result})
