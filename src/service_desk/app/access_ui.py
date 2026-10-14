"""Provenance-first human review, exact confirmation and restricted audit queries."""

import json
import secrets
from collections.abc import Callable
from html import escape
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs
from uuid import UUID

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.responses import Response

from service_desk.app.access_api import AccessBackend
from service_desk.app.tasks import page
from service_desk.core.auth.tokens import AuthenticationDenied
from service_desk.core.gateway.registry import BoundaryDenied

if TYPE_CHECKING:
    from service_desk.app.identity import BrowserSession


def review_html(record: dict[str, Any], csrf: str) -> str:
    def show(value: Any) -> str:
        return escape(json.dumps(value, indent=2))

    ticket = record["ticket"]
    html = '<p><a href="/access">Access requests</a></p><h2>Original ticket and submitter</h2>'
    html += (
        "<pre>"
        + show(ticket)
        + "</pre><h2>Source provenance</h2><pre>"
        + show(record["sources"])
        + "</pre>"
    )
    html += (
        "<h2>Policy results</h2><pre>"
        + show(
            {
                "version": record["policy_version"],
                "valid": record["policy_valid"],
                "state": record["state"],
                "expires_at": record["expires_at"],
            }
        )
        + "</pre>"
    )
    html += "<h2>Recorded approvals</h2><pre>" + show(record["approvals"]) + "</pre>"
    html += "<h2>Exact proposed change</h2><pre>" + show(record["action"]) + "</pre>"
    html += (
        "<h2>Untrusted proposal justification</h2><p>This text is not an approval.</p><pre>"
        + escape(record["justification"])
        + "</pre>"
    )
    if record.get("grant"):
        html += "<h2>Grant and review deadlines</h2><pre>" + show(record["grant"]) + "</pre>"
    rid = escape(record["request_id"], quote=True)
    if record.get("confirmation_token"):
        label = {
            "submit": "Confirm submission for independent approval",
            "approve": "Approve this exact request",
            "review": "Confirm continued access without extending expiry",
        }[record["operation"]]
        html += f'<form method="post" action="/access/requests/{rid}/confirm">'
        for key, value in {
            "csrf": csrf,
            "confirmation_token": record["confirmation_token"],
            "action_hash": record["action_hash"],
        }.items():
            html += f'<input type="hidden" name="{key}" value="{escape(value, quote=True)}">'
        html += '<button type="submit">' + label + "</button></form>"
    else:
        html += "".join(
            f'<p><a href="/access/requests/{rid}/review?operation={op}">{label}</a></p>'
            for op, label in (
                ("submit", "Review submission"),
                ("approve", "Review approval"),
                ("review", "Review continued access"),
            )
        )
    html += "<p>Correlation: " + escape(record["correlation_id"]) + "</p>"
    return page(html)


def install_access_routes(
    app: FastAPI,
    backend: AccessBackend,
    current: Callable[[Request], "BrowserSession"],
    origin: str,
) -> None:
    async def call(request: Request, operation: str, data: dict[str, Any]) -> dict[str, Any]:
        try:
            return await backend.invoke(current(request).login, operation, data)
        except BoundaryDenied as error:
            raise HTTPException(
                429 if error.reason == "BUDGET_EXHAUSTED" else 403, "Action unavailable"
            ) from None
        except AuthenticationDenied:
            raise HTTPException(401, "Sign-in required") from None
        except (ValueError, TypeError):
            raise HTTPException(422, "Invalid action") from None

    async def form(request: Request) -> dict[str, Any]:
        session = current(request)
        if request.headers.get("origin") != origin:
            raise HTTPException(403, "Action denied")
        body = bytearray()
        async for part in request.stream():
            body.extend(part)
            if len(body) > 8192:
                raise HTTPException(413, "Action too large")
        try:
            if (
                request.headers.get("content-type", "").split(";")[0]
                == "application/x-www-form-urlencoded"
            ):
                values = parse_qs(body.decode(), keep_blank_values=True, max_num_fields=6)
                if any(len(v) != 1 for v in values.values()):
                    raise ValueError()
                data: dict[str, Any] = {k: v[0] for k, v in values.items()}
                csrf = data.pop("csrf", "")
                if "duration_seconds" in data:
                    data["duration_seconds"] = (
                        int(data["duration_seconds"]) if data["duration_seconds"] else None
                    )
            elif request.headers.get("content-type") == "application/json":
                data = json.loads(body)
                csrf = request.headers.get("x-csrf-token", "")
            else:
                raise HTTPException(415, "Unsupported content type")
            if not isinstance(data, dict) or not isinstance(csrf, str):
                raise ValueError()
            if not secrets.compare_digest(csrf.encode(), session.csrf.encode()):
                raise HTTPException(403, "Action denied")
            return data
        except (ValueError, UnicodeError):
            raise HTTPException(422, "Invalid action") from None

    @app.get("/access", response_class=HTMLResponse)
    async def home(request: Request) -> str:
        session = current(request)
        inbox = await call(request, "inbox", {})
        html = (
            '<p><a href="/">Assistant</a></p><h2>Prepare an access draft</h2>'
            "<p>The beneficiary is the original ticket requester. Nothing is submitted "
            'until you confirm the exact action.</p><form method="post" action="/access/drafts">'
        )
        html += f'<input type="hidden" name="csrf" value="{escape(session.csrf, quote=True)}">'
        for name, label in (
            ("ticket_id", "Ticket ID"),
            ("resource_id", "Resource group"),
            ("duration_seconds", "Duration in seconds (blank uses policy default)"),
            ("justification", "Untrusted justification"),
        ):
            html += f'<p><label>{label}<input name="{name}" maxlength="2048"></label></p>'
        html += (
            '<button type="submit">Prepare draft</button></form>'
            "<h2>Your requests and approval inbox</h2>"
        )
        for row in inbox["requests"]:
            html += (
                '<p><a href="/access/requests/'
                + escape(row["request_id"], quote=True)
                + '">'
                + escape(row["ticket_id"] + " / " + row["resource_id"] + " / " + row["state"])
                + "</a></p>"
            )
        html += (
            "<h2>Audit lookup</h2><p>Only the configured lab auditor can query collected "
            'events.</p><form method="get" action="/access/audit"><label>Correlation ID '
            '<input name="correlation_id" required></label><button>Find events</button></form>'
        )
        return page(html)

    @app.post("/access/drafts")
    async def draft(request: Request) -> Response:
        result = await call(request, "draft", await form(request))
        if request.headers.get("content-type") == "application/json":
            return JSONResponse(result)
        return RedirectResponse("/access/requests/" + result["request_id"], status_code=303)

    @app.get("/access/requests/{request_id}")
    async def view(request: Request, request_id: UUID) -> Response:
        result = await call(request, "view", {"request_id": str(request_id)})
        return (
            JSONResponse(result)
            if request.headers.get("accept") == "application/json"
            else HTMLResponse(review_html(result, current(request).csrf))
        )

    @app.get("/access/requests/{request_id}/review")
    async def review(request: Request, request_id: UUID, operation: str) -> Response:
        result = await call(
            request,
            "review",
            {
                "request_id": str(request_id),
                "operation": operation,
                "session": current(request).csrf,
            },
        )
        return (
            JSONResponse(result)
            if request.headers.get("accept") == "application/json"
            else HTMLResponse(review_html(result, current(request).csrf))
        )

    @app.post("/access/requests/{request_id}/confirm")
    async def confirm(request: Request, request_id: UUID) -> Response:
        data = await form(request)
        if set(data) != {"confirmation_token", "action_hash"}:
            raise HTTPException(422, "Invalid action")
        result = await call(
            request,
            "confirm",
            {**data, "request_id": str(request_id), "session": current(request).csrf},
        )
        return (
            JSONResponse(result)
            if request.headers.get("content-type") == "application/json"
            else RedirectResponse("/access/requests/" + str(request_id), status_code=303)
        )

    @app.get("/access/audit")
    async def audit(request: Request, correlation_id: UUID) -> Response:
        result = await call(request, "audit", {"correlation_id": str(correlation_id)})
        return (
            JSONResponse(result)
            if request.headers.get("accept") == "application/json"
            else HTMLResponse(
                page(
                    "<h2>Collected audit events</h2><pre>"
                    + escape(json.dumps(result, indent=2))
                    + "</pre>"
                )
            )
        )
