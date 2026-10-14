"""Authenticated human workflow RPC and a scoped append-only collector interface."""

import asyncio
import json
import secrets
from typing import Annotated, Any, Literal, Protocol
from uuid import UUID

import httpx
import psycopg
from fastapi import FastAPI, HTTPException, Request
from pydantic import Field, ValidationError

from service_desk.app.rpc import Secret
from service_desk.contracts import Contract, Identifier
from service_desk.core.access import AccessStore
from service_desk.core.auth.oidc import LoginResult
from service_desk.core.auth.tokens import AuthenticationDenied, TokenValidator
from service_desk.core.gateway.registry import BoundaryDenied


class AccessDraftInput(Contract):
    ticket_id: Identifier
    resource_id: Identifier
    duration_seconds: int | None = Field(default=None, ge=1, le=2592000)
    justification: str = Field(min_length=1, max_length=2048)


class AccessReference(Contract):
    request_id: UUID


class AccessReviewInput(AccessReference):
    session: Secret
    operation: Literal["submit", "approve", "review"]


class AccessConfirmInput(AccessReference):
    session: Secret
    confirmation_token: Secret
    action_hash: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]


class AccessCheckInput(Contract):
    beneficiary: Identifier
    resource_id: Identifier


class AuditQuery(Contract):
    correlation_id: UUID


class Empty(Contract):
    pass


class AccessBackend(Protocol):
    async def invoke(
        self, login: LoginResult, operation: str, data: dict[str, Any]
    ) -> dict[str, Any]: ...


class LocalAccessBackend:
    def __init__(self, validator: TokenValidator, store: AccessStore) -> None:
        self.validator, self.store = validator, store

    async def invoke(
        self, login: LoginResult, operation: str, data: dict[str, Any]
    ) -> dict[str, Any]:
        who = await asyncio.to_thread(self.validator.access, login.access_token, "gateway")
        if who != login.identity:
            raise AuthenticationDenied()
        # Validate JSON mode so UUIDs have the same strict wire contract locally and remotely.
        body = json.dumps(data)
        if operation == "draft":
            draft = AccessDraftInput.model_validate_json(body, strict=True)
            return await asyncio.to_thread(
                self.store.draft,
                who,
                draft.ticket_id,
                draft.resource_id,
                draft.duration_seconds,
                draft.justification,
            )
        if operation == "review":
            review = AccessReviewInput.model_validate_json(body, strict=True)
            return await asyncio.to_thread(
                self.store.review, who, review.request_id, review.session, review.operation
            )
        if operation == "confirm":
            confirm = AccessConfirmInput.model_validate_json(body, strict=True)
            return await asyncio.to_thread(
                self.store.confirm,
                who,
                confirm.request_id,
                confirm.session,
                confirm.confirmation_token,
                confirm.action_hash,
            )
        if operation == "view":
            ref = AccessReference.model_validate_json(body, strict=True)
            return await asyncio.to_thread(self.store.view, who, ref.request_id)
        if operation == "check":
            check = AccessCheckInput.model_validate_json(body, strict=True)
            return await asyncio.to_thread(
                self.store.check, who, check.beneficiary, check.resource_id
            )
        if operation == "audit":
            audit = AuditQuery.model_validate_json(body, strict=True)
            return await asyncio.to_thread(self.store.audit, who, audit.correlation_id)
        if operation == "inbox":
            Empty.model_validate_json(body, strict=True)
            result: dict[str, Any] = await asyncio.to_thread(
                self.store.call, "access_inbox", who.issuer, who.subject
            )
            return result
        raise BoundaryDenied("TOOL_DENIED")


class RemoteAccessBackend:
    def __init__(self, http: httpx.AsyncClient, secret: str) -> None:
        self.http, self.secret = http, secret

    async def invoke(
        self, login: LoginResult, operation: str, data: dict[str, Any]
    ) -> dict[str, Any]:
        if operation not in {"draft", "view", "review", "confirm", "check", "audit", "inbox"}:
            raise BoundaryDenied("TOOL_DENIED")
        try:
            async with (
                asyncio.timeout(10),
                self.http.stream(
                    "POST",
                    "https://127.0.0.1:19488/" + operation,
                    json=data,
                    headers={
                        "Authorization": "Bearer " + login.access_token,
                        "X-Desk-Service": self.secret,
                        "Accept-Encoding": "identity",
                    },
                ) as response,
            ):
                if response.status_code == 429:
                    raise BoundaryDenied("BUDGET_EXHAUSTED")
                if response.status_code != 200 or response.headers.get("content-encoding"):
                    raise BoundaryDenied("RESOURCE_DENIED")
                body = bytearray()
                async for part in response.aiter_raw():
                    body.extend(part)
                    if len(body) > 131072:
                        raise BoundaryDenied("OUTPUT_LIMIT")
                result = json.loads(body)
                if not isinstance(result, dict):
                    raise ValueError()
                return result
        except (httpx.HTTPError, TimeoutError, ValueError):
            raise BoundaryDenied("SERVICE_ERROR") from None


async def limited_body(request: Request) -> bytes:
    if request.headers.get("content-type") != "application/json" or request.headers.get(
        "content-encoding"
    ):
        raise HTTPException(415, "Invalid action")
    result = bytearray()
    async for part in request.stream():
        result.extend(part)
        if len(result) > 8192:
            raise HTTPException(413, "Action too large")
    return bytes(result)


def authorized_service(request: Request, secret: str) -> bool:
    return (
        request.url.scheme == "https"
        and len(request.headers.getlist("x-desk-service")) == 1
        and secrets.compare_digest(request.headers["x-desk-service"].encode(), secret.encode())
    )


def create_workflow_app(backend: LocalAccessBackend, secret: str) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.post("/{operation}")
    async def invoke(operation: str, request: Request) -> dict[str, Any]:
        if (
            not authorized_service(request, secret)
            or len(request.headers.getlist("authorization")) != 1
            or not request.headers["authorization"].startswith("Bearer ")
        ):
            raise HTTPException(401, "Authentication required")
        try:
            token = request.headers["authorization"][7:]
            who = await asyncio.to_thread(backend.validator.access, token, "gateway")
            data = json.loads(await limited_body(request))
            if not isinstance(data, dict):
                raise ValueError()
            return await backend.invoke(LoginResult(who, token), operation, data)
        except AuthenticationDenied:
            raise HTTPException(401, "Authentication required") from None
        except (ValidationError, ValueError):
            raise HTTPException(422, "Invalid action") from None
        except BoundaryDenied as error:
            raise HTTPException(
                429 if error.reason == "BUDGET_EXHAUSTED" else 403, "Action unavailable"
            ) from None
        except psycopg.Error:
            raise HTTPException(503, "Service unavailable") from None

    return app


class AuditEnvelope(Contract):
    event_id: UUID
    payload: dict[str, Any]


def create_collector_app(store: AccessStore, writers: dict[str, str]) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.post("/events/{writer}")
    async def append(writer: str, request: Request) -> dict[str, bool]:
        if writer not in writers or not authorized_service(request, writers[writer]):
            raise HTTPException(401, "Authentication required")
        try:
            event = AuditEnvelope.model_validate_json(await limited_body(request), strict=True)
            accepted = await asyncio.to_thread(store.accept, writer, event.event_id, event.payload)
            if not accepted:
                raise HTTPException(409, "Event rejected")
            return {"accepted": True}
        except (ValidationError, ValueError):
            raise HTTPException(422, "Invalid event") from None
        except psycopg.Error:
            raise HTTPException(503, "Collector unavailable") from None

    return app
