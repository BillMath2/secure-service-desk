"""Narrow browser-to-agent and browser-to-publisher authenticated interfaces."""

import asyncio
import json
import secrets
from typing import Annotated, Any, Literal
from uuid import UUID

import httpx
import psycopg
from fastapi import FastAPI, HTTPException, Request
from pydantic import Field, ValidationError, model_validator

from service_desk.app.backend import Channel, DraftChannel, LocalTaskBackend
from service_desk.app.publication import InternalPublicationStore, PublicationStore
from service_desk.contracts import Contract, Identifier
from service_desk.core.auth.oidc import LoginResult
from service_desk.core.auth.tokens import AuthenticationDenied, TokenValidator
from service_desk.core.gateway.registry import BoundaryDenied

Secret = Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{43}$")]


class RunInput(Contract):
    channel: Channel
    ticket_id: Identifier
    question: str | None = Field(default=None, min_length=1, max_length=2048)

    @model_validator(mode="after")
    def fixed_draft(self) -> "RunInput":
        if (self.channel == "chat") != (self.question is not None):
            raise ValueError("Only chat accepts a question")
        if self.question is not None and len(self.question.encode()) > 2048:
            raise ValueError("Question too large")
        return self


class ReviewInput(Contract):
    channel: DraftChannel
    draft_id: UUID
    session: Secret


class ConfirmInput(ReviewInput):
    confirmation_token: Secret
    body_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


def service_app(
    role: Literal["agent", "publisher"],
    validator: TokenValidator,
    service_secret: str,
    *,
    agent: LocalTaskBackend | None = None,
    publisher: PublicationStore | None = None,
) -> FastAPI:
    if (role == "agent") != (agent is not None) or (role == "publisher") != (publisher is not None):
        raise ValueError("Invalid service authority")
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    async def authenticate(request: Request) -> LoginResult:
        if (
            request.url.scheme != "https"
            or len(request.headers.getlist("x-desk-service")) != 1
            or not secrets.compare_digest(
                request.headers.get("x-desk-service", "").encode(), service_secret.encode()
            )
            or len(request.headers.getlist("authorization")) != 1
            or not request.headers.get("authorization", "").startswith("Bearer ")
        ):
            raise HTTPException(401, "Service authentication required")
        token = request.headers["authorization"][7:]
        try:
            identity = await asyncio.to_thread(validator.access, token, "gateway")
        except AuthenticationDenied:
            raise HTTPException(401, "User authentication required") from None
        return LoginResult(identity, token)

    async def body(request: Request) -> bytes:
        if request.headers.get("content-type") != "application/json" or request.headers.get(
            "content-encoding"
        ):
            raise HTTPException(415, "Invalid request encoding")
        data = bytearray()
        async for chunk in request.stream():
            if len(data) + len(chunk) > 8192:
                raise HTTPException(413, "Request too large")
            data.extend(chunk)
        return bytes(data)

    @app.post("/run" if role == "agent" else "/{operation}")
    async def action(request: Request, operation: str = "run") -> dict[str, Any]:
        login = await authenticate(request)
        if role == "publisher" and operation not in {"review", "confirm"}:
            raise HTTPException(404, "Unknown action")
        try:
            data = await body(request)
            if role == "agent":
                task = RunInput.model_validate_json(data, strict=True)
                assert agent is not None
                return await agent.submit(login, task.channel, task.ticket_id, task.question)
            assert publisher is not None
            value = (ConfirmInput if operation == "confirm" else ReviewInput).model_validate_json(
                data, strict=True
            )
            store = (
                InternalPublicationStore(publisher.dsn)
                if value.channel == "internal"
                else publisher
            )
            if isinstance(value, ConfirmInput):
                return await asyncio.to_thread(
                    store.confirm,
                    login.identity,
                    value.draft_id,
                    value.session,
                    value.confirmation_token,
                    value.body_sha256,
                )
            return await asyncio.to_thread(
                store.review, login.identity, value.draft_id, value.session
            )
        except ValidationError:
            raise HTTPException(422, "Invalid action") from None
        except BoundaryDenied as error:
            raise HTTPException(
                429 if error.reason == "BUDGET_EXHAUSTED" else 403, "Action unavailable"
            ) from None
        except (AuthenticationDenied, psycopg.Error):
            raise HTTPException(403, "Action unavailable") from None
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(503, "Service unavailable") from None

    return app


class RemoteTaskBackend:
    can_publish = True

    def __init__(
        self,
        http: httpx.AsyncClient,
        agent_secret: str,
        publisher_secret: str,
        *,
        provider_label: str,
    ) -> None:
        self.http = http
        self.secrets = {"agent": agent_secret, "publisher": publisher_secret}
        self.provider_label = provider_label

    async def call(
        self,
        role: Literal["agent", "publisher"],
        operation: str,
        login: LoginResult,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        port = 19486 if role == "agent" else 19487
        try:
            async with (
                asyncio.timeout(120),
                self.http.stream(
                    "POST",
                    f"https://127.0.0.1:{port}/{operation}",
                    json=payload,
                    headers={
                        "Authorization": "Bearer " + login.access_token,
                        "X-Desk-Service": self.secrets[role],
                        "Accept-Encoding": "identity",
                    },
                ) as response,
            ):
                if response.status_code == 429:
                    raise BoundaryDenied("BUDGET_EXHAUSTED")
                if response.status_code != 200 or response.headers.get("content-encoding"):
                    raise BoundaryDenied("SERVICE_ERROR")
                data = bytearray()
                async for chunk in response.aiter_raw():
                    if len(data) + len(chunk) > 65536:
                        raise BoundaryDenied("OUTPUT_LIMIT")
                    data.extend(chunk)
                result = json.loads(data)
                if not isinstance(result, dict):
                    raise ValueError()
                return result
        except (httpx.HTTPError, TimeoutError, ValueError):
            raise BoundaryDenied("SERVICE_ERROR") from None

    async def submit(
        self, login: LoginResult, channel: Channel, ticket_id: str, question: str | None
    ) -> dict[str, Any]:
        return await self.call(
            "agent",
            "run",
            login,
            {"channel": channel, "ticket_id": ticket_id, "question": question},
        )

    async def review(
        self, login: LoginResult, channel: DraftChannel, draft_id: UUID, session: str
    ) -> dict[str, Any]:
        return await self.call(
            "publisher",
            "review",
            login,
            {"channel": channel, "draft_id": str(draft_id), "session": session},
        )

    async def confirm(
        self,
        login: LoginResult,
        channel: DraftChannel,
        draft_id: UUID,
        session: str,
        token: str,
        body_hash: str,
    ) -> dict[str, Any]:
        return await self.call(
            "publisher",
            "confirm",
            login,
            {
                "channel": channel,
                "draft_id": str(draft_id),
                "session": session,
                "confirmation_token": token,
                "body_sha256": body_hash,
            },
        )
