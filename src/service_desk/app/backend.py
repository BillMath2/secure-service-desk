"""Browser task interface; deployment may put generation and publication in separate services."""

import asyncio
from typing import Any, Literal, Protocol
from uuid import UUID

from service_desk.agent.loop import Assistant
from service_desk.agent.requester import (
    InternalDrafter,
    InternalStore,
    RequesterDrafter,
    RequesterStore,
)
from service_desk.app.publication import InternalPublicationStore, PublicationStore
from service_desk.core.auth.oidc import LoginResult
from service_desk.core.auth.tokens import AuthenticationDenied, VerifiedIdentity

Channel = Literal["chat", "requester", "internal"]
DraftChannel = Literal["requester", "internal"]


class TaskBackend(Protocol):
    provider_label: str
    can_publish: bool

    async def submit(
        self, login: LoginResult, channel: Channel, ticket_id: str, question: str | None
    ) -> dict[str, Any]: ...

    async def review(
        self, login: LoginResult, channel: DraftChannel, draft_id: UUID, session: str
    ) -> dict[str, Any]: ...

    async def confirm(
        self,
        login: LoginResult,
        channel: DraftChannel,
        draft_id: UUID,
        session: str,
        token: str,
        body_hash: str,
    ) -> dict[str, Any]: ...


class LocalTaskBackend:
    """Compatibility/test adapter; isolated deployment uses the remote implementation."""

    def __init__(self, assistant: Assistant, publisher: PublicationStore | None = None) -> None:
        self.assistant = assistant
        self.publisher = publisher
        self.provider_label = assistant.provider_label
        self.can_publish = publisher is not None

    async def identity(self, login: LoginResult) -> VerifiedIdentity:
        identity = await asyncio.to_thread(
            self.assistant.validator.access, login.access_token, "gateway"
        )
        if identity != login.identity:
            raise AuthenticationDenied()
        return identity

    async def submit(
        self, login: LoginResult, channel: Channel, ticket_id: str, question: str | None
    ) -> dict[str, Any]:
        identity = await self.identity(login)
        if channel == "chat":
            if question is None:
                raise AuthenticationDenied()
            task_id = await asyncio.to_thread(self.assistant.store.create, identity, ticket_id)
            result = await self.assistant.run(login, task_id, question)
        else:
            drafter = (
                InternalDrafter(self.assistant)
                if channel == "internal"
                else RequesterDrafter(self.assistant)
            )
            task_id = await asyncio.to_thread(drafter.store.create_draft, identity, ticket_id)
            result = await drafter.run(login, task_id)
        return {"task_id": str(task_id), **result}

    def publication(self, channel: DraftChannel) -> PublicationStore:
        if self.publisher is None:
            raise AuthenticationDenied()
        return (
            InternalPublicationStore(self.publisher.dsn)
            if channel == "internal"
            else self.publisher
        )

    async def review(
        self, login: LoginResult, channel: DraftChannel, draft_id: UUID, session: str
    ) -> dict[str, Any]:
        identity = await self.identity(login)
        if self.publisher is not None:
            return await asyncio.to_thread(
                self.publication(channel).review, identity, draft_id, session
            )
        store_type = InternalStore if channel == "internal" else RequesterStore
        return await asyncio.to_thread(
            store_type(self.assistant.store.dsn).review, identity, draft_id
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
        identity = await self.identity(login)
        return await asyncio.to_thread(
            self.publication(channel).confirm, identity, draft_id, session, token, body_hash
        )
