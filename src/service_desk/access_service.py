"""Read-only access checks and local proposal drafts; no approval or execution tools."""

from typing import Any

from service_desk.core.access import AccessStore
from service_desk.core.gateway.store import TaskContext
from service_desk.reads import ReadService


class AccessProposalService(ReadService):
    def __init__(self, store: AccessStore) -> None:
        self.service = "access"
        self.store = store

    def _read(self, context: TaskContext, name: str, args: dict[str, Any]) -> dict[str, Any]:
        store = AccessStore(self.store.dsn)
        result = store.call(
            "access_model_draft" if name == "propose_access_change" else "access_model_check",
            context.issuer,
            context.subject,
            context.id,
            args["resource_id"],
            *([args["duration_seconds"]] if name == "propose_access_change" else []),
        )
        return {"allowed": True, **result}
