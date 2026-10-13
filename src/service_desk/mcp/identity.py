"""Identity-only transport probe. No document, ticket, grant or model dispatch."""

from mcp.server import MCPServer
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import AuthSettings
from pydantic import AnyHttpUrl
from starlette.applications import Starlette

from service_desk.core.auth.tokens import MCPTokenVerifier, ResourceBinding, TokenValidator


def create_identity_mcp(validator: TokenValidator, binding: ResourceBinding) -> Starlette:
    server = MCPServer(
        "service-desk-identity-" + binding.audience,
        token_verifier=MCPTokenVerifier(validator, binding),
        auth=AuthSettings(
            issuer_url=AnyHttpUrl(validator.issuer),
            resource_server_url=AnyHttpUrl(binding.url),
            required_scopes=[binding.scope],
            validate_token_resource=True,
        ),
        log_level="CRITICAL",
    )

    @server.tool()
    def identity_status() -> dict[str, str]:
        """Return the authenticated subject and client for compatibility testing only."""
        token = get_access_token()
        assert token is not None and token.subject is not None
        return {"subject": token.subject, "client_id": token.client_id}

    return server.streamable_http_app(stateless_http=True, json_response=True)
