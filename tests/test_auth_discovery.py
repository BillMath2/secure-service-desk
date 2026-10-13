"""Pinned MCP discovery order, challenge parsing and hostile metadata boundaries."""

import time
from typing import Any

import httpx
import pytest

from service_desk.core.auth.discovery import (
    Discovery,
    challenge_parameters,
    issuer_locations,
    resource_locations,
)
from service_desk.core.auth.tokens import AuthenticationDenied, ResourceBinding

ISSUER = "https://identity.example/realms/desk"
AUTH = ISSUER + "/protocol/openid-connect/auth"
TOKEN = ISSUER + "/protocol/openid-connect/token"
JWKS = ISSUER + "/protocol/openid-connect/certs"
BINDING = ResourceBinding("knowledge", "https://mcp.example/mcp", "knowledge:read")
METADATA = {
    "issuer": ISSUER,
    "authorization_endpoint": AUTH,
    "token_endpoint": TOKEN,
    "jwks_uri": JWKS,
    "code_challenge_methods_supported": ["S256"],
    "response_types_supported": ["code"],
    "token_endpoint_auth_methods_supported": ["client_secret_post"],
}
RESOURCE = {
    "resource": BINDING.url,
    "authorization_servers": [ISSUER],
    "scopes_supported": [BINDING.scope],
    "bearer_methods_supported": ["header"],
}


@pytest.mark.parametrize("index", range(3))
def test_issuer_discovery_priority_and_fallback(index: int) -> None:
    locations = issuer_locations(ISSUER)
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return (
            httpx.Response(200, json=METADATA)
            if str(request.url) == locations[index]
            else httpx.Response(404)
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        assert Discovery(http).issuer(ISSUER, AUTH, TOKEN, JWKS) == locations[index]
    assert calls == list(locations[: index + 1])
    assert issuer_locations("https://id.example") == (
        "https://id.example/.well-known/oauth-authorization-server",
        "https://id.example/.well-known/openid-configuration",
    )


@pytest.mark.parametrize("mode", ["challenge", "path", "root"])
def test_resource_challenge_and_well_known_fallbacks(mode: str) -> None:
    locations = resource_locations(BINDING.url)
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if str(request.url) == BINDING.url:
            headers = (
                {
                    "WWW-Authenticate": f'Bearer resource_metadata="{locations[1]}", '
                    'scope="knowledge:read"'
                }
                if mode == "challenge"
                else {}
            )
            return httpx.Response(401, headers=headers)
        if str(request.url) == locations[0] and mode == "root":
            return httpx.Response(404)
        return httpx.Response(200, json=RESOURCE)

    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        selected = Discovery(http).resource(BINDING, ISSUER)
    assert selected == locations[0 if mode == "path" else 1]
    assert calls == [BINDING.url, *(locations if mode == "root" else (selected,))]


@pytest.mark.parametrize(
    "field,value",
    [
        ("issuer", "https://evil.invalid"),
        ("token_endpoint", "https://evil.invalid/token"),
        ("authorization_endpoint", "http://identity.example/auth"),
        ("jwks_uri", "https://evil.invalid/jwks"),
        ("code_challenge_methods_supported", ["plain"]),
        ("code_challenge_methods_supported", "S256"),
        ("response_types_supported", None),
        ("token_endpoint_auth_methods_supported", ["none"]),
    ],
)
def test_valid_http_with_invalid_issuer_metadata_does_not_fall_back(
    field: str, value: object
) -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, json={**METADATA, field: value})

    with (
        httpx.Client(transport=httpx.MockTransport(handler)) as http,
        pytest.raises(AuthenticationDenied),
    ):
        Discovery(http).issuer(ISSUER, AUTH, TOKEN, JWKS)
    assert len(calls) == 1


@pytest.mark.parametrize(
    "override",
    [
        {"resource": "https://other.example/mcp"},
        {"authorization_servers": ["https://evil.invalid"]},
        {"authorization_servers": [ISSUER, "https://evil.invalid"]},
        {"scopes_supported": []},
        {"scopes_supported": "knowledge:read"},
        {"bearer_methods_supported": ["query"]},
    ],
)
def test_resource_metadata_never_changes_issuer_or_scope(override: dict[str, Any]) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return (
            httpx.Response(401)
            if str(request.url) == BINDING.url
            else httpx.Response(200, json={**RESOURCE, **override})
        )

    with (
        httpx.Client(transport=httpx.MockTransport(handler)) as http,
        pytest.raises(AuthenticationDenied),
    ):
        Discovery(http).resource(BINDING, ISSUER)


@pytest.mark.parametrize(
    "challenge",
    [
        'Bearer resource_metadata="https://evil.invalid/steal"',
        'Bearer resource_metadata="http://mcp.example/.well-known/oauth-protected-resource"',
        'Bearer scope="knowledge:read access:execute"',
        'Bearer scope="knowledge:read", scope="knowledge:read"',
        'Bearer resource_metadata="unterminated',
    ],
)
def test_untrusted_challenges_never_trigger_another_request(challenge: str) -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(401, headers={"WWW-Authenticate": challenge})

    with (
        httpx.Client(transport=httpx.MockTransport(handler)) as http,
        pytest.raises(AuthenticationDenied),
    ):
        Discovery(http).resource(BINDING, ISSUER)
    assert calls == [BINDING.url]


@pytest.mark.parametrize("mode", ["redirect", "large", "compressed", "outage", "deadline"])
def test_metadata_transport_fails_closed_without_credentials(mode: str) -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if mode == "redirect":
            return httpx.Response(302, headers={"Location": "https://evil.invalid"})
        if mode == "large":
            return httpx.Response(200, content=b" " * 32769)
        if mode == "compressed":
            return httpx.Response(200, headers={"Content-Encoding": "br"})
        return httpx.Response(503)

    with (
        httpx.Client(
            transport=httpx.MockTransport(handler),
            auth=("secret", "secret"),
            headers={"Authorization": "Bearer secret", "Proxy-Authorization": "secret"},
            cookies={"session": "secret"},
            follow_redirects=True,
        ) as http,
        pytest.raises(AuthenticationDenied),
    ):
        Discovery(http, deadline=time.monotonic() - 1 if mode == "deadline" else None).issuer(
            ISSUER, AUTH, TOKEN, JWKS
        )
    assert len(calls) == (0 if mode == "deadline" else 1)
    for request in calls:
        assert all(
            h not in request.headers for h in ("authorization", "cookie", "proxy-authorization")
        )


def test_bearer_parameters_ignore_other_header_schemes_and_reject_ambiguity() -> None:
    assert challenge_parameters(['Basic realm="desk"', 'bEaReR scope="knowledge:read"']) == {
        "scope": "knowledge:read"
    }
    with pytest.raises(AuthenticationDenied):
        challenge_parameters(['Bearer scope="knowledge:read"', 'Bearer scope="access:read"'])
