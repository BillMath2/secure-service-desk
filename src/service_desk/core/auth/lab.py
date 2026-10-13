"""Synthetic Keycloak realm contract. Secrets are supplied only by local preparation."""

from uuid import NAMESPACE_URL, uuid5

from service_desk.contracts import FixtureSet
from service_desk.core.auth.tokens import ResourceBinding

ISSUER = "https://127.0.0.1:19443/realms/service-desk-phase2"
REDIRECT = "https://127.0.0.1:19481/callback"
RESOURCES = tuple(
    ResourceBinding(name, f"https://127.0.0.1:{port}/mcp", name + ":read")
    for name, port in (("knowledge", 19482), ("tickets", 19483), ("access", 19484))
)


def subject_for(principal: str) -> str:
    return str(uuid5(NAMESPACE_URL, ISSUER + "/fixture/" + principal))


def realm_configuration(
    fixtures: FixtureSet,
    secrets: dict[str, str],
    passwords: dict[str, str],
) -> dict[str, object]:
    def scope(name: str, audience: str | None = None) -> dict[str, object]:
        return {
            "name": name,
            "protocol": "openid-connect",
            "attributes": {"include.in.token.scope": "false" if audience else "true"},
            "protocolMappers": []
            if not audience
            else [
                {
                    "name": audience,
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-audience-mapper",
                    "config": {"included.client.audience": audience, "access.token.claim": "true"},
                }
            ],
        }

    read_scopes = [r.scope for r in RESOURCES]
    audiences = [r.audience for r in RESOURCES] + ["gateway", "execution", "lifecycle"]
    clients: list[dict[str, object]] = [
        {
            "clientId": "web",
            "publicClient": False,
            "secret": secrets["web"],
            "standardFlowEnabled": True,
            "directAccessGrantsEnabled": False,
            "serviceAccountsEnabled": False,
            "fullScopeAllowed": False,
            "redirectUris": [REDIRECT],
            "webOrigins": [],
            "attributes": {"pkce.code.challenge.method": "S256"},
            "defaultClientScopes": ["gateway-audience"],
            "optionalClientScopes": read_scopes,
        },
        {
            "clientId": "gateway",
            "publicClient": False,
            "secret": secrets["gateway"],
            "standardFlowEnabled": False,
            "directAccessGrantsEnabled": False,
            "serviceAccountsEnabled": False,
            "fullScopeAllowed": False,
            "attributes": {"standard.token.exchange.enabled": "true"},
            "defaultClientScopes": [r.audience + "-audience" for r in RESOURCES],
            "optionalClientScopes": read_scopes,
        },
    ]
    for client, audience, capability in (
        ("executor", "execution", "access:execute"),
        ("worker", "lifecycle", "access:lifecycle"),
    ):
        clients.append(
            {
                "clientId": client,
                "publicClient": False,
                "secret": secrets[client],
                "standardFlowEnabled": False,
                "directAccessGrantsEnabled": False,
                "serviceAccountsEnabled": True,
                "fullScopeAllowed": False,
                "defaultClientScopes": [audience + "-audience", capability],
                "optionalClientScopes": [],
            }
        )
    clients.extend(
        {"clientId": name, "bearerOnly": True, "publicClient": False}
        for name in audiences
        if name != "gateway"
    )
    for registered_client in clients:
        if not registered_client.get("bearerOnly"):
            registered_client["protocolMappers"] = [
                {
                    "name": "subject",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-sub-mapper",
                    "config": {"access.token.claim": "true"},
                }
            ]
    return {
        "realm": "service-desk-phase2",
        "enabled": True,
        "sslRequired": "all",
        "registrationAllowed": False,
        "resetPasswordAllowed": False,
        "accessTokenLifespan": 120,
        "clients": clients,
        "clientScopes": [scope(s) for s in [*read_scopes, "access:execute", "access:lifecycle"]]
        + [scope(a + "-audience", a) for a in audiences],
        "users": [
            {
                "id": subject_for(p.id),
                "username": p.id,
                "enabled": True,
                "emailVerified": True,
                "email": p.id + "@example.invalid",
                "firstName": p.id.title(),
                "lastName": "Synthetic",
                "credentials": [{"type": "password", "value": passwords[p.id], "temporary": False}],
            }
            for p in fixtures.principals
            if p.kind == "human"
        ],
    }
