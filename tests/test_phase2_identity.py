"""Real signatures and HTTP boundaries; local provider replies are deterministic doubles."""

import base64
import hashlib
import json
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from service_desk.app.identity import SESSION_COOKIE, ExpiringStore, create_identity_app
from service_desk.contracts import FixtureSet
from service_desk.core.auth.lab import realm_configuration
from service_desk.core.auth.oidc import LoginResult, OIDCClient
from service_desk.core.auth.tokens import (
    AuthenticationDenied,
    ResourceBinding,
    TokenValidator,
    key_client,
)
from service_desk.mcp.identity import create_identity_mcp

ISSUER = "https://identity.example/realms/desk"
RESOURCES = tuple(
    ResourceBinding(name, f"https://127.0.0.1:{port}/mcp", name + ":read")
    for name, port in (("knowledge", 19482), ("tickets", 19483), ("access", 19484))
)
IDENTITIES = {(ISSUER, "subject-erin"): "erin", (ISSUER, "subject-alice"): "alice"}


class RotatingKeys(jwt.PyJWKClient):
    def __init__(self) -> None:
        super().__init__(ISSUER + "/certs", cooldown_duration=0)
        self.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.kid = "first"
        self.fetches = 0
        self.unavailable = False

    def fetch_data(self) -> dict[str, Any]:
        self.fetches += 1
        if self.unavailable:
            raise jwt.PyJWKClientConnectionError("synthetic private provider failure")
        public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.private.public_key()))
        result = {"keys": [{**public, "kid": self.kid, "use": "sig", "alg": "RS256"}]}
        assert self.jwk_set_cache is not None
        self.jwk_set_cache.put(result)
        return result

    def sign(self, **overrides: Any) -> str:
        now = int(time.time())
        claims = {
            "iss": ISSUER,
            "sub": "subject-erin",
            "azp": "gateway",
            "aud": "knowledge",
            "exp": now + 120,
            "iat": now - 1,
            "scope": "knowledge:read",
            "typ": "Bearer",
            **overrides,
        }
        return jwt.encode(claims, self.private, algorithm="RS256", headers={"kid": self.kid})


@pytest.fixture
def keys() -> RotatingKeys:
    return RotatingKeys()


@pytest.mark.parametrize(
    "overrides",
    [
        {"iss": "https://attacker.invalid"},
        {"aud": "tickets"},
        {"aud": ["knowledge", "tickets"]},
        {"azp": "executor"},
        {"azp": "unregistered"},
        {"sub": "unknown"},
        {"sub": "agent"},
        {"exp": 1},
        {"iat": 9999999999},
        {"nbf": 9999999999},
        {"exp": "9999999999"},
        {"scope": ["knowledge:read"]},
        {"typ": "ID"},
    ],
)
def test_signed_token_contract_denials(keys: RotatingKeys, overrides: dict[str, Any]) -> None:
    validator = TokenValidator(ISSUER, keys, IDENTITIES)
    with pytest.raises(AuthenticationDenied) as error:
        validator.access(keys.sign(**overrides), "knowledge")
    assert str(error.value) == ""


def test_signature_algorithm_missing_claims_and_unknown_kid(keys: RotatingKeys) -> None:
    validator = TokenValidator(ISSUER, keys, IDENTITIES)
    claims = jwt.decode(keys.sign(), options={"verify_signature": False})
    missing = dict(claims)
    del missing["exp"]
    other = RotatingKeys()
    for token in (
        "malformed",
        "x" * 16385,
        jwt.encode(claims, "a sufficiently long unrelated secret", algorithm="HS256"),
        jwt.encode(claims, "", algorithm="none"),
        jwt.encode(missing, keys.private, algorithm="RS256", headers={"kid": keys.kid}),
        jwt.encode(claims, keys.private, algorithm="RS256", headers={"kid": "missing"}),
        other.sign(),
    ):
        with pytest.raises(AuthenticationDenied):
            validator.access(token, "knowledge")


def test_jwks_rotation_removal_and_outage_fail_closed(keys: RotatingKeys) -> None:
    validator = TokenValidator(ISSUER, keys, IDENTITIES)
    old = keys.sign()
    assert validator.access(old, "knowledge").principal_id == "erin"
    assert keys.fetches == 1
    keys.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    keys.kid = "rotated"
    fresh = keys.sign()
    assert validator.access(fresh, "knowledge").principal_id == "erin"
    assert keys.fetches == 2
    with pytest.raises(AuthenticationDenied):
        validator.access(old, "knowledge")
    assert keys.jwk_set_cache is not None
    keys.jwk_set_cache.put(None)
    keys.unavailable = True
    with pytest.raises(AuthenticationDenied):
        validator.access(fresh, "knowledge")


@pytest.mark.parametrize("binding", RESOURCES)
def test_mcp_auth_metadata_and_direct_calls(keys: RotatingKeys, binding: ResourceBinding) -> None:
    validator = TokenValidator(ISSUER, keys, IDENTITIES)
    app = create_identity_mcp(validator, binding)
    with TestClient(app, base_url=binding.url.removesuffix("/mcp")) as http:
        message = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "auth-test", "version": "1"},
            },
        }
        accept = {"Accept": "application/json, text/event-stream"}
        for headers in ({}, {"X-User": "erin", "X-Client": "gateway"}):
            denied = http.post("/mcp", headers={**accept, **headers}, json=message)
            assert denied.status_code == 401
            assert "resource_metadata=" in denied.headers["www-authenticate"]
        metadata = http.get("/.well-known/oauth-protected-resource/mcp").json()
        assert metadata["resource"] == binding.url
        assert metadata["authorization_servers"] == [ISSUER]
        assert metadata["scopes_supported"] == [binding.scope]
        for other in RESOURCES:
            token = keys.sign(aud=other.audience, scope=other.scope)
            response = http.post(
                "/mcp", json=message, headers={**accept, "Authorization": "Bearer " + token}
            )
            assert response.status_code == (200 if other == binding else 401)
        no_scope = http.post(
            "/mcp",
            json=message,
            headers={
                **accept,
                "Authorization": "Bearer " + keys.sign(aud=binding.audience, scope=""),
            },
        )
        assert no_scope.status_code == 403
        good = {
            **accept,
            "Authorization": "Bearer " + keys.sign(aud=binding.audience, scope=binding.scope),
        }
        response = http.post("/mcp", headers=good, json=message)
        assert response.json()["result"]["protocolVersion"] == "2025-11-25"
        result = http.post(
            "/mcp",
            headers=good,
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "identity_status", "arguments": {}},
            },
        ).json()["result"]
        assert not result.get("isError")
        assert result["structuredContent"] == {"subject": "subject-erin", "client_id": "gateway"}
        tools = http.post(
            "/mcp",
            headers=good,
            json={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/list",
            },
        ).json()["result"]["tools"]
        assert [t["name"] for t in tools] == ["identity_status"]


class Provider:
    def __init__(self, keys: RotatingKeys) -> None:
        self.keys = keys
        self.nonce = ""
        self.posts: list[dict[str, list[str]]] = []
        self.id_overrides: dict[str, Any] = {}
        self.access_overrides: dict[str, Any] = {}
        self.exchange_overrides: dict[str, Any] = {}
        self.fail = False

    def respond(self, request: httpx.Request) -> httpx.Response:
        if self.fail:
            return httpx.Response(400, json={"error_description": "DO-NOT-EXPOSE-secret"})
        fields = parse_qs(request.content.decode())
        self.posts.append(fields)
        if fields["grant_type"] == ["authorization_code"]:
            return httpx.Response(
                200,
                json={
                    "token_type": "Bearer",
                    "id_token": self.keys.sign(
                        azp="web", aud="web", nonce=self.nonce, typ="ID", **self.id_overrides
                    ),
                    "access_token": self.keys.sign(
                        azp="web",
                        aud="gateway",
                        scope="openid knowledge:read tickets:read access:read",
                        **self.access_overrides,
                    ),
                },
            )
        return httpx.Response(
            200,
            json={
                "token_type": "Bearer",
                "access_token": self.keys.sign(
                    **{
                        "aud": fields["audience"][0],
                        "scope": fields["scope"][0],
                        **self.exchange_overrides,
                    }
                ),
            },
        )


def client_for(keys: RotatingKeys) -> tuple[OIDCClient, Provider]:
    provider = Provider(keys)
    client = OIDCClient(
        TokenValidator(ISSUER, keys, IDENTITIES, client_id="web"),
        "synthetic-web-secret",
        "https://127.0.0.1:19481/callback",
        RESOURCES,
        httpx.Client(transport=httpx.MockTransport(provider.respond), follow_redirects=False),
        TokenValidator(ISSUER, keys, IDENTITIES),
        "synthetic-gateway-secret",
    )
    return client, provider


def sign_in(oidc: OIDCClient, provider: Provider) -> LoginResult:
    attempt, url = oidc.begin(RESOURCES[0].url)
    params = parse_qs(urlsplit(url).query)
    assert params["code_challenge_method"] == ["S256"]
    expected = base64.urlsafe_b64encode(hashlib.sha256(attempt.verifier.encode()).digest())
    assert params["code_challenge"] == [expected.rstrip(b"=").decode()]
    assert params["resource"] == [RESOURCES[0].url]
    provider.nonce = attempt.nonce
    login = oidc.finish(attempt, attempt.state, "synthetic-code")
    assert provider.posts[-1]["code_verifier"] == [attempt.verifier]
    assert provider.posts[-1]["client_secret"] == ["synthetic-web-secret"]
    return login


def test_confidential_login_and_allowlisted_delegation(keys: RotatingKeys) -> None:
    oidc, provider = client_for(keys)
    login = sign_in(oidc, provider)
    assert login.access_token not in repr(login)
    for binding in RESOURCES:
        token = oidc.exchange(login, binding.url)
        identity = oidc.delegated_validator.access(token, binding.audience)
        assert identity.subject == login.identity.subject
        assert identity.scopes == {binding.scope}
        assert provider.posts[-1]["resource"] == [binding.url]
        assert provider.posts[-1]["client_secret"] == ["synthetic-gateway-secret"]
    before = len(provider.posts)
    for resource in ("https://attacker.invalid/mcp", "https://127.0.0.1:19484/execute"):
        with pytest.raises(AuthenticationDenied):
            oidc.exchange(login, resource)
    assert len(provider.posts) == before


@pytest.mark.parametrize(
    "overrides",
    [
        {"scope": "knowledge:read execute:grant"},
        {"scope": "tickets:read"},
        {"sub": "subject-alice"},
        {"aud": "tickets"},
        {"azp": "executor"},
    ],
)
def test_exchange_rejects_escalation_and_subject_replacement(
    keys: RotatingKeys,
    overrides: dict[str, Any],
) -> None:
    oidc, provider = client_for(keys)
    login = sign_in(oidc, provider)
    provider.exchange_overrides = overrides
    with pytest.raises(AuthenticationDenied):
        oidc.exchange(login, RESOURCES[0].url)


def test_exchange_requires_original_scope_and_bound_identity(keys: RotatingKeys) -> None:
    oidc, provider = client_for(keys)
    login = sign_in(oidc, provider)
    token = keys.sign(azp="web", aud="gateway", scope="tickets:read")
    limited = LoginResult(oidc.validator.access(token, "gateway"), token)
    before = len(provider.posts)
    for attempted in (
        limited,
        replace(login, identity=replace(login.identity, subject="subject-alice")),
    ):
        with pytest.raises(AuthenticationDenied):
            oidc.exchange(attempted, RESOURCES[0].url)
    assert len(provider.posts) == before


def test_nonce_state_subject_mismatch_and_provider_error_are_safe(keys: RotatingKeys) -> None:
    oidc, provider = client_for(keys)
    attempt, _ = oidc.begin(RESOURCES[0].url)
    with pytest.raises(AuthenticationDenied):
        oidc.finish(attempt, "wrong-state", "code")
    assert not provider.posts
    with pytest.raises(AuthenticationDenied):
        oidc.finish(attempt, attempt.state, "code")  # provider nonce does not match
    provider.nonce = attempt.nonce
    provider.id_overrides = {"sub": "subject-alice"}
    with pytest.raises(AuthenticationDenied):
        oidc.finish(attempt, attempt.state, "code")
    provider.fail = True
    with pytest.raises(AuthenticationDenied) as error:
        oidc.finish(attempt, attempt.state, "code")
    assert str(error.value) == ""


def test_server_sessions_callback_replay_and_csrf(keys: RotatingKeys) -> None:
    oidc, provider = client_for(keys)
    with TestClient(create_identity_app(oidc), base_url="https://127.0.0.1:19481") as http:
        assert http.get("/session", headers={"X-User": "erin"}).status_code == 401
        start = http.get("/login", follow_redirects=False)
        assert start.status_code == 302
        cookie = start.headers["set-cookie"]
        assert all(flag in cookie for flag in ("Secure", "HttpOnly", "SameSite=lax", "Path=/"))
        query = parse_qs(urlsplit(start.headers["location"]).query)
        provider.nonce = query["nonce"][0]
        callback = "/callback?" + "state=" + query["state"][0] + "&code=code"
        response = http.get(callback)
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        session_id = http.cookies[SESSION_COOKIE]
        assert len(session_id) > 32 and "." not in session_id
        assert http.get(callback).status_code == 401
        info = http.get("/session").json()
        assert info["principal_id"] == "erin"
        assert "access_token" not in info
        for headers in (
            {},
            {"Origin": "https://evil.invalid", "X-CSRF-Token": info["csrf"]},
            {"Origin": "https://127.0.0.1:19481", "X-CSRF-Token": "wrong"},
        ):
            assert http.post("/logout", headers=headers).status_code == 403
        assert (
            http.post(
                "/logout",
                headers={
                    "Origin": "https://127.0.0.1:19481",
                    "X-CSRF-Token": info["csrf"],
                },
            ).status_code
            == 200
        )
        assert http.get("/session").status_code == 401
        http.cookies.set(SESSION_COOKIE, session_id)
        assert http.get("/session").status_code == 401


def test_callback_is_browser_bound_and_sessions_expire(keys: RotatingKeys) -> None:
    oidc, provider = client_for(keys)
    now = [time.time()]
    app = create_identity_app(oidc, clock=lambda: now[0])
    with (
        TestClient(app, base_url="https://127.0.0.1:19481") as first,
        TestClient(app, base_url="https://127.0.0.1:19481") as other,
    ):
        start = first.get("/login", follow_redirects=False)
        query = parse_qs(urlsplit(start.headers["location"]).query)
        provider.nonce = query["nonce"][0]
        path = "/callback?state=" + query["state"][0] + "&code=code"
        assert other.get(path).status_code == 401
        assert first.get(path).status_code == 200
        now[0] += 121
        assert first.get("/session").status_code == 401
        assert first.get("http://127.0.0.1:19481/login").status_code == 400


def test_pending_state_expiry_and_atomic_consumption() -> None:
    now = [100.0]
    store = ExpiringStore[str](lambda: now[0])
    key = store.put("attempt", 110)
    with ThreadPoolExecutor(max_workers=8) as pool:
        values = list(pool.map(lambda _: store.get(key, consume=True), range(16)))
    assert values.count("attempt") == 1
    key = store.put("expired", 110)
    now[0] = 110
    assert store.get(key) is None


def test_untrusted_identity_urls_rejected() -> None:
    import ssl

    for url in ("http://identity.example/certs", "file:///secret", "https://user:pass@host/jwks"):
        with pytest.raises(ValueError):
            key_client(url, ssl.create_default_context())


def test_realm_separates_login_delegation_and_workload_capabilities(fixtures: FixtureSet) -> None:
    clients = {name: "synthetic-secret" for name in ("web", "gateway", "executor", "worker")}
    humans = {p.id: "synthetic-password" for p in fixtures.principals if p.kind == "human"}
    realm = realm_configuration(fixtures, clients, humans)
    # Round-trip as data so this also checks the actual serialized import shape.
    data = json.loads(json.dumps(realm))
    registered = {c["clientId"]: c for c in data["clients"]}
    assert registered["web"]["publicClient"] is False
    assert registered["web"]["attributes"]["pkce.code.challenge.method"] == "S256"
    assert registered["gateway"]["attributes"]["standard.token.exchange.enabled"] == "true"
    assert set(registered["gateway"]["optionalClientScopes"]) == {
        "knowledge:read",
        "tickets:read",
        "access:read",
    }
    assert "execution-audience" not in registered["gateway"]["defaultClientScopes"]
    assert registered["executor"]["defaultClientScopes"] == ["execution-audience", "access:execute"]
    assert registered["worker"]["defaultClientScopes"] == ["lifecycle-audience", "access:lifecycle"]
    assert {u["username"] for u in data["users"]} == set(humans)
    for name in clients:
        assert registered[name]["directAccessGrantsEnabled"] is False
        assert registered[name]["protocolMappers"][0]["protocolMapper"] == "oidc-sub-mapper"


@pytest.mark.parametrize("claim", ["iss", "sub", "aud", "azp", "exp", "iat"])
def test_required_signed_claims_fail_closed(keys: RotatingKeys, claim: str) -> None:
    claims = jwt.decode(keys.sign(), options={"verify_signature": False})
    del claims[claim]
    token = jwt.encode(claims, keys.private, algorithm="RS256", headers={"kid": keys.kid})
    with pytest.raises(AuthenticationDenied):
        TokenValidator(ISSUER, keys, IDENTITIES).access(token, "knowledge")


def test_malformed_callback_state_fails_closed(keys: RotatingKeys) -> None:
    oidc, provider = client_for(keys)
    with TestClient(create_identity_app(oidc), base_url="https://127.0.0.1:19481") as http:
        for state in ("unicode-\u2603", "wrong"):
            http.get("/login", follow_redirects=False)
            assert http.get("/callback", params={"state": state, "code": "code"}).status_code == 401
        assert not provider.posts


def test_token_endpoint_redirect_cannot_forward_credentials(keys: RotatingKeys) -> None:
    oidc, _ = client_for(keys)
    calls: list[str] = []

    def redirect(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(307, headers={"Location": "https://attacker.invalid/steal"})

    oidc.http = httpx.Client(transport=httpx.MockTransport(redirect), follow_redirects=True)
    attempt, _ = oidc.begin(RESOURCES[0].url)
    with pytest.raises(AuthenticationDenied):
        oidc.finish(attempt, attempt.state, "code")
    assert calls == [oidc.token_endpoint]
