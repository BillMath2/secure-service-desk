"""Disposable OIDC + delegated MCP + PostgreSQL probe. Never emits usable tokens."""

import asyncio
import base64
import hashlib
import json
import secrets
import ssl
import threading
import time
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import psycopg
import uvicorn
from mcp.server import MCPServer
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from pydantic import AnyHttpUrl

ROOT = Path(__file__).resolve().parents[1]
ISSUER = "https://127.0.0.1:18443/realms/service-desk-spike"
RESOURCE = "http://127.0.0.1:18082/mcp"
REDIRECT = "http://127.0.0.1:18081/callback"


class LoginForm(HTMLParser):
    action: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if tag == "form" and attributes.get("id") == "kc-form-login":
            self.action = attributes.get("action")


def main() -> None:
    credentials = json.loads((ROOT / ".lab/spike-credentials.json").read_text())
    checks: dict[str, object] = {}
    trust = ssl.create_default_context(cafile=str(ROOT / ".lab/tls/certificate.pem"))
    with httpx.Client(timeout=15, trust_env=False, verify=trust) as client:
        deadline = time.monotonic() + 45
        while True:
            try:
                discovery = client.get(ISSUER + "/.well-known/openid-configuration", timeout=2)
                if discovery.status_code == 200:
                    break
            except httpx.TransportError:
                pass
            if time.monotonic() >= deadline:
                raise RuntimeError("local identity provider not ready; inspect spike startup logs")
            time.sleep(1)
        discovery.raise_for_status()
        metadata = discovery.json()
        assert "S256" in metadata["code_challenge_methods_supported"]
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(
            b"="
        )
        state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
        login = client.get(
            metadata["authorization_endpoint"],
            params={
                "client_id": "web",
                "response_type": "code",
                "redirect_uri": REDIRECT,
                "scope": "openid",
                "state": state,
                "nonce": nonce,
                "code_challenge": challenge.decode(),
                "code_challenge_method": "S256",
                "resource": RESOURCE,
            },
        )
        login.raise_for_status()
        form = LoginForm()
        form.feed(login.text)
        assert form.action and form.action.startswith(ISSUER + "/")
        signed_in = client.post(
            form.action,
            data={
                "username": credentials["username"],
                "password": credentials["password"],
            },
        )
        if signed_in.status_code != 302:
            hints = [
                text
                for text in (
                    "Invalid username or password",
                    "Update Account Information",
                    "Update password",
                    "Cookie not found",
                    "Unexpected error",
                    "Email",
                    "Verify email",
                    "Invalid user credentials",
                    "Sign in",
                    "Restart login",
                )
                if text in signed_in.text
            ]
            raise RuntimeError(
                f"synthetic OIDC login status={signed_in.status_code}; hints={hints}"
            )
        location = signed_in.headers["location"]
        assert location.startswith(REDIRECT + "?")
        query = parse_qs(urlparse(location).query)
        assert query["state"] == [state]
        token_response = client.post(
            metadata["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "client_id": "web",
                "redirect_uri": REDIRECT,
                "code": query["code"][0],
                "code_verifier": verifier,
                "resource": RESOURCE,
            },
        )
        token_response.raise_for_status()
        original = token_response.json()
        keys = jwt.PyJWKClient(metadata["jwks_uri"], ssl_context=trust)
        id_claims = jwt.decode(
            original["id_token"],
            keys.get_signing_key_from_jwt(original["id_token"]).key,
            algorithms=["RS256"],
            audience="web",
            issuer=ISSUER,
        )
        assert id_claims["nonce"] == nonce
        exchanged_response = client.post(
            metadata["token_endpoint"],
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "client_id": "gateway",
                "client_secret": credentials["client_secret"],
                "subject_token": original["access_token"],
                "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "audience": "knowledge",
                "resource": RESOURCE,
            },
        )
        exchanged_response.raise_for_status()
        delegated = exchanged_response.json()["access_token"]
        claims = jwt.decode(
            delegated,
            keys.get_signing_key_from_jwt(delegated).key,
            algorithms=["RS256"],
            audience="knowledge",
            issuer=ISSUER,
            options={"require": ["sub", "azp", "exp", "iat"]},
        )
        assert claims["sub"] == id_claims["sub"] and claims["azp"] == "gateway"
        checks["oidc_code_pkce_nonce"] = True
        checks["delegated_user_preserved"] = True
        checks["delegated_client"] = claims["azp"]
        checks["delegated_audience"] = claims["aud"]
        checks["delegated_scopes"] = claims.get("scope", "").split()
        checks["act_claim_present"] = "act" in claims

        class Verifier:
            async def verify_token(self, token: str) -> AccessToken | None:
                try:
                    token_claims = jwt.decode(
                        token,
                        keys.get_signing_key_from_jwt(token).key,
                        algorithms=["RS256"],
                        audience="knowledge",
                        issuer=ISSUER,
                        options={"require": ["sub", "azp", "exp", "iat"]},
                    )
                    if token_claims["azp"] != "gateway":
                        return None
                    return AccessToken(
                        token=token,
                        client_id=token_claims["azp"],
                        subject=token_claims["sub"],
                        scopes=token_claims.get("scope", "").split(),
                        expires_at=token_claims["exp"],
                        resource=RESOURCE,
                    )
                except jwt.PyJWTError:
                    return None

        server = MCPServer(
            "Identity spike",
            token_verifier=Verifier(),
            auth=AuthSettings(
                issuer_url=AnyHttpUrl(ISSUER),
                resource_server_url=AnyHttpUrl(RESOURCE),
                required_scopes=["knowledge:read"],
                validate_token_resource=True,
            ),
            log_level="CRITICAL",
        )

        @server.tool()
        def whoami() -> dict[str, str]:
            token = get_access_token()
            assert token is not None and token.subject
            return {"subject": token.subject, "client_id": token.client_id}

        application = server.streamable_http_app(stateless_http=True, json_response=True)
        runner = uvicorn.Server(
            uvicorn.Config(
                application,
                host="127.0.0.1",
                port=18082,
                log_level="critical",
                access_log=False,
            )
        )
        thread = threading.Thread(target=lambda: asyncio.run(runner.serve()), daemon=True)
        thread.start()
        try:
            for _ in range(100):
                if runner.started:
                    break
                time.sleep(0.05)
            assert runner.started
            headers = {"Accept": "application/json, text/event-stream"}
            initialize = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "phase0-probe", "version": "0.1"},
                },
            }
            missing = client.post(RESOURCE, headers=headers, json=initialize)
            assert missing.status_code == 401
            assert "resource_metadata=" in missing.headers["www-authenticate"]
            checks["missing_token_denied"] = True
            wrong = client.post(
                RESOURCE,
                headers={
                    **headers,
                    "Authorization": "Bearer " + original["access_token"],
                },
                json=initialize,
            )
            assert wrong.status_code == 401
            checks["wrong_audience_denied"] = True
            forged = client.post(RESOURCE, headers={**headers, "X-User": "alice"}, json=initialize)
            assert forged.status_code == 401
            checks["forged_username_denied"] = True
            authorized_headers = {**headers, "Authorization": "Bearer " + delegated}
            initialized = client.post(RESOURCE, headers=authorized_headers, json=initialize)
            initialized.raise_for_status()
            checks["negotiated_protocol"] = initialized.json()["result"]["protocolVersion"]
            called = client.post(
                RESOURCE,
                headers=authorized_headers,
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "whoami", "arguments": {}},
                },
            )
            called.raise_for_status()
            result = called.json()["result"]
            assert not result.get("isError")
            assert id_claims["sub"] in json.dumps(result)
            checks["mcp_tool_round_trip"] = True
        finally:
            runner.should_exit = True
            thread.join(timeout=10)

    with psycopg.connect(
        host="127.0.0.1",
        port=15432,
        dbname="service_desk",
        user="lab_migrator",
        password=(ROOT / ".lab/postgres-password").read_text(),
        autocommit=True,
    ) as connection:
        exists = connection.execute("SELECT to_regclass('service_desk.schema_version')").fetchone()
        applied = set()
        if exists and exists[0] is not None:
            applied = {
                row[0]
                for row in connection.execute("SELECT version FROM service_desk.schema_version")
            }
        for migration in sorted((ROOT / "migrations").glob("*.sql")):
            if int(migration.name.split("_", 1)[0]) not in applied:
                connection.execute(migration.read_text())
        row = connection.execute("SELECT max(version) FROM service_desk.schema_version").fetchone()
        assert row and row[0] == 2
        assert connection.execute(
            "SELECT has_table_privilege('desk_knowledge', 'service_desk.document', 'SELECT')"
        ).fetchone() == (True,)
        assert connection.execute(
            "SELECT has_table_privilege('desk_knowledge', 'service_desk.document', 'INSERT')"
        ).fetchone() == (False,)
        checks["postgres_migrations"] = True
        checks["knowledge_role_read_only"] = True
    output = ROOT / "reports/phase0-identity-spike.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(checks, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(checks, indent=2))


if __name__ == "__main__":
    main()
