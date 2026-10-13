"""Real Keycloak rotation, retirement, expiry and pinned MCP discovery on the disposable lab."""

import copy
import hashlib
import json
import ssl
import threading
import time
from datetime import UTC, datetime
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import httpx
import jwt
import uvicorn
from check_phase2_identity import LoginForm
from phase2_runtime import LOCAL, ROOT, load_client, load_validator, server_config

from service_desk.core.auth.discovery import Discovery, issuer_locations
from service_desk.core.auth.lab import ISSUER, RESOURCES
from service_desk.core.auth.tokens import AuthenticationDenied
from service_desk.core.gateway.dispatch import ReadGateway
from service_desk.core.gateway.store import TaskStore
from service_desk.mcp.identity import create_identity_mcp
from service_desk.mcp.reads import create_read_mcp
from service_desk.reads import ReadService

ADMIN = "https://127.0.0.1:19443/admin/realms/service-desk-phase2"


def main() -> None:
    checks = {}
    report = {
        "phase": "2-auth-compatibility",
        "recorded_at": datetime.now(UTC).isoformat(),
        "checks": checks,
        "passed": False,
        "cache_lifetime_seconds": 60,
        "registration": "pre-registered confidential clients",
    }
    servers = []
    stage = "startup"
    original_component = None
    created_component = None
    original_lifespan = None
    admin_token = None
    admin_expires = 0.0

    def check(name, condition):
        checks[name] = bool(condition)
        if not condition:
            raise RuntimeError(name)

    trust = ssl.create_default_context(cafile=str(LOCAL / "tls/certificate.pem"))
    with httpx.Client(verify=trust, trust_env=False, timeout=10, follow_redirects=False) as http:

        def admin(method, path, body=None):
            nonlocal admin_token, admin_expires
            if time.monotonic() >= admin_expires:
                renewed = http.post(
                    "https://127.0.0.1:19443/realms/master/protocol/openid-connect/token",
                    data={"client_id": "admin-cli", "grant_type": "password", **rotation},
                )
                if renewed.status_code != 200:
                    raise RuntimeError("Temporary admin renewal failed")
                data = renewed.json()
                admin_token = data["access_token"]
                admin_expires = time.monotonic() + max(0, int(data["expires_in"]) - 10)
            response = http.request(
                method, ADMIN + path, headers={"Authorization": "Bearer " + admin_token}, json=body
            )
            if response.status_code not in (200, 201, 204):
                raise RuntimeError("Admin operation failed")
            return response

        try:
            credentials = json.loads((LOCAL / "credentials.json").read_text())
            rotation = json.loads((ROOT / ".lab/phase2-rotation/credentials.json").read_text())
            connections = json.loads((ROOT / ".lab/phase2-read/connections.json").read_text())
            oidc = load_client(http, trust)
            deadline = time.monotonic() + 45
            while True:
                try:
                    if http.get(ISSUER + "/.well-known/openid-configuration").status_code == 200:
                        break
                except httpx.TransportError:
                    pass
                if time.monotonic() >= deadline:
                    raise RuntimeError("Issuer unavailable")
                time.sleep(0.5)
            oidc.check_discovery()
            response = http.post(
                "https://127.0.0.1:19443/realms/master/protocol/openid-connect/token",
                data={"client_id": "admin-cli", "grant_type": "password", **rotation},
            )
            check("temporary_admin_authenticated", response.status_code == 200)
            admin_token = response.json()["access_token"]
            admin_expires = time.monotonic() + max(0, int(response.json()["expires_in"]) - 10)
            realm = admin("GET", "").json()
            check("dedicated_realm", realm["realm"] == "service-desk-phase2")
            original_lifespan = realm["accessTokenLifespan"]
            for binding in RESOURCES:
                app = (
                    create_identity_mcp(oidc.delegated_validator, binding)
                    if binding.audience == "access"
                    else create_read_mcp(
                        oidc.delegated_validator,
                        binding,
                        ReadService(binding.audience, TaskStore(connections[binding.audience])),
                    )
                )
                server = uvicorn.Server(server_config(app, urlsplit(binding.url).port))
                thread = threading.Thread(target=server.run, daemon=True)
                servers.append((server, thread))
                thread.start()
            deadline = time.monotonic() + 10
            while not all(s.started for s, _ in servers) and time.monotonic() < deadline:
                time.sleep(0.05)
            check("tls_resources_started", all(s.started for s, _ in servers))
            stage = "discovery"
            for binding in RESOURCES:
                discovery = Discovery(http)
                selected = discovery.resource(binding, ISSUER)
                check(binding.audience + "_challenge_discovery", selected.endswith("/mcp"))
                check(
                    binding.audience + "_issuer_discovery",
                    discovery.issuer(
                        ISSUER,
                        oidc.authorization_endpoint,
                        oidc.token_endpoint,
                        oidc.validator.keys.uri,
                    )
                    == issuer_locations(ISSUER)[0],
                )

            def login():
                attempt, url = oidc.begin(RESOURCES[0].url)
                with httpx.Client(verify=trust, timeout=10, trust_env=False) as browser:
                    form = LoginForm()
                    form.feed(browser.get(url).text)
                    if not form.action or not form.action.startswith(ISSUER + "/"):
                        raise RuntimeError("Untrusted form")
                    redirected = browser.post(
                        form.action,
                        data={"username": "alice", "password": credentials["users"]["alice"]},
                    )
                    query = parse_qs(urlsplit(redirected.headers["location"]).query)
                return oidc.finish(attempt, query["state"][0], query["code"][0])

            initialize = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "rotation-probe", "version": "1"},
                },
            }

            def mcp_status(token):
                return http.post(
                    RESOURCES[0].url,
                    headers={
                        "Authorization": "Bearer " + token,
                        "Accept": "application/json, text/event-stream",
                    },
                    json=initialize,
                ).status_code

            def read(login_result):
                task = TaskStore(connections["creator"]).create(
                    login_result.identity, "ticket-alice"
                )
                result = ReadGateway(oidc, TaskStore(connections["gateway"]), http).call(
                    login_result, task, "read_document", {"document_id": "doc-public"}
                )
                data = json.loads(result["content"][0]["text"]) if "content" in result else result
                return (
                    data.get("allowed") is True
                    and data["document"]["citation"] == "document:doc-public@1"
                )

            stage = "old-key"
            old_login = login()
            old_token = oidc.exchange(old_login, RESOURCES[0].url)
            old_kid = jwt.get_unverified_header(old_token)["kid"]
            check("old_key_mcp_allowed", mcp_status(old_token) == 200)
            check("old_key_protected_read", read(old_login))
            keys = admin("GET", "/keys").json()
            key = next(k for k in keys["keys"] if k["kid"] == old_kid)
            original_component = admin("GET", "/components/" + key["providerId"]).json()
            check("generated_rsa_source", original_component["providerId"] == "rsa-generated")
            stage = "rotation"
            priority = int(original_component["config"].get("priority", ["100"])[0]) + 100
            name = "phase2-rotation-" + uuid4().hex
            admin(
                "POST",
                "/components",
                {
                    "name": name,
                    "parentId": realm["id"],
                    "providerId": "rsa-generated",
                    "providerType": "org.keycloak.keys.KeyProvider",
                    "config": {
                        "priority": [str(priority)],
                        "enabled": ["true"],
                        "active": ["true"],
                        "algorithm": ["RS256"],
                        "keySize": ["2048"],
                    },
                },
            )
            components = admin("GET", "/components").json()
            created_component = next(c["id"] for c in components if c["name"] == name)
            # Exercise the real five-second unknown-kid refresh cooldown without clearing caches.
            deadline = time.monotonic() + 10
            while True:
                try:
                    new_login = login()
                    new_token = oidc.exchange(new_login, RESOURCES[0].url)
                    if mcp_status(new_token) == 200:
                        break
                except AuthenticationDenied:
                    pass
                if time.monotonic() >= deadline:
                    raise RuntimeError("New key refresh failed")
                time.sleep(0.5)
            check(
                "new_signing_key_selected", jwt.get_unverified_header(new_token)["kid"] != old_kid
            )
            check("new_key_mcp_allowed_without_restart", mcp_status(new_token) == 200)
            check("old_key_overlap_allowed", mcp_status(old_token) == 200)
            check("new_key_protected_read", read(new_login))
            print(
                "Rotation and protected reads passed; checking retirement against "
                "the real JWKS cache lifetime.",
                flush=True,
            )
            stage = "retirement"
            disabled = copy.deepcopy(original_component)
            disabled["config"]["enabled"] = ["false"]
            disabled["config"]["active"] = ["false"]
            admin("PUT", "/components/" + original_component["id"], disabled)
            published = http.get(oidc.validator.keys.uri).json()
            check("old_key_removed_from_jwks", old_kid not in {k["kid"] for k in published["keys"]})
            try:
                load_validator(trust).access(old_token, "knowledge")
                cold_denied = False
            except AuthenticationDenied:
                cold_denied = True
            check("cold_verifier_rejects_retired_key", cold_denied)
            check("warm_cache_overlap_is_explicit", mcp_status(old_token) == 200)
            started = time.monotonic()
            while mcp_status(old_token) == 200 and time.monotonic() - started < 65:
                time.sleep(1)
            check("warm_verifier_rejects_after_cache_expiry", mcp_status(old_token) == 401)
            check(
                "retirement_denial_precedes_token_expiry",
                old_login.identity.expires_at > time.time(),
            )
            check("new_key_still_accepted", mcp_status(new_token) == 200)
            report["retirement_wait_seconds"] = round(time.monotonic() - started, 2)
            stage = "expiry"
            admin("PUT", "", {"accessTokenLifespan": 3})
            expiring_login = login()
            expiring_token = oidc.exchange(expiring_login, RESOURCES[0].url)
            check("short_lived_real_token_allowed", mcp_status(expiring_token) == 200)
            time.sleep(4)
            check("expired_real_token_denied", mcp_status(expiring_token) == 401)
            report["passed"] = True
        except Exception:
            report["failure_stage"] = stage
        finally:
            try:
                if original_lifespan is not None:
                    admin("PUT", "", {"accessTokenLifespan": original_lifespan})
                if original_component is not None:
                    admin("PUT", "/components/" + original_component["id"], original_component)
                if created_component is not None:
                    admin("DELETE", "/components/" + created_component)
                checks["realm_configuration_restored"] = True
            except Exception:
                checks["realm_configuration_restored"] = False
                report["passed"] = False
            for server, _ in servers:
                server.should_exit = True
            for _, thread in servers:
                thread.join(5)
            files = [
                *sorted((ROOT / "src/service_desk/core/auth").glob("*.py")),
                ROOT / "src/service_desk/core/gateway/dispatch.py",
                ROOT / "scripts/check_phase2_auth_compat.py",
                ROOT / "infra/compose.phase2-rotation.yaml",
                ROOT / "uv.lock",
            ]
            report["source_sha256"] = {
                p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in files
            }
            output = (
                ROOT
                / "reports/phase2-auth-compat/runs"
                / datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
            )
            output.mkdir(parents=True, exist_ok=True)
            (output / "results.json").write_text(
                json.dumps(report, indent=2) + "\n", encoding="utf-8"
            )
            print(
                json.dumps(
                    {
                        "passed": report["passed"],
                        "checks": len(checks),
                        "report": str(output.relative_to(ROOT)),
                    }
                )
            )
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
