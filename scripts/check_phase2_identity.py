"""Opt-in real Keycloak + TLS + browser session + three MCP identity round trips."""

import hashlib
import json
import ssl
import threading
import time
from datetime import UTC, datetime
from html.parser import HTMLParser
from importlib.metadata import version
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
import uvicorn
from phase2_runtime import LOCAL, ROOT, create_server, load_client

from service_desk.app.identity import create_identity_app
from service_desk.core.auth.lab import ISSUER, REDIRECT, RESOURCES, subject_for
from service_desk.core.auth.tokens import AuthenticationDenied
from service_desk.mcp.identity import create_identity_mcp


class LoginForm(HTMLParser):
    action: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if tag == "form" and attributes.get("id") == "kc-form-login":
            self.action = attributes.get("action")


class ProbeFailure(Exception):
    pass


def main() -> None:
    checks: dict[str, bool] = {}
    shapes: dict[str, object] = {}
    servers: list[tuple[uvicorn.Server, threading.Thread]] = []
    report: dict[str, object] = {
        "schema_version": 1,
        "recorded_at": datetime.now(UTC).isoformat(),
        "phase": "2-identity-foundation",
        "checks": checks,
        "claim_shapes": shapes,
        "protected_data_tools_enabled": False,
        "versions": {package: version(package) for package in ("mcp", "PyJWT", "httpx")},
        "configuration": "infra/compose.phase2-identity.yaml",
        "source_sha256": {
            str(path.relative_to(ROOT)).replace("\\", "/"): hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
            for path in sorted(
                [
                    *(ROOT / "src/service_desk/core/auth").glob("*.py"),
                    ROOT / "src/service_desk/app/identity.py",
                    ROOT / "src/service_desk/mcp/identity.py",
                    ROOT / "scripts/check_phase2_identity.py",
                    ROOT / "scripts/phase2_runtime.py",
                    ROOT / "scripts/prepare_phase2.py",
                    ROOT / "infra/compose.phase2-identity.yaml",
                    ROOT / "fixtures/company.json",
                    ROOT / "uv.lock",
                ]
            )
        },
    }

    def check(name: str, condition: bool) -> None:
        checks[name] = bool(condition)
        if not condition:
            raise ProbeFailure(name)

    def authenticate(browser: httpx.Client, url: str, user: str) -> str:
        response = browser.get(url)
        if response.status_code == 200:
            form = LoginForm()
            form.feed(response.text)
            check(
                "login_form_pinned_to_issuer",
                bool(form.action and form.action.startswith(ISSUER + "/")),
            )
            response = browser.post(
                form.action,
                data={
                    "username": user,
                    "password": credentials["users"][user],
                },
            )
        check("login_redirect", response.status_code == 302)
        location = response.headers["location"]
        check("callback_pinned", location.startswith(REDIRECT + "?"))
        return location

    try:
        credentials = json.loads((LOCAL / "credentials.json").read_text())
        trust = ssl.create_default_context(cafile=str(LOCAL / "tls/certificate.pem"))
        with httpx.Client(
            verify=trust, timeout=10, trust_env=False, follow_redirects=False
        ) as http:
            oidc = load_client(http, trust)
            deadline = time.monotonic() + 45
            while True:
                try:
                    ready = http.get(ISSUER + "/.well-known/openid-configuration", timeout=2)
                    if ready.status_code == 200:
                        break
                except httpx.TransportError:
                    pass
                if time.monotonic() >= deadline:
                    check("identity_provider_ready", False)
                time.sleep(0.5)
            oidc.check_discovery()
            check("discovery_and_pkce", True)
            applications = [(create_identity_app(oidc), 19481)] + [
                (create_identity_mcp(oidc.delegated_validator, r), urlsplit(r.url).port)
                for r in RESOURCES
            ]
            for app, port in applications:
                runner = create_server(app, port)
                thread = threading.Thread(target=runner.run, daemon=True)
                servers.append((runner, thread))
                thread.start()
            deadline = time.monotonic() + 10
            while not all(server.started for server, _ in servers) and time.monotonic() < deadline:
                time.sleep(0.05)
            check("tls_listeners_ready", all(server.started for server, _ in servers))
            tokens: dict[str, str] = {}
            # Each user has a fresh browser cookie jar. No password-grant shortcut.
            for user in ("erin", "alice"):
                attempt, url = oidc.begin(RESOURCES[0].url)
                with httpx.Client(verify=trust, timeout=10, trust_env=False) as browser:
                    location = authenticate(browser, url, user)
                query = parse_qs(urlsplit(location).query)
                login = oidc.finish(attempt, query["state"][0], query["code"][0])
                check(user + "_subject_mapping", login.identity.principal_id == user)
                for resource in RESOURCES:
                    token = oidc.exchange(login, resource.url)
                    claims = oidc.delegated_validator.claims(token, resource.audience)
                    check(
                        user + "_delegated_" + resource.audience, claims["sub"] == subject_for(user)
                    )
                    shapes[resource.audience] = {
                        "issuer": claims["iss"],
                        "subject_preserved": True,
                        "client_id": claims["azp"],
                        "audience": claims["aud"],
                        "scopes": claims.get("scope", "").split(),
                        "act_present": "act" in claims,
                    }
                    tokens[resource.audience] = token
                for forbidden in ("execution", "lifecycle"):
                    denied = http.post(
                        oidc.token_endpoint,
                        data={
                            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                            "client_id": "gateway",
                            "client_secret": credentials["clients"]["gateway"],
                            "subject_token": login.access_token,
                            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                            "audience": forbidden,
                            "scope": "access:execute"
                            if forbidden == "execution"
                            else "access:lifecycle",
                        },
                    )
                    check(
                        user + "_privileged_exchange_denied_" + forbidden, denied.status_code == 400
                    )
                if user == "alice":
                    original_token = login.access_token

            # Valid login with reduced original scope: adapter must refuse upscoping.
            attempt, url = oidc.begin(RESOURCES[0].url)
            params = parse_qs(urlsplit(url).query)
            params["scope"] = ["openid tickets:read"]
            url = oidc.authorization_endpoint + "?" + urlencode(params, doseq=True)
            with httpx.Client(verify=trust, timeout=10, trust_env=False) as browser:
                location = authenticate(browser, url, "alice")
            query = parse_qs(urlsplit(location).query)
            limited = oidc.finish(attempt, query["state"][0], query["code"][0])
            try:
                oidc.exchange(limited, RESOURCES[0].url)
            except AuthenticationDenied:
                check("adapter_rejects_scope_expansion", True)
            else:
                check("adapter_rejects_scope_expansion", False)

            accept = {"Accept": "application/json, text/event-stream"}
            initialize = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "phase2-identity-probe", "version": "1"},
                },
            }
            for resource in RESOURCES:
                prefix = resource.audience + "_"
                missing = http.post(resource.url, headers=accept, json=initialize)
                check(prefix + "missing_token_denied", missing.status_code == 401)
                challenge = missing.headers.get("www-authenticate", "")
                metadata_url = resource.url.replace(
                    "/mcp", "/.well-known/oauth-protected-resource/mcp"
                )
                check(
                    prefix + "challenge_metadata",
                    f'resource_metadata="{metadata_url}"' in challenge,
                )
                metadata = http.get(metadata_url).json()
                check(
                    prefix + "resource_discovery",
                    metadata["resource"] == resource.url
                    and metadata["authorization_servers"] == [ISSUER],
                )
                for name, token in {**tokens, "web": original_token}.items():
                    response = http.post(
                        resource.url,
                        json=initialize,
                        headers={
                            **accept,
                            "Authorization": "Bearer " + token,
                        },
                    )
                    check(
                        prefix + "audience_" + name,
                        response.status_code == (200 if name == resource.audience else 401),
                    )
                forged = http.post(
                    resource.url, headers={**accept, "X-User": "erin"}, json=initialize
                )
                check(prefix + "forged_header_denied", forged.status_code == 401)
                no_scope_response = http.post(
                    oidc.token_endpoint,
                    data={
                        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                        "client_id": "gateway",
                        "client_secret": credentials["clients"]["gateway"],
                        "subject_token": original_token,
                        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                        "audience": resource.audience,
                        "resource": resource.url,
                    },
                )
                check(prefix + "no_scope_token_issued", no_scope_response.status_code == 200)
                no_scope = no_scope_response.json()["access_token"]
                denied_scope = http.post(
                    resource.url,
                    json=initialize,
                    headers={
                        **accept,
                        "Authorization": "Bearer " + no_scope,
                    },
                )
                check(prefix + "missing_scope_denied", denied_scope.status_code == 403)
                called = http.post(
                    resource.url,
                    headers={
                        **accept,
                        "Authorization": "Bearer " + tokens[resource.audience],
                    },
                    json={
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/call",
                        "params": {"name": "identity_status", "arguments": {}},
                    },
                )
                result = called.json()["result"]
                check(
                    prefix + "identity_tool",
                    not result.get("isError")
                    and result["structuredContent"]
                    == {"subject": subject_for("alice"), "client_id": "gateway"},
                )

            for workload, audience, scope in (
                ("executor", "execution", "access:execute"),
                ("worker", "lifecycle", "access:lifecycle"),
            ):
                issued = http.post(
                    oidc.token_endpoint,
                    data={
                        "grant_type": "client_credentials",
                        "client_id": workload,
                        "client_secret": credentials["clients"][workload],
                    },
                )
                check(workload + "_token_issued", issued.status_code == 200)
                token = issued.json()["access_token"]
                # Workloads deliberately have no human principal mapping.
                import jwt

                claims = jwt.decode(
                    token,
                    oidc.delegated_validator.keys.get_signing_key_from_jwt(token).key,
                    algorithms=["RS256"],
                    issuer=ISSUER,
                    audience=audience,
                )
                check(
                    workload + "_narrow_capability",
                    claims["aud"] == audience
                    and claims["azp"] == workload
                    and claims["scope"] == scope,
                )
                for resource in RESOURCES:
                    denied = http.post(
                        resource.url,
                        json=initialize,
                        headers={
                            **accept,
                            "Authorization": "Bearer " + token,
                        },
                    )
                    check(workload + "_denied_" + resource.audience, denied.status_code == 401)

            with httpx.Client(verify=trust, timeout=10, trust_env=False) as browser:
                base = REDIRECT.removesuffix("/callback")
                start = browser.get(base + "/login")
                location = authenticate(browser, start.headers["location"], "erin")
                response = browser.get(location)
                check("browser_callback", response.status_code == 200)
                cookie = response.headers["set-cookie"]
                check(
                    "protected_cookie",
                    all(s in cookie for s in ("Secure", "HttpOnly", "SameSite=lax")),
                )
                info = browser.get(base + "/session").json()
                check(
                    "server_session_identity",
                    info["principal_id"] == "erin" and "access_token" not in info,
                )
                check("callback_replay_denied", browser.get(location).status_code == 401)
                check("csrf_required", browser.post(base + "/logout").status_code == 403)
                check(
                    "logout",
                    browser.post(
                        base + "/logout",
                        headers={
                            "Origin": base,
                            "X-CSRF-Token": info["csrf"],
                        },
                    ).status_code
                    == 200,
                )
                check("session_consumed", browser.get(base + "/session").status_code == 401)
            report["status"] = "success"
    except Exception as error:
        report["status"] = "failure" if isinstance(error, ProbeFailure) else "error"
        report["error_type"] = type(error).__name__
    finally:
        for server, _ in servers:
            server.should_exit = True
        for _, thread in servers:
            thread.join(timeout=5)
        output = ROOT / "reports/runs/phase2-identity"
        output.mkdir(parents=True, exist_ok=True)
        path = output / (str(time.time_ns()) + ".json")
        path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2))
    if report.get("status") != "success":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
