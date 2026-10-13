"""Confidential code/PKCE sign-in and allowlisted Keycloak exchange adapter."""

import base64
import hashlib
import secrets
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

import httpx

from service_desk.core.auth.discovery import Discovery
from service_desk.core.auth.tokens import (
    AuthenticationDenied,
    ResourceBinding,
    TokenValidator,
    VerifiedIdentity,
    require_https,
)


@dataclass(frozen=True)
class LoginAttempt:
    state: str
    nonce: str
    verifier: str = field(repr=False)
    resource: str


@dataclass(frozen=True)
class LoginResult:
    identity: VerifiedIdentity
    access_token: str = field(repr=False)


class OIDCClient:
    def __init__(
        self,
        validator: TokenValidator,
        client_secret: str,
        redirect_uri: str,
        resources: tuple[ResourceBinding, ...],
        http: httpx.Client,
        delegated_validator: TokenValidator,
        gateway_secret: str,
    ) -> None:
        self.validator = validator
        self._secret = client_secret
        self.delegated_validator = delegated_validator
        self._gateway_secret = gateway_secret
        if delegated_validator.issuer != validator.issuer:
            raise ValueError("Login and exchange must use the same trusted issuer")
        self.redirect_uri = require_https(redirect_uri)
        self.resources = {r.url: r for r in resources}
        if not self.resources or len(self.resources) != len(resources):
            raise ValueError("Resource URLs must be nonempty and unique")
        if len({r.audience for r in resources}) != len(resources):
            raise ValueError("Each MCP resource needs a distinct audience")
        self.http = http
        self.authorization_endpoint = validator.issuer + "/protocol/openid-connect/auth"
        self.token_endpoint = validator.issuer + "/protocol/openid-connect/token"

    def check_discovery(self) -> None:
        """Try RFC 8414 and OIDC locations in order, retaining exact endpoint pins."""
        Discovery(self.http).issuer(
            self.validator.issuer,
            self.authorization_endpoint,
            self.token_endpoint,
            self.validator.keys.uri,
        )

    def discover_resource(self, resource_url: str, *, deadline: float) -> None:
        binding = self.resources.get(resource_url)
        if binding is None:
            raise AuthenticationDenied()
        discovery = Discovery(self.http, deadline=deadline)
        discovery.resource(binding, self.validator.issuer)
        discovery.issuer(
            self.validator.issuer,
            self.authorization_endpoint,
            self.token_endpoint,
            self.validator.keys.uri,
        )

    def begin(self, resource_url: str) -> tuple[LoginAttempt, str]:
        if resource_url not in self.resources:
            raise AuthenticationDenied()
        attempt = LoginAttempt(
            secrets.token_urlsafe(32),
            secrets.token_urlsafe(32),
            secrets.token_urlsafe(48),
            resource_url,
        )
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(attempt.verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        # Read scopes are capability ceilings, never resource entitlement.
        scope = "openid " + " ".join(sorted(r.scope for r in self.resources.values()))
        query = urlencode(
            {
                "client_id": self.validator.client_id,
                "response_type": "code",
                "redirect_uri": self.redirect_uri,
                "scope": scope,
                "state": attempt.state,
                "nonce": attempt.nonce,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "resource": resource_url,
            }
        )
        return attempt, self.authorization_endpoint + "?" + query

    def _post(self, fields: dict[str, str], *, exchange: bool = False) -> dict[str, Any]:
        try:
            response = self.http.post(
                self.token_endpoint,
                follow_redirects=False,
                timeout=10,
                data={
                    **fields,
                    "client_id": (
                        self.delegated_validator if exchange else self.validator
                    ).client_id,
                    "client_secret": self._gateway_secret if exchange else self._secret,
                },
            )
            response.raise_for_status()
            result: dict[str, Any] = response.json()
            if not isinstance(result, dict) or result.get("token_type", "").lower() != "bearer":
                raise AuthenticationDenied()
            return result
        except (httpx.HTTPError, ValueError, TypeError, AttributeError):
            raise AuthenticationDenied() from None

    def finish(self, attempt: LoginAttempt, state: str, code: str) -> LoginResult:
        if (
            not secrets.compare_digest(attempt.state.encode(), state.encode())
            or not code
            or len(code) > 4096
        ):
            raise AuthenticationDenied()
        tokens = self._post(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.redirect_uri,
                "code_verifier": attempt.verifier,
                "resource": attempt.resource,
            }
        )
        try:
            claims = self.validator.claims(tokens["id_token"], self.validator.client_id)
            if claims.get("typ") != "ID" or not secrets.compare_digest(
                claims.get("nonce", ""), attempt.nonce
            ):
                raise AuthenticationDenied()
            identity = self.validator.access(
                tokens["access_token"], self.delegated_validator.client_id
            )
            if identity.subject != claims["sub"]:
                raise AuthenticationDenied()
            return LoginResult(identity, tokens["access_token"])
        except (KeyError, TypeError):
            raise AuthenticationDenied() from None

    def exchange(self, login: LoginResult, resource_url: str) -> str:
        binding = self.resources.get(resource_url)
        # Revalidate expiry and bind stored identity to the signed subject on every exchange.
        original = self.validator.access(login.access_token, self.delegated_validator.client_id)
        if binding is None or original != login.identity or binding.scope not in original.scopes:
            raise AuthenticationDenied()
        result = self._post(
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": login.access_token,
                "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "audience": binding.audience,
                "scope": binding.scope,
                "resource": binding.url,
            },
            exchange=True,
        )
        try:
            token: str = result["access_token"]
            delegated = self.delegated_validator.access(token, binding.audience)
            if (
                delegated.subject != original.subject
                or binding.scope not in delegated.scopes
                or not delegated.scopes <= original.scopes
                or not delegated.scopes <= {binding.scope, "openid"}
            ):
                raise AuthenticationDenied()
            return token
        except (KeyError, TypeError):
            raise AuthenticationDenied() from None
