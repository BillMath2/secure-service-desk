"""Pinned issuer, client, audience and subject contracts for signed tokens."""

import asyncio
import ssl
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import jwt
from mcp.server.auth.provider import AccessToken


class AuthenticationDenied(Exception):
    """Intentionally contains no provider response, token or claim values."""


def require_https(url: str) -> str:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Identity endpoints must be fixed HTTPS URLs")
    return url


@dataclass(frozen=True)
class ResourceBinding:
    audience: str
    url: str
    scope: str

    def __post_init__(self) -> None:
        require_https(self.url)


@dataclass(frozen=True)
class VerifiedIdentity:
    issuer: str
    subject: str
    principal_id: str
    client_id: str
    scopes: frozenset[str]
    expires_at: int


class TokenValidator:
    def __init__(
        self,
        issuer: str,
        keys: jwt.PyJWKClient,
        identities: Mapping[tuple[str, str], str],
        client_id: str = "gateway",
    ) -> None:
        self.issuer = require_https(issuer)
        self.keys = keys
        self.identities = dict(identities)
        self.client_id = client_id

    def claims(self, token: str, audience: str) -> dict[str, Any]:
        try:
            if not token or len(token) > 16384:
                raise AuthenticationDenied()
            header = jwt.get_unverified_header(token)
            if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
                raise AuthenticationDenied()
            claims: dict[str, Any] = jwt.decode(
                token,
                self.keys.get_signing_key_from_jwt(token).key,
                algorithms=["RS256"],
                issuer=self.issuer,
                audience=audience,
                options={"require": ["iss", "sub", "aud", "azp", "exp", "iat"]},
            )
            # A single audience is required. Multi-resource bearer tokens are not delegated.
            if claims["aud"] not in (audience, [audience]):
                raise AuthenticationDenied()
            if claims["azp"] != self.client_id or not isinstance(claims["sub"], str):
                raise AuthenticationDenied()
            if type(claims["exp"]) is not int or type(claims["iat"]) is not int:
                raise AuthenticationDenied()
            if claims["exp"] <= claims["iat"]:
                raise AuthenticationDenied()
            if (self.issuer, claims["sub"]) not in self.identities:
                raise AuthenticationDenied()
            return claims
        except (jwt.PyJWTError, ValueError, TypeError, KeyError):
            raise AuthenticationDenied() from None

    def access(self, token: str, audience: str) -> VerifiedIdentity:
        claims = self.claims(token, audience)
        if claims.get("typ") != "Bearer" or not isinstance(claims.get("scope", ""), str):
            raise AuthenticationDenied()
        return VerifiedIdentity(
            issuer=self.issuer,
            subject=claims["sub"],
            principal_id=self.identities[(self.issuer, claims["sub"])],
            client_id=claims["azp"],
            scopes=frozenset(claims.get("scope", "").split()),
            expires_at=claims["exp"],
        )


def key_client(jwks_url: str, trust: ssl.SSLContext) -> jwt.PyJWKClient:
    return jwt.PyJWKClient(
        require_https(jwks_url),
        ssl_context=trust,
        timeout=5,
        lifespan=60,
        cooldown_duration=5,
        cache_keys=False,
    )


class MCPTokenVerifier:
    def __init__(self, validator: TokenValidator, binding: ResourceBinding) -> None:
        self.validator = validator
        self.binding = binding

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            identity = await asyncio.to_thread(self.validator.access, token, self.binding.audience)
        except AuthenticationDenied:
            return None
        return AccessToken(
            token=token,
            client_id=identity.client_id,
            subject=identity.subject,
            scopes=sorted(identity.scopes),
            expires_at=identity.expires_at,
            # This fixed mapping is applied ONLY after exact signed audience validation.
            resource=self.binding.url,
            claims={"iss": identity.issuer},
        )
