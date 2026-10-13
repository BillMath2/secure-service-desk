"""Credential-free discovery within the operator's pinned resource/issuer boundary."""

import json
import re
import time
from contextlib import closing
from typing import Any
from urllib.parse import urlsplit

import httpx

from service_desk.core.auth.tokens import AuthenticationDenied, ResourceBinding, require_https

PARAM = re.compile(r'\s*([a-zA-Z_][a-zA-Z0-9_-]*)\s*=\s*(?:"([^"\\]*)"|([^\s,]+))\s*(?:,|$)')


def supports(metadata: dict[str, Any], field: str, value: str) -> bool:
    values = metadata.get(field)
    return isinstance(values, list) and all(isinstance(v, str) for v in values) and value in values


def issuer_locations(issuer: str) -> tuple[str, ...]:
    parsed = urlsplit(require_https(issuer))
    origin = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path.rstrip("/")
    return tuple(
        dict.fromkeys(
            (
                origin + "/.well-known/oauth-authorization-server" + path,
                origin + "/.well-known/openid-configuration" + path,
                issuer.rstrip("/") + "/.well-known/openid-configuration",
            )
        )
    )


def resource_locations(resource: str) -> tuple[str, ...]:
    parsed = urlsplit(require_https(resource))
    origin = f"{parsed.scheme}://{parsed.netloc}"
    return tuple(
        dict.fromkeys(
            (
                origin + "/.well-known/oauth-protected-resource" + parsed.path,
                origin + "/.well-known/oauth-protected-resource",
            )
        )
    )


def challenge_parameters(headers: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    found = False
    for header in headers:
        scheme, _, rest = header.partition(" ")
        if scheme.lower() != "bearer":
            continue
        if found or len(header) > 4096:
            raise AuthenticationDenied()
        found = True
        while rest:
            match = PARAM.match(rest)
            if not match or match[1].lower() in result:
                raise AuthenticationDenied()
            result[match[1].lower()] = match[2] if match[2] is not None else match[3]
            rest = rest[match.end() :]
    return result


class Discovery:
    def __init__(self, http: httpx.Client, *, deadline: float | None = None) -> None:
        self.http = http
        self.deadline = time.monotonic() + 10 if deadline is None else deadline

    def get(self, url: str) -> tuple[int, httpx.Headers, dict[str, Any] | None]:
        try:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise AuthenticationDenied()
            request = self.http.build_request(
                "GET",
                require_https(url),
                timeout=min(5, remaining),
                headers={
                    "Accept": "application/json, text/event-stream",
                    "Accept-Encoding": "identity",
                },
            )
            # A shared HTTP pool must not attach cached cookies or default credentials to discovery.
            for key in ("Authorization", "Cookie", "Proxy-Authorization"):
                request.headers.pop(key, None)
            with closing(
                self.http.send(request, stream=True, follow_redirects=False, auth=None)
            ) as response:
                if response.status_code in (401, 403, 404, 405):
                    return response.status_code, response.headers, None
                if (
                    response.status_code != 200
                    or response.headers.get("content-encoding", "identity") != "identity"
                ):
                    raise AuthenticationDenied()
                body = bytearray()
                for chunk in response.iter_bytes():
                    if time.monotonic() >= self.deadline or len(body) + len(chunk) > 32768:
                        raise AuthenticationDenied()
                    body.extend(chunk)
                metadata = json.loads(body)
                if not isinstance(metadata, dict):
                    raise AuthenticationDenied()
                return 200, response.headers, metadata
        except (httpx.HTTPError, ValueError, TypeError):
            raise AuthenticationDenied() from None

    def issuer(self, issuer: str, authorization: str, token: str, jwks: str) -> str:
        for url in issuer_locations(issuer):
            status, _, metadata = self.get(url)
            if status in (404, 405):
                continue
            if not metadata or (
                metadata.get("issuer") != issuer
                or metadata.get("authorization_endpoint") != authorization
                or metadata.get("token_endpoint") != token
                or metadata.get("jwks_uri") != jwks
                or not supports(metadata, "code_challenge_methods_supported", "S256")
                or not supports(metadata, "response_types_supported", "code")
                or not supports(
                    metadata, "token_endpoint_auth_methods_supported", "client_secret_post"
                )
            ):
                raise AuthenticationDenied()
            return url
        raise AuthenticationDenied()

    def resource(self, binding: ResourceBinding, issuer: str) -> str:
        status, headers, _ = self.get(binding.url)
        if status != 401:
            raise AuthenticationDenied()
        params = challenge_parameters(headers.get_list("www-authenticate"))
        if "scope" in params and set(params["scope"].split()) != {binding.scope}:
            raise AuthenticationDenied()
        locations = resource_locations(binding.url)
        if "resource_metadata" in params:
            # Only the two standard metadata locations on this registered endpoint are trusted.
            if params["resource_metadata"] not in locations:
                raise AuthenticationDenied()
            locations = (params["resource_metadata"],)
        for url in locations:
            status, _, metadata = self.get(url)
            if status in (404, 405):
                continue
            if not metadata or (
                metadata.get("resource") != binding.url
                or metadata.get("authorization_servers") != [issuer]
                or not supports(metadata, "scopes_supported", binding.scope)
                or (
                    "bearer_methods_supported" in metadata
                    and not supports(metadata, "bearer_methods_supported", "header")
                )
            ):
                raise AuthenticationDenied()
            return url
        raise AuthenticationDenied()
