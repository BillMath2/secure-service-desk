"""Single-process login/session boundary, optionally hosting the read-only assistant."""

import secrets
import threading
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import Response

from service_desk.agent.loop import Assistant
from service_desk.app.backend import LocalTaskBackend, TaskBackend
from service_desk.app.publication import PublicationStore
from service_desk.app.tasks import install_task_routes
from service_desk.core.auth.oidc import LoginAttempt, LoginResult, OIDCClient
from service_desk.core.auth.tokens import AuthenticationDenied

SESSION_COOKIE = "__Host-desk-session"
LOGIN_COOKIE = "__Host-desk-login"


class ExpiringStore[T]:
    """Bounded, locked, server-owned state. Restart requires signing in again."""

    def __init__(self, clock: Callable[[], float] = time.time, capacity: int = 256) -> None:
        self.clock = clock
        self.capacity = capacity
        self._records: dict[str, tuple[float, T]] = {}
        self._lock = threading.Lock()

    def put(self, value: T, expires: float) -> str:
        with self._lock:
            now = self.clock()
            self._records = {k: v for k, v in self._records.items() if v[0] > now}
            if len(self._records) >= self.capacity:
                raise HTTPException(503, "Sign-in temporarily unavailable")
            key = secrets.token_urlsafe(32)
            self._records[key] = (expires, value)
            return key

    def get(self, key: str, *, consume: bool = False) -> T | None:
        with self._lock:
            record = self._records.pop(key, None) if consume else self._records.get(key)
            if record is None:
                return None
            if record[0] <= self.clock():
                self._records.pop(key, None)
                return None
            return record[1]


@dataclass(frozen=True)
class BrowserSession:
    login: LoginResult = field(repr=False)
    csrf: str = field(repr=False)


def create_identity_app(
    oidc: OIDCClient,
    clock: Callable[[], float] = time.time,
    *,
    assistant: Assistant | None = None,
    publisher: PublicationStore | None = None,
    backend: TaskBackend | None = None,
) -> FastAPI:
    """Install protected login/session routes and optional authenticated task routes."""
    if backend is not None and (assistant is not None or publisher is not None):
        raise ValueError("Choose one task backend")
    if assistant is not None:
        backend = LocalTaskBackend(assistant, publisher)
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    parsed = urlsplit(oidc.redirect_uri)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=[parsed.hostname or ""])
    attempts = ExpiringStore[LoginAttempt](clock)
    sessions = ExpiringStore[BrowserSession](clock)

    @app.middleware("http")
    async def secure_response(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        # Ignore spoofed forwarding headers; launch Uvicorn with proxy_headers=False.
        if request.url.scheme != "https":
            return JSONResponse({"detail": "HTTPS required"}, status_code=400)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'"
        )
        return response

    @app.get("/login")
    def login(request: Request) -> RedirectResponse:
        # Fixed resource selection, not an arbitrary return URL from the browser.
        attempt, location = oidc.begin(next(iter(oidc.resources)))
        attempts.get(request.cookies.get(LOGIN_COOKIE, ""), consume=True)
        key = attempts.put(attempt, clock() + 300)
        response = RedirectResponse(location, status_code=302)
        response.set_cookie(
            LOGIN_COOKIE, key, max_age=300, secure=True, httponly=True, samesite="lax", path="/"
        )
        return response

    @app.get("/callback")
    def callback(request: Request) -> Response:
        attempt = attempts.get(request.cookies.get(LOGIN_COOKIE, ""), consume=True)
        try:
            if (
                attempt is None
                or "error" in request.query_params
                or any(len(request.query_params.getlist(key)) != 1 for key in ("state", "code"))
            ):
                raise AuthenticationDenied()
            result = oidc.finish(
                attempt, request.query_params["state"], request.query_params["code"]
            )
            sessions.get(request.cookies.get(SESSION_COOKIE, ""), consume=True)
            key = sessions.put(
                BrowserSession(result, secrets.token_urlsafe(32)),
                min(clock() + 900, result.identity.expires_at),
            )
            response: Response = (
                RedirectResponse("/", status_code=303)
                if backend is not None
                else JSONResponse({"authenticated": True})
            )
            response.set_cookie(
                SESSION_COOKIE,
                key,
                max_age=max(0, min(900, int(result.identity.expires_at - clock()))),
                secure=True,
                httponly=True,
                samesite="lax",
                path="/",
            )
        except AuthenticationDenied:
            response = JSONResponse({"detail": "Sign-in failed"}, status_code=401)
        response.delete_cookie(LOGIN_COOKIE, secure=True, httponly=True, samesite="lax")
        return response

    def current(request: Request) -> BrowserSession:
        session = sessions.get(request.cookies.get(SESSION_COOKIE, ""))
        if session is None:
            raise HTTPException(401, "Sign-in required")
        return session

    if backend is not None:
        install_task_routes(app, backend, current, origin)

    @app.get("/session")
    def session_info(request: Request) -> dict[str, str]:
        session = current(request)
        return {"principal_id": session.login.identity.principal_id, "csrf": session.csrf}

    @app.post("/logout")
    def logout(request: Request) -> JSONResponse:
        session = current(request)
        if request.headers.get("origin") != origin or not secrets.compare_digest(
            request.headers.get("x-csrf-token", "").encode(), session.csrf.encode()
        ):
            raise HTTPException(403, "Action denied")
        sessions.get(request.cookies.get(SESSION_COOKIE, ""), consume=True)
        response = JSONResponse({"authenticated": False})
        response.delete_cookie(SESSION_COOKIE, secure=True, httponly=True, samesite="lax")
        return response

    return app
