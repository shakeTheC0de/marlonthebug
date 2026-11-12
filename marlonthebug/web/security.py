"""Local panel authentication and CSRF helpers."""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import logging
import secrets

from fastapi import Request, Response

from marlonthebug.paths import AppPaths

logger = logging.getLogger("marlonthebug.web.security")

COOKIE_NAME = "mtb_session"


class PanelAuth:
    def __init__(self, paths: AppPaths, enabled: bool = True) -> None:
        self.paths = paths
        self.enabled = enabled
        self.token = self._load_or_create()

    def _load_or_create(self) -> str:
        if self.paths.token_path.exists():
            token = self.paths.token_path.read_text(encoding="utf-8").strip()
            if token:
                return token
        token = secrets.token_urlsafe(32)
        self.paths.token_path.parent.mkdir(parents=True, exist_ok=True)
        self.paths.token_path.write_text(token, encoding="utf-8")
        with contextlib.suppress(OSError):
            self.paths.token_path.chmod(0o600)
        return token

    def is_authenticated(self, request: Request) -> bool:
        if not self.enabled:
            return True
        cookie = request.cookies.get(COOKIE_NAME, "")
        return hmac.compare_digest(cookie, self.token)

    def login(self, response: Response) -> None:
        response.set_cookie(
            COOKIE_NAME,
            self.token,
            httponly=True,
            samesite="strict",
            max_age=60 * 60 * 24 * 30,
        )

    def logout(self, response: Response) -> None:
        response.delete_cookie(COOKIE_NAME)

    def csrf_token(self) -> str:
        return hashlib.sha256(f"{self.token}:csrf".encode()).hexdigest()[:40]

    def check_csrf(self, request: Request, token: str) -> bool:
        if not self.enabled:
            return True
        expected = self.csrf_token()
        return hmac.compare_digest(token or "", expected)


def safe_next(value: str | None, default: str = "/") -> str:
    """Only allow local redirects."""
    if not value:
        return default
    if not value.startswith("/") or value.startswith("//"):
        return default
    return value


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "local"


__all__ = ["COOKIE_NAME", "PanelAuth", "client_ip", "safe_next"]
