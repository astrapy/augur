"""Auth providers. Each one returns headers and cookies for a given request."""

from __future__ import annotations

import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

import httpx

from augur.utils.logging import get_logger

log = get_logger(__name__)


@dataclass
class AuthContext:
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)


class AuthProvider(ABC):
    @abstractmethod
    def context(self) -> AuthContext:
        """Return current auth headers and cookies. May refresh tokens internally."""


class NoAuth(AuthProvider):
    def context(self) -> AuthContext:
        return AuthContext()


@dataclass
class BearerAuth(AuthProvider):
    token: str

    @classmethod
    def from_env(cls, var: str = "AUGUR_BEARER") -> BearerAuth:
        tok = os.environ.get(var)
        if not tok:
            raise RuntimeError(f"environment variable {var} is not set")
        return cls(token=tok)

    def context(self) -> AuthContext:
        return AuthContext(headers={"Authorization": f"Bearer {self.token}"})


@dataclass
class CookieAuth(AuthProvider):
    cookies: dict[str, str]

    def context(self) -> AuthContext:
        return AuthContext(cookies=dict(self.cookies))


@dataclass
class HeaderAuth(AuthProvider):
    """Generic escape hatch for custom auth headers (e.g. X-API-Key)."""
    headers: dict[str, str]

    def context(self) -> AuthContext:
        return AuthContext(headers=dict(self.headers))


@dataclass
class JWTRefreshAuth(AuthProvider):
    """Bearer auth with automatic refresh via a configured endpoint.

    Refresh fires when the cached token has at most `min_remaining_s` left.
    The refresh response is expected to contain `access_token` and `expires_in`,
    matching the OAuth2 password and refresh-token grants. Other shapes can be
    handled by overriding `_extract`.
    """
    refresh_url: str
    refresh_payload: dict[str, Any]
    min_remaining_s: int = 30
    _token: str | None = None
    _expires_at: float = 0.0

    def context(self) -> AuthContext:
        if not self._token or self._expires_at - time.time() < self.min_remaining_s:
            self._refresh()
        return AuthContext(headers={"Authorization": f"Bearer {self._token}"})

    def _refresh(self) -> None:
        # do not log the url verbatim, it may contain credentials in the userinfo
        log.debug("refreshing jwt")
        with httpx.Client(timeout=10.0, verify=True, follow_redirects=False) as c:
            r = c.post(self.refresh_url, json=self.refresh_payload)
            if r.status_code >= 400:
                # do not include the body in the exception, it may contain
                # the rejected token or other auth material
                raise RuntimeError(f"jwt refresh failed with status {r.status_code}")
            try:
                body = r.json()
            except Exception:
                raise RuntimeError("jwt refresh returned non-json body")
            tok, ttl = self._extract(body)
        self._token = tok
        self._expires_at = time.time() + ttl

    @staticmethod
    def _extract(body: dict[str, Any]) -> tuple[str, int]:
        tok = body.get("access_token") or body.get("token")
        ttl = int(body.get("expires_in", 300))
        if not isinstance(tok, str) or not tok:
            raise RuntimeError(f"refresh response missing access_token. keys={list(body)}")
        return tok, ttl
