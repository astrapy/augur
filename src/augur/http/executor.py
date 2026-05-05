"""Request executor. Sends requests through the scope guard and auth, streams
response bodies with a hard cap.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from augur.http.auth import AuthProvider, NoAuth
from augur.http.scope import ScopeGuard
from augur.utils.logging import get_logger

log = get_logger(__name__)


@dataclass
class PlannedRequest:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    params: dict[str, Any] = field(default_factory=dict)
    json_body: Any | None = None
    raw_body: bytes | None = None
    tag: str = ""


@dataclass
class Response:
    status_code: int
    headers: dict[str, str]
    body: bytes
    elapsed_ms: float
    request: PlannedRequest
    truncated: bool = False

    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self) -> Any:
        import json as _json
        return _json.loads(self.body)

    def is_json(self) -> bool:
        ct = self.headers.get("content-type", "").lower()
        return ct.startswith("application/json") or ct.endswith("+json") or "json" in ct


_VALID_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})


class Executor:
    def __init__(
        self,
        scope: ScopeGuard,
        auth: AuthProvider | None = None,
        timeout_s: float = 10.0,
        verify_tls: bool = True,
        max_body_bytes: int = 2 * 1024 * 1024,
    ):
        self.scope = scope
        self.auth = auth or NoAuth()
        self.timeout_s = timeout_s
        self.max_body_bytes = max_body_bytes
        # no redirects: a 302 must not smuggle us off-host
        self._client = httpx.Client(
            timeout=timeout_s,
            verify=verify_tls,
            follow_redirects=False,
            http2=False,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> Executor:
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def send(self, req: PlannedRequest) -> Response:
        method = req.method.upper()
        if method not in _VALID_METHODS:
            raise ValueError(f"refusing unknown http method: {req.method!r}")
        self.scope.check(req.url)

        ctx = self.auth.context()
        headers = {**ctx.headers, **req.headers}

        kwargs: dict[str, Any] = {
            "method": method,
            "url": req.url,
            "headers": headers,
            "params": req.params or None,
            "cookies": ctx.cookies or None,
        }
        if req.json_body is not None:
            kwargs["json"] = req.json_body
        elif req.raw_body is not None:
            kwargs["content"] = req.raw_body

        t0 = time.perf_counter()
        # stream so a lying Content-Length can't OOM us
        body_chunks: list[bytes] = []
        truncated = False
        total = 0
        with self._client.stream(**kwargs) as r:
            for chunk in r.iter_bytes():
                if total + len(chunk) > self.max_body_bytes:
                    body_chunks.append(chunk[: self.max_body_bytes - total])
                    truncated = True
                    break
                body_chunks.append(chunk)
                total += len(chunk)
            status = r.status_code
            resp_headers = {k.lower(): v for k, v in r.headers.items()}
        elapsed = (time.perf_counter() - t0) * 1000.0

        return Response(
            status_code=status,
            headers=resp_headers,
            body=b"".join(body_chunks),
            elapsed_ms=elapsed,
            request=req,
            truncated=truncated,
        )
