from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

import pytest
import respx
from httpx import Response as HTTPXResponse

from augur.http.executor import Executor, PlannedRequest, Response
from augur.http.scope import ScopeGuard
from augur.invariants.loader import Invariant
from augur.llm.client import LLMClient
from augur.report.finding import Finding


@pytest.fixture
def tmp_path_factory_dir(tmp_path: Path) -> Path:
    return tmp_path


@pytest.fixture
def respx_mock_factory():
    def _make(base_url: str = "http://api.test"):
        return respx.mock(base_url=base_url, assert_all_called=False)
    return _make


@pytest.fixture
def scope_localhost() -> ScopeGuard:
    return ScopeGuard.from_base_urls(["http://localhost:8080"])


@pytest.fixture
def executor_localhost(scope_localhost) -> Executor:
    ex = Executor(scope=scope_localhost)
    yield ex
    ex.close()


@pytest.fixture
def make_response() -> Callable[..., Response]:
    def _mk(
        status: int = 200,
        body: bytes | str = b"{}",
        headers: dict[str, str] | None = None,
        method: str = "GET",
        url: str = "http://api.test/",
    ) -> Response:
        if isinstance(body, str):
            body = body.encode("utf-8")
        h = {"content-type": "application/json"}
        if headers:
            h.update({k.lower(): v for k, v in headers.items()})
        req = PlannedRequest(method=method, url=url)
        return Response(
            status_code=status,
            headers=h,
            body=body,
            elapsed_ms=1.0,
            request=req,
        )
    return _mk


@pytest.fixture
def make_invariant() -> Callable[..., Invariant]:
    def _mk(
        name: str = "rule",
        method: str = "GET",
        path_pattern: str = "/users/*",
        rule: str = "no leak",
        severity: str = "high",
    ) -> Invariant:
        return Invariant(
            name=name, method=method, path_pattern=path_pattern, rule=rule, severity=severity
        )
    return _mk


@pytest.fixture
def make_finding() -> Callable[..., Finding]:
    def _mk(**kw: Any) -> Finding:
        defaults: dict[str, Any] = dict(
            category="API1:2023 Broken Object Level Authorization",
            severity="high",
            title="t",
            rationale="r",
            request_method="GET",
            request_url="http://api.test/users/1",
            invariant_name="rule",
        )
        defaults.update(kw)
        return Finding(**defaults)
    return _mk


class FakeLLM(LLMClient):
    """Returns a canned reply for every complete() call."""

    def __init__(self, reply: str = '{"violates": false, "evidence": ""}'):
        self.reply = reply
        self.calls: list[tuple[str, str | None]] = []

    def complete(self, prompt: str, *, system: str | None = None, max_tokens: int = 2048) -> str:
        self.calls.append((prompt, system))
        return self.reply


@pytest.fixture
def fake_llm_factory():
    def _make(reply: Any = None) -> FakeLLM:
        if reply is None:
            return FakeLLM()
        if isinstance(reply, dict):
            return FakeLLM(json.dumps(reply))
        return FakeLLM(str(reply))
    return _make


@pytest.fixture
def tiny_openapi_spec() -> dict[str, Any]:
    return {
        "openapi": "3.0.0",
        "info": {"title": "tiny", "version": "0"},
        "paths": {
            "/users/{id}": {
                "get": {
                    "operationId": "getUser",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer"},
                        }
                    ],
                    "responses": {"200": {"description": "ok"}},
                }
            },
            "/users": {
                "get": {
                    "operationId": "listUsers",
                    "responses": {"200": {"description": "ok"}},
                }
            },
            "/login": {
                "post": {
                    "operationId": "login",
                    "responses": {"200": {"description": "ok"}},
                }
            },
        },
    }
