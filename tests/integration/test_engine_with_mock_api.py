import json
from pathlib import Path

import respx
from httpx import Response as HTTPXResponse

from augur.engine import Engine, EngineConfig
from augur.http.auth import BearerAuth
from augur.http.executor import Executor
from augur.http.scope import ScopeGuard
from augur.invariants.checker import InvariantChecker
from augur.invariants.loader import Invariant
from augur.llm.client import LLMClient
from augur.report.html import render
from augur.schema.loader import load as load_spec
from augur.state.graph import StateGraph
from augur.strategies.bola import BolaStrategy


class AlwaysViolates(LLMClient):
    """Fake LLM. Always says the response violates the invariant. Evidence is
    a string the test response bodies contain, since the checker now requires
    evidence to be a verbatim substring of the body."""

    def complete(self, prompt: str, *, system=None, max_tokens=2048) -> str:
        return json.dumps({"violates": True, "evidence": '"name":"'})


BASE = "http://api.test"


def _spec_file(tmp_path: Path) -> Path:
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "t", "version": "0"},
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
            "/login": {
                "post": {"operationId": "login", "responses": {"200": {"description": "ok"}}}
            },
        },
    }
    p = tmp_path / "spec.json"
    p.write_text(json.dumps(spec), encoding="utf-8")
    return p


@respx.mock
def test_engine_finds_bola_and_writes_report(tmp_path: Path):
    respx.get(f"{BASE}/users/1").mock(
        return_value=HTTPXResponse(200, json={"id": 1, "name": "alice"})
    )
    respx.get(f"{BASE}/users/2").mock(
        return_value=HTTPXResponse(200, json={"id": 2, "name": "bob"})
    )
    respx.post(f"{BASE}/login").mock(
        return_value=HTTPXResponse(200, json={"access_token": "t", "expires_in": 3600})
    )

    catalog = load_spec(_spec_file(tmp_path))

    scope = ScopeGuard.from_base_urls([BASE])
    executor = Executor(scope=scope, auth=BearerAuth(token="t"))

    inv = Invariant(
        name="no-cross-tenant-leak",
        method="GET",
        path_pattern="/users/*",
        rule="response must not contain another user's data",
        severity="high",
    )
    checker = InvariantChecker(AlwaysViolates(), [inv])

    engine = Engine(
        catalog=catalog,
        executor=executor,
        strategies=[BolaStrategy()],
        invariant_checker=checker,
        config=EngineConfig(
            base_url=BASE,
            duration_s=0.5,
            max_requests=10,
            findings_dir=tmp_path / "findings",
        ),
        principal="alice",
    )

    # seed cross-principal observations directly so BolaStrategy has work
    engine.state.record_response({"id": 2}, "/users/{id}", owner="bob")
    engine.state.record_response({"id": 1}, "/users/{id}", owner="alice")

    findings = engine.run()
    executor.close()

    assert len(findings) >= 1
    assert any(f.category.startswith("API1") for f in findings)

    out = tmp_path / "report.html"
    render(findings, out)
    assert out.exists()
    text = out.read_text(encoding="utf-8")
    assert "augur findings" in text
