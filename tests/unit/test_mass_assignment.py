from __future__ import annotations

from augur.schema.catalog import Catalog, Endpoint, Parameter
from augur.state.graph import StateGraph
from augur.strategies.base import StrategyContext
from augur.strategies.mass_assignment import MassAssignmentStrategy


def _ctx(catalog: Catalog) -> StrategyContext:
    return StrategyContext(
        catalog=catalog,
        state=StateGraph(),
        base_url="http://api.test",
        principal="alice",
    )


def _endpoint(method: str, path: str, body_schema: dict | None) -> Endpoint:
    return Endpoint(
        method=method,
        path=path,
        operation_id=f"{method.lower()}{path.replace('/', '_')}",
        request_body_schema=body_schema,
    )


def test_emits_one_request_per_tamper_field():
    schema = {
        "type": "object",
        "required": ["name"],
        "properties": {
            "name": {"type": "string"},
            "email": {"type": "string", "format": "email"},
        },
    }
    cat = Catalog(endpoints=[_endpoint("POST", "/profile", schema)])
    reqs = list(MassAssignmentStrategy().plan(_ctx(cat), budget=20))
    assert len(reqs) >= 6
    assert all(r.method == "POST" for r in reqs)
    assert all(r.url == "http://api.test/profile" for r in reqs)
    assert all("content-type" in r.headers for r in reqs)
    tampered_keys = [k for r in reqs for k in r.json_body if k != "name"]
    assert "is_admin" in tampered_keys
    assert "role" in tampered_keys


def test_required_fields_filled_with_synthetic_values():
    schema = {
        "type": "object",
        "required": ["count", "active"],
        "properties": {
            "count": {"type": "integer"},
            "active": {"type": "boolean"},
        },
    }
    cat = Catalog(endpoints=[_endpoint("PUT", "/widget", schema)])
    reqs = list(MassAssignmentStrategy().plan(_ctx(cat), budget=2))
    body = reqs[0].json_body
    assert body["count"] == 1
    assert body["active"] is False


def test_skips_endpoints_without_object_schema():
    cat = Catalog(endpoints=[
        _endpoint("POST", "/raw", None),
        _endpoint("POST", "/list", {"type": "array"}),
        _endpoint("GET", "/users/1", {"type": "object"}),
    ])
    assert list(MassAssignmentStrategy().plan(_ctx(cat), budget=20)) == []


def test_skips_tamper_field_already_in_schema():
    schema = {
        "type": "object",
        "required": [],
        "properties": {"role": {"type": "string"}},
    }
    cat = Catalog(endpoints=[_endpoint("POST", "/u", schema)])
    reqs = list(MassAssignmentStrategy().plan(_ctx(cat), budget=20))
    keys = [k for r in reqs for k in r.json_body]
    assert "role" not in keys
    assert "is_admin" in keys


def test_path_params_filled_with_placeholder():
    schema = {"type": "object", "required": []}
    ep = Endpoint(
        method="PATCH",
        path="/users/{id}",
        operation_id="patchUser",
        parameters=[Parameter(name="id", location="path", schema={"type": "integer"}, required=True)],
        request_body_schema=schema,
    )
    cat = Catalog(endpoints=[ep])
    reqs = list(MassAssignmentStrategy().plan(_ctx(cat), budget=1))
    assert reqs[0].url == "http://api.test/users/1"


def test_budget_respected():
    schema = {"type": "object", "required": []}
    cat = Catalog(endpoints=[_endpoint("POST", "/p", schema)])
    assert len(list(MassAssignmentStrategy().plan(_ctx(cat), budget=3))) == 3
