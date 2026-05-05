import json
from pathlib import Path

import yaml

from augur.schema.loader import load


def _write(tmp_path: Path, data, name: str) -> Path:
    p = tmp_path / name
    if name.endswith((".yaml", ".yml")):
        p.write_text(yaml.safe_dump(data), encoding="utf-8")
    else:
        p.write_text(json.dumps(data), encoding="utf-8")
    return p


def _spec_with_ref():
    return {
        "openapi": "3.0.0",
        "info": {"title": "t", "version": "0"},
        "components": {
            "parameters": {
                "UserId": {
                    "name": "id",
                    "in": "path",
                    "required": True,
                    "schema": {"type": "integer"},
                }
            }
        },
        "paths": {
            "/users/{id}": {
                "parameters": [{"$ref": "#/components/parameters/UserId"}],
                "get": {
                    "operationId": "getUser",
                    "responses": {"200": {"description": "ok"}},
                },
            },
            "/items": {
                "get": {"operationId": "listItems", "responses": {"200": {"description": "ok"}}}
            },
        },
    }


def test_loads_yaml(tmp_path: Path):
    p = _write(tmp_path, _spec_with_ref(), "spec.yaml")
    cat = load(p)
    assert {e.operation_id for e in cat.endpoints} == {"getUser", "listItems"}


def test_loads_json(tmp_path: Path):
    p = _write(tmp_path, _spec_with_ref(), "spec.json")
    cat = load(p)
    assert any(e.operation_id == "getUser" for e in cat.endpoints)


def test_resolves_ref(tmp_path: Path):
    p = _write(tmp_path, _spec_with_ref(), "spec.yaml")
    cat = load(p)
    ep = cat.by_id("getUser")
    assert ep is not None
    assert ep.parameters[0].name == "id"
    assert ep.parameters[0].location == "path"


def test_identifies_path_id(tmp_path: Path):
    p = _write(tmp_path, _spec_with_ref(), "spec.yaml")
    cat = load(p)
    ids = [e.operation_id for e in cat.with_path_id()]
    assert "getUser" in ids
    assert "listItems" not in ids


def test_dedupes_path_and_op_params(tmp_path: Path):
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "t", "version": "0"},
        "paths": {
            "/x/{id}": {
                "parameters": [
                    {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}
                ],
                "get": {
                    "operationId": "g",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer"},
                        }
                    ],
                    "responses": {"200": {"description": "ok"}},
                },
            }
        },
    }
    p = _write(tmp_path, spec, "spec.yaml")
    cat = load(p)
    ep = cat.by_id("g")
    path_params = [pp for pp in ep.parameters if pp.location == "path" and pp.name == "id"]
    assert len(path_params) == 1
    assert path_params[0].schema.get("type") == "integer"


def test_handles_missing_request_body(tmp_path: Path):
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "t", "version": "0"},
        "paths": {"/x": {"post": {"operationId": "p", "responses": {"200": {"description": "ok"}}}}},
    }
    p = _write(tmp_path, spec, "spec.yaml")
    cat = load(p)
    assert cat.by_id("p").request_body_schema is None
