"""Mass assignment / BOPLA (API3). For each write endpoint with a body schema,
craft a request body that contains the schema's required fields plus a
tampering field the API was not supposed to accept (is_admin, role, verified,
balance, ...). The invariant decides if the response shows it was honoured.
"""

from __future__ import annotations

from typing import Any, Iterator

from augur.http.executor import PlannedRequest
from augur.schema.catalog import Endpoint
from augur.strategies.base import OwaspCategory, Strategy, StrategyContext

_WRITE_METHODS = ("POST", "PUT", "PATCH")

# names commonly used for privilege or trust flags. one finding here is
# usually enough, so we send each name as a separate request rather than
# stuffing them all in at once (the API may reject the whole body if any
# unknown field is present).
_TAMPER_FIELDS: tuple[tuple[str, Any], ...] = (
    ("is_admin", True),
    ("isAdmin", True),
    ("role", "admin"),
    ("admin", True),
    ("verified", True),
    ("email_verified", True),
    ("available_credit", 999999),
    ("balance", 999999),
)


class MassAssignmentStrategy(Strategy):
    category = OwaspCategory.BOPLA

    def plan(self, ctx: StrategyContext, budget: int) -> Iterator[PlannedRequest]:
        emitted = 0
        for ep in ctx.catalog.endpoints:
            if emitted >= budget:
                return
            if ep.method not in _WRITE_METHODS:
                continue
            schema = ep.request_body_schema
            if not isinstance(schema, dict) or schema.get("type") != "object":
                continue
            base_body = _build_body(schema)
            url = _join(ctx.base_url, _fill_path_params(ep))
            for name, value in _TAMPER_FIELDS:
                if emitted >= budget:
                    return
                if name in (schema.get("properties") or {}):
                    # the field is part of the legitimate schema, not a
                    # mass-assignment candidate.
                    continue
                body = dict(base_body)
                body[name] = value
                yield PlannedRequest(
                    method=ep.method,
                    url=url,
                    json_body=body,
                    headers={"content-type": "application/json"},
                    tag=f"bopla:{ep.operation_id}:{name}",
                )
                emitted += 1


def _build_body(schema: dict[str, Any]) -> dict[str, Any]:
    props = schema.get("properties") or {}
    required = schema.get("required") or []
    out: dict[str, Any] = {}
    for name in required:
        prop = props.get(name) or {}
        out[name] = _synthetic(prop)
    return out


def _synthetic(prop: dict[str, Any]) -> Any:
    t = prop.get("type")
    fmt = prop.get("format")
    if t == "string":
        if fmt == "email":
            return "test@example.com"
        if fmt == "uuid":
            return "00000000-0000-0000-0000-000000000000"
        return prop.get("example") or "x"
    if t == "integer":
        return prop.get("example") or 1
    if t == "number":
        return prop.get("example") or 1.0
    if t == "boolean":
        return False
    if t == "array":
        return []
    if t == "object":
        return {}
    return None


def _fill_path_params(ep: Endpoint) -> str:
    # mass assignment targets the body, not path ids. fill any path params
    # with a benign placeholder so the URL is well-formed.
    out = ep.path
    for p in ep.path_params():
        placeholder = "1" if (p.schema or {}).get("type") == "integer" else "x"
        out = out.replace("{" + p.name + "}", placeholder)
    return out


def _join(base: str, path: str) -> str:
    if not path.startswith("/"):
        path = "/" + path
    return base.rstrip("/") + path
