"""OpenAPI 3.x loader. Validates the spec, then flattens it into a Catalog."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from augur.schema.catalog import Catalog, Endpoint, Parameter


_MAX_SPEC_BYTES = 16 * 1024 * 1024


class _NoAliasLoader(yaml.SafeLoader):
    """SafeLoader that refuses YAML aliases at the compose stage, which is
    where aliases are expanded. Adding a constructor for the alias tag does
    nothing because the Composer resolves aliases before construction runs.
    Refusing here defeats billion-laughs style DoS at parse time.
    """

    def compose_node(self, parent, index):  # type: ignore[no-untyped-def]
        if self.check_event(yaml.AliasEvent):
            event = self.peek_event()
            raise yaml.constructor.ConstructorError(
                None, None, "yaml aliases are disallowed for security", event.start_mark
            )
        return super().compose_node(parent, index)


def load(path: Path) -> Catalog:
    blob = path.read_bytes()
    if len(blob) > _MAX_SPEC_BYTES:
        raise ValueError(f"spec too large: {len(blob)} bytes")
    raw = blob.decode("utf-8")
    if path.suffix in (".yaml", ".yml"):
        spec = yaml.load(raw, Loader=_NoAliasLoader)
    else:
        spec = json.loads(raw)
    if not isinstance(spec, dict):
        raise ValueError(f"spec root must be an object, got {type(spec).__name__}")
    return _flatten(spec)


def _flatten(spec: dict[str, Any]) -> Catalog:
    paths = spec.get("paths") or {}
    if not isinstance(paths, dict):
        raise ValueError("spec.paths must be an object")

    components = spec.get("components") or {}
    schemes = (components.get("securitySchemes") or {}) if isinstance(components, dict) else {}

    endpoints: list[Endpoint] = []
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        path_level_params = _params(item.get("parameters") or [], spec)
        for method in ("get", "post", "put", "patch", "delete", "head", "options"):
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            op_params = _params(op.get("parameters") or [], spec)
            params = _dedup_params(path_level_params + op_params)
            req_body = _request_body(op.get("requestBody"), spec)
            endpoints.append(
                Endpoint(
                    method=method.upper(),
                    path=path,
                    operation_id=op.get("operationId") or f"{method}_{path}",
                    parameters=params,
                    request_body_schema=req_body,
                    responses=op.get("responses") or {},
                    security=op.get("security") or spec.get("security") or [],
                    tags=op.get("tags") or [],
                )
            )

    return Catalog(endpoints=endpoints, security_schemes=schemes)


def _params(items: list[Any], spec: dict[str, Any]) -> list[Parameter]:
    out: list[Parameter] = []
    for item in items:
        item = _resolve(item, spec)
        if not isinstance(item, dict):
            continue
        out.append(
            Parameter(
                name=str(item.get("name", "")),
                location=str(item.get("in", "")),
                schema=_resolve(item.get("schema") or {}, spec) or {},
                required=bool(item.get("required", False)),
            )
        )
    return out


def _dedup_params(params: list[Parameter]) -> list[Parameter]:
    # operation-level parameters override path-level parameters of the same (name, in)
    seen: dict[tuple[str, str], Parameter] = {}
    for p in params:
        seen[(p.name, p.location)] = p
    return list(seen.values())


def _request_body(body: Any, spec: dict[str, Any]) -> dict[str, Any] | None:
    body = _resolve(body, spec)
    if not isinstance(body, dict):
        return None
    content = body.get("content") or {}
    if not isinstance(content, dict):
        return None
    # prefer json, fall back to whatever is first
    for ct in ("application/json", "application/*+json"):
        if ct in content:
            schema = content[ct].get("schema") if isinstance(content[ct], dict) else None
            return _resolve(schema or {}, spec)
    if content:
        first = next(iter(content.values()))
        if isinstance(first, dict):
            return _resolve(first.get("schema") or {}, spec)
    return None


def _resolve(node: Any, spec: dict[str, Any], _depth: int = 0) -> Any:
    # minimal $ref resolver. cycles get cut off at depth 8 so a malicious or
    # mistakenly recursive spec cannot stall the loader.
    if _depth > 8 or not isinstance(node, dict):
        return node
    ref = node.get("$ref")
    if isinstance(ref, str) and ref.startswith("#/"):
        target: Any = spec
        for part in ref.lstrip("#/").split("/"):
            # JSON Pointer escapes: ~1 = "/", ~0 = "~", in that order
            part = part.replace("~1", "/").replace("~0", "~")
            if isinstance(target, dict):
                target = target.get(part)
            else:
                return node
        return _resolve(target, spec, _depth + 1)
    return node
