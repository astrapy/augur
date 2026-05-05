"""Endpoint catalog: a flat, easy-to-iterate view of an OpenAPI spec."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Parameter:
    name: str
    location: str  # "path" | "query" | "header" | "cookie"
    schema: dict[str, Any]
    required: bool = False


@dataclass
class Endpoint:
    method: str
    path: str
    operation_id: str
    parameters: list[Parameter] = field(default_factory=list)
    request_body_schema: dict[str, Any] | None = None
    responses: dict[str, dict[str, Any]] = field(default_factory=dict)
    security: list[dict[str, list[str]]] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    def path_params(self) -> list[Parameter]:
        return [p for p in self.parameters if p.location == "path"]

    def has_path_id(self) -> bool:
        # heuristic: any path param whose name ends in "id" or matches integer/uuid schema
        for p in self.path_params():
            t = (p.schema or {}).get("type", "")
            fmt = (p.schema or {}).get("format", "")
            if p.name.lower().endswith("id") or t == "integer" or fmt == "uuid":
                return True
        return False


@dataclass
class Catalog:
    endpoints: list[Endpoint]
    base_path: str = ""
    security_schemes: dict[str, dict[str, Any]] = field(default_factory=dict)

    def by_id(self, op_id: str) -> Endpoint | None:
        for e in self.endpoints:
            if e.operation_id == op_id:
                return e
        return None

    def with_path_id(self) -> list[Endpoint]:
        return [e for e in self.endpoints if e.has_path_id()]

    def matching(self, pattern: str) -> list[Endpoint]:
        # pattern is a glob-ish path matcher, supporting * for any path segment.
        # used by invariants and strategy filters.
        regex = "^" + re.escape(pattern).replace(r"\*", "[^/]*").replace(r"\{", "{").replace(r"\}", "}")
        regex = re.sub(r"\{[^}]+\}", "[^/]+", regex) + "$"
        compiled = re.compile(regex)
        return [e for e in self.endpoints if compiled.match(e.path)]
