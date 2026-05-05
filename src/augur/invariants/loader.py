"""YAML invariant loader.

Schema:

    invariants:
      - name: no-cross-tenant-leak
        endpoint: "GET /users/*"
        rule: "response must not contain any user other than the requester"
        severity: high
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

_VALID_SEVERITY = {"low", "medium", "high", "critical"}
_PATTERN_RE = re.compile(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|\*)\s+(.+)$")
_MAX_INV_BYTES = 1 * 1024 * 1024


class _NoAliasLoader(yaml.SafeLoader):
    def compose_node(self, parent, index):  # type: ignore[no-untyped-def]
        if self.check_event(yaml.AliasEvent):
            event = self.peek_event()
            raise yaml.constructor.ConstructorError(
                None, None, "yaml aliases are disallowed for security", event.start_mark
            )
        return super().compose_node(parent, index)


@dataclass(frozen=True)
class Invariant:
    name: str
    method: str  # "GET" or "*"
    path_pattern: str  # glob-ish, * matches one segment
    rule: str
    severity: str

    def matches(self, method: str, path: str) -> bool:
        if self.method != "*" and self.method != method.upper():
            return False
        regex = "^" + re.sub(r"\{[^}]+\}", "[^/]+", re.escape(self.path_pattern).replace(r"\*", "[^/]*")) + "$"
        return re.match(regex, path) is not None


def load(path: Path) -> list[Invariant]:
    blob = path.read_bytes()
    if len(blob) > _MAX_INV_BYTES:
        raise ValueError(f"invariants file too large: {len(blob)} bytes")
    raw = blob.decode("utf-8")
    doc = yaml.load(raw, Loader=_NoAliasLoader) or {}
    items = doc.get("invariants") or []
    if not isinstance(items, list):
        raise ValueError("invariants: must be a list")
    out: list[Invariant] = []
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            raise ValueError(f"invariants[{i}] must be a mapping")
        out.append(_one(item, i))
    return out


def _one(item: dict, idx: int) -> Invariant:
    name = item.get("name")
    endpoint = item.get("endpoint")
    rule = item.get("rule")
    severity = (item.get("severity") or "medium").lower()
    if not isinstance(name, str) or not name:
        raise ValueError(f"invariants[{idx}].name required")
    if not isinstance(endpoint, str) or not _PATTERN_RE.match(endpoint):
        raise ValueError(f"invariants[{idx}].endpoint must be 'METHOD path-pattern'")
    if not isinstance(rule, str) or not rule:
        raise ValueError(f"invariants[{idx}].rule required")
    if severity not in _VALID_SEVERITY:
        raise ValueError(f"invariants[{idx}].severity must be one of {_VALID_SEVERITY}")
    m = _PATTERN_RE.match(endpoint)
    method, path = m.group(1), m.group(2)
    return Invariant(name=name, method=method, path_pattern=path, rule=rule, severity=severity)
