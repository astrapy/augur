"""Observation graph. Records identifiers seen in responses so later requests
can reference them. This is the core of observation-driven state and the thing
RestlerFuzzer needs the spec to declare but augur learns from the wire.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

# id-shaped JSON keys we sniff from responses. extended at runtime by the engine.
_ID_KEY_PATTERNS = [
    re.compile(r"(?:^|_)id$", re.I),
    re.compile(r"(?:^|_)uuid$", re.I),
    re.compile(r"^[a-z]+_id$", re.I),
    re.compile(r"^id_[a-z]+$", re.I),
]
_MAX_VALUES_PER_KEY = 256


@dataclass
class Observation:
    key: str
    value: Any
    source_endpoint: str
    seen_owner: str | None = None  # which auth principal saw this value, if known


@dataclass
class StateGraph:
    """Per-key bag of observed values, with provenance.

    The graph is the source for two things:
    - filling in path/query parameters with values seen on prior responses
    - generating BOLA test cases by feeding values from one principal's
      session into another principal's session
    """
    by_key: dict[str, list[Observation]] = field(default_factory=lambda: defaultdict(list))
    by_owner: dict[str, set[tuple[str, str]]] = field(default_factory=lambda: defaultdict(set))

    def record_response(self, body: Any, source_endpoint: str, owner: str | None = None) -> int:
        added = self._walk(body, source_endpoint, owner)
        return added

    def _walk(self, node: Any, source: str, owner: str | None) -> int:
        added = 0
        if isinstance(node, dict):
            for k, v in node.items():
                # accept str, int, or stringified non-bool numeric. exclude bool
                # because in python isinstance(True, int) is True.
                if self._looks_like_id_key(k) and self._is_id_value(v):
                    if self._add(k, v, source, owner):
                        added += 1
                added += self._walk(v, source, owner)
        elif isinstance(node, list):
            for item in node:
                added += self._walk(item, source, owner)
        return added

    @staticmethod
    def _is_id_value(v: Any) -> bool:
        if isinstance(v, bool):
            return False
        return isinstance(v, (str, int, float))

    def _looks_like_id_key(self, key: str) -> bool:
        return any(p.search(key) for p in _ID_KEY_PATTERNS)

    def _add(self, key: str, value: Any, source: str, owner: str | None) -> bool:
        bucket = self.by_key[key]
        if any(o.value == value for o in bucket):
            return False
        if len(bucket) >= _MAX_VALUES_PER_KEY:
            # drop oldest, keep recent observations more useful for fuzzing
            bucket.pop(0)
        bucket.append(Observation(key=key, value=value, source_endpoint=source, seen_owner=owner))
        if owner is not None:
            self.by_owner[owner].add((key, str(value)))
        return True

    def values_for(self, key: str) -> list[Observation]:
        # exact match first, then loose suffix match (e.g. user_id matches "id")
        if key in self.by_key:
            return list(self.by_key[key])
        loose: list[Observation] = []
        for k, vs in self.by_key.items():
            if k.lower() == key.lower() or k.lower().endswith("_" + key.lower()):
                loose.extend(vs)
        return loose

    def cross_owner_pairs(self, key: str) -> list[tuple[Observation, str]]:
        """For every observation of `key`, return (obs, other_owner) where other_owner
        has NOT seen this value. Drives BOLA generation."""
        pairs: list[tuple[Observation, str]] = []
        owners = list(self.by_owner.keys())
        for obs in self.values_for(key):
            for other in owners:
                if other == obs.seen_owner:
                    continue
                if (obs.key, str(obs.value)) in self.by_owner.get(other, set()):
                    continue
                pairs.append((obs, other))
        return pairs
