"""Finding model. One per detected issue."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

# collapse id-shaped path segments so /users/42 dedups with /users/99
_NUMERIC = re.compile(r"(?<!/v)/\d+(?=/|$)")  # spare /v1/
_UUID = re.compile(
    r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=/|$)",
    re.IGNORECASE,
)
_OBJECTID = re.compile(r"/[0-9a-f]{24}(?=/|$)", re.IGNORECASE)
_ULID = re.compile(r"/[0-9A-HJKMNP-TV-Z]{26}(?=/|$)")


@dataclass
class Finding:
    category: str
    severity: str
    title: str
    rationale: str
    request_method: str
    request_url: str
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: bytes | None = None
    response_status: int = 0
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body_preview: str = ""
    invariant_name: str | None = None
    strategy_tag: str = ""
    principal: str = ""

    def fingerprint(self) -> str:
        # status range and short body hash keep two different bugs at the same path apart
        body_hash = hashlib.sha256(self.response_body_preview.encode("utf-8", errors="replace")).hexdigest()[:8]
        status_range = f"{self.response_status // 100}xx"
        key = "|".join([
            self.category,
            self.request_method,
            self._normalised_url(),
            self.invariant_name or "",
            self.principal,
            status_range,
            body_hash,
        ])
        return hashlib.sha256(key.encode()).hexdigest()

    def _normalised_url(self) -> str:
        url = self.request_url.split("?")[0]
        url = _UUID.sub("/{uuid}", url)
        url = _ULID.sub("/{ulid}", url)
        url = _OBJECTID.sub("/{oid}", url)
        url = _NUMERIC.sub("/{id}", url)
        return url
