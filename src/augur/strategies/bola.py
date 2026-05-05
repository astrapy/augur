"""Broken Object Level Authorization (API1).

Idea: pick endpoints whose path contains an id. For each one, find an id that
was observed under a *different* principal and try to access it with the
current principal. If the response is 2xx and contains the other principal's
data, that is BOLA.

Detection of "contains the other principal's data" is left to the invariant
checker. This strategy only generates the requests.
"""

from __future__ import annotations

import re
from typing import Iterator
from urllib.parse import quote

from augur.http.executor import PlannedRequest
from augur.schema.catalog import Endpoint
from augur.strategies.base import OwaspCategory, Strategy, StrategyContext

# id values from observed responses must look like an id, not a path. this
# rejects /, ?, #, ., space, and any control char so a hostile target cannot
# steer requests off the intended endpoint via a poisoned id value.
_ID_VALUE_RE = re.compile(r"^[A-Za-z0-9_\-]{1,128}$")


class BolaStrategy(Strategy):
    category = OwaspCategory.BOLA

    def __init__(self, methods: tuple[str, ...] = ("GET", "PUT", "PATCH", "DELETE")):
        self.methods = methods

    def plan(self, ctx: StrategyContext, budget: int) -> Iterator[PlannedRequest]:
        emitted = 0
        for ep in ctx.catalog.with_path_id():
            if ep.method not in self.methods:
                continue
            for req in self._for_endpoint(ep, ctx):
                if emitted >= budget:
                    return
                yield req
                emitted += 1

    def _for_endpoint(self, ep: Endpoint, ctx: StrategyContext) -> Iterator[PlannedRequest]:
        for p in ep.path_params():
            for obs, _other_owner in ctx.state.cross_owner_pairs(p.name):
                if obs.seen_owner == ctx.principal:
                    continue
                value = str(obs.value)
                if not _ID_VALUE_RE.match(value):
                    # poisoned or unsafe id value, skip rather than substitute
                    continue
                # url-encode anyway in case the regex ever loosens
                encoded = quote(value, safe="")
                path = ep.path.replace("{" + p.name + "}", encoded)
                url = _join(ctx.base_url, path)
                yield PlannedRequest(
                    method=ep.method,
                    url=url,
                    tag=f"bola:{ep.operation_id}:{p.name}={value}@{obs.seen_owner}",
                )


def _join(base: str, path: str) -> str:
    if not path.startswith("/"):
        path = "/" + path
    return base.rstrip("/") + path
