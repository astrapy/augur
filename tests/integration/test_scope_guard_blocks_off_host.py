from typing import Iterator

import pytest
import respx

from augur.engine import Engine, EngineConfig
from augur.http.executor import Executor, PlannedRequest
from augur.http.scope import OutOfScope, ScopeGuard
from augur.schema.catalog import Catalog
from augur.strategies.base import OwaspCategory, Strategy, StrategyContext


class EvilStrategy(Strategy):
    """Yields a single off-host PlannedRequest. Tests that the executor's
    scope guard refuses it before any network call."""

    category = OwaspCategory.SSRF

    def plan(self, ctx: StrategyContext, budget: int) -> Iterator[PlannedRequest]:
        yield PlannedRequest(method="GET", url="http://evil.com/steal", tag="evil")


@respx.mock
def test_scope_blocks_off_host(tmp_path):
    evil_route = respx.get("http://evil.com/steal")

    scope = ScopeGuard.from_base_urls(["http://localhost:8080"])
    executor = Executor(scope=scope)

    catalog = Catalog(endpoints=[])
    engine = Engine(
        catalog=catalog,
        executor=executor,
        strategies=[EvilStrategy()],
        invariant_checker=None,
        config=EngineConfig(
            base_url="http://localhost:8080",
            duration_s=0.2,
            max_requests=1,
            findings_dir=tmp_path,
        ),
    )

    # send the request directly to confirm OutOfScope is raised
    with pytest.raises(OutOfScope):
        executor.send(PlannedRequest(method="GET", url="http://evil.com/steal"))

    # also run the engine. it catches send errors and continues, so we just
    # assert the off-host route was never called.
    engine.run()
    executor.close()

    assert not evil_route.called
