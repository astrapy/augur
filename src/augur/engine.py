"""Engine. Drives strategies, sends requests via the executor, runs invariants
on responses, accumulates findings."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from augur.http.executor import Executor, PlannedRequest, Response
from augur.invariants.checker import InvariantChecker
from augur.report.finding import Finding
from augur.schema.catalog import Catalog
from augur.state.graph import StateGraph
from augur.strategies.base import Strategy, StrategyContext
from augur.utils.logging import get_logger

log = get_logger(__name__)

_SENSITIVE_HEADERS = frozenset({
    "authorization", "cookie", "set-cookie",
    "x-api-key", "x-auth-token", "x-csrf-token", "proxy-authorization",
})


def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        k: ("<REDACTED>" if k.lower() in _SENSITIVE_HEADERS else v)
        for k, v in headers.items()
    }


@dataclass
class EngineConfig:
    base_url: str
    duration_s: float = 300.0
    max_requests: int | None = None
    requests_per_strategy_round: int = 8
    warmup_max_endpoints: int = 50
    findings_dir: Path = Path("./findings")


@dataclass
class EngineStats:
    requests_sent: int = 0
    findings: int = 0
    started_at: float = field(default_factory=time.time)

    def rps(self) -> float:
        return self.requests_sent / max(time.time() - self.started_at, 1e-6)


class Engine:
    def __init__(
        self,
        catalog: Catalog,
        executor: Executor,
        strategies: list[Strategy],
        invariant_checker: InvariantChecker | None,
        config: EngineConfig,
        principal: str = "default",
    ):
        self.catalog = catalog
        self.executor = executor
        self.strategies = strategies
        self.invariants = invariant_checker
        self.config = config
        self.state = StateGraph()
        self.findings: list[Finding] = []
        self._seen_fps: set[str] = set()
        self.stats = EngineStats()
        self.principal = principal

    def warmup(self) -> None:
        # safe GETs to seed the state graph with real ids before strategies run
        seeded = 0
        attempted = 0
        for ep in self.catalog.endpoints:
            if attempted >= self.config.warmup_max_endpoints:
                break
            if ep.method != "GET":
                continue
            if any(p.required for p in ep.parameters if p.location == "path"):
                continue
            attempted += 1
            url = self.config.base_url.rstrip("/") + ep.path
            try:
                res = self.executor.send(PlannedRequest(method="GET", url=url, tag="warmup"))
            except Exception as e:
                log.debug("warmup skip %s: %s", url, type(e).__name__)
                continue
            self.stats.requests_sent += 1
            if res.is_json():
                try:
                    self.state.record_response(res.json(), ep.path, owner=self.principal)
                    seeded += 1
                except Exception as e:
                    log.debug("warmup decode skip %s: %s", url, type(e).__name__)
        log.info("warmup seeded %d endpoint(s)", seeded)

    def run(self) -> list[Finding]:
        # reset clock so warmup time doesn't eat the duration budget
        self.stats.started_at = time.time()
        deadline = self.stats.started_at + self.config.duration_s
        log.info("engine running for %.0fs", self.config.duration_s)

        while time.time() < deadline:
            if self.config.max_requests is not None and self.stats.requests_sent >= self.config.max_requests:
                break
            for strat in self.strategies:
                ctx = StrategyContext(
                    catalog=self.catalog,
                    state=self.state,
                    base_url=self.config.base_url,
                    principal=self.principal,
                )
                for req in strat.plan(ctx, self.config.requests_per_strategy_round):
                    if time.time() >= deadline:
                        break
                    try:
                        res = self.executor.send(req)
                    except Exception as e:
                        log.debug("send failed %s: %s", req.url, type(e).__name__)
                        continue
                    self.stats.requests_sent += 1
                    if res.is_json():
                        try:
                            self.state.record_response(res.json(), req.url, owner=self.principal)
                        except Exception as e:
                            log.debug("record skip %s: %s", req.url, type(e).__name__)
                    strat.observe(ctx, req, res)
                    self._evaluate(strat, req, res)
        return self.findings

    def _evaluate(self, strategy: Strategy, req: PlannedRequest, res: Response) -> None:
        if self.invariants is None:
            return
        path = urlparse(req.url).path
        for verdict in self.invariants.check(req.method, path, res):
            f = Finding(
                category=strategy.category.value,
                severity=verdict.invariant.severity,
                title=f"{strategy.category.name}: {verdict.invariant.name}",
                rationale=verdict.evidence,
                request_method=req.method,
                request_url=req.url,
                request_headers=_redact_headers(req.headers),
                request_body=req.raw_body,
                response_status=res.status_code,
                response_headers=_redact_headers(res.headers),
                response_body_preview=res.text()[:1024],
                invariant_name=verdict.invariant.name,
                strategy_tag=req.tag,
                principal=self.principal,
            )
            fp = f.fingerprint()
            if fp in self._seen_fps:
                continue
            self._seen_fps.add(fp)
            self.findings.append(f)
            self.stats.findings += 1
            log.warning("finding: %s [%s]", f.title, f.severity)
