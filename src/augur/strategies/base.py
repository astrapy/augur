"""Strategy framework. Each strategy emits PlannedRequest objects targeting a
specific OWASP API Top 10 category."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Iterator

from augur.http.executor import PlannedRequest, Response
from augur.schema.catalog import Catalog
from augur.state.graph import StateGraph


class OwaspCategory(str, Enum):
    BOLA = "API1:2023 Broken Object Level Authorization"
    BROKEN_AUTH = "API2:2023 Broken Authentication"
    BOPLA = "API3:2023 Broken Object Property Level Authorization"
    UNRESTRICTED_RESOURCE = "API4:2023 Unrestricted Resource Consumption"
    BFLA = "API5:2023 Broken Function Level Authorization"
    SENSITIVE_BUSINESS_FLOW = "API6:2023 Unrestricted Access to Sensitive Business Flows"
    SSRF = "API7:2023 Server Side Request Forgery"
    SECURITY_MISCONFIG = "API8:2023 Security Misconfiguration"
    INVENTORY = "API9:2023 Improper Inventory Management"
    UNSAFE_CONSUMPTION = "API10:2023 Unsafe Consumption of APIs"


@dataclass
class StrategyContext:
    catalog: Catalog
    state: StateGraph
    base_url: str
    principal: str  # which auth principal will send these requests


class Strategy(ABC):
    """A strategy plans requests aimed at one OWASP category.

    Strategies are pure planners. They do not send requests, they emit
    PlannedRequest objects. The engine sends and feeds responses back via
    `observe()` so the strategy can refine its next batch.
    """

    category: OwaspCategory

    @abstractmethod
    def plan(self, ctx: StrategyContext, budget: int) -> Iterator[PlannedRequest]:
        """Yield up to `budget` planned requests."""

    def observe(self, ctx: StrategyContext, req: PlannedRequest, res: Response) -> None:
        """Default no-op. Strategies may override to learn from responses."""
        return None
