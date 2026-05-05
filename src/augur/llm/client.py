"""LLM client interface."""

from __future__ import annotations

from abc import ABC, abstractmethod


class LLMClient(ABC):
    @abstractmethod
    def complete(self, prompt: str, *, system: str | None = None, max_tokens: int = 2048) -> str:
        """Send prompt, return text reply. Implementations must not raise on
        rate limit, network failure, etc. Callers handle every Exception."""
