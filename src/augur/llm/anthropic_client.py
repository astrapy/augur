"""Anthropic client. Uses the official SDK."""

from __future__ import annotations

import os

from augur.llm.client import LLMClient


class AnthropicClient(LLMClient):
    def __init__(self, model: str = "claude-haiku-4-5-20251001", api_key: str | None = None):
        try:
            from anthropic import Anthropic
        except ImportError as e:
            raise RuntimeError("install with: pip install augur-fuzz[anthropic]") from e
        self._client = Anthropic(api_key=api_key or os.environ.get("ANTHROPIC_API_KEY"))
        self.model = model

    def complete(self, prompt: str, *, system: str | None = None, max_tokens: int = 2048) -> str:
        kwargs = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            kwargs["system"] = system
        msg = self._client.messages.create(**kwargs)
        parts = [b.text for b in msg.content if getattr(b, "type", None) == "text"]
        return "".join(parts)
