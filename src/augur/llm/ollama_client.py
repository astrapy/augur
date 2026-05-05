"""Ollama client. Talks to a locally running ollama server."""

from __future__ import annotations

import os

import httpx

from augur.llm.client import LLMClient


class OllamaClient(LLMClient):
    def __init__(self, model: str = "llama3.2", host: str | None = None, timeout_s: float = 60.0):
        self.host = host or os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        self.model = model
        self.timeout_s = timeout_s

    def complete(self, prompt: str, *, system: str | None = None, max_tokens: int = 2048) -> str:
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"num_predict": max_tokens},
        }
        if system:
            payload["system"] = system
        with httpx.Client(timeout=self.timeout_s) as c:
            r = c.post(f"{self.host}/api/generate", json=payload)
            r.raise_for_status()
            return r.json().get("response", "")
