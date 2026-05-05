# Changelog

## 0.1.0 — 2026-05-05

First public release.

- BOLA strategy (API1) and Mass Assignment strategy (API3).
- LLM-backed invariant checker with prompt-injection hardening: random
  sentinels around response bodies, evidence-must-be-substring verifier,
  control-char stripping on rule and body before they reach the LLM.
- Scope guard: origin allow-list, IDNA hostname normalization, no-redirect
  executor, default block on private and loopback IPs, always-block on
  cloud metadata IPs.
- Auth: bearer, cookie, header, JWT-refresh providers. Sensitive headers
  redacted at finding capture time.
- HTML report with autoescaped templating and shell-safe curl reproducer.
- Anthropic and Ollama LLM backends.
- 78 tests covering scope, auth, schema, state graph, strategies,
  invariants, and reporting.
