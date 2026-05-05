# augur

LLM-driven fuzzer for HTTP APIs. Reads an OpenAPI spec, sends requests, hunts
for the OWASP API Top 10. Tells you what broke and how to reproduce it.

The name comes from the Roman priest who read omens to predict the future.
augur reads API responses to find what is rotten.

## What makes it different

There are already half a dozen API fuzzers. Most either follow the spec
strictly (Schemathesis) or generate sequences from the spec (RestlerFuzzer).
None of them understand the application.

augur has three things the others do not:

1. **OWASP-mapped test strategies.** Each request is generated with a goal:
   BOLA, BFLA, mass assignment, broken auth, excessive data exposure. Findings
   are tagged with the OWASP category, not just "spec violation".
2. **Observation-driven state.** When `POST /users` returns `{"id": 42}`, the
   fuzzer remembers that 42 is a valid user id and uses it as input to other
   endpoints. RestlerFuzzer needs the dependency declared in the spec. We
   learn it from the wire.
3. **Natural-language invariants.** Users can write rules like "no response to
   GET /users/{id} should contain another user's email." The LLM checks every
   response against the rule set and flags violations. This catches logic bugs
   that no schema-only fuzzer can.

The only competitor doing close to this is StackHawk, which is closed-source
and enterprise-priced.

## v1 scope

In:
- OpenAPI 3.x ingestion
- Auth: bearer token, session cookie, custom header. JWT refresh handled when
  the spec declares the refresh endpoint.
- Goal-driven request generation (six OWASP-mapped strategies)
- Response fingerprinting and corpus-style coverage of distinct response shapes
- Observed-id propagation between requests
- Invariant DSL (YAML), checked by the LLM each response
- HTML report with reproducer curl commands per finding
- `augur run --spec openapi.yaml --base-url https://localhost:8888 --time 5m`

Out (v2 or later):
- GraphQL
- gRPC, WebSocket
- OAuth flows beyond bearer
- Auto-discovery without a spec
- Distributed runs

## Demo target

crAPI ([https://github.com/OWASP/crAPI](https://github.com/OWASP/crAPI)).
Vulnerable-by-design API for an automotive shop. Has BOLA, mass assignment,
SSRF, JWT issues. Ships with an OpenAPI spec. Runs in Docker. Realistic shape,
not a CTF toy.

The README demo is "spin up crAPI, run augur for 5 minutes, screenshot the
report showing 4+ OWASP findings with reproducer curls."

## Architecture

```
src/augur/
  schema/        OpenAPI loader, endpoint catalog
  strategies/    one module per OWASP category, each implements Strategy
  state/         observed values, id graph
  invariants/    YAML loader, LLM-based response checker
  http/          executor, scope guard, auth providers
  llm/           Anthropic and Ollama clients
  report/        finding model, html renderer, curl reproducer
  utils/         logging
  engine.py
  cli.py
runner-rs/       optional, for v2 high-throughput dumb-fuzz pass
```

Reused from neurofuzz: `LLMClient` interface and the two backends, the
corpus admission pattern, `AGENTS.md` style rules.

Replaced: `Target`, `Mutator`, `CoverageTracker`. They were byte-shaped, this
project is request-shaped.

## Outstanding-ness checklist

To beat the obvious "why not Schemathesis" comment:

- [ ] OWASP API Top 10 coverage table in the README, with example finding for each
- [ ] One-command Docker setup that runs crAPI and augur together
- [ ] Reproducer curls in every finding, copy-pasteable
- [ ] HTML report with severity, OWASP tag, request, response, why it is a bug
- [ ] Invariant DSL examples for at least three real scenarios
- [ ] CI integration example (GitHub Action that fails build on new findings)
- [ ] At least one finding in a real open-source API, written up as a blog post

The last point is the unfair advantage. Pick a small open-source API project,
run augur against it, find a real bug, file the issue with the report as
evidence. That single GitHub issue link in the README is worth more than all
the architecture docs combined.

## Effort

Three weeks of focused work to v1. One week to demo-quality, two more weeks
to OSS-quality with the polish above.

## Locked-in decisions

1. **Name:** augur
2. **Auth:** bearer + session cookie + custom header escape hatch. JWT refresh
   when declared in the spec.
3. **LLM provider:** Anthropic default, Ollama documented, swappable via env var.
4. **Invariant format:** YAML. Each invariant has a name, an endpoint pattern,
   a plain-English rule, and a severity.
