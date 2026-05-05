# augur

LLM-driven fuzzer for HTTP APIs. Reads an OpenAPI spec, sends crafted
requests, hunts for the OWASP API Top 10. Tells you what broke and how to
reproduce it.

augur reads API responses to find what is rotten.

> **Authorized testing only.** augur sends active, sometimes hostile traffic
> at the target. Do not point it at any service you do not have written
> permission to test. See [docs/security.md](docs/security.md).

## Why this exists

Schemathesis and RestlerFuzzer find spec violations and crashes. They cannot
find BOLA, mass assignment, or broken object-level auth, because those are
not violations of the spec. Those are the bugs that ship to production and
end up in CVE databases.

augur is built around three ideas:

1. Every request has a goal mapped to an OWASP API Top 10 category.
2. Observed response data feeds the next request, so we learn the application
   state without needing the spec to declare every dependency.
3. Findings are checked against natural-language invariants, so logic bugs
   are caught even when the response looks well-formed.

## Status

Pre-alpha. Active build.

## Quick start

```
pip install -e .
augur run --spec ./openapi.yaml --base-url http://localhost:8888 --time 5m
```

Exit codes: 0 clean, 1 tool error, 2 findings present (use
`--no-fail-on-findings` to keep CI green while still emitting a report).

See [docs/usage.md](docs/usage.md) for the full reference.

## Demo

Spin up [crAPI](https://github.com/OWASP/crAPI) (a deliberately vulnerable
API), point augur at it, get a report in five minutes. See
[examples/crapi/README.md](examples/crapi/README.md).

## Layout

```
src/augur/         core code
tests/             unit and integration tests
examples/          demo configs and invariants
docs/              architecture, usage, security, strategies, invariants
```

## License

Apache 2.0
