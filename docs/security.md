# Security

augur sends crafted, sometimes hostile, traffic at HTTP APIs. Read this before
you point it at anything.

## Only run against systems you own

Do not point augur at a service you do not have written authorization to test.
Active fuzzing is unauthorized access on a system you do not own. The tool
does not enforce this for you. The default `ScopeGuard` enforces a single
origin once you have decided which one is fair game. It does not verify that
the target is yours.

## Scope guard model

Every outgoing request goes through `ScopeGuard.check()` before the executor
hits the network. The guard:

- accepts only `http` and `https` schemes
- compares the request origin (scheme, host, port) against the allow-list
  built from `--base-url`
- rejects URLs with userinfo, surrounding whitespace, or trailing-dot FQDNs
- IDNA-encodes hostnames so unicode homograph hosts cannot slip through
- by default refuses any private or loopback IP, including IPv4-mapped
  IPv6 wrappers like `[::ffff:127.0.0.1]`. The guard is lifted if the user
  scopes to a private host themselves (e.g. `http://localhost:8080`)
- always blocks cloud metadata IPs unless they are explicitly allow-listed
- raises `OutOfScope` on any mismatch, which the engine logs and skips

`Executor` disables redirect following. A 302 from the target cannot redirect
augur to a different host. The executor also caps response bodies to two
megabytes by default so a hostile target cannot exhaust memory.

The guard is the only line of defence against an LLM-generated request that
wanders. It runs on every request, including warmup and replay.

## Auth handling

Auth providers live in `augur.http.auth`. Tokens and cookies are held in
process memory and attached per request. They are not written to disk by the
core engine.

What you control:

- pass tokens via `AUGUR_BEARER` to keep them out of shell history
- the `JWTRefreshAuth` provider rotates tokens against an endpoint you point
  it at, with the refresh response staying in memory only

Common auth headers (`Authorization`, `Cookie`, `Set-Cookie`, `X-API-Key`,
`X-Auth-Token`, `X-CSRF-Token`, `Proxy-Authorization`) are redacted as soon
as a finding is captured, so they do not sit on disk or in memory in
cleartext. The curl reproducer redacts the same set as a backstop.

What augur does not do:

- it does not encrypt tokens at rest, because it does not store them
- if you use a non-standard auth header, add it to the redaction set in
  `augur.engine` before running

## How findings can leak data

The HTML report and the raw findings include:

- the request URL with path and query parameters
- request headers (sensitive ones redacted, see above)
- request body
- response status, headers (sensitive ones redacted), and the first 1024
  bytes of the response body

If the API returns sensitive data (PII, tokens, internal ids) those bytes
will appear in the report. Treat the report directory as sensitive. Do not
attach it to public issue trackers without redaction.

## Sandboxing

augur runs in your shell, not in a sandbox. There is no chroot, no cgroup,
no syscall filter. The blast radius is what your shell can do. Two practical
recommendations:

1. Run augur from a container or a dedicated VM when fuzzing services that
   sit on a network you also use for development. The scope guard prevents
   augur from leaving the allowed origin, but local DNS or `/etc/hosts`
   tricks during a run can still surprise you.
2. Use a dedicated, low-privilege account in the target system. Do not
   point augur at production with admin credentials.

## Key handling

- `ANTHROPIC_API_KEY` is read by the Anthropic SDK from the environment.
  augur does not log it. Rotate it on a normal cadence.
- `AUGUR_BEARER` is read on startup. Do not commit it to a YAML config or
  to a CI workflow file. Use the secrets feature of your CI provider.
- LLM prompts include the response body so the checker can judge it. If
  the response contains secrets, those bytes go to your LLM provider. For
  sensitive targets, prefer `--llm-backend ollama` so the data stays
  local.
