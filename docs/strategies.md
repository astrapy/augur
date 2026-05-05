# Strategies

Each strategy targets one OWASP API Top 10 category. A strategy is a planner.
It reads the catalog and the state graph and yields `PlannedRequest` objects.
The engine sends them and feeds responses back. Detection is split between
two places:

- the strategy itself, when the signal is in the response shape (status,
  headers, structural cues)
- the invariant checker, when the signal is semantic and best judged by the
  LLM against a written rule

## Status

| OWASP API category                                | Status   | Module                       |
| ------------------------------------------------- | -------- | ---------------------------- |
| API1:2023 Broken Object Level Authorization       | Shipped  | `augur.strategies.bola`      |
| API2:2023 Broken Authentication                   | Planned  | (none yet)                   |
| API3:2023 Broken Object Property Level Auth       | Shipped  | `augur.strategies.mass_assignment` |
| API4:2023 Unrestricted Resource Consumption       | Planned  | (none yet)                   |
| API5:2023 Broken Function Level Authorization     | Planned  | (none yet)                   |
| API6:2023 Unrestricted Sensitive Business Flows   | Planned  | (none yet)                   |
| API7:2023 Server Side Request Forgery             | Planned  | (none yet)                   |
| API8:2023 Security Misconfiguration               | Planned  | (none yet)                   |
| API9:2023 Improper Inventory Management           | Planned  | (none yet)                   |
| API10:2023 Unsafe Consumption of APIs             | Planned  | (none yet)                   |

## API1: BOLA (shipped)

Implementation: `BolaStrategy` in `src/augur/strategies/bola.py`.

Detection idea. For every endpoint with a path id parameter, find ids that
were observed under a different principal and try to access them with the
current principal. If the response is 2xx and the body looks like the other
principal's data, the API has Broken Object Level Authorization.

What the strategy does:

1. Walks the catalog for endpoints whose path contains a parameter
   (`with_path_id()`).
2. For each path id, queries the state graph for cross-principal
   observations.
3. Substitutes the foreign id into the path and yields a request tagged
   `bola:<operation_id>:<param>=<value>@<other_owner>`.

What the LLM does. The strategy itself does not look at the body. It hands
the response to the invariant checker. The checker fires every YAML
invariant whose endpoint pattern matches and asks the LLM whether the
response violates the rule. For BOLA the typical rule is "no response to
this endpoint should contain data belonging to a user other than the
requester." The LLM returns strict JSON; the checker only records a
finding when the verdict is unambiguous.

## API2: Broken Authentication (planned)

Detection idea. Probe the auth surface for missing or weak controls:
unauthenticated access to authenticated endpoints, accepted tokens with
broken signatures, replay of expired tokens, leaky reset flows. The LLM
helps judge response bodies that hint at "you are logged in" without a
valid principal.

## API3: Object Property Level / Mass Assignment (shipped)

Implementation: `MassAssignmentStrategy` in `src/augur/strategies/mass_assignment.py`.

For each write endpoint with an object request schema, the strategy builds
a body containing the schema's required fields filled with synthetic values,
then adds a single tampering field per request (`is_admin`, `role`,
`verified`, `available_credit`, ...). One request per tampering field, so a
strict server that rejects the whole body on one unknown field still gives
the others a chance.

Detection happens in the invariant checker. The matching rule for crAPI is
`mass-assignment-profile-forbidden-fields` in
`examples/invariants/crapi.yaml`. Adapt it to your data shape.

## API4: Unrestricted Resource Consumption (planned)

Detection idea. Pagination without limits, expensive search parameters,
request amplification. Send oversized inputs and watch for response time
explosion or 5xx. The LLM is not strictly required; this is largely
metric-driven.

## API5: BFLA (planned)

Detection idea. Operations that look like admin (`/admin/*`, `DELETE` on
collections, `PUT` on other users' resources) are tried with a
non-privileged principal. Same shape as BOLA, but on the function
boundary, not the object boundary.

## API6: Sensitive Business Flows (planned)

Detection idea. Detect flows like coupon redemption, password reset, OTP
verification and try to abuse them at high rate or out of order. Heavy on
domain knowledge, so the LLM is used to identify which endpoints
constitute a flow worth abusing.

## API7: SSRF (planned)

Detection idea. For any input that looks like a URL or hostname, supply
internal addresses (`127.0.0.1`, `169.254.169.254`, `localhost`). Watch
for the metadata service signature in the response or for timing
deltas. The LLM is asked to judge whether the response indicates the
target fetched an attacker-controlled URL.

## API8: Security Misconfiguration (planned)

Detection idea. Verbose error pages, stack traces, default admin paths,
permissive CORS, missing security headers. Mostly heuristic, with the LLM
flagging rare cases like "this 500 page leaks a database error."

## API9: Improper Inventory Management (planned)

Detection idea. Probe for undocumented or older API versions next to the
documented one (`/v1`, `/v2`, `/internal`). Compare behaviour. The LLM is
asked to flag responses that suggest a deprecated host is reachable.

## API10: Unsafe Consumption of APIs (planned)

Detection idea. Hard to test from the outside. Where the spec advertises
upstream calls (webhooks, integrations), inject controlled payloads and
look for naive forwarding. Largely LLM-driven invariant work.

## Adding a strategy

See `docs/architecture.md` for the contract. The smallest possible
strategy is roughly thirty lines. The hard part is the detection idea,
which often comes down to writing the right invariant.
