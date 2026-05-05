# Architecture

augur is a small set of components wired together by a single `Engine`. Each
component has one job. The engine drives the loop.

## Components

- **ScopeGuard** (`augur.http.scope`). Holds the allow-list of origins. Every
  request passes through its `check()` before going to the network. Refuses
  non-http schemes and unknown hosts. Not bypassable by strategies or by the
  LLM.
- **AuthProvider** (`augur.http.auth`). Returns headers and cookies for the
  current principal. Implementations: `NoAuth`, `BearerAuth`, `CookieAuth`,
  `HeaderAuth`, `JWTRefreshAuth`. The refresh provider rotates tokens when
  the cached one is close to expiry.
- **Executor** (`augur.http.executor`). The single chokepoint that sends
  requests. Uses `httpx`, redirects disabled so a 302 cannot smuggle a
  request out of scope. Caps response bodies to keep memory bounded.
- **Catalog** (`augur.schema.catalog`). The parsed OpenAPI doc. Exposes the
  list of endpoints, their parameters, and helpers like `with_path_id()`
  that strategies use to find candidate targets.
- **StateGraph** (`augur.state.graph`). Records id-shaped values seen in
  responses, tagged with the principal that observed them. Drives two
  things: filling in path parameters with real ids, and generating
  cross-principal pairs for BOLA.
- **Strategy** (`augur.strategies.base`). One module per OWASP category.
  A strategy is a planner. Given a `StrategyContext`, it yields
  `PlannedRequest` objects. It does not send. The engine sends and feeds
  the response back through `observe()`.
- **InvariantChecker** (`augur.invariants.checker`). Loads YAML rules,
  matches them by method and path pattern, and asks the LLM whether the
  response violates each rule. Conservative by design. A non-JSON or
  ambiguous reply produces no finding.
- **Engine** (`augur.engine`). Owns the loop. Warms up by issuing safe
  GETs to seed the state graph. Then rotates strategies until the
  deadline or request budget is hit. For each response, it runs the
  invariant checker and records findings, deduped by fingerprint.
- **Report** (`augur.report`). Wraps findings as a Finding model, renders
  HTML, formats reproducer curl commands.

## Flow

```
                    +---------------------+
                    |   OpenAPI spec      |
                    +----------+----------+
                               |
                               v
                    +---------------------+
                    |   schema.Catalog    |
                    +----------+----------+
                               |
                               v
+------------+     +-----------+----------+     +-----------------+
| Strategies | --> |        Engine        | <-- | InvariantChecker|
+------------+     |  - warmup            |     +--------+--------+
                   |  - plan / send / obs |              |
                   |  - dedup findings    |              v
                   +-----------+----------+        +-----+-----+
                               |                   |    LLM    |
                               v                   +-----------+
                    +---------------------+
                    |      Executor       |
                    |  ScopeGuard + Auth  |
                    +----------+----------+
                               |
                               v
                          +----+----+      +-------------+
                          |  Target | ---> | StateGraph  |
                          +---------+      +------+------+
                                                  |
                                                  v
                                          +-------+--------+
                                          |    Report      |
                                          | (HTML + curl)  |
                                          +----------------+
```

The engine is the only component with mutable state across the run. Strategies
are pure planners. The executor is request-scoped. The state graph is the
shared memory between requests.

## Versus Schemathesis

Schemathesis fuzzes against the spec. Its bug class is "the API does not match
its OpenAPI". That covers schema violations, 500 errors on valid input, and
type confusion. It cannot find BOLA, because a BOLA response is well-formed,
schema-conformant, and 200 OK. The bug is that it returned someone else's
data.

augur is built around the OWASP API Top 10 instead. Each request has a goal.
Findings are tagged by category, not by spec field.

## Versus RestlerFuzzer

RestlerFuzzer infers request sequences from the spec. If `POST /users`
returns an id, and `GET /users/{id}` takes one, it chains them. The chain
information has to be declared or inferred from the spec.

augur learns the same chains, but from the wire. The state graph watches
every response for id-shaped keys and stores them with the principal who
observed them. This means augur works on specs that omit dependencies and
on responses with embedded ids the spec does not advertise. It also gives
us cross-principal pairs for free, which is what makes the BOLA strategy
possible without manual configuration.

## Adding a strategy

1. Subclass `Strategy` in `src/augur/strategies/`.
2. Set `category` to the right `OwaspCategory` value.
3. Implement `plan(ctx, budget)` to yield `PlannedRequest` objects.
4. Optionally override `observe()` to refine future plans from responses.
5. Register the strategy in the engine wiring (currently `cli.py`).

A strategy never sends, never authenticates, never decides scope. Those
belong to the executor.
