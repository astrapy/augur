# Invariants

Invariants are natural-language rules the LLM checks against every matching
response. They cover the bugs no schema can describe: cross-tenant leaks,
forbidden fields accepted, sensitive data in the wrong place.

## YAML format

```yaml
invariants:
  - name: <short-id>
    endpoint: "<METHOD> <path-pattern>"
    rule: "<one-sentence rule in plain English>"
    severity: low | medium | high | critical
```

Fields:

- `name`. Short identifier. Appears in the report and in finding
  fingerprints. Use a slug: `no-cross-tenant-leak`, not `Rule 1`.
- `endpoint`. `METHOD path-pattern`. Method is one of `GET POST PUT PATCH
  DELETE HEAD OPTIONS *`. The path pattern matches one segment per `*` and
  treats `{param}` as a single segment wildcard. Examples:
  - `GET /users/*` matches `/users/42` but not `/users/42/orders`
  - `POST /workshop/api/shop/orders/*` matches the order id slot
  - `* /admin/*` matches any method on a single admin segment
- `rule`. One sentence. Write it as a property the response must hold. The
  LLM has to decide "does this response violate this rule" with only the
  endpoint, status, and body in front of it.
- `severity`. Drives the report grouping. Critical and high should be
  reserved for confirmed data exposure or auth bypass.

## Three real examples for crAPI

```yaml
invariants:
  - name: no-cross-tenant-leak
    endpoint: "GET /workshop/api/shop/orders/*"
    rule: >
      The response must not contain order data, customer email, or vehicle
      data belonging to a user other than the authenticated requester.
      If the response includes any user identifier or email, it must
      match the requester.
    severity: critical

  - name: no-jwt-in-response-body
    endpoint: "* /*"
    rule: >
      No JSON field in the response body should contain a JWT. A JWT is a
      string of three base64url segments separated by dots, with the first
      segment decoding to a JSON header containing 'alg'. Authorization
      tokens belong in cookies or response headers, never in the body of a
      generic resource.
    severity: high

  - name: mass-assignment-forbidden-fields
    endpoint: "POST /identity/api/v2/user/dashboard"
    rule: >
      The response must not show that any of these fields were accepted
      from the request: 'role', 'is_admin', 'isAdmin', 'verified',
      'email_verified', 'tenant_id'. If any of these appear set to a value
      the requester is not entitled to, that is a mass-assignment bug.
    severity: high
```

## How the LLM checker uses them

For every response the engine receives, the checker:

1. Filters invariants whose `endpoint` matches the request method and path.
2. For each match, sends the LLM a short prompt: the rule, the method,
   the path, the status, and the first 4 KB of the response body.
3. Asks the model for strict JSON: `{"violates": true|false, "evidence":
   "..."}`.
4. Records a finding only when `violates` is `true` and the JSON parses
   cleanly. A non-JSON reply, an empty reply, or `violates: false` produces
   nothing.

The system prompt asks the model to be a security reviewer and to set
`violates=true` only when the response clearly demonstrates the rule is
broken. This conservative posture is the lever for false positives.

## False positive guidance

LLM judgements are not deterministic. Some practical guidance:

- **Be specific in the rule.** "Must not contain other users' data" is
  vague. "Must not contain a `user_id` other than the authenticated
  requester's" is concrete. The model performs better on concrete rules.
- **Anchor with field names.** Mention exact JSON keys when you can. The
  model can then match on structure rather than meaning.
- **Use severity to triage.** A high-volume `medium` invariant that fires
  with 30 percent precision is still useful as a triage queue. A
  `critical` finding should make engineers stop their day, so reserve it
  for rules where a true positive is unambiguous.
- **Keep response bodies under 4 KB.** The checker truncates, but rules
  that depend on text deep in a 50 KB body will miss. Prefer endpoints
  that return compact data, or write the rule to focus on the first
  fields.
- **Re-read findings.** The report includes the evidence string the model
  produced. If you see a pattern of weak evidence, tighten the rule.
- **Pair with strategies.** A BOLA finding is most credible when the BOLA
  strategy generated the request and the invariant fires. A finding from
  a non-BOLA strategy under a BOLA invariant is still possible but worth
  more scrutiny.
