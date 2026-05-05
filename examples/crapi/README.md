# crAPI demo

[crAPI](https://github.com/OWASP/crAPI) is the OWASP "completely ridiculous
API", a deliberately vulnerable application for an automotive workshop. It
ships an OpenAPI spec, runs in Docker, and contains real instances of BOLA,
mass assignment, SSRF, BFLA, and JWT issues. It is the canonical demo
target for augur.

## Run crAPI

```
git clone https://github.com/OWASP/crAPI.git
cd crAPI/deploy/docker
docker compose pull
docker compose -f docker-compose.yml up -d
```

The web app comes up at `http://localhost:8888`. Register two users via
the web UI so augur has cross-principal data to work with. Capture a
bearer JWT from the browser dev tools after login.

## Run augur against it

From the augur repo root:

```
export ANTHROPIC_API_KEY=sk-ant-...
export AUGUR_BEARER="$JWT"

augur run \
  --spec ./examples/crapi/openapi-crapi.yaml \
  --base-url http://localhost:8888 \
  --auth bearer \
  --invariants ./examples/invariants/crapi.yaml \
  --time 5m \
  --out ./findings/crapi
```

Drop the OpenAPI spec from the crAPI repo into
`examples/crapi/openapi-crapi.yaml` first. crAPI ships it under
`openapi/openapi-spec.yaml`.

## Expected output

After five minutes you should see something like:

```
loaded spec with 38 endpoint(s)
loaded 6 invariant(s)
warmup seeded 9 endpoint(s)
engine running for 300s
finding: API1: no-cross-tenant-leak [critical]
finding: API3: mass-assignment-forbidden-fields [high]
finding: API2: no-jwt-in-response-body [high]
finding: API7: ssrf-mechanic-id [high]
done. requests=412 findings=4 report=findings/crapi/report.html
```

Open `findings/crapi/report.html`. Each finding lists the OWASP category,
severity, the request, the response, and a copy-pasteable curl reproducer.

The exit code is `1` because findings were recorded. That makes the
command useful as a CI gate.
