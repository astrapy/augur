# Usage

## Install

```
git clone https://github.com/your-org/augur.git
cd augur
pip install -e ".[anthropic,dev]"
```

Python 3.10 or newer. The `anthropic` extra pulls the official SDK. Skip it
if you only use Ollama.

## Quick run

```
export ANTHROPIC_API_KEY=sk-ant-...
augur run \
  --spec ./openapi.yaml \
  --base-url http://localhost:8888 \
  --time 5m \
  --invariants ./examples/invariants/crapi.yaml \
  --auth bearer \
  --auth-value "$JWT" \
  --out ./findings
```

The exit code is `0` when no findings, `1` when at least one finding is
recorded. Useful in CI.

## CLI flags

`augur run` accepts:

- `--spec PATH` (required). Path to an OpenAPI 3.x file. YAML or JSON.
- `--base-url URL` (required). The target. Only this origin is in scope.
  All requests to other hosts are refused at the executor.
- `--time SECONDS` (default `300`). Wall-clock budget. The engine stops at
  the deadline even mid-strategy.
- `--max-requests N` (default unset). Cap on total requests. The engine
  stops at whichever of `--time` or `--max-requests` hits first.
- `--invariants PATH` (optional). YAML file with rules. Without this flag
  the LLM is not consulted and only strategy-internal signals can produce
  findings. See `docs/invariants.md`.
- `--auth {none,bearer,cookie,header}` (default `none`). Auth scheme.
- `--auth-value VALUE`. Meaning depends on `--auth`:
  - `bearer`: the raw token. Falls back to `AUGUR_BEARER` if omitted.
  - `cookie`: `name=value;other=value`.
  - `header`: `Header-Name: value`.
- `--llm-backend {anthropic,ollama}` (default `anthropic`). Which LLM
  client the invariant checker uses.
- `--llm-model NAME` (optional). Model id. Defaults: Anthropic uses
  `claude-haiku-4-5-20251001`, Ollama uses `llama3.2`.
- `--verify-tls / --no-verify-tls` (default verify). Disable for staging
  with self-signed certs. Do not disable in production.
- `--out PATH` (default `./findings`). Output directory. The HTML report
  is written to `report.html` inside it.

## Environment variables

- `ANTHROPIC_API_KEY`. Required when `--llm-backend anthropic` is in use
  and `--invariants` is set. Read by the Anthropic SDK directly.
- `AUGUR_BEARER`. Fallback for `--auth-value` when `--auth bearer`. Lets
  you keep tokens out of shell history.
- `AUGUR_LOG`. Log level. `debug`, `info`, `warning`, `error`. Default
  `info`. Read by `augur.utils.logging`.
- `OLLAMA_HOST`. Where the Ollama server lives. Default
  `http://localhost:11434`. Read by `OllamaClient`.

## Examples

Fuzz an unauthenticated API for five minutes, no LLM checks:

```
augur run --spec spec.yaml --base-url http://localhost:8000 --time 5m
```

Fuzz crAPI with cookie auth and the bundled invariants:

```
augur run \
  --spec ./openapi-crapi.yaml \
  --base-url http://localhost:8888 \
  --auth cookie \
  --auth-value "session=abc;csrf=def" \
  --invariants ./examples/invariants/crapi.yaml \
  --time 10m
```

Use a local Ollama model instead of Anthropic:

```
export OLLAMA_HOST=http://localhost:11434
augur run \
  --spec ./openapi.yaml \
  --base-url http://localhost:8888 \
  --invariants ./inv.yaml \
  --llm-backend ollama \
  --llm-model llama3.2 \
  --time 5m
```

## Output

`./findings/report.html` contains:

- a finding per dedup fingerprint
- severity, OWASP category, invariant name
- the request method, URL, headers, body
- the response status, headers, body preview
- a copy-pasteable curl reproducer

The same fingerprint logic suppresses duplicates within a run. Across runs,
expect repeats unless you diff reports yourself.

## Programmatic use

```python
from pathlib import Path
from augur.engine import Engine, EngineConfig
from augur.http.auth import BearerAuth
from augur.http.executor import Executor
from augur.http.scope import ScopeGuard
from augur.schema.loader import load as load_spec
from augur.strategies.bola import BolaStrategy

base = "http://localhost:8888"
catalog = load_spec(Path("openapi.yaml"))
executor = Executor(scope=ScopeGuard.from_base_urls([base]), auth=BearerAuth("..."))
engine = Engine(
    catalog=catalog,
    executor=executor,
    strategies=[BolaStrategy()],
    invariant_checker=None,
    config=EngineConfig(base_url=base, duration_s=60),
)
engine.warmup()
findings = engine.run()
executor.close()
```
