"""augur CLI."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import click

from augur.engine import Engine, EngineConfig
from augur.http.auth import AuthProvider, BearerAuth, CookieAuth, HeaderAuth, NoAuth
from augur.http.executor import Executor
from augur.http.scope import ScopeGuard
from augur.invariants.checker import InvariantChecker
from augur.invariants.loader import load as load_invariants
from augur.report.html import render as render_html
from augur.schema.loader import load as load_spec
from augur.strategies.bola import BolaStrategy
from augur.strategies.mass_assignment import MassAssignmentStrategy
from augur.utils.logging import get_logger

log = get_logger(__name__)

# exit codes follow CI conventions:
#   0  clean run, no findings
#   1  tool error (bad config, network down, exception)
#   2  findings present, optionally treated as failure via --fail-on-findings
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_FINDINGS = 2

_DURATION_RE = re.compile(r"^(\d+(?:\.\d+)?)([smhd])?$")
_DURATION_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


class Duration(click.ParamType):
    """Accepts 5m, 30s, 1h, 2d, or a bare number of seconds."""
    name = "duration"

    def convert(self, value, param, ctx):  # type: ignore[no-untyped-def]
        if isinstance(value, (int, float)):
            return float(value)
        m = _DURATION_RE.match(str(value).strip())
        if not m:
            self.fail(f"invalid duration {value!r}, expected e.g. 5m, 30s, 300", param, ctx)
        n = float(m.group(1))
        unit = m.group(2) or "s"
        return n * _DURATION_UNITS[unit]


def _build_llm(backend: str, model: str | None):
    if backend == "anthropic":
        from augur.llm.anthropic_client import AnthropicClient
        return AnthropicClient(model=model) if model else AnthropicClient()
    if backend == "ollama":
        from augur.llm.ollama_client import OllamaClient
        return OllamaClient(model=model) if model else OllamaClient()
    raise click.BadParameter(f"unknown llm backend: {backend}")


def _build_auth(auth_type: str, value: str | None) -> AuthProvider:
    if auth_type == "none":
        return NoAuth()
    # for non-default auth types, prefer env var so tokens do not appear in
    # ps output or shell history
    env_value = os.environ.get("AUGUR_AUTH_VALUE")
    if value is None and env_value:
        value = env_value
    elif value and env_value:
        log.warning("both --auth-value and AUGUR_AUTH_VALUE set, using --auth-value")
    if auth_type == "bearer":
        token = value or os.environ.get("AUGUR_BEARER")
        if not token:
            raise click.BadParameter(
                "bearer auth requires --auth-value, AUGUR_AUTH_VALUE, or AUGUR_BEARER env var"
            )
        return BearerAuth(token=token)
    if auth_type == "cookie":
        if not value:
            raise click.BadParameter("cookie auth requires --auth-value 'k=v;k2=v2'")
        cookies = {}
        for pair in value.split(";"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookies[k.strip()] = v.strip()
        return CookieAuth(cookies=cookies)
    if auth_type == "header":
        if not value or ":" not in value:
            raise click.BadParameter("header auth requires --auth-value 'X-Header: value'")
        name, val = value.split(":", 1)
        return HeaderAuth(headers={name.strip(): val.strip()})
    raise click.BadParameter(f"unknown auth type: {auth_type}")


@click.group()
def main() -> None:
    """augur: LLM-driven API fuzzer."""


@main.command()
@click.option("--spec", required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--base-url", required=True)
@click.option("--time", "duration", type=Duration(), default="5m",
              help="run duration, e.g. 5m, 30s, 1h, or seconds")
@click.option("--max-requests", type=int, default=None)
@click.option("--invariants", "inv_path", type=click.Path(exists=True, path_type=Path), default=None)
@click.option("--auth", "auth_type",
              type=click.Choice(["none", "bearer", "cookie", "header"]), default="none")
@click.option("--auth-value", default=None,
              help="prefer AUGUR_AUTH_VALUE env var to keep tokens out of ps")
@click.option("--llm-backend", type=click.Choice(["anthropic", "ollama"]), default="anthropic")
@click.option("--llm-model", default=None)
@click.option("--verify-tls/--no-verify-tls", default=True)
@click.option("--fail-on-findings/--no-fail-on-findings", default=True,
              help="exit 2 if findings present (default), 0 if disabled")
@click.option("--out", "out_dir", type=click.Path(path_type=Path), default=Path("./findings"))
@click.option("--yes", "-y", "assume_yes", is_flag=True, default=False,
              help="skip the authorization confirmation prompt (for CI)")
def run(
    spec: Path,
    base_url: str,
    duration: float,
    max_requests: int | None,
    inv_path: Path | None,
    auth_type: str,
    auth_value: str | None,
    llm_backend: str,
    llm_model: str | None,
    verify_tls: bool,
    fail_on_findings: bool,
    out_dir: Path,
    assume_yes: bool,
) -> None:
    """Fuzz an API."""
    if not verify_tls:
        log.warning("TLS verification disabled, auth tokens may be visible to anyone on path")
    if not assume_yes:
        click.echo(f"augur will fuzz {base_url}. Only proceed if you have written authorization.")
        if not click.confirm("continue?", default=False):
            raise click.Abort()
    try:
        catalog = load_spec(spec)
        log.info("loaded spec with %d endpoint(s)", len(catalog.endpoints))

        scope = ScopeGuard.from_base_urls([base_url])
        auth = _build_auth(auth_type, auth_value)
        executor = Executor(scope=scope, auth=auth, verify_tls=verify_tls)

        invariants_checker: InvariantChecker | None = None
        if inv_path is not None:
            invariants = load_invariants(inv_path)
            log.info("loaded %d invariant(s)", len(invariants))
            client = _build_llm(llm_backend, llm_model)
            invariants_checker = InvariantChecker(client=client, invariants=invariants)

        config = EngineConfig(
            base_url=base_url,
            duration_s=duration,
            max_requests=max_requests,
            findings_dir=out_dir,
        )

        engine = Engine(
            catalog=catalog,
            executor=executor,
            strategies=[BolaStrategy(), MassAssignmentStrategy()],
            invariant_checker=invariants_checker,
            config=config,
        )

        try:
            engine.warmup()
            findings = engine.run()
        finally:
            executor.close()

        out_dir.mkdir(parents=True, exist_ok=True)
        report_path = out_dir / "report.html"
        render_html(findings, report_path)
        log.info(
            "done. requests=%d findings=%d report=%s",
            engine.stats.requests_sent, len(findings), report_path,
        )
    except click.BadParameter:
        raise
    except Exception as e:
        log.error("run failed: %s: %s", type(e).__name__, e)
        sys.exit(EXIT_ERROR)

    if findings and fail_on_findings:
        sys.exit(EXIT_FINDINGS)
    sys.exit(EXIT_OK)


if __name__ == "__main__":
    main()
