"""Render a list of findings to a self-contained HTML report.

Output is a single file with inline CSS, suitable for sharing or attaching to
a ticket. All user-controlled content is escaped via Jinja2 autoescaping.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, select_autoescape

from augur.report.curl import to_curl
from augur.report.finding import Finding

_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>augur report</title>
<style>
body { font: 14px/1.45 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
       margin: 0; background: #0d1117; color: #c9d1d9; }
header { padding: 24px; background: #161b22; border-bottom: 1px solid #30363d; }
h1 { margin: 0; font-size: 22px; }
.meta { color: #8b949e; font-size: 13px; margin-top: 4px; }
.summary { padding: 16px 24px; background: #161b22; border-bottom: 1px solid #30363d; }
.pill { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 12px;
        margin-right: 6px; }
.pill.crit { background: #6e1818; color: #fff; }
.pill.high { background: #b8541a; color: #fff; }
.pill.med { background: #6f5d1a; color: #fff; }
.pill.low { background: #2d4f3a; color: #c9d1d9; }
main { padding: 24px; max-width: 1100px; }
.finding { background: #161b22; border: 1px solid #30363d; border-radius: 8px;
           padding: 16px; margin-bottom: 14px; }
.finding h2 { margin: 0 0 6px 0; font-size: 16px; }
.k { color: #8b949e; }
.code { background: #0d1117; border: 1px solid #30363d; border-radius: 4px;
        padding: 8px 10px; margin-top: 8px; white-space: pre-wrap;
        word-break: break-all; font-family: ui-monospace, monospace; font-size: 12px; }
.tag { font-size: 12px; color: #8b949e; }
</style>
</head>
<body>
<header>
  <h1>augur findings</h1>
  <div class="meta">{{ generated_at }} &middot; {{ findings|length }} unique finding(s)</div>
</header>
<div class="summary">
  {% for sev, count in counts %}
  <span class="pill {{ sev }}">{{ sev }}: {{ count }}</span>
  {% endfor %}
</div>
<main>
{% for f in findings %}
<section class="finding">
  <h2>{{ f.title }}</h2>
  <div>
    <span class="pill {{ severity_class(f.severity) }}">{{ f.severity }}</span>
    <span class="tag">{{ f.category }}</span>
  </div>
  <p>{{ f.rationale }}</p>
  <div class="k">request</div>
  <div class="code">{{ f.request_method }} {{ f.request_url }}</div>
  <div class="k">response</div>
  <div class="code">{{ f.response_status }}
{{ f.response_body_preview }}</div>
  <div class="k">reproduce</div>
  <div class="code">{{ curl(f) }}</div>
</section>
{% endfor %}
</main>
</body>
</html>
"""


def render(findings: list[Finding], out_path: Path) -> None:
    env = Environment(autoescape=select_autoescape(["html"]))
    env.globals["curl"] = to_curl
    env.globals["severity_class"] = _sev_class
    tmpl = env.from_string(_TEMPLATE)
    html = tmpl.render(
        findings=findings,
        counts=_counts(findings),
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html, encoding="utf-8")


def _sev_class(sev: str) -> str:
    return {"critical": "crit", "high": "high", "medium": "med", "low": "low"}.get(sev, "low")


def _counts(findings: list[Finding]) -> list[tuple[str, int]]:
    out: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        out[f.severity] = out.get(f.severity, 0) + 1
    return [(k, v) for k, v in out.items() if v > 0]
