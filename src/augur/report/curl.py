"""curl reproducer for a finding. Everything shlex-quoted so a poisoned URL
or header can't inject shell commands when pasted.
"""

from __future__ import annotations

import shlex

from augur.report.finding import Finding

_SENSITIVE_HEADERS = {
    "authorization", "cookie", "set-cookie",
    "x-api-key", "x-auth-token", "x-csrf-token", "proxy-authorization",
}
_VALID_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


def to_curl(f: Finding, *, redact_auth: bool = True) -> str:
    method = f.request_method.upper()
    if method not in _VALID_METHODS:
        method = "GET"
    parts = ["curl", "-i", "-X", shlex.quote(method), shlex.quote(f.request_url)]
    for name, value in f.request_headers.items():
        rendered = "<REDACTED>" if redact_auth and name.lower() in _SENSITIVE_HEADERS else value
        parts += ["-H", shlex.quote(f"{name}: {rendered}")]
    if f.request_body:
        body = f.request_body.decode("utf-8", errors="replace")
        parts += ["--data-raw", shlex.quote(body)]
    return " ".join(parts)
