from augur.report.curl import to_curl


def test_bearer_redacted_by_default(make_finding):
    f = make_finding(request_headers={"Authorization": "Bearer secret"})
    cmd = to_curl(f)
    assert "secret" not in cmd
    assert "<REDACTED>" in cmd


def test_bearer_not_redacted_when_disabled(make_finding):
    f = make_finding(request_headers={"Authorization": "Bearer secret"})
    cmd = to_curl(f, redact_auth=False)
    assert "Bearer secret" in cmd


def test_body_included(make_finding):
    f = make_finding(request_method="POST", request_body=b'{"a": 1}')
    cmd = to_curl(f)
    assert "--data-raw" in cmd
    assert '{"a": 1}' in cmd


def test_special_chars_in_url_quoted(make_finding):
    f = make_finding(request_url="http://api.test/x?q=a b&c=d;e")
    cmd = to_curl(f)
    # shlex.quote wraps strings with shell-special chars in single quotes
    assert "'http://api.test/x?q=a b&c=d;e'" in cmd
