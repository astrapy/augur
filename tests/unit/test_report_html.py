from pathlib import Path

from augur.report.html import render


def test_render_writes_file(tmp_path: Path, make_finding):
    out = tmp_path / "out" / "report.html"
    render([make_finding()], out)
    assert out.exists()
    assert out.read_text(encoding="utf-8").startswith("<!doctype html>")


def test_contains_every_finding_url(tmp_path: Path, make_finding):
    findings = [
        make_finding(request_url="http://api.test/users/1", invariant_name="a"),
        make_finding(request_url="http://api.test/users/2", invariant_name="b"),
        make_finding(request_url="http://api.test/orders/9", invariant_name="c"),
    ]
    out = tmp_path / "r.html"
    render(findings, out)
    text = out.read_text(encoding="utf-8")
    for f in findings:
        assert f.request_url in text


def test_escapes_html_in_rationale(tmp_path: Path, make_finding):
    f = make_finding(rationale="<script>alert('x')</script>")
    out = tmp_path / "r.html"
    render([f], out)
    text = out.read_text(encoding="utf-8")
    assert "<script>alert" not in text
    assert "&lt;script&gt;" in text
