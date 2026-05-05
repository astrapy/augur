import json

from augur.invariants.checker import InvariantChecker


def test_violates_true_produces_verdict(make_response, make_invariant, fake_llm_factory):
    inv = make_invariant(path_pattern="/users/*")
    # evidence must be a verbatim substring of the body or the checker rejects
    # it as a likely prompt injection
    body = '{"email":"alice@example.com","leaked_field":"sensitive payload"}'
    llm = fake_llm_factory({"violates": True, "evidence": "leaked_field"})
    chk = InvariantChecker(llm, [inv])
    res = make_response(body=body)
    out = chk.check("GET", "/users/1", res)
    assert len(out) == 1
    assert out[0].violates is True
    assert "leaked_field" in out[0].evidence


def test_evidence_not_in_body_rejected(make_response, make_invariant, fake_llm_factory):
    """Defends against prompt injection that flips violates=true with fabricated evidence."""
    inv = make_invariant(path_pattern="/users/*")
    llm = fake_llm_factory({"violates": True, "evidence": "this string is nowhere in the body"})
    chk = InvariantChecker(llm, [inv])
    out = chk.check("GET", "/users/1", make_response(body='{"ok": true}'))
    assert out == []


def test_violates_false_skipped(make_response, make_invariant, fake_llm_factory):
    inv = make_invariant(path_pattern="/users/*")
    llm = fake_llm_factory({"violates": False, "evidence": ""})
    chk = InvariantChecker(llm, [inv])
    out = chk.check("GET", "/users/1", make_response())
    assert out == []


def test_malformed_json_skipped(make_response, make_invariant, fake_llm_factory):
    inv = make_invariant(path_pattern="/users/*")
    llm = fake_llm_factory("not json at all")
    chk = InvariantChecker(llm, [inv])
    assert chk.check("GET", "/users/1", make_response()) == []


def test_empty_reply_skipped(make_response, make_invariant, fake_llm_factory):
    inv = make_invariant(path_pattern="/users/*")
    llm = fake_llm_factory("")
    chk = InvariantChecker(llm, [inv])
    assert chk.check("GET", "/users/1", make_response()) == []


def test_oversized_reply_rejected(make_response, make_invariant, fake_llm_factory):
    inv = make_invariant(path_pattern="/users/*")
    huge = json.dumps({"violates": True, "evidence": "x" * (64 * 1024)})
    llm = fake_llm_factory(huge)
    chk = InvariantChecker(llm, [inv])
    assert chk.check("GET", "/users/1", make_response()) == []
