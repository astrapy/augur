from augur.report.finding import Finding


def _mk(url: str) -> Finding:
    return Finding(
        category="API1:2023 Broken Object Level Authorization",
        severity="high",
        title="t",
        rationale="r",
        request_method="GET",
        request_url=url,
        invariant_name="rule",
    )


def test_fingerprint_dedupes_numeric_path_ids():
    a = _mk("http://api.test/users/42")
    b = _mk("http://api.test/users/99")
    assert a.fingerprint() == b.fingerprint()


def test_fingerprint_dedupes_uuid_path_ids():
    a = _mk("http://api.test/users/11111111-2222-3333-4444-555555555555")
    b = _mk("http://api.test/users/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
    assert a.fingerprint() == b.fingerprint()


def test_fingerprint_differs_for_different_endpoints():
    a = _mk("http://api.test/users/1")
    b = _mk("http://api.test/orders/1")
    assert a.fingerprint() != b.fingerprint()
