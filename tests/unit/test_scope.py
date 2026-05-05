import pytest

from augur.http.scope import OutOfScope, ScopeGuard


@pytest.fixture
def guard() -> ScopeGuard:
    return ScopeGuard.from_base_urls(["http://api.test"])


def test_accepts_in_scope(guard: ScopeGuard) -> None:
    guard.check("http://api.test/users/1")


def test_rejects_off_host(guard: ScopeGuard) -> None:
    with pytest.raises(OutOfScope):
        guard.check("http://evil.com/users/1")


def test_rejects_https_vs_http_mismatch(guard: ScopeGuard) -> None:
    with pytest.raises(OutOfScope):
        guard.check("https://api.test/users/1")


def test_rejects_bad_scheme() -> None:
    g = ScopeGuard.from_base_urls(["http://api.test"])
    with pytest.raises(OutOfScope):
        g.check("file:///etc/passwd")


def test_rejects_port_mismatch() -> None:
    g = ScopeGuard.from_base_urls(["http://api.test:8080"])
    with pytest.raises(OutOfScope):
        g.check("http://api.test:9090/users")


def test_rejects_missing_scheme() -> None:
    g = ScopeGuard.from_base_urls(["http://api.test"])
    with pytest.raises(OutOfScope):
        g.check("api.test/users")


def test_rejects_empty_url() -> None:
    g = ScopeGuard.from_base_urls(["http://api.test"])
    with pytest.raises(OutOfScope):
        g.check("")


def test_rejects_trailing_dot_hostname() -> None:
    g = ScopeGuard.from_base_urls(["http://api.test"])
    with pytest.raises(OutOfScope):
        g.check("http://api.test./users")


def test_rejects_url_with_whitespace() -> None:
    g = ScopeGuard.from_base_urls(["http://api.test"])
    with pytest.raises(OutOfScope):
        g.check(" http://api.test/users")


def test_rejects_userinfo_in_url() -> None:
    g = ScopeGuard.from_base_urls(["http://api.test"])
    with pytest.raises(OutOfScope):
        g.check("http://user:pass@api.test/users")


def test_rejects_metadata_ipv4_when_scope_is_public() -> None:
    g = ScopeGuard.from_base_urls(["http://api.test"])
    # different origin, will be rejected as off-host before metadata check,
    # but if origin is broad we still want metadata blocked. test the helper
    # via a localhost scope instead:
    g2 = ScopeGuard.from_base_urls(["http://169.254.169.254"])
    with pytest.raises(OutOfScope):
        g2.check("http://169.254.169.254/latest/meta-data/")


def test_rejects_ipv4_loopback_off_scope() -> None:
    g = ScopeGuard.from_base_urls(["http://api.test"])
    with pytest.raises(OutOfScope):
        g.check("http://127.0.0.1/users")


def test_rejects_ipv6_loopback_off_scope() -> None:
    g = ScopeGuard.from_base_urls(["http://api.test"])
    with pytest.raises(OutOfScope):
        g.check("http://[::1]/users")


def test_allows_explicit_localhost_scope() -> None:
    g = ScopeGuard.from_base_urls(["http://localhost:8080"])
    g.check("http://localhost:8080/users")


def test_allows_explicit_loopback_ipv4_scope() -> None:
    g = ScopeGuard.from_base_urls(["http://127.0.0.1:8080"])
    g.check("http://127.0.0.1:8080/users")


def test_allows_explicit_ipv6_loopback_scope() -> None:
    g = ScopeGuard.from_base_urls(["http://[::1]:8080"])
    g.check("http://[::1]:8080/users")


def test_rejects_ipv4_mapped_ipv6_loopback_when_public_scope() -> None:
    g = ScopeGuard.from_base_urls(["http://api.test"])
    with pytest.raises(OutOfScope):
        g.check("http://[::ffff:127.0.0.1]/users")


def test_rejects_link_local_ipv6_off_scope() -> None:
    g = ScopeGuard.from_base_urls(["http://api.test"])
    with pytest.raises(OutOfScope):
        g.check("http://[fe80::1]/users")


def test_rejects_private_ipv4_off_scope() -> None:
    g = ScopeGuard.from_base_urls(["http://api.test"])
    for url in ("http://10.0.0.1/x", "http://192.168.1.1/x", "http://172.16.0.1/x"):
        with pytest.raises(OutOfScope):
            g.check(url)


def test_metadata_ip_blocked_even_with_localhost_scope() -> None:
    # localhost scope turns off the broad private-IP guard, but cloud
    # metadata IPs stay blocked unless explicitly allow-listed.
    g = ScopeGuard.from_base_urls(["http://localhost:80"])
    with pytest.raises(OutOfScope):
        g.check("http://169.254.169.254/")
