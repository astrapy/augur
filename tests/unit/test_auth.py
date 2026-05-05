import time

import respx
from httpx import Response as HTTPXResponse

from augur.http.auth import BearerAuth, CookieAuth, HeaderAuth, JWTRefreshAuth, NoAuth


def test_no_auth_empty():
    ctx = NoAuth().context()
    assert ctx.headers == {}
    assert ctx.cookies == {}


def test_bearer_auth():
    ctx = BearerAuth(token="abc").context()
    assert ctx.headers == {"Authorization": "Bearer abc"}
    assert ctx.cookies == {}


def test_cookie_auth():
    ctx = CookieAuth(cookies={"sid": "x"}).context()
    assert ctx.cookies == {"sid": "x"}
    assert ctx.headers == {}


def test_header_auth():
    ctx = HeaderAuth(headers={"X-API-Key": "secret"}).context()
    assert ctx.headers == {"X-API-Key": "secret"}


@respx.mock
def test_jwt_refresh_when_token_expires_soon():
    route = respx.post("http://auth.test/token").mock(
        return_value=HTTPXResponse(200, json={"access_token": "fresh", "expires_in": 600})
    )
    a = JWTRefreshAuth(
        refresh_url="http://auth.test/token",
        refresh_payload={"grant_type": "client_credentials"},
        min_remaining_s=30,
    )
    a._token = "stale"
    a._expires_at = time.time() + 10  # less than min_remaining_s
    ctx = a.context()
    assert ctx.headers["Authorization"] == "Bearer fresh"
    assert route.called


@respx.mock
def test_jwt_does_not_refresh_when_fresh():
    route = respx.post("http://auth.test/token").mock(
        return_value=HTTPXResponse(200, json={"access_token": "new", "expires_in": 600})
    )
    a = JWTRefreshAuth(
        refresh_url="http://auth.test/token",
        refresh_payload={},
        min_remaining_s=30,
    )
    a._token = "still-good"
    a._expires_at = time.time() + 3600
    ctx = a.context()
    assert ctx.headers["Authorization"] == "Bearer still-good"
    assert not route.called
