"""Egress clients must not be broken by a hostile NO_PROXY on the host.

Regression this pins.  ``httpx`` reads proxy configuration inside
``Client.__init__`` - before any request object exists - and derives mount keys
from the environment.  This machine sets

    NO_PROXY=localhost,127.0.0.1,::1,[::1]

(the bracketed form is what mihomo/verge writes).  ``get_environment_proxies()``
emits the literal mount key ``all://*[::1]`` for it, ``Client.__init__`` then
parses that key as a URL, and it dies with

    httpx.InvalidURL: Invalid port: ':1]'

Observed for real:

    >>> httpx.Client(base_url="http://127.0.0.1:8000")
    InvalidURL: Invalid port: ':1]'
    >>> httpx.Client(base_url="http://127.0.0.1:8000", trust_env=False)
    OK   (GET /healthz -> 200)

Two consequences are pinned here.

1. The backend talking to itself (127.0.0.1) must never be proxied, and a JWKS
   endpoint is fetched directly rather than through an interception proxy, so
   both call sites pass ``trust_env=False``.

2. ``InvalidURL`` is not an ``httpx.HTTPError`` subclass, so the failure escaped
   ``AuthAdapter._verify_jwt``'s ``except httpx.HTTPError`` and surfaced as a 500
   instead of a clean 401.  That is why the guard is asserted at the call rather
   than left to the caller's error handling.
"""

from __future__ import annotations

import inspect

import httpx
import pytest

from threat_report_agent import auth as auth_module
from threat_report_agent.auth import AuthAdapter


def test_invalid_url_is_not_an_httpx_http_error() -> None:
    """The specific reason the JWKS crash could not be caught by the caller."""

    assert not issubclass(httpx.InvalidURL, httpx.HTTPError)
    assert not issubclass(httpx.InvalidURL, httpx.TransportError)


def test_jwks_fetch_disables_environment_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    """``_verify_rs256`` must call httpx without letting the host env interfere."""

    adapter = AuthAdapter(
        environment="production",
        jwks_url="https://issuer.test/.well-known/jwks.json",
    )
    captured: dict[str, object] = {}

    class _Response:
        def raise_for_status(self) -> None:
            raise httpx.ConnectError("stop here: network behaviour is not under test")

    def _fake_get(url: str, **kwargs: object) -> _Response:
        captured["url"] = url
        captured.update(kwargs)
        return _Response()

    monkeypatch.setattr(auth_module.httpx, "get", _fake_get)

    with pytest.raises(httpx.HTTPError):
        adapter._verify_rs256(b"header.payload", b"signature", "kid-1")

    assert captured["url"] == "https://issuer.test/.well-known/jwks.json"
    assert captured["trust_env"] is False, (
        "JWKS fetch must not read proxy configuration from the environment: "
        "httpx raises InvalidURL from Client.__init__ on hosts whose NO_PROXY "
        "contains a bracketed IPv6 entry, and InvalidURL is not an HTTPError"
    )
    assert captured["timeout"] == 10.0


def test_no_module_level_httpx_call_reads_the_environment() -> None:
    """Fail loudly if a future egress call reintroduces the implicit proxy read."""

    source = inspect.getsource(auth_module)
    offenders = [
        line.strip()
        for line in source.splitlines()
        if "httpx.get(" in line and "trust_env=False" not in line
    ]
    assert not offenders, (
        "unprotected httpx.get call(s) in auth.py - pass trust_env=False: "
        f"{offenders}"
    )
