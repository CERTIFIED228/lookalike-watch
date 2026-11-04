import pytest
import requests

from lookalike_watch.ct import CTError, ct_candidates, fetch_ct_hostnames
from lookalike_watch.domain import parse_domain

SAMPLE = [
    {
        "common_name": "paypal-secure-login.com",
        "name_value": "paypal-secure-login.com\nwww.paypal-secure-login.com",
    },
    {"common_name": "*.paypa1.net", "name_value": "*.paypa1.net"},
    {"common_name": "www.paypal.com", "name_value": "www.paypal.com\nPAYPAL.COM"},
    {"common_name": "admin@paypal.com", "name_value": "admin@paypal.com"},
    {"common_name": "xn--pypal-4ve.com", "name_value": "xn--pypal-4ve.com"},
    {"common_name": "mypaypalhelp.co.uk", "name_value": "login.mypaypalhelp.co.uk"},
    {"common_name": "unrelated.org", "name_value": "unrelated.org"},
]


class FakeResponse:
    def __init__(self, status=200, payload=None, bad_json=False):
        self.status_code = status
        self.payload = payload
        self.bad_json = bad_json

    def json(self):
        if self.bad_json:
            raise ValueError("not json")
        return self.payload


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def get(self, url, params=None, timeout=None, headers=None):
        self.calls.append(params)
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def test_fetch_cleans_and_dedupes_hostnames():
    session = FakeSession([FakeResponse(payload=SAMPLE)])
    names = fetch_ct_hostnames("paypal", session=session, sleep=lambda s: None)
    assert "paypal-secure-login.com" in names
    assert "www.paypal-secure-login.com" in names
    assert "paypa1.net" in names            # wildcard stripped
    assert "paypal.com" in names            # lowercased
    assert not any("@" in n for n in names)


def test_fetch_searches_for_keyword_anywhere():
    session = FakeSession([FakeResponse(payload=[])])
    fetch_ct_hostnames("paypal", session=session, sleep=lambda s: None)
    assert session.calls[0]["q"] == "%paypal%"
    assert session.calls[0]["output"] == "json"


def test_fetch_retries_then_succeeds():
    session = FakeSession([
        requests.Timeout(),
        FakeResponse(status=502),
        FakeResponse(payload=SAMPLE),
    ])
    names = fetch_ct_hostnames("paypal", session=session, retries=3, sleep=lambda s: None)
    assert names


def test_fetch_gives_up_with_clear_error():
    session = FakeSession([FakeResponse(status=503)] * 3)
    with pytest.raises(CTError):
        fetch_ct_hostnames("paypal", session=session, retries=3, sleep=lambda s: None)


def test_fetch_handles_garbage_body():
    session = FakeSession([FakeResponse(bad_json=True)])
    with pytest.raises(CTError):
        fetch_ct_hostnames("paypal", session=session, retries=1, sleep=lambda s: None)


def test_fetch_rejects_tiny_keywords():
    with pytest.raises(ValueError):
        fetch_ct_hostnames("pp", session=FakeSession([]))


def test_ct_candidates_drop_the_real_domain_and_unrelated_ones():
    names = {
        "www.paypal.com", "paypal.com", "paypal-secure-login.com",
        "www.paypal-secure-login.com", "paypa1.net", "unrelated.org",
        "xn--pypal-4ve.com", "login.mypaypalhelp.co.uk",
    }
    found = {c.ascii: c for c in ct_candidates(parse_domain("paypal.com"), names)}
    assert set(found) == {
        "paypal-secure-login.com", "paypa1.net", "xn--pypal-4ve.com", "mypaypalhelp.co.uk",
    }
    assert all(c.technique == "ct-log" for c in found.values())
    assert found["xn--pypal-4ve.com"].domain == "pаypal.com"
