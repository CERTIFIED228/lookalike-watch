import pytest
import requests

from lookalike_watch.alerts import AlertError, build_message, mask_url, send_webhook
from lookalike_watch.scoring import Finding

SECRET_URL = "https://hooks.slack.com/services/T000/B000/supersecrettoken"


def make(domain, score=80, level="critical"):
    return Finding(domain=domain, ascii=domain, technique="homoglyph", source="permutation",
                   score=score, level=level, reasons=["looks identical"], a=[], mx=[], ns=[])


class FakeSession:
    def __init__(self, status=200, exc=None):
        self.status = status
        self.exc = exc
        self.posts = []

    def post(self, url, json=None, timeout=None):
        self.posts.append((url, json, timeout))
        if self.exc:
            raise self.exc

        class R:
            status_code = self.status
        return R()


def test_message_lists_worst_first():
    msg = build_message("paypal.com", [make("meh.com", 30, "medium"), make("bad.com")])
    assert "2 new lookalike" in msg
    assert msg.index("bad.com") < msg.index("meh.com")


def test_message_is_capped():
    many = [make(f"evil{i}.com") for i in range(500)]
    msg = build_message("paypal.com", many)
    assert len(msg) <= 1900
    assert "more" in msg


def test_send_posts_slack_and_discord_friendly_payload():
    session = FakeSession()
    send_webhook(SECRET_URL, "paypal.com", [make("bad.com")], session=session)
    url, payload, timeout = session.posts[0]
    assert url == SECRET_URL
    assert payload["text"] == payload["content"]
    assert timeout


def test_failed_delivery_never_leaks_the_url():
    session = FakeSession(status=403)
    with pytest.raises(AlertError) as err:
        send_webhook(SECRET_URL, "paypal.com", [make("bad.com")], session=session)
    assert "supersecrettoken" not in str(err.value)


def test_network_error_never_leaks_the_url():
    exc = requests.ConnectionError(f"Failed to connect to {SECRET_URL}")
    session = FakeSession(exc=exc)
    with pytest.raises(AlertError) as err:
        send_webhook(SECRET_URL, "paypal.com", [make("bad.com")], session=session)
    assert "supersecrettoken" not in str(err.value)


def test_mask_url_keeps_only_the_host():
    assert mask_url(SECRET_URL) == "https://hooks.slack.com/***"
