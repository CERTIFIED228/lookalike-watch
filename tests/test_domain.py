import pytest

from lookalike_watch.domain import Domain, is_valid_label, parse_domain, to_ascii


def test_parse_simple_domain():
    d = parse_domain("PayPal.com")
    assert d == Domain(name="paypal", suffix="com")
    assert d.fqdn == "paypal.com"


def test_parse_strips_url_parts_and_subdomains():
    d = parse_domain("https://www.paypal.co.uk/signin?x=1")
    assert d.name == "paypal"
    assert d.suffix == "co.uk"


def test_parse_keeps_registered_domain_only():
    assert parse_domain("mail.google.com").fqdn == "google.com"


def test_parse_handles_trailing_dot_and_whitespace():
    assert parse_domain("  example.org. ").fqdn == "example.org"


@pytest.mark.parametrize("bad", ["", "localhost", "not a domain", "-bad.com", "bad-.com", "com"])
def test_parse_rejects_garbage(bad):
    with pytest.raises(ValueError):
        parse_domain(bad)


@pytest.mark.parametrize("label", ["paypal", "pay-pal", "a", "x" * 63, "xn--pypal-4ve"])
def test_valid_labels(label):
    assert is_valid_label(label)


@pytest.mark.parametrize("label", ["", "-paypal", "paypal-", "x" * 64, "pay_pal", "pay pal"])
def test_invalid_labels(label):
    assert not is_valid_label(label)


def test_to_ascii_converts_unicode_to_punycode():
    assert to_ascii("pаypal").startswith("xn--")


def test_to_ascii_leaves_plain_ascii_alone():
    assert to_ascii("paypal") == "paypal"


def test_to_ascii_returns_none_for_unencodable():
    assert to_ascii("bad‍" * 30) is None
