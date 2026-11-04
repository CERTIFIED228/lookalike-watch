from lookalike_watch.domain import parse_domain
from lookalike_watch.resolver import DnsRecord
from lookalike_watch.scoring import level_for, score

BRAND = parse_domain("paypal.com")
BRAND_DNS = DnsRecord(ns=["ns1.p01.dynect.net", "ns2.p01.dynect.net"], mx=["mx1.paypal.com"])

LIVE_WITH_MAIL = DnsRecord(ns=["ns1.cheap-host.net"], a=["203.0.113.7"], mx=["mail.x.com"])
LIVE_NO_MAIL = DnsRecord(ns=["ns1.cheap-host.net"], a=["203.0.113.7"])


def test_homoglyph_with_web_and_mail_is_critical():
    f = score("pаypal.com", "xn--pypal-4ve.com", "homoglyph", BRAND, LIVE_WITH_MAIL)
    assert f.level == "critical"
    assert any("looks identical" in r for r in f.reasons)
    assert any("punycode" in r for r in f.reasons)
    assert any("email" in r for r in f.reasons)


def test_combosquat_with_phishing_keyword():
    f = score("paypal-login.com", "paypal-login.com", "combosquat", BRAND, LIVE_NO_MAIL)
    assert f.level in {"high", "critical"}
    assert any("'paypal'" in r for r in f.reasons)
    assert any("'login'" in r for r in f.reasons)


def test_one_typo_away_scores_on_spelling():
    f = score("paypl.com", "paypl.com", "omission", BRAND, LIVE_NO_MAIL)
    assert any("1 edit" in r for r in f.reasons)
    assert f.score >= 30


def test_unrelated_domain_is_low():
    f = score("weather.com", "weather.com", "ct-log", BRAND, LIVE_NO_MAIL)
    assert f.level == "low"


def test_mail_and_web_add_risk():
    bare = score("paypl.com", "paypl.com", "omission", BRAND, DnsRecord(ns=["ns.x"]))
    full = score("paypl.com", "paypl.com", "omission", BRAND, LIVE_WITH_MAIL)
    assert full.score > bare.score


def test_shared_nameservers_suggests_brand_owns_it():
    owned = DnsRecord(ns=["ns1.p01.dynect.net"], a=["64.4.250.36"])
    f = score("paypal.net", "paypal.net", "tld-swap", BRAND, owned, brand_dns=BRAND_DNS)
    unowned = score("paypal.net", "paypal.net", "tld-swap", BRAND, LIVE_NO_MAIL,
                    brand_dns=BRAND_DNS)
    assert f.score < unowned.score
    assert "same nameservers" in f.reasons[0]  # most useful thing to know, so it goes first


def test_parked_domains_are_flagged():
    parked = DnsRecord(ns=["ns1.sedoparking.com", "ns2.sedoparking.com"])
    f = score("paypl.com", "paypl.com", "omission", BRAND, parked)
    assert "parked" in f.reasons[0]


def test_score_stays_within_bounds():
    huge = DnsRecord(ns=["x"], a=["1.1.1.1"], aaaa=["::1"], mx=["m"])
    f = score("pаypal-login.com", "xn--pypal-login-xyz.com", "homoglyph", BRAND, huge)
    assert 0 <= f.score <= 100


def test_finding_carries_dns_details():
    f = score("paypl.com", "paypl.com", "omission", BRAND, LIVE_WITH_MAIL)
    assert f.a == ["203.0.113.7"]
    assert f.mx == ["mail.x.com"]


def test_levels():
    assert level_for(90) == "critical"
    assert level_for(70) == "critical"
    assert level_for(55) == "high"
    assert level_for(35) == "medium"
    assert level_for(10) == "low"
