from lookalike_watch.domain import parse_domain
from lookalike_watch.resolver import DnsRecord
from lookalike_watch.scoring import level_for, score

BRAND = parse_domain("paypal.com")
BRAND_DNS = DnsRecord(ns=["a.ns.paypal-dns.example", "b.ns.paypal-dns.example"],
                      mx=["mx1.paypalcorp.com"])

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
    owned = DnsRecord(ns=["a.ns.paypal-dns.example"], a=["64.4.250.36"])
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


def test_brand_plus_one_letter_is_not_counted_twice():
    # "paypalc" is 1 edit away AND contains "paypal" - that's one signal, not two.
    f = score("paypalc.com", "paypalc.com", "addition", BRAND, LIVE_WITH_MAIL)
    assert any("1 edit" in r for r in f.reasons)
    assert not any("contains the brand name" in r for r in f.reasons)
    assert f.score == 64


def test_brand_protection_registrar_means_defensive_registration():
    mm = DnsRecord(ns=["ns1.markmonitor.com", "ns7.markmonitor.com"], a=["3.33.139.32"],
                   mx=["bh.markmonitor.com"])
    f = score("paypal.net", "paypal.net", "tld-swap", BRAND, mm, brand_dns=BRAND_DNS)
    assert "MarkMonitor" in f.reasons[0]
    assert f.level == "low"


def test_nameservers_under_the_brand_domain_mean_owned():
    own = DnsRecord(ns=["ns1-pchnet.paypal.com"], a=["64.4.250.36"])
    f = score("paypal.de", "paypal.de", "tld-swap", BRAND, own, brand_dns=BRAND_DNS)
    assert "probably owned by the brand" in f.reasons[0]


def test_mail_records_alone_never_prove_ownership():
    # Anyone can point their MX at the brand's mail servers. Doing that to
    # NS records breaks the domain, so only NS counts as evidence.
    for mx in (["mx1.paypalcorp.com"], ["mx.markmonitor.com"], ["paypal.com"]):
        spoofed = DnsRecord(ns=["ns1.cheap-host.net"], a=["203.0.113.9"], mx=mx)
        f = score("paypal-login.com", "paypal-login.com", "combosquat", BRAND, spoofed,
                  brand_dns=BRAND_DNS)
        assert not any("owned by the brand" in r or "defensive" in r for r in f.reasons), mx
        assert f.level in {"high", "critical"}, (mx, f.score)


def test_sharing_a_big_dns_provider_is_not_ownership():
    brand = DnsRecord(ns=["grace.ns.cloudflare.com", "rob.ns.cloudflare.com"])
    cand = DnsRecord(ns=["grace.ns.cloudflare.com"], a=["1.2.3.4"])
    f = score("paypl.com", "paypl.com", "omission", BRAND, cand, brand_dns=brand)
    assert not any("owned by the brand" in r for r in f.reasons)


def test_parking_check_matches_whole_domains():
    record = DnsRecord(ns=["ns1.jordan.com"], a=["1.2.3.4"])
    f = score("paypl.com", "paypl.com", "omission", BRAND, record)
    assert not any("parked" in r for r in f.reasons)


def test_sharing_gmail_with_the_brand_is_not_ownership():
    brand_dns = DnsRecord(ns=["ns1.brand.net"], mx=["aspmx.l.google.com"])
    cand = DnsRecord(ns=["ns1.other.net"], a=["1.2.3.4"], mx=["alt1.aspmx.l.google.com"])
    f = score("paypl.com", "paypl.com", "omission", BRAND, cand, brand_dns=brand_dns)
    assert not any("owned by the brand" in r for r in f.reasons)


def test_parking_infrastructure_does_not_count_as_web_or_mail():
    parked = DnsRecord(ns=["ns2.abovedomains.com"], a=["103.224.182.239"],
                       mx=["park-mx.above.com"])
    f = score("paypl.com", "paypl.com", "omission", BRAND, parked)
    assert "parked" in f.reasons[0]
    assert not any("email" in r for r in f.reasons)
    assert f.level in {"low", "medium"}


def test_one_borrowed_nameserver_doesnt_prove_ownership():
    # A mixed set still resolves (resolvers retry the working one), so an
    # attacker can add one of the brand's nameservers to look official.
    mixed = [
        ["ns1.evil-dns.net", "ns1.markmonitor.com"],
        ["ns1.evil-dns.net", "ns1.paypal.com"],
        ["ns1.evil-dns.net", "a.ns.paypal-dns.example"],
    ]
    for ns in mixed:
        record = DnsRecord(ns=ns, a=["203.0.113.9"])
        f = score("paypal-login.com", "paypal-login.com", "combosquat", BRAND, record,
                  brand_dns=BRAND_DNS)
        assert not any("owned by the brand" in r or "defensive" in r for r in f.reasons), ns


def test_brand_domains_on_their_own_and_a_shared_provider_are_owned():
    brand = DnsRecord(ns=["ns1-pchnet.paypal.com", "pdns100.ultradns.com"])
    cand = DnsRecord(ns=["pdns100.ultradns.com", "ns1-pchnet.paypal.com"], a=["64.4.250.36"])
    f = score("paypal.co", "paypal.co", "tld-swap", BRAND, cand, brand_dns=brand)
    assert "owned by the brand" in f.reasons[0]
