import pytest

from lookalike_watch.ct import CTError
from lookalike_watch.domain import parse_domain
from lookalike_watch.resolver import DnsRecord
from lookalike_watch.scan import run_scan

BRAND = parse_domain("paypal.com")

FAKE_DNS = {
    "paypal.com": DnsRecord(ns=["ns1.brand-dns.net"], a=["64.4.250.36"], mx=["mx.paypal.com"]),
    "paypl.com": DnsRecord(ns=["ns1.cheap.net"], a=["203.0.113.7"]),
    "papyal.com": DnsRecord(ns=["ns1.brand-dns.net"], a=["64.4.250.37"]),
    "paypal-secure-login.com": DnsRecord(ns=["ns1.cheap.net"], a=["203.0.113.9"]),
}


class FakeCTSession:
    def get(self, url, params=None, timeout=None, headers=None):
        class R:
            status_code = 200

            def json(self):
                return [{"common_name": "paypal-secure-login.com",
                         "name_value": "paypal-secure-login.com"},
                        {"common_name": "paypl.com", "name_value": "paypl.com"}]
        return R()


def test_scan_reports_only_registered_lookalikes():
    result = run_scan(BRAND, lookup=FAKE_DNS.get, techniques=["omission", "transposition"])
    assert {f.ascii for f in result.findings} == {"paypl.com", "papyal.com"}
    assert result.checked > 2


def test_scan_never_reports_the_brand_itself():
    result = run_scan(BRAND, lookup=FAKE_DNS.get)
    assert "paypal.com" not in {f.ascii for f in result.findings}


def test_brand_owned_domains_rank_lower():
    result = run_scan(BRAND, lookup=FAKE_DNS.get, techniques=["omission", "transposition"])
    scores = {f.ascii: f.score for f in result.findings}
    assert scores["papyal.com"] < scores["paypl.com"]


def test_allow_list_skips_known_domains():
    result = run_scan(BRAND, lookup=FAKE_DNS.get, techniques=["omission"], allow={"paypl.com"})
    assert result.findings == []


def test_ct_adds_domains_that_permutations_miss():
    result = run_scan(BRAND, lookup=FAKE_DNS.get, techniques=["omission"],
                      use_ct=True, session=FakeCTSession())
    by_name = {f.ascii: f for f in result.findings}
    assert "paypal-secure-login.com" in by_name
    assert by_name["paypal-secure-login.com"].source == "ct"
    assert any("certificate" in r for r in by_name["paypl.com"].reasons)


def test_ct_only_skips_permutations():
    result = run_scan(BRAND, lookup=FAKE_DNS.get, ct_only=True, session=FakeCTSession())
    assert {f.source for f in result.findings} == {"ct"}


def test_results_are_sorted_worst_first():
    result = run_scan(BRAND, lookup=FAKE_DNS.get, use_ct=True, session=FakeCTSession())
    scores = [f.score for f in result.findings]
    assert scores == sorted(scores, reverse=True)


class DownCTSession:
    def get(self, url, params=None, timeout=None, headers=None):
        class R:
            status_code = 503
        return R()


def test_ct_outage_does_not_lose_the_dns_results():
    result = run_scan(BRAND, lookup=FAKE_DNS.get, techniques=["omission"],
                      use_ct=True, session=DownCTSession(), ct_retries=1)
    assert {f.ascii for f in result.findings} == {"paypl.com"}
    assert "503" in result.ct_error


def test_ct_only_still_fails_loudly_when_ct_is_down():
    with pytest.raises(CTError):
        run_scan(BRAND, lookup=FAKE_DNS.get, ct_only=True, session=DownCTSession(),
                 ct_retries=1)


def test_answers_without_nameservers_are_not_reported_as_registered():
    # A real registered domain always has NS records. Seen live: an ISP filter
    # answering A queries for brand-like names that have no NS at all.
    dns_with_filter = {**FAKE_DNS, "paypa.com": DnsRecord(a=["81.99.162.48"])}
    result = run_scan(BRAND, lookup=dns_with_filter.get, techniques=["omission"])
    assert "paypa.com" not in {f.ascii for f in result.findings}
    assert result.unverified == ["paypa.com"]
