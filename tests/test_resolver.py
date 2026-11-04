import dns.exception
import dns.resolver

from lookalike_watch.resolver import DnsLookup, DnsRecord, resolve_all


class FakeRdata:
    def __init__(self, text):
        self.text = text

    def to_text(self):
        return self.text


class FakeResolver:
    def __init__(self, zones):
        self.zones = zones
        self.queries = []

    def resolve(self, name, rdtype, lifetime=None):
        self.queries.append((name, rdtype))
        if name not in self.zones:
            raise dns.resolver.NXDOMAIN()
        answers = self.zones[name].get(rdtype)
        if not answers:
            raise dns.resolver.NoAnswer()
        return [FakeRdata(a) for a in answers]


def test_unregistered_domain_returns_none():
    lookup = DnsLookup(resolver=FakeResolver({}))
    assert lookup("nothing-here.com") is None


def test_nxdomain_stops_after_first_query():
    fake = FakeResolver({})
    DnsLookup(resolver=fake)("nothing-here.com")
    assert len(fake.queries) == 1


def test_registered_domain_collects_records():
    fake = FakeResolver({
        "paypa1.com": {
            "NS": ["ns1.evil.net."],
            "A": ["203.0.113.7"],
            "MX": ["10 mail.paypa1.com."],
        }
    })
    record = DnsLookup(resolver=fake)("paypa1.com")
    assert record == DnsRecord(
        ns=["ns1.evil.net"], a=["203.0.113.7"], aaaa=[], mx=["mail.paypa1.com"]
    )
    assert record.live
    assert record.has_mail


def test_domain_with_only_ns_counts_as_registered_but_not_live():
    fake = FakeResolver({"parked.com": {"NS": ["ns1.parking.example."]}})
    record = DnsLookup(resolver=fake)("parked.com")
    assert record is not None
    assert not record.live
    assert not record.has_mail


def test_null_mx_is_not_treated_as_mail():
    # RFC 7505: "0 ." means "this domain does not accept mail"
    fake = FakeResolver({"nomail.com": {"NS": ["ns1.x."], "MX": ["0 ."]}})
    record = DnsLookup(resolver=fake)("nomail.com")
    assert record.mx == []


def test_resolve_all_keeps_only_registered():
    records = {"a.com": DnsRecord(ns=["ns"]), "b.com": None}
    result = resolve_all(["a.com", "b.com"], records.get, workers=2)
    assert set(result.found) == {"a.com"}
    assert result.errors == []


def test_resolve_all_records_errors_without_crashing():
    def lookup(name):
        if name == "slow.com":
            raise dns.exception.Timeout()
        return DnsRecord(ns=["ns"])

    result = resolve_all(["ok.com", "slow.com"], lookup, workers=2)
    assert set(result.found) == {"ok.com"}
    assert result.errors == ["slow.com"]


def test_resolve_all_reports_progress():
    seen = []
    resolve_all(["a.com", "b.com", "c.com"], lambda n: None, workers=2,
                progress=lambda done, total: seen.append((done, total)))
    assert seen[-1] == (3, 3)
