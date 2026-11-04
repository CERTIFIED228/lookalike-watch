import pytest

from lookalike_watch.domain import is_valid_label, parse_domain
from lookalike_watch.homoglyphs import skeleton
from lookalike_watch.permutations import TECHNIQUES, generate


@pytest.fixture(scope="module")
def candidates():
    return generate(parse_domain("paypal.com"))


@pytest.fixture(scope="module")
def by_domain(candidates):
    return {c.domain: c for c in candidates}


def test_original_domain_is_never_a_candidate(by_domain):
    assert "paypal.com" not in by_domain


def test_candidates_are_unique(candidates):
    names = [c.ascii for c in candidates]
    assert len(names) == len(set(names))


def test_every_candidate_is_a_valid_hostname(candidates):
    for c in candidates:
        labels = c.ascii.split(".")
        assert all(is_valid_label(label) for label in labels), c.ascii


@pytest.mark.parametrize(
    "domain, technique",
    [
        ("paypl.com", "omission"),
        ("paypall.com", "repetition"),
        ("papyal.com", "transposition"),
        ("paypak.com", "replacement"),
        ("paqypal.com", "insertion"),
        ("qaypal.com", "bitsquatting"),
        ("paypel.com", "vowel-swap"),
        ("pay-pal.com", "hyphenation"),
        ("paypal1.com", "addition"),
        ("paypa1.com", "homoglyph"),
        ("paypal.net", "tld-swap"),
        ("paypal-login.com", "combosquat"),
        ("secure-paypal.com", "combosquat"),
    ],
)
def test_technique_examples(by_domain, domain, technique):
    assert domain in by_domain
    assert by_domain[domain].technique == technique


def test_unicode_homoglyphs_are_punycoded(candidates):
    idn = [c for c in candidates if c.technique == "homoglyph" and c.ascii.startswith("xn--")]
    assert idn, "expected at least one IDN homoglyph"
    assert all(skeleton(c.domain.split(".")[0]) == skeleton("paypal") for c in idn)


def test_can_limit_techniques():
    only = generate(parse_domain("paypal.com"), techniques=["omission", "tld-swap"])
    assert {c.technique for c in only} == {"omission", "tld-swap"}


def test_unknown_technique_is_rejected():
    with pytest.raises(ValueError):
        generate(parse_domain("paypal.com"), techniques=["nope"])


def test_technique_list_is_stable():
    assert "homoglyph" in TECHNIQUES
    assert "combosquat" in TECHNIQUES


def test_works_with_multi_part_suffix():
    out = generate(parse_domain("bbc.co.uk"), techniques=["omission"])
    assert {c.domain for c in out} == {"bc.co.uk", "bb.co.uk"}
