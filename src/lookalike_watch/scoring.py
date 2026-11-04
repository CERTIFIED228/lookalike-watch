from dataclasses import dataclass, field

from .domain import Domain, parse_domain
from .homoglyphs import skeleton
from .resolver import DnsRecord
from .similarity import edit_distance, similarity

# Words attackers bolt onto a brand name to make a phishing link look official.
PHISHING_WORDS = [
    "login", "signin", "logon", "secure", "security", "verify", "verification",
    "account", "update", "billing", "payment", "invoice", "support", "help",
    "service", "wallet", "auth", "password", "reset", "unlock", "confirm", "refund",
]

PARKING_HINTS = [
    "sedoparking", "parkingcrew", "bodis", "above.com", "dan.com", "afternic",
    "parklogic", "domaincontrol-park", "uniregistrymarket", "huge-domains",
]


@dataclass
class Finding:
    domain: str
    ascii: str
    technique: str
    source: str
    score: int
    level: str
    reasons: list[str]
    a: list[str] = field(default_factory=list)
    mx: list[str] = field(default_factory=list)
    ns: list[str] = field(default_factory=list)


def level_for(points: int) -> str:
    if points >= 70:
        return "critical"
    if points >= 50:
        return "high"
    if points >= 30:
        return "medium"
    return "low"


def _label(domain: str) -> str:
    try:
        return parse_domain(domain).name
    except ValueError:
        return domain.split(".")[0]


def score(domain: str, ascii_domain: str, technique: str, brand: Domain,
          record: DnsRecord, *, brand_dns: DnsRecord | None = None,
          in_ct: bool = False, source: str = "permutation") -> Finding:
    """Score how dangerous a registered lookalike is, and say why.

    Every point comes with a reason so a human can check the logic instead
    of trusting a magic number.
    """
    points = 0
    reasons: list[str] = []

    name = _label(domain)
    look, brand_look = skeleton(name), skeleton(brand.name)

    if look == brand_look:
        points += 45
        reasons.append(f"looks identical to '{brand.name}' at a glance")
    else:
        sim = similarity(look, brand_look)
        if sim >= 0.75:
            edits = edit_distance(look, brand_look)
            points += round(40 * sim)
            reasons.append(f"{edits} edit{'s' if edits != 1 else ''} away from '{brand.name}'")
        if brand_look in look:
            points += 25
            reasons.append(f"contains the brand name '{brand.name}'")

    words = [w for w in PHISHING_WORDS if w in name]
    if words:
        points += 15
        reasons.append(f"contains '{words[0]}' (common in credential phishing)")

    if "xn--" in ascii_domain:
        points += 10
        reasons.append(f"internationalised domain, real name is {ascii_domain} (punycode)")

    points += 5
    reasons.append("is registered")

    if record.live:
        points += 10
        reasons.append(f"has a live web host ({(record.a + record.aaaa)[0]})")
    if record.has_mail:
        points += 15
        reasons.append("can send/receive email (MX records), so it can be used for phishing mail")
    if in_ct:
        points += 10
        reasons.append("has a TLS certificate in CT logs (someone set up HTTPS for it)")

    # These two change what you'd actually do about a domain, so they go to
    # the front of the list (that's what the table and alerts show).
    ns_text = " ".join(record.ns)
    if any(hint in ns_text for hint in PARKING_HINTS):
        points -= 10
        reasons.insert(0, "looks parked (for sale or ad page) - keep an eye on it")

    if brand_dns and set(record.ns) & set(brand_dns.ns):
        points -= 40
        reasons.insert(0, f"uses the same nameservers as {brand.fqdn}, probably owned by the brand")

    points = max(0, min(100, points))
    return Finding(
        domain=domain, ascii=ascii_domain, technique=technique, source=source,
        score=points, level=level_for(points), reasons=reasons,
        a=record.a + record.aaaa, mx=record.mx, ns=record.ns,
    )
