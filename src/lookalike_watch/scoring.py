from dataclasses import dataclass, field

from .domain import Domain, parse_domain, registered_part
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
    "sedoparking", "parkingcrew", "bodis.com", "abovedomains", "above.com", "dan.com",
    "afternic", "parklogic", "uniregistrymarket", "hugedomains",
]

# Registrars big companies use for defensive registrations. Attackers don't:
# they're expensive and check who you are. On a real scan of paypal.com, most
# registered lookalikes turned out to be PayPal's own, through MarkMonitor.
BRAND_PROTECTION = {
    "markmonitor.com": "MarkMonitor",
    "cscdns.net": "CSC",
    "cscdns.uk": "CSC",
    "comlaude-dns.com": "Com Laude",
    "comlaude-dns.net": "Com Laude",
    "comlaude-dns.eu": "Com Laude",
    "safenames.net": "Safenames",
}


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
        # "paypalc" is both one edit away and contains "paypal". That's one
        # signal, so only the stronger of the two counts.
        options = []
        sim = similarity(look, brand_look)
        if sim >= 0.75:
            edits = edit_distance(look, brand_look)
            plural = "s" if edits != 1 else ""
            options.append((round(40 * sim), f"{edits} edit{plural} away from '{brand.name}'"))
        if brand_look in look:
            options.append((25, f"contains the brand name '{brand.name}'"))
        if options:
            best = max(options)
            points += best[0]
            reasons.append(best[1])

    words = [w for w in PHISHING_WORDS if w in name]
    if words:
        points += 15
        reasons.append(f"contains '{words[0]}' (common in credential phishing)")

    if "xn--" in ascii_domain:
        points += 10
        reasons.append(f"internationalised domain, real name is {ascii_domain} (punycode)")

    points += 5
    reasons.append("is registered")

    owner = ownership_hint(record, brand, brand_dns)
    parked = not owner and _is_parked(record)

    # For brand-owned and parked domains the web server and mail server belong
    # to the brand or the parking company, so they don't add risk.
    if not owner and not parked:
        if record.live:
            points += 10
            reasons.append(f"has a live web host ({(record.a + record.aaaa)[0]})")
        if record.has_mail:
            points += 15
            reasons.append(
                "can send/receive email (MX records), so it can be used for phishing mail"
            )
        if in_ct:
            points += 10
            reasons.append("has a TLS certificate in CT logs (someone set up HTTPS for it)")

    # These change what you'd actually do about a domain, so they go to the
    # front of the list (that's what the table and alerts show).
    if parked:
        points -= 10
        reasons.insert(0, "looks parked (for sale or ad page) - keep an eye on it")
    if owner:
        points -= 40
        reasons.insert(0, owner)

    points = max(0, min(100, points))
    return Finding(
        domain=domain, ascii=ascii_domain, technique=technique, source=source,
        score=points, level=level_for(points), reasons=reasons,
        a=record.a + record.aaaa, mx=record.mx, ns=record.ns,
    )


def _hosts_under(hosts: list[str], domain: str) -> bool:
    return any(h == domain or h.endswith("." + domain) for h in hosts)


def _is_parked(record: DnsRecord) -> bool:
    text = " ".join(record.ns + record.mx)
    return any(hint in text for hint in PARKING_HINTS)


def ownership_hint(record: DnsRecord, brand: Domain,
                   brand_dns: DnsRecord | None) -> str | None:
    """Return a reason if the lookalike is probably the brand's own domain."""
    hosts = record.ns + record.mx
    for provider, company in BRAND_PROTECTION.items():
        if _hosts_under(hosts, provider):
            return (f"registered through {company}, a brand-protection registrar, "
                    "so most likely a defensive registration")

    if _hosts_under(hosts, brand.fqdn):
        return f"its DNS or mail is run from {brand.fqdn}, probably owned by the brand"

    if brand_dns:
        if set(record.ns) & set(brand_dns.ns):
            return f"uses the same nameservers as {brand.fqdn}, probably owned by the brand"
        # Only count mail domains with the brand in the name (paypalcorp.com),
        # not shared providers like Google or Microsoft that half the internet uses.
        brand_mail = {registered_part(m) for m in brand_dns.mx}
        brand_mail = {m for m in brand_mail if m and brand.name in m}
        shared = brand_mail & {registered_part(m) for m in record.mx}
        if shared:
            return (f"uses the brand's own mail servers ({sorted(shared)[0]}), "
                    "probably owned by the brand")
    return None
