from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

import dns.exception

from .ct import CTError, ct_candidates, fetch_ct_hostnames
from .domain import Domain
from .permutations import Candidate, generate
from .resolver import Lookup, resolve_all
from .scoring import Finding, score


@dataclass
class ScanResult:
    findings: list[Finding]
    checked: int
    errors: list[str] = field(default_factory=list)
    from_ct: int = 0
    ct_error: str = ""


def run_scan(brand: Domain, *, lookup: Lookup, techniques: Iterable[str] | None = None,
             use_ct: bool = False, ct_only: bool = False, session=None, workers: int = 20,
             allow: Iterable[str] = (), ct_retries: int = 3,
             progress: Callable[[int, int], None] | None = None) -> ScanResult:
    candidates: dict[str, Candidate] = {}
    if not ct_only:
        for c in generate(brand, techniques):
            candidates[c.ascii] = c

    ct_names: set[str] = set()
    ct_error = ""
    if use_ct or ct_only:
        try:
            hostnames = fetch_ct_hostnames(brand.name, session=session, retries=ct_retries)
        except CTError as exc:
            # crt.sh being down shouldn't throw away the DNS half of the scan.
            if ct_only:
                raise
            ct_error = str(exc)
            hostnames = set()
        for c in ct_candidates(brand, hostnames):
            ct_names.add(c.ascii)
            candidates.setdefault(c.ascii, c)

    skip = {a.lower() for a in allow}
    to_check = [name for name in candidates if name not in skip]

    # Look the real domain up too, so we can spot lookalikes the brand owns itself.
    try:
        brand_dns = lookup(brand.fqdn)
    except (dns.exception.DNSException, OSError):
        brand_dns = None

    resolved = resolve_all(to_check, lookup, workers=workers, progress=progress)

    findings = []
    for name, record in resolved.found.items():
        c = candidates[name]
        source = "ct" if c.technique == "ct-log" else "permutation"
        findings.append(score(c.domain, c.ascii, c.technique, brand, record,
                              brand_dns=brand_dns, in_ct=name in ct_names, source=source))

    findings.sort(key=lambda f: (-f.score, f.ascii))
    return ScanResult(findings=findings, checked=len(to_check), errors=resolved.errors,
                      from_ct=len(ct_names), ct_error=ct_error)
