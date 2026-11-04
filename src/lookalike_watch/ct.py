import time
from collections.abc import Callable, Iterable

import idna
import requests

from . import __version__
from .domain import Domain, parse_domain
from .homoglyphs import skeleton
from .permutations import Candidate
from .similarity import similarity

CRT_SH = "https://crt.sh/"
USER_AGENT = f"lookalike-watch/{__version__}"


class CTError(Exception):
    pass


def _clean(name: str) -> str | None:
    name = name.strip().lower().rstrip(".")
    if name.startswith("*."):
        name = name[2:]
    if not name or "@" in name or " " in name or "." not in name:
        return None
    return name


def fetch_ct_hostnames(keyword: str, session=None, timeout: float = 60, retries: int = 3,
                       sleep: Callable[[float], None] = time.sleep) -> set[str]:
    """Ask crt.sh for every unexpired certificate whose names contain `keyword`.

    Certificate Transparency logs are public, append-only records of every
    certificate a CA issues. Phishing sites want the padlock too, so new
    lookalikes tend to show up here, often before the site goes live.
    crt.sh is free but slow and flaky under load, hence the retries.
    """
    if len(keyword) < 4:
        raise ValueError("keyword too short for a CT search (needs 4+ characters)")

    session = session or requests.Session()
    params = {"q": f"%{keyword}%", "output": "json", "exclude": "expired", "deduplicate": "Y"}

    last_problem = "no attempts made"
    for attempt in range(retries):
        if attempt:
            sleep(2 ** attempt)
        try:
            resp = session.get(CRT_SH, params=params, timeout=timeout,
                               headers={"User-Agent": USER_AGENT})
        except requests.RequestException as exc:
            last_problem = type(exc).__name__
            continue
        if resp.status_code != 200:
            last_problem = f"HTTP {resp.status_code}"
            continue
        try:
            entries = resp.json()
        except ValueError:
            last_problem = "response was not valid JSON"
            continue
        return _hostnames_from(entries)

    raise CTError(f"crt.sh lookup failed after {retries} attempt(s): {last_problem}")


def _hostnames_from(entries) -> set[str]:
    names: set[str] = set()
    for entry in entries or []:
        raw = f"{entry.get('common_name', '')}\n{entry.get('name_value', '')}"
        for line in raw.splitlines():
            cleaned = _clean(line)
            if cleaned:
                names.add(cleaned)
    return names


def _display(ascii_domain: str) -> str:
    try:
        return idna.decode(ascii_domain)
    except idna.IDNAError:
        return ascii_domain


def ct_candidates(brand: Domain, hostnames: Iterable[str]) -> list[Candidate]:
    """Reduce raw certificate names to registered domains that resemble the brand."""
    brand_look = skeleton(brand.name)
    out: dict[str, Candidate] = {}

    for host in hostnames:
        try:
            parsed = parse_domain(_display(host))
        except ValueError:
            continue
        if parsed.fqdn == brand.fqdn:
            continue

        look = skeleton(parsed.name)
        if brand_look not in look and similarity(look, brand_look) < 0.75:
            continue

        try:
            ascii_name = idna.encode(parsed.fqdn).decode("ascii")
        except idna.IDNAError:
            continue
        out.setdefault(ascii_name, Candidate(parsed.fqdn, ascii_name, "ct-log"))

    return sorted(out.values(), key=lambda c: c.ascii)
