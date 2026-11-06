"""Rebuild the data files bundled with the extension.

  data/top-sites.json    registered domains of the 10,000 most visited sites,
                         from Google's Chrome UX Report (via zakird/crux-top-lists)
  data/known-sites.json  the rest of the top 100,000, only used to avoid false alarms
  data/suffixes.json     multi-part public suffixes (co.uk, com.au...) from the
                       Public Suffix List snapshot that ships with tldextract

Run from the extension folder:  python scripts/build_data.py
"""
import csv
import gzip
import io
import json
import sys
import urllib.request
from pathlib import Path

import tldextract

CRUX_URL = "https://raw.githubusercontent.com/zakird/crux-top-lists/main/data/global/current.csv.gz"
TOP_N = 10_000
KNOWN_N = 100_000
DATA = Path(__file__).resolve().parent.parent / "data"


def load_crux(source: str | None) -> bytes:
    if source:
        return Path(source).read_bytes()
    with urllib.request.urlopen(CRUX_URL, timeout=60) as resp:
        return resp.read()


def ranked_sites(raw_gz: bytes, limit: int) -> list[str]:
    extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
    rows = csv.DictReader(io.StringIO(gzip.decompress(raw_gz).decode("utf-8")))
    ranked = sorted(
        (r for r in rows if int(r["rank"]) <= limit),
        key=lambda r: int(r["rank"]),
    )
    seen: dict[str, None] = {}
    for row in ranked:
        host = row["origin"].split("://", 1)[-1].split(":", 1)[0]
        parts = extract(host)
        if parts.domain and parts.suffix:
            seen.setdefault(f"{parts.domain}.{parts.suffix}", None)
    return list(seen)


def multi_part_suffixes() -> list[str]:
    snapshot = Path(tldextract.__file__).with_name(".tld_set_snapshot").read_text("utf-8")
    icann = snapshot.split("===BEGIN ICANN DOMAINS===")[1].split("===END ICANN DOMAINS===")[0]
    out = set()
    for line in icann.splitlines():
        line = line.strip()
        if not line or line.startswith(("//", "*", "!")) or "." not in line:
            continue
        out.add(line.encode("idna").decode("ascii") if not line.isascii() else line)
    return sorted(out)


def main() -> None:
    DATA.mkdir(exist_ok=True)
    raw = load_crux(sys.argv[1] if len(sys.argv) > 1 else None)
    sites = ranked_sites(raw, TOP_N)
    top = set(sites)
    known = [d for d in ranked_sites(raw, KNOWN_N) if d not in top]
    (DATA / "top-sites.json").write_text(json.dumps(sites, indent=0) + "\n", "utf-8")
    (DATA / "known-sites.json").write_text(json.dumps(known, separators=(",", ":")) + "\n", "utf-8")
    suffixes = multi_part_suffixes()
    (DATA / "suffixes.json").write_text(json.dumps(suffixes, indent=0) + "\n", "utf-8")
    print(f"{len(sites)} top sites, {len(known)} known sites, {len(suffixes)} multi-part suffixes")


if __name__ == "__main__":
    main()
