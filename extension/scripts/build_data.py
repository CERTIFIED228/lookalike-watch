"""Rebuild the data files bundled with the extension.

  data/top-sites.json    registered domains of the 10,000 most visited sites,
                         from Google's Chrome UX Report (via zakird/crux-top-lists)
  data/known-sites.json  the rest of the top 100,000, only used to avoid false alarms
  data/popular-hosts.json  subdomains among the top 100,000 (support.roku.com), which
                         phishing feeds sometimes list because a scam was hosted on them
  data/suffixes.json     public suffixes like co.uk and com.au (the ICANN part of
                         the Public Suffix List snapshot that ships with tldextract)
  data/platforms.json    services anyone can get a subdomain on, like github.io,
                         myshopify.com or S3 buckets (the private part of that list)

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


def ranked_rows(raw_gz: bytes, limit: int) -> list[dict]:
    rows = csv.DictReader(io.StringIO(gzip.decompress(raw_gz).decode("utf-8")))
    return sorted((r for r in rows if int(r["rank"]) <= limit), key=lambda r: int(r["rank"]))


def popular_subdomains(raw_gz: bytes, limit: int) -> list[str]:
    extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
    out: dict[str, None] = {}
    for row in ranked_rows(raw_gz, limit):
        host = row["origin"].split("://", 1)[-1].split(":", 1)[0]
        parts = extract(host)
        if parts.subdomain and parts.subdomain != "www":
            out.setdefault(host, None)
    return list(out)


def ranked_sites(raw_gz: bytes, limit: int) -> list[str]:
    extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
    ranked = ranked_rows(raw_gz, limit)
    seen: dict[str, None] = {}
    for row in ranked:
        host = row["origin"].split("://", 1)[-1].split(":", 1)[0]
        parts = extract(host)
        if parts.domain and parts.suffix:
            seen.setdefault(f"{parts.domain}.{parts.suffix}", None)
    return list(seen)


def psl_section(name: str) -> list[str]:
    """Rules from one section of the Public Suffix List snapshot, wildcards included."""
    snapshot = Path(tldextract.__file__).with_name(".tld_set_snapshot").read_text("utf-8")
    section = snapshot.split(f"===BEGIN {name} DOMAINS===")[1].split(f"===END {name} DOMAINS===")[0]
    out = set()
    for line in section.splitlines():
        line = line.strip()
        if not line or line.startswith(("//", "!")) or "." not in line:
            continue
        out.add(line if line.isascii() else line.encode("idna").decode("ascii"))
    return sorted(out)


def main() -> None:
    DATA.mkdir(exist_ok=True)
    raw = load_crux(sys.argv[1] if len(sys.argv) > 1 else None)
    sites = ranked_sites(raw, TOP_N)
    top = set(sites)
    known = [d for d in ranked_sites(raw, KNOWN_N) if d not in top]
    (DATA / "top-sites.json").write_text(json.dumps(sites, indent=0) + "\n", "utf-8")
    (DATA / "known-sites.json").write_text(json.dumps(known, separators=(",", ":")) + "\n", "utf-8")
    hosts = popular_subdomains(raw, KNOWN_N)
    compact = json.dumps(hosts, separators=(",", ":"))
    (DATA / "popular-hosts.json").write_text(compact + "\n", "utf-8")
    suffixes = psl_section("ICANN")
    (DATA / "suffixes.json").write_text(json.dumps(suffixes, indent=0) + "\n", "utf-8")
    platforms = psl_section("PRIVATE")
    (DATA / "platforms.json").write_text(json.dumps(platforms, indent=0) + "\n", "utf-8")
    print(f"{len(sites)} top sites, {len(known)} known sites, {len(hosts)} popular subdomains, "
          f"{len(suffixes)} suffixes, {len(platforms)} shared platforms")


if __name__ == "__main__":
    main()
