import argparse
import os
import secrets
import sys
import time
from pathlib import Path

import requests
from dotenv import load_dotenv

from . import __version__
from .alerts import AlertError, mask_url, send_webhook
from .ct import CTError
from .domain import parse_domain
from .permutations import TECHNIQUES, generate
from .report import as_csv, as_json, as_table
from .resolver import DnsLookup
from .scan import run_scan
from .state import SeenStore, StateError

WEBHOOK_ENV = "LOOKALIKE_WEBHOOK_URL"


class ResolverError(Exception):
    pass


def make_lookup(timeout: float, nameservers: list[str] | None = None):
    return DnsLookup(timeout=timeout, nameservers=nameservers)


def make_session() -> requests.Session:
    return requests.Session()


def log(message: str) -> None:
    print(message, file=sys.stderr)


def _progress(done: int, total: int) -> None:
    if sys.stderr.isatty():
        end = "\n" if done == total else ""
        print(f"\rchecked {done}/{total}", end=end, file=sys.stderr, flush=True)


def resolver_is_lying(lookup) -> bool:
    """Some ISP resolvers answer for domains that don't exist (to show ads).

    That would make every candidate look registered, so test with a name
    that can't possibly exist first.
    """
    try:
        return lookup(f"lw-{secrets.token_hex(12)}.com") is not None
    except Exception:
        return False


def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("domain", help="the real domain to protect, e.g. paypal.com")
    p.add_argument("-t", "--technique", action="append", choices=TECHNIQUES, dest="techniques",
                   help="only use this technique (repeatable)")


def _add_scan_options(p: argparse.ArgumentParser) -> None:
    _add_common(p)
    p.add_argument("--ct", action="store_true",
                   help="also search Certificate Transparency logs (crt.sh)")
    p.add_argument("--ct-only", action="store_true", help="only use CT logs, skip permutations")
    p.add_argument("--workers", type=int, default=20, help="parallel DNS lookups (default 20)")
    p.add_argument("--timeout", type=float, default=3.0, help="DNS timeout in seconds")
    p.add_argument("--nameserver", action="append", dest="nameservers",
                   help="DNS server to use instead of the system one (repeatable)")
    p.add_argument("--allow", action="append", default=[],
                   help="domain you already own, never report it (repeatable)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lookalike-watch",
        description="Find registered lookalike domains of a brand and watch for new ones.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate", help="list possible lookalikes (no network)")
    _add_common(gen)
    gen.add_argument("--format", choices=["table", "json", "csv"], default="table")

    scan = sub.add_parser("scan", help="check which lookalikes are registered and score them")
    _add_scan_options(scan)
    scan.add_argument("--min-score", type=int, default=0, help="hide findings below this score")
    scan.add_argument("--format", choices=["table", "json", "csv"], default="table")
    scan.add_argument("-o", "--output", help="write the report to a file (format from extension)")

    watch = sub.add_parser("watch", help="scan on a schedule and alert on new lookalikes")
    _add_scan_options(watch)
    watch.add_argument("--min-score", type=int, default=50,
                       help="only alert at or above this score (default 50)")
    watch.add_argument("--interval", type=int, default=3600, help="seconds between scans")
    watch.add_argument("--once", action="store_true",
                       help="run a single scan and exit (for cron / Task Scheduler)")
    watch.add_argument("--baseline", action="store_true",
                       help="first run only records what exists, without alerting")
    watch.add_argument("--state", help="where to remember seen domains")
    return parser


def _render(findings, fmt: str, target: str) -> str:
    if fmt == "json":
        return as_json(findings, target)
    if fmt == "csv":
        return as_csv(findings)
    return as_table(findings)


def cmd_generate(args) -> int:
    brand = parse_domain(args.domain)
    candidates = generate(brand, args.techniques)
    if args.format == "json":
        import json
        print(json.dumps([c.__dict__ for c in candidates], indent=2, ensure_ascii=False))
    elif args.format == "csv":
        print("domain,ascii,technique")
        for c in candidates:
            print(f"{c.domain},{c.ascii},{c.technique}")
    else:
        width = max((len(c.domain) for c in candidates), default=0)
        for c in candidates:
            extra = f"  ({c.ascii})" if c.ascii != c.domain else ""
            print(f"{c.domain.ljust(width)}  {c.technique}{extra}")
        log(f"{len(candidates)} candidates")
    return 0


def _scan(args, brand):
    lookup = make_lookup(args.timeout, args.nameservers)
    if resolver_is_lying(lookup):
        raise ResolverError(
            "your DNS resolver answers for domains that don't exist, so every candidate "
            "would look registered. Try a different one, e.g. --nameserver 1.1.1.1"
        )
    result = run_scan(
        brand, lookup=lookup, techniques=args.techniques, use_ct=args.ct,
        ct_only=args.ct_only, session=make_session(), workers=args.workers,
        allow=args.allow, progress=_progress,
    )
    msg = f"checked {result.checked} domains, {len(result.findings)} registered"
    if result.from_ct:
        msg += f", {result.from_ct} seen in CT logs"
    if result.errors:
        msg += f", {len(result.errors)} lookups timed out"
    log(msg)
    if result.ct_error:
        log(f"warning: CT search skipped - {result.ct_error}")
    return result


def cmd_scan(args) -> int:
    brand = parse_domain(args.domain)
    result = _scan(args, brand)
    findings = [f for f in result.findings if f.score >= args.min_score]

    if args.output:
        out = Path(args.output)
        fmt = out.suffix.lower().lstrip(".")
        fmt = fmt if fmt in {"json", "csv"} else "table"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(_render(findings, fmt, brand.fqdn) + "\n", encoding="utf-8")
        log(f"report written to {args.output}")
    else:
        print(_render(findings, args.format, brand.fqdn))
    return 0


def cmd_watch(args) -> int:
    brand = parse_domain(args.domain)
    state_path = args.state or Path(".lookalike-watch") / f"{brand.fqdn}.json"
    store = SeenStore(state_path)
    webhook = os.environ.get(WEBHOOK_ENV, "").strip()
    baseline = args.baseline
    interval = max(60, args.interval)

    if webhook:
        log(f"alerts go to {mask_url(webhook)}")
    else:
        log(f"no webhook set ({WEBHOOK_ENV}), new findings will be printed instead")

    while True:
        result = _scan(args, brand)
        hits = [f for f in result.findings if f.score >= args.min_score]
        new = store.new(hits)
        failed = False

        if baseline:
            log(f"baseline recorded: {len(hits)} existing lookalike(s), no alert sent")
        elif not new:
            log("nothing new")
        elif webhook:
            try:
                send_webhook(webhook, brand.fqdn, new, session=make_session())
                log(f"alerted on {len(new)} new lookalike(s)")
            except AlertError as exc:
                # Don't mark them as seen, so the next run tries again.
                log(f"error: {exc}")
                hits = [f for f in hits if f not in new]
                failed = True
        else:
            print(as_table(new))

        store.remember(hits)
        store.save()
        baseline = False

        if args.once:
            return 1 if failed else 0
        time.sleep(interval)


def _safe_streams() -> None:
    # A homoglyph domain printed to a cp1252 console (common on Windows when
    # output is redirected) would otherwise crash with UnicodeEncodeError.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="backslashreplace")


def main(argv: list[str] | None = None) -> int:
    _safe_streams()
    load_dotenv()
    parser = build_parser()
    args = parser.parse_args(argv)
    handlers = {"generate": cmd_generate, "scan": cmd_scan, "watch": cmd_watch}
    try:
        return handlers[args.command](args)
    except ValueError as exc:
        log(f"error: {exc}")
        return 2
    except (CTError, StateError, ResolverError) as exc:
        log(f"error: {exc}")
        return 1
    except KeyboardInterrupt:
        log("stopped")
        return 130


if __name__ == "__main__":
    sys.exit(main())
