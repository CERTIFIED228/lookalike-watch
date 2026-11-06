from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

import dns.exception
import dns.resolver


@dataclass
class DnsRecord:
    ns: list[str] = field(default_factory=list)
    a: list[str] = field(default_factory=list)
    aaaa: list[str] = field(default_factory=list)
    mx: list[str] = field(default_factory=list)

    @property
    def live(self) -> bool:
        return bool(self.a or self.aaaa)

    @property
    def has_mail(self) -> bool:
        return bool(self.mx)


Lookup = Callable[[str], DnsRecord | None]


class DnsLookup:
    """Checks whether a domain exists and what it points at.

    NS first: if the name doesn't exist (NXDOMAIN) there's no point asking
    for anything else, and most candidates don't exist, so this saves ~75%
    of queries.
    """

    def __init__(self, timeout: float = 3.0, nameservers: list[str] | None = None,
                 resolver=None):
        if resolver is None:
            resolver = dns.resolver.Resolver()
            if nameservers:
                resolver.nameservers = nameservers
        self._resolver = resolver
        self._timeout = timeout

    def _query(self, name: str, rdtype: str) -> list[str]:
        try:
            answer = self._resolver.resolve(name, rdtype, lifetime=self._timeout)
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return []
        return [r.to_text() for r in answer]

    def __call__(self, name: str) -> DnsRecord | None:
        try:
            ns = self._query(name, "NS")
        except dns.resolver.NXDOMAIN:
            return None

        try:
            a = self._query(name, "A")
            aaaa = self._query(name, "AAAA")
            mx = self._query(name, "MX")
        except dns.resolver.NXDOMAIN:
            return None

        record = DnsRecord(
            ns=[n.rstrip(".").lower() for n in ns],
            a=a,
            aaaa=aaaa,
            mx=_mail_hosts(mx),
        )
        return record if (record.ns or record.live or record.mx) else None


def _mail_hosts(mx_answers: list[str]) -> list[str]:
    hosts = []
    for answer in mx_answers:
        host = answer.split()[-1].rstrip(".").lower()
        # Skips "0 ." (a null MX, RFC 7505: "no mail here") and junk seen on
        # parked domains like "localhost" or "~".
        if "." in host and not host.startswith("localhost"):
            hosts.append(host)
    return hosts


@dataclass
class ResolveResult:
    found: dict[str, DnsRecord]
    errors: list[str]


def resolve_all(names: Iterable[str], lookup: Lookup, workers: int = 20,
                progress: Callable[[int, int], None] | None = None) -> ResolveResult:
    names = list(names)
    found: dict[str, DnsRecord] = {}
    errors: list[str] = []

    # DNS lookups are almost all waiting on the network, so threads are fine
    # here - the GIL isn't the bottleneck.
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {pool.submit(lookup, name): name for name in names}
        for done, future in enumerate(as_completed(futures), start=1):
            name = futures[future]
            try:
                record = future.result()
            except (dns.exception.DNSException, OSError):
                errors.append(name)
            else:
                if record is not None:
                    found[name] = record
            if progress:
                progress(done, len(names))

    errors.sort()
    return ResolveResult(found=found, errors=errors)
