import re
from dataclasses import dataclass

import idna
import tldextract

# Use the public suffix list snapshot that ships with tldextract instead of
# downloading a fresh one on every run. It changes slowly enough.
_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


@dataclass(frozen=True)
class Domain:
    name: str
    suffix: str

    @property
    def fqdn(self) -> str:
        return f"{self.name}.{self.suffix}"


def is_valid_label(label: str) -> bool:
    return bool(_LABEL.match(label))


def to_ascii(label: str) -> str | None:
    """Punycode a single label, or None if it can't be a real hostname."""
    if label.isascii():
        return label if is_valid_label(label) else None
    try:
        encoded = idna.encode(label).decode("ascii")
    except idna.IDNAError:
        return None
    return encoded if is_valid_label(encoded) else None


def parse_domain(raw: str) -> Domain:
    """Turn whatever the user typed (URL, subdomain, mixed case) into name + suffix."""
    text = raw.strip().lower().rstrip(".")
    if not text or " " in text:
        raise ValueError(f"not a domain: {raw!r}")

    parts = _extract(text)
    if not parts.domain or not parts.suffix:
        raise ValueError(f"not a registrable domain: {raw!r}")
    if to_ascii(parts.domain) is None:
        raise ValueError(f"invalid domain name: {raw!r}")

    return Domain(name=parts.domain, suffix=parts.suffix)


def registered_part(hostname: str) -> str | None:
    """'login.paypal-secure.com' -> 'paypal-secure.com'."""
    try:
        return parse_domain(hostname).fqdn
    except ValueError:
        return None
