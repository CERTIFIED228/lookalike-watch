import string
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass

from .domain import Domain, to_ascii
from .homoglyphs import ASCII_LOOKALIKES, UNICODE_LOOKALIKES
from .keyboards import QWERTY

VOWELS = "aeiou"
LDH = set(string.ascii_lowercase + string.digits + "-")

# TLDs that show up a lot in phishing reports (cheap, or easy to confuse).
SWAP_TLDS = [
    "com", "net", "org", "co", "io", "info", "biz", "xyz", "top", "online",
    "site", "shop", "app", "live", "support", "help", "store", "co.uk", "uk",
    "us", "eu", "de", "me", "cc", "ru", "cn",
]

COMBO_WORDS = [
    "login", "secure", "account", "support", "verify", "help", "signin",
    "auth", "update", "billing", "pay", "wallet", "online", "service",
    "mail", "my", "portal", "app",
]


@dataclass(frozen=True)
class Candidate:
    domain: str      # how it looks to a human (may contain unicode)
    ascii: str       # what actually goes on the wire / into DNS
    technique: str


def _omission(name: str) -> Iterator[str]:
    for i in range(len(name)):
        yield name[:i] + name[i + 1:]


def _repetition(name: str) -> Iterator[str]:
    for i, ch in enumerate(name):
        yield name[:i] + ch + name[i:]


def _transposition(name: str) -> Iterator[str]:
    for i in range(len(name) - 1):
        yield name[:i] + name[i + 1] + name[i] + name[i + 2:]


def _replacement(name: str) -> Iterator[str]:
    for i, ch in enumerate(name):
        for key in QWERTY.get(ch, ""):
            yield name[:i] + key + name[i + 1:]


def _insertion(name: str) -> Iterator[str]:
    for i, ch in enumerate(name):
        for key in QWERTY.get(ch, ""):
            yield name[:i] + key + ch + name[i + 1:]
            yield name[:i] + ch + key + name[i + 1:]


def _bitsquatting(name: str) -> Iterator[str]:
    # A single flipped bit in RAM or on the wire turns one letter into another.
    # Rare per request, but at the scale of a big brand it happens daily.
    for i, ch in enumerate(name):
        for bit in range(8):
            flipped = chr(ord(ch) ^ (1 << bit))
            if flipped in LDH:
                yield name[:i] + flipped + name[i + 1:]


def _vowel_swap(name: str) -> Iterator[str]:
    for i, ch in enumerate(name):
        if ch in VOWELS:
            for v in VOWELS:
                if v != ch:
                    yield name[:i] + v + name[i + 1:]


def _hyphenation(name: str) -> Iterator[str]:
    for i in range(1, len(name)):
        yield name[:i] + "-" + name[i:]


def _addition(name: str) -> Iterator[str]:
    for ch in string.ascii_lowercase + string.digits:
        yield name + ch


def _homoglyph(name: str) -> Iterator[str]:
    for i, ch in enumerate(name):
        for glyph in ASCII_LOOKALIKES.get(ch, []) + UNICODE_LOOKALIKES.get(ch, []):
            yield name[:i] + glyph + name[i + 1:]


def _combosquat(name: str) -> Iterator[str]:
    for word in COMBO_WORDS:
        yield f"{name}-{word}"
        yield f"{word}-{name}"
        yield f"{name}{word}"
        yield f"{word}{name}"


# Order matters: if two techniques produce the same domain, the first one
# listed gets the credit. The narrow, easy-to-explain ones go first, so
# "pay-pal" is labelled hyphenation rather than "inserted the - key".
NAME_TECHNIQUES: dict[str, Callable[[str], Iterable[str]]] = {
    "omission": _omission,
    "repetition": _repetition,
    "transposition": _transposition,
    "vowel-swap": _vowel_swap,
    "hyphenation": _hyphenation,
    "replacement": _replacement,
    "insertion": _insertion,
    "bitsquatting": _bitsquatting,
    "addition": _addition,
    "homoglyph": _homoglyph,
    "combosquat": _combosquat,
}

TECHNIQUES = [*NAME_TECHNIQUES, "tld-swap"]


def _ascii_suffix(suffix: str) -> str | None:
    labels = [to_ascii(part) for part in suffix.split(".")]
    if any(label is None for label in labels):
        return None
    return ".".join(labels)


def generate(domain: Domain, techniques: Iterable[str] | None = None) -> list[Candidate]:
    selected = list(techniques) if techniques is not None else TECHNIQUES
    unknown = set(selected) - set(TECHNIQUES)
    if unknown:
        raise ValueError(f"unknown technique(s): {', '.join(sorted(unknown))}")

    suffix_ascii = _ascii_suffix(domain.suffix)
    if suffix_ascii is None:
        raise ValueError(f"can't encode suffix {domain.suffix!r}")

    original = f"{to_ascii(domain.name)}.{suffix_ascii}"
    seen = {original}
    results: list[Candidate] = []

    def add(name: str, suffix: str, suffix_ascii: str, technique: str) -> None:
        ascii_name = to_ascii(name)
        if ascii_name is None:
            return
        full_ascii = f"{ascii_name}.{suffix_ascii}"
        if full_ascii in seen:
            return
        seen.add(full_ascii)
        results.append(Candidate(f"{name}.{suffix}", full_ascii, technique))

    for technique in TECHNIQUES:
        if technique not in selected:
            continue
        if technique == "tld-swap":
            for tld in SWAP_TLDS:
                if tld != domain.suffix:
                    add(domain.name, tld, tld, technique)
            continue
        for variant in NAME_TECHNIQUES[technique](domain.name):
            if variant and variant != domain.name:
                add(variant, domain.suffix, suffix_ascii, technique)

    return results
