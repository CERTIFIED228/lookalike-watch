# Characters that render (almost) the same as a Latin letter in most fonts.
# Not exhaustive - the full Unicode confusables list has thousands of entries -
# but these are the ones that keep turning up in real phishing domains.
UNICODE_LOOKALIKES: dict[str, list[str]] = {
    "a": ["а", "ɑ", "à", "á", "ä"],
    "b": ["Ƅ", "Ь"],
    "c": ["с", "ϲ", "ç"],
    "d": ["ԁ", "ɗ"],
    "e": ["е", "è", "é", "ė"],
    "g": ["ɡ"],
    "h": ["һ"],
    "i": ["і", "í", "ï", "ı"],
    "j": ["ј"],
    "k": ["κ"],
    "l": ["ӏ", "ł"],
    "m": ["м"],
    "n": ["ո", "ñ"],
    "o": ["о", "ο", "ö", "ó"],
    "p": ["р", "ρ"],
    "q": ["ԛ"],
    "s": ["ѕ"],
    "t": ["т"],
    "u": ["υ", "ü", "ú"],
    "v": ["ν", "ѵ"],
    "w": ["ԝ"],
    "x": ["х"],
    "y": ["у", "ý"],
    "z": ["ʐ"],
}

# Plain ASCII tricks. These are nastier in a way because they don't need an
# IDN at all, so browsers show them as-is.
ASCII_LOOKALIKES: dict[str, list[str]] = {
    "o": ["0"],
    "l": ["1", "i"],
    "i": ["1", "l"],
    "m": ["rn"],
    "w": ["vv"],
    "d": ["cl"],
}

_MULTI_CHAR = [("rn", "m"), ("vv", "w"), ("cl", "d")]
_SINGLE_CHAR = {"0": "o", "1": "l", "i": "l"}

_REVERSE: dict[str, str] = {}
for latin, glyphs in UNICODE_LOOKALIKES.items():
    for glyph in glyphs:
        _REVERSE.setdefault(glyph, latin)


def skeleton(text: str) -> str:
    """Reduce a string to a 'what it looks like' form.

    Two strings with the same skeleton look the same to a person skimming a
    URL bar. This is a simplified take on the idea behind Unicode TR39.
    """
    out = "".join(_REVERSE.get(ch, ch) for ch in text.lower())
    for multi, single in _MULTI_CHAR:
        out = out.replace(multi, single)
    return "".join(_SINGLE_CHAR.get(ch, ch) for ch in out)
