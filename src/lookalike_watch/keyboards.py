_ROWS = [
    "1234567890-",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
]


def _build_qwerty() -> dict[str, str]:
    """Keys that sit next to each other on a UK/US QWERTY layout.

    Rows are staggered, so the key below-left and below-right of a letter
    are both neighbours (e.g. 'f' has 'r' and 't' above it).
    """
    neighbours: dict[str, set[str]] = {}
    for r, row in enumerate(_ROWS):
        for c, key in enumerate(row):
            near = neighbours.setdefault(key, set())
            for dc in (-1, 1):
                if 0 <= c + dc < len(row):
                    near.add(row[c + dc])
            for dr, offsets in ((-1, (0, 1)), (1, (-1, 0))):
                rr = r + dr
                if 0 <= rr < len(_ROWS):
                    for dc in offsets:
                        cc = c + dc
                        if 0 <= cc < len(_ROWS[rr]):
                            near.add(_ROWS[rr][cc])
    return {k: "".join(sorted(v)) for k, v in neighbours.items()}


QWERTY = _build_qwerty()
