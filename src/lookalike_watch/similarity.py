def edit_distance(a: str, b: str) -> int:
    """Damerau-Levenshtein distance (optimal string alignment variant).

    Same as Levenshtein, but swapping two neighbouring characters costs 1
    instead of 2. Typos like "papyal" are one keystroke away from "paypal",
    so the score should say so.
    """
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            cur[j] = min(
                prev[j] + 1,
                cur[j - 1] + 1,
                prev[j - 1] + cost,
            )
            if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        prev2, prev = prev, cur
    return prev[-1]


def similarity(a: str, b: str) -> float:
    longest = max(len(a), len(b))
    if longest == 0:
        return 1.0
    return 1 - edit_distance(a, b) / longest
