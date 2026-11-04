import csv
import io
import json
from dataclasses import asdict
from datetime import datetime, timezone

from .scoring import Finding

_COLUMNS = ["score", "level", "domain", "ascii", "technique", "source", "a", "mx", "ns", "reasons"]


def _sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-f.score, f.ascii))


def as_table(findings: list[Finding]) -> str:
    if not findings:
        return "No lookalike domains found."

    rows = [("SCORE", "LEVEL", "DOMAIN", "TECHNIQUE", "TOP REASON")]
    for f in _sorted(findings):
        shown = f.domain if f.domain == f.ascii else f"{f.domain} ({f.ascii})"
        rows.append((str(f.score), f.level, shown, f.technique, f.reasons[0] if f.reasons else ""))

    widths = [max(len(r[i]) for r in rows) for i in range(4)]
    lines = []
    for row in rows:
        cells = [row[i].ljust(widths[i]) for i in range(4)] + [row[4]]
        lines.append("  ".join(cells).rstrip())
    return "\n".join(lines)


def as_json(findings: list[Finding], target: str) -> str:
    return json.dumps(
        {
            "target": target,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "count": len(findings),
            "findings": [asdict(f) for f in _sorted(findings)],
        },
        indent=2,
        ensure_ascii=False,
    )


def as_csv(findings: list[Finding]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_COLUMNS, lineterminator="\n")
    writer.writeheader()
    for f in _sorted(findings):
        row = asdict(f)
        for key in ("a", "mx", "ns"):
            row[key] = " ".join(row[key])
        row["reasons"] = "; ".join(row["reasons"])
        writer.writerow({k: row[k] for k in _COLUMNS})
    return buf.getvalue()
