import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .scoring import Finding


class StateError(Exception):
    pass


class SeenStore:
    """Remembers which lookalikes we've already alerted on.

    Without this, `watch` would re-send the same 40 domains every hour and
    people would mute the channel within a day.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._seen: dict[str, dict] = {}
        if self.path.exists():
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
                self._seen = dict(data["domains"])
            except (ValueError, KeyError, TypeError) as exc:
                raise StateError(
                    f"state file {self.path} is unreadable ({exc}); "
                    "fix or delete it to start fresh"
                ) from exc

    @property
    def is_empty(self) -> bool:
        return not self._seen

    def new(self, findings: list[Finding]) -> list[Finding]:
        return [f for f in findings if f.ascii not in self._seen]

    def first_seen(self, ascii_domain: str) -> str | None:
        entry = self._seen.get(ascii_domain)
        return entry["first_seen"] if entry else None

    def remember(self, findings: list[Finding], when: str | None = None) -> None:
        when = when or datetime.now(timezone.utc).isoformat(timespec="seconds")
        for f in findings:
            entry = self._seen.setdefault(f.ascii, {"first_seen": when})
            entry["last_seen"] = when
            entry["score"] = f.score

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps({"domains": self._seen}, indent=2, sort_keys=True)
        # Write to a temp file then swap it in, so a crash mid-write can't
        # leave a half-written state file behind.
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".seen-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
            os.replace(tmp, self.path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
