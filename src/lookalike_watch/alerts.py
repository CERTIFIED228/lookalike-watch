from urllib.parse import urlsplit

import requests

from .scoring import Finding

MAX_LENGTH = 1900  # Discord rejects messages over 2000 characters


class AlertError(Exception):
    pass


def mask_url(url: str) -> str:
    """Webhook URLs are secrets - the token is in the path. Only show the host."""
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}/***" if parts.netloc else "***"


def build_message(target: str, findings: list[Finding]) -> str:
    ranked = sorted(findings, key=lambda f: (-f.score, f.ascii))
    header = f"lookalike-watch: {len(ranked)} new lookalike domain(s) for {target}"
    lines = [header]
    for i, f in enumerate(ranked):
        reason = f.reasons[0] if f.reasons else ""
        line = f"- [{f.level.upper()} {f.score}] {f.domain} ({f.technique}) - {reason}"
        remaining = len(ranked) - i
        footer = f"...and {remaining} more"
        if len("\n".join(lines + [line, footer])) > MAX_LENGTH:
            lines.append(footer)
            break
        lines.append(line)
    return "\n".join(lines)


def send_webhook(url: str, target: str, findings: list[Finding], session=None,
                 timeout: float = 10) -> None:
    message = build_message(target, findings)
    # Slack reads "text", Discord reads "content". Both ignore the other key.
    payload = {"text": message, "content": message}
    session = session or requests.Session()
    try:
        resp = session.post(url, json=payload, timeout=timeout)
    except requests.RequestException as exc:
        # The exception text can contain the full URL, so don't pass it on.
        raise AlertError(
            f"could not reach webhook {mask_url(url)} ({type(exc).__name__})"
        ) from None
    if resp.status_code >= 300:
        raise AlertError(f"webhook {mask_url(url)} returned HTTP {resp.status_code}")
