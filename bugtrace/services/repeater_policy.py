"""Pure Repeater exchange validation (Phase 5).

No FS, DB, or network. Ensures target, finding URL, and raw request describe
one HTTP exchange (origin + path/query parity).
"""

from __future__ import annotations

from typing import Tuple
from urllib.parse import parse_qsl, urlsplit


def normalized_origin(url: str) -> Tuple[str, str, int]:
    """Return (scheme, hostname, effective-port) for absolute HTTP(S) URLs."""
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("URL must be absolute HTTP(S)")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid URL origin: {url}") from exc
    return parsed.scheme.lower(), parsed.hostname.lower(), port


def validate_repeater_exchange(
    target_url: str, finding_url: str, raw_request: str
) -> None:
    """Raise ValueError when target / finding / raw request disagree."""
    if normalized_origin(target_url) != normalized_origin(finding_url):
        raise ValueError("Finding URL origin does not match scan target origin")

    lines = raw_request.replace("\r\n", "\n").split("\n")
    request_line = lines[0].strip().split()
    if len(request_line) < 2:
        raise ValueError("Raw request has an invalid request line")
    request_target = request_line[1]
    declared = urlsplit(finding_url)
    hosts = []
    for line in lines[1:]:
        if line.lower().startswith("host:"):
            hosts.append(line.split(":", 1)[1].strip())
    if len(hosts) != 1 or not hosts[0]:
        raise ValueError("Raw request must contain exactly one Host header")
    host = hosts[0]
    if normalized_origin(f"{declared.scheme}://{host}") != normalized_origin(
        finding_url
    ):
        raise ValueError("Raw request Host does not match finding URL")
    if request_target.startswith(("http://", "https://")):
        raw_url = request_target
    else:
        path = (
            request_target
            if request_target.startswith("/")
            else f"/{request_target}"
        )
        raw_url = f"{declared.scheme}://{host}{path}"

    raw = urlsplit(raw_url)
    if normalized_origin(raw_url) != normalized_origin(finding_url):
        raise ValueError("Raw request origin does not match finding URL")
    if raw.path != declared.path or sorted(
        parse_qsl(raw.query, keep_blank_values=True)
    ) != sorted(parse_qsl(declared.query, keep_blank_values=True)):
        raise ValueError("Raw request path/query does not match finding URL")


__all__ = ["normalized_origin", "validate_repeater_exchange"]
