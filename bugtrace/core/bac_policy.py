"""PURE Broken Access Control (admin path) policy.

Shell owns HTTP probes; this module owns:
  - which URLs look admin/sensitive
  - SPA catch-all shell false-positive decision
  - BAC finding dict construction
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

# Default path substrings (orig team.py / phase3_strategy).
DEFAULT_ADMIN_PATTERNS: Tuple[str, ...] = ("/admin", "/internal", "/management")

# SPA shell size tolerance (bytes) — same body length as junk path ⇒ FP.
SPA_SHELL_LEN_TOLERANCE = 64

# Minimum body size to treat 200 as contentful BAC signal.
MIN_CONTENTFUL_BODY = 50

# Cap probes in shell (policy documents the orig limit).
MAX_ADMIN_URLS_TO_PROBE = 10


def is_admin_url(url: str, patterns: Sequence[str] = DEFAULT_ADMIN_PATTERNS) -> bool:
    """True when any pattern appears as substring of the URL (case-insensitive)."""
    u = (url or "").lower()
    if not u:
        return False
    return any(pat.lower() in u for pat in patterns if pat)


def filter_admin_urls(
    urls: Iterable[str],
    patterns: Sequence[str] = DEFAULT_ADMIN_PATTERNS,
    *,
    limit: int = MAX_ADMIN_URLS_TO_PROBE,
) -> List[str]:
    """Return up to ``limit`` admin-looking URLs (order preserved, first wins)."""
    out: List[str] = []
    for u in urls or []:
        if is_admin_url(u, patterns):
            out.append(u)
            if limit and len(out) >= limit:
                break
    return out


def origin_of(url: str) -> str:
    """scheme://netloc for SPA shell control probe."""
    p = urlparse(url or "")
    if not p.scheme or not p.netloc:
        return ""
    return f"{p.scheme}://{p.netloc}"


def is_spa_shell_false_positive(
    *,
    is_json: bool,
    body_len: int,
    junk_status: Optional[int],
    junk_body_len: int,
    tolerance: int = SPA_SHELL_LEN_TOLERANCE,
) -> bool:
    """Skip HTML 200s that match the origin catch-all shell (SPA).

    JSON admin data is never treated as SPA shell.
    """
    if is_json:
        return False
    if junk_status != 200:
        return False
    if junk_body_len < 0:
        return False
    return abs(junk_body_len - body_len) <= tolerance


def is_contentful_unauth_200(status: int, body_len: int) -> bool:
    """Unauth 200 with enough body to be interesting."""
    return status == 200 and body_len > MIN_CONTENTFUL_BODY


def build_bac_finding(
    admin_url: str,
    *,
    status_code: int,
    body: str,
    content_preview_len: int = 200,
) -> Dict[str, Any]:
    """Construct pre-validated BAC finding (orig team.py shape)."""
    path = urlparse(admin_url or "").path or admin_url
    body = body or ""
    return {
        "type": "Broken Access Control",
        "parameter": path,
        "url": admin_url,
        "severity": "High",
        "confidence": 0.85,
        "validated": True,
        "status": "VALIDATED_CONFIRMED",
        "validation_method": "unauthenticated_admin_access",
        "description": (
            f"Admin endpoint {path} is accessible "
            f"without authentication. Response: {status_code} with "
            f"{len(body)} bytes of content."
        ),
        "evidence": {
            "status_code": status_code,
            "content_length": len(body),
            "content_preview": body[:content_preview_len],
        },
        "_source_file": "bac_detection",
    }


def decide_bac_from_probe(
    admin_url: str,
    *,
    status_code: int,
    body: str,
    content_type: str = "",
    junk_status: Optional[int] = None,
    junk_body_len: int = -1,
) -> Optional[Dict[str, Any]]:
    """Full pure decision: probe response → BAC finding or None (skip/FP)."""
    body = body or ""
    if not is_contentful_unauth_200(status_code, len(body)):
        return None
    is_json = "json" in (content_type or "").lower()
    if is_spa_shell_false_positive(
        is_json=is_json,
        body_len=len(body),
        junk_status=junk_status,
        junk_body_len=junk_body_len,
    ):
        return None
    return build_bac_finding(admin_url, status_code=status_code, body=body)
