"""Pure CreateScanRequest → ScanOptions field mapping (Phase 5).

No FastAPI, DB, or ScanService. Takes plain dicts (from model_dump / kwargs).
"""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional


def scope_path_from_auth(auth: object) -> Optional[str]:
    """Extract scope_path from auth config dict when present."""
    if auth and isinstance(auth, dict):
        value = auth.get("scope_path")
        return value if value is not None else None
    return None


def sanitize_target_url(target_url: object) -> str:
    """Strip whitespace; empty after strip is invalid."""
    text = str(target_url if target_url is not None else "").strip()
    if not text:
        raise ValueError("target_url is required")
    return text


def scan_options_kwargs_from_request(fields: Mapping[str, Any]) -> Dict[str, Any]:
    """Map WEB CreateScanRequest fields to ScanOptions constructor kwargs.

    Unknown keys ignored. scope_path derived from auth when not explicit.
    """
    auth = fields.get("auth")
    scope = fields.get("scope_path")
    if scope is None:
        scope = scope_path_from_auth(auth)

    target = fields.get("target_url")
    if target is not None:
        target = sanitize_target_url(target)

    return {
        "target_url": target,
        "scan_type": fields.get("scan_type"),
        "safe_mode": fields.get("safe_mode"),
        "max_depth": fields.get("max_depth"),
        "max_urls": fields.get("max_urls"),
        "resume": fields.get("resume"),
        "use_vertical": fields.get("use_vertical"),
        "focused_agents": fields.get("focused_agents"),
        "param": fields.get("param"),
        "scan_depth": fields.get("scan_depth"),
        "auth_token": fields.get("auth_token"),
        "auth": auth,
        "url_list": fields.get("url_list"),
        "scope_path": scope,
        "custom_headers": fields.get("custom_headers"),
    }


def drop_none_kwargs(kwargs: Mapping[str, Any]) -> Dict[str, Any]:
    """Drop keys whose value is None (ScanOptions defaults apply)."""
    return {k: v for k, v in kwargs.items() if v is not None}


__all__ = [
    "scope_path_from_auth",
    "sanitize_target_url",
    "scan_options_kwargs_from_request",
    "drop_none_kwargs",
]
