"""Pure policy helpers for the BugTraceAI API → CLI handoff.

The handoff is deliberately data-only.  These helpers never invent a host or
an endpoint; they only preserve the inventory supplied by the API engine.
"""
from __future__ import annotations

from collections.abc import Iterable
from typing import Any
from urllib.parse import urlparse


def validate_handoff(handoff: Any) -> dict[str, Any] | None:
    if handoff is None:
        return None
    if not isinstance(handoff, dict):
        raise ValueError("handoff must be a JSON object")
    version = handoff.get("handoff_version")
    if version != 1:
        raise ValueError(f"Unsupported handoff_version {version!r}; expected major version 1")
    target = str(handoff.get("target") or "").strip()
    if target and urlparse(target).scheme not in {"http", "https"}:
        raise ValueError("handoff.target must be an absolute http(s) URL")
    return handoff


def _unique(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if text and text not in seen:
            seen.add(text)
            result.append(text)
    return result


def operations_from_handoff(handoff: dict[str, Any]) -> list[dict[str, Any]]:
    operations = handoff.get("operations")
    if not isinstance(operations, list):
        return []
    return [item for item in operations if isinstance(item, dict) and item.get("method") and item.get("url")]


def inventory_from_handoff(handoff: dict[str, Any]) -> list[dict[str, Any]]:
    """Return method-aware operations, falling back to kept live endpoints."""
    operations = operations_from_handoff(handoff)
    if operations:
        return operations
    endpoints = handoff.get("endpoints")
    return [item for item in endpoints or [] if isinstance(item, dict) and item.get("method") and item.get("url")]


def urls_from_handoff(handoff: dict[str, Any]) -> list[str]:
    """Build deterministic URL fallback without inventing a target host."""
    operations = operations_from_handoff(handoff)
    if operations:
        return _unique(item["url"] for item in operations)
    endpoints = handoff.get("endpoints")
    if isinstance(endpoints, list):
        openapi = [item.get("url") for item in endpoints if isinstance(item, dict) and item.get("source") == "openapi"]
        chosen = openapi or [item.get("url") for item in endpoints if isinstance(item, dict)]
        urls = _unique(chosen)
        if urls:
            return urls
    spec = (handoff.get("schema") or {}).get("spec")
    target = str(handoff.get("target") or "").strip()
    if isinstance(spec, dict) and target:
        try:
            from bugtrace.agents.gospider.core import extract_openapi_urls
            return _unique(extract_openapi_urls(spec, target, urlparse(target).netloc))
        except Exception:
            return []
    return []


def prioritized_findings(handoff: dict[str, Any]) -> list[dict[str, Any]]:
    """Return confirmed findings first, then suspicious hints only."""
    findings = [item for item in handoff.get("findings", []) if isinstance(item, dict)]
    allowed = {"confirmed", "suspicious", "needs_validation"}
    findings = [item for item in findings if str(item.get("classification") or "").lower() in allowed]
    rank = {"confirmed": 0, "suspicious": 1, "needs_validation": 1}
    return sorted(findings, key=lambda item: rank.get(str(item.get("classification") or "").lower(), 9))


def route_hint(finding: dict[str, Any]) -> str | None:
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    source_tools = finding.get("source_tools") if isinstance(finding.get("source_tools"), list) else []
    haystack = " ".join(str(value) for value in [
        finding.get("title"), finding.get("category"), evidence.get("kind"), *source_tools,
    ]).lower()
    if any(token in haystack for token in ("bola", "bfla", "idor", "broken object", "access control")):
        return "idor"
    if "sql" in haystack or "sqli" in haystack:
        return "sqli"
    if "jwt" in haystack or "json web token" in haystack:
        return "jwt"
    if "graphql" in haystack:
        return "graphql"
    if "mass assignment" in haystack:
        return "mass_assignment"
    return None


__all__ = [
    "inventory_from_handoff", "operations_from_handoff", "prioritized_findings",
    "route_hint", "urls_from_handoff", "validate_handoff",
]
