"""PURE finding type canonicalization, inference, and presentation noise gates.

Addresses A/B gaps vs stable:
  - dry/analysis candidates with missing ``type`` → ``Unknown`` spam
  - verbose aliases (GraphQL / CSTI / IDOR / DOM XSS) not collapsing
  - RCE candidates (e.g. param ``cmd``) losing specialist route when type empty

No I/O. Shells call these before enqueue, report load, and API presentation.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional
from urllib.parse import parse_qs, urlparse

# Canonical display / routing labels (stable-friendly strings).
CANONICAL_TYPE_ALIASES: Dict[str, str] = {
    # Injection
    "sqli": "SQLi",
    "sql injection": "SQLi",
    "sql": "SQLi",
    "information disclosure (sql error exposure)": "SQLi",
    "xss": "XSS",
    "cross-site scripting": "XSS",
    "reflected xss": "XSS",
    "stored xss": "XSS",
    "dom xss": "XSS",
    "dom-based xss": "XSS",
    "dom xss via hash fragment": "XSS",
    "dom-based xss via hash fragment": "XSS",
    "rce": "RCE",
    "remote code execution": "RCE",
    "command injection": "RCE",
    "os command injection": "RCE",
    "code injection": "RCE",
    "lfi": "LFI",
    "local file inclusion": "LFI",
    "path traversal": "LFI",
    "ssrf": "SSRF",
    "server-side request forgery": "SSRF",
    "xxe": "XXE",
    "csti": "CSTI",
    "ssti": "CSTI",
    "client-side template injection": "CSTI",
    "server-side template injection": "CSTI",
    "server-side template injection (ssti)": "CSTI",
    "client-side template injection (angularjs)": "CSTI",
    "client-side template injection / angularjs vulnerability": "CSTI",
    "angularjs 1.7.7 template injection": "CSTI",
    "template injection": "CSTI",
    # Access control
    "idor": "IDOR",
    "insecure direct object reference": "IDOR",
    "insecure direct object reference (idor)": "IDOR",
    "broken object level authorization (bola)": "IDOR",
    "bola": "IDOR",
    "broken access control": "Broken Access Control",
    "authentication bypass / weak access control": "Broken Access Control",
    "authentication bypass / unauthenticated admin access": "Broken Access Control",
    "authorization bypass": "Broken Access Control",
    # Auth / JWT
    "jwt": "JWT",
    "jwt_discovered": "JWT",
    "weak jwt secret": "Weak JWT Secret",
    "weak jwt": "Weak JWT Secret",
    # GraphQL / API
    "graphql": "GraphQL Introspection",
    "graphql introspection": "GraphQL Introspection",
    "graphql introspection enabled": "GraphQL Introspection",
    "graphql introspection exposure": "GraphQL Introspection",
    "no authentication on graphql endpoint": "GraphQL Introspection",
    "missing authentication on graphql endpoint": "GraphQL Introspection",
    "potential graphql query complexity/dos": "GraphQL Introspection",
    "graphql batch query attack (dos)": "GraphQL Introspection",
    "api documentation exposure": "API Documentation Exposure",
    # Misconfig families
    "cors misconfiguration": "CORS Misconfiguration",
    "insecure cookie configuration": "Insecure Cookie Configuration",
    "missing rate limiting": "Missing Rate Limiting",
    "missing_security_header": "MISSING_SECURITY_HEADER",
    "missing security header": "MISSING_SECURITY_HEADER",
    "vulnerable and outdated components": "Vulnerable and Outdated Components",
    "open_redirect": "OPEN_REDIRECT",
    "open redirect": "OPEN_REDIRECT",
    "mass assignment": "Mass Assignment",
    "prototype pollution": "Prototype Pollution",
    "insecure deserialization": "RCE",
    "deserialization": "RCE",
}

# Parameter name → likely vuln family (only when type missing/unknown).
PARAM_TYPE_HINTS: Dict[str, str] = {
    "cmd": "RCE",
    "command": "RCE",
    "exec": "RCE",
    "execute": "RCE",
    "shell": "RCE",
    "ping": "RCE",
    "query": "SQLi",
    "sql": "SQLi",
    "search": "XSS",
    "q": "XSS",
    "keyword": "XSS",
    "redirect": "OPEN_REDIRECT",
    "returnurl": "OPEN_REDIRECT",
    "return_url": "OPEN_REDIRECT",
    "next": "OPEN_REDIRECT",
    "continue": "OPEN_REDIRECT",
    "file": "LFI",
    "path": "LFI",
    "template": "CSTI",
    "body": "CSTI",
    "url": "OPEN_REDIRECT",  # often open redirect; overridden if path has /redirect
}

# Substrings in free text (reasoning/description) → type.
TEXT_TYPE_HINTS: tuple[tuple[str, str], ...] = (
    ("command injection", "RCE"),
    ("remote code", "RCE"),
    ("os command", "RCE"),
    ("sleep ", "RCE"),  # time-based RCE proof language
    ("sql injection", "SQLi"),
    ("sqli", "SQLi"),
    ("cross-site scripting", "XSS"),
    ("dom-based xss", "XSS"),
    ("dom xss", "XSS"),
    ("path traversal", "LFI"),
    ("local file", "LFI"),
    ("template injection", "CSTI"),
    ("ssti", "CSTI"),
    ("csti", "CSTI"),
    ("open redirect", "OPEN_REDIRECT"),
    ("server-side request", "SSRF"),
    ("ssrf", "SSRF"),
    ("graphql", "GraphQL Introspection"),
    ("mass assignment", "Mass Assignment"),
    ("prototype pollution", "Prototype Pollution"),
    ("jwt", "JWT"),
    ("broken access", "Broken Access Control"),
    ("idor", "IDOR"),
    ("bola", "IDOR"),
)

_UNKNOWN_LABELS = frozenset({"", "unknown", "none", "n/a", "null", "undefined", "?"})


def is_unknown_type(type_str: object) -> bool:
    return str(type_str or "").strip().lower() in _UNKNOWN_LABELS


def canonical_finding_type(type_str: object) -> str:
    """Map verbose/alias type strings to a stable display label (PURE)."""
    raw = str(type_str or "").strip()
    if is_unknown_type(raw):
        return "Unknown"
    key = raw.lower()
    if key in CANONICAL_TYPE_ALIASES:
        return CANONICAL_TYPE_ALIASES[key]
    # NUCLEI:Name → keep family-ish or strip prefix for known fragments
    if key.startswith("nuclei:"):
        inner = raw[7:].strip()
        mapped = canonical_finding_type(inner)
        if mapped != "Unknown" and mapped != inner:
            return mapped
        # cookies / headers common nuclei names
        il = inner.lower()
        if "cookie" in il:
            return "Insecure Cookie Configuration"
        if "security header" in il or "missing subresource" in il:
            return "MISSING_SECURITY_HEADER"
        if "cors" in il:
            return "CORS Misconfiguration"
        if "graphql" in il or "graphiql" in il:
            return "GraphQL Introspection"
        if "openapi" in il or "swagger" in il or "redoc" in il:
            return "API Documentation Exposure"
        return f"NUCLEI:{inner}"
    # Substring alias scan (longest key first)
    for alias, canon in sorted(CANONICAL_TYPE_ALIASES.items(), key=lambda kv: len(kv[0]), reverse=True):
        if len(alias) >= 4 and alias in key:
            return canon
    return raw


def _param_name(parameter: object, url: object) -> str:
    p = str(parameter or "").strip().lower()
    if p and p not in _UNKNOWN_LABELS:
        # Cookie: name / Header: name
        if ":" in p:
            p = p.split(":", 1)[-1].strip()
        return p.split()[0] if p else ""
    # fall back to first query key
    try:
        qs = parse_qs(urlparse(str(url or "")).query)
        if qs:
            return next(iter(qs.keys())).lower()
    except Exception:
        pass
    return ""


def infer_finding_type(
    type_str: object = None,
    *,
    parameter: object = None,
    url: object = None,
    reasoning: object = None,
    description: object = None,
    payload: object = None,
    evidence: object = None,
) -> str:
    """Resolve a display/routing type; infer only when current type is unknown."""
    if not is_unknown_type(type_str):
        return canonical_finding_type(type_str)

    text_bits = [
        str(reasoning or ""),
        str(description or ""),
        str(payload or ""),
        str(evidence or "") if not isinstance(evidence, dict) else str(evidence),
        str(url or ""),
        str(parameter or ""),
    ]
    blob = " ".join(text_bits).lower()
    for needle, canon in TEXT_TYPE_HINTS:
        if needle in blob:
            return canon

    param = _param_name(parameter, url)
    if param in PARAM_TYPE_HINTS:
        return PARAM_TYPE_HINTS[param]

    # URL path hints
    path = (urlparse(str(url or "")).path or "").lower()
    if "redirect" in path or "logout" in path:
        return "OPEN_REDIRECT"
    if "graphql" in path:
        return "GraphQL Introspection"
    if "admin" in path:
        return "Broken Access Control"

    return "Unknown"


def has_substantive_evidence(finding: Mapping[str, Any]) -> bool:
    """True when finding carries more than a dry empty stub."""
    payload = str(finding.get("payload") or finding.get("exploitation_strategy") or "").strip()
    if payload and payload.lower() not in _UNKNOWN_LABELS:
        return True
    evidence = finding.get("evidence")
    if isinstance(evidence, dict) and any(evidence.values()):
        return True
    if isinstance(evidence, str) and evidence.strip():
        return True
    details = finding.get("details")
    if isinstance(details, str) and len(details.strip()) > 20:
        return True
    if isinstance(details, dict) and any(details.values()):
        return True
    reasoning = str(finding.get("reasoning") or finding.get("description") or "").strip()
    if len(reasoning) > 20:
        return True
    # Validated statuses always keep (specialist already accepted)
    status = str(finding.get("status") or "").upper()
    if status in {"VALIDATED_CONFIRMED", "MANUAL_REVIEW_RECOMMENDED"}:
        return True
    # nuclei template id is substantive signal
    if finding.get("nuclei_template") or (
        isinstance(evidence, dict) and evidence.get("nuclei_template")
    ):
        return True
    return False


def is_presentation_noise(finding: Mapping[str, Any]) -> bool:
    """Drop dry Unknown stubs with no proof from API/report presentation."""
    t = infer_finding_type(
        finding.get("type"),
        parameter=finding.get("parameter"),
        url=finding.get("url"),
        reasoning=finding.get("reasoning"),
        description=finding.get("description"),
        payload=finding.get("payload") or finding.get("exploitation_strategy"),
        evidence=finding.get("evidence") or finding.get("details"),
    )
    if t != "Unknown" and not is_unknown_type(finding.get("type")):
        # Known typed findings always present (dedup handles volume)
        return False
    if t != "Unknown" and is_unknown_type(finding.get("type")):
        # Will be retyped — keep if any signal, else drop empty
        return not has_substantive_evidence(finding) and str(
            finding.get("status") or ""
        ).upper() in {"", "PENDING_VALIDATION", "PENDING"}
    # Still Unknown after inference
    if not has_substantive_evidence(finding):
        return True
    # Unknown + weak pending dry source
    source = str(
        finding.get("_source") or finding.get("_source_dir") or finding.get("_source_file") or ""
    ).lower()
    if source in {"dry", "wet", "analysis"} and str(finding.get("status") or "").upper() in {
        "PENDING_VALIDATION",
        "PENDING",
        "",
    }:
        return True
    return False


def apply_type_policy(finding: Mapping[str, Any]) -> Dict[str, Any]:
    """Return shallow copy with canonical/inferred type (PURE)."""
    out = dict(finding)
    resolved = infer_finding_type(
        out.get("type"),
        parameter=out.get("parameter"),
        url=out.get("url"),
        reasoning=out.get("reasoning"),
        description=out.get("description"),
        payload=out.get("payload") or out.get("exploitation_strategy"),
        evidence=out.get("evidence") or out.get("details"),
    )
    out["type"] = resolved
    return out


def prepare_findings_for_presentation(findings: list) -> list:
    """Apply type policy + drop presentation noise (PURE, non-mutating)."""
    if not findings:
        return []
    out = []
    for f in findings:
        if not isinstance(f, Mapping):
            continue
        if is_presentation_noise(f):
            continue
        out.append(apply_type_policy(f))
    return out
