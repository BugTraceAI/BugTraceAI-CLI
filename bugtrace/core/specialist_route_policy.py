"""PURE vuln-type → specialist queue routing.

Single source of truth for type→queue. Consolidation shell re-exports this map.
"""

from __future__ import annotations

from typing import Dict, Optional

# Keys lowercase. Order of iteration for substring match: longer keys first.
VULN_TYPE_TO_SPECIALIST: Dict[str, str] = {
    # XSS
    "xss": "xss",
    "cross-site scripting": "xss",
    "reflected xss": "xss",
    "stored xss": "xss",
    "dom xss": "xss",
    "dom-based xss": "xss",
    "http response splitting": "xss",
    # SQLi
    "sql injection": "sqli",
    "sqli": "sqli",
    "sql": "sqli",
    "blind sql injection": "sqli",
    "boolean-based sqli": "sqli",
    "time-based sqli": "sqli",
    "error-based sqli": "sqli",
    "input validation": "sqli",
    "type confusion": "sqli",
    # Template injection
    "ssti": "csti",
    "csti": "csti",
    "server-side template injection": "csti",
    "client-side template injection": "csti",
    "template injection": "csti",
    # LFI
    "lfi": "lfi",
    "local file inclusion": "lfi",
    "path traversal": "lfi",
    "directory traversal": "lfi",
    "file read": "lfi",
    # Access control / IDOR
    "idor": "idor",
    "insecure direct object reference": "idor",
    "broken access control": "idor",
    "broken access control (admin)": "idor",
    "authorization bypass": "idor",
    "privilege escalation": "idor",
    "bola": "idor",
    "broken object level authorization": "idor",
    "no rate limiting": "idor",
    "rate limiting": "idor",
    # RCE
    "rce": "rce",
    "remote code execution": "rce",
    "command injection": "rce",
    "os command injection": "rce",
    "code injection": "rce",
    "deserialization": "rce",
    "insecure deserialization": "rce",
    # Open redirect BEFORE ssrf (compound types)
    "open redirect": "openredirect",
    "openredirect": "openredirect",
    "url redirect": "openredirect",
    "redirect": "openredirect",
    # SSRF
    "ssrf": "ssrf",
    "server-side request forgery": "ssrf",
    "url injection": "ssrf",
    # XXE
    "xxe": "xxe",
    "xml external entity": "xxe",
    "xml injection": "xxe",
    # JWT
    "jwt": "jwt",
    "json web token": "jwt",
    "weak jwt": "jwt",
    "jwt vulnerability": "jwt",
    "jwt bypass": "jwt",
    "jwt manipulation": "jwt",
    "authentication bypass": "jwt",
    "jwt_discovered": "jwt",
    # API / GraphQL
    "api security": "api_security",
    "graphql": "api_security",
    "graphql introspection": "api_security",
    "graphql information disclosure": "api_security",
    "information exposure": "api_security",
    # Prototype pollution
    "prototype pollution": "prototype_pollution",
    "prototype_pollution": "prototype_pollution",
    "__proto__ pollution": "prototype_pollution",
    # Header injection
    "header injection": "header_injection",
    "host header injection": "header_injection",
    "crlf": "xss",
    "crlf injection": "xss",
    "http response header injection": "header_injection",
    "response splitting": "header_injection",
    "http header injection": "header_injection",
    # Mass assignment / upload
    "mass assignment": "mass_assignment",
    "overposting": "mass_assignment",
    "file upload": "file_upload",
    "unrestricted file upload": "file_upload",
}


def normalize_vuln_type(vuln_type: object) -> str:
    return str(vuln_type or "").strip().lower()


def specialist_queue_for_type(vuln_type: object) -> Optional[str]:
    """Exact map hit, else longest-substring pattern scan."""
    key = normalize_vuln_type(vuln_type)
    if not key:
        return None
    if key in VULN_TYPE_TO_SPECIALIST:
        return VULN_TYPE_TO_SPECIALIST[key]
    for pattern, queue in sorted(
        VULN_TYPE_TO_SPECIALIST.items(), key=lambda kv: len(kv[0]), reverse=True
    ):
        if pattern in key:
            return queue
    return None


def classify_vuln_type(vuln_type: object) -> Optional[str]:
    """Compatibility name for callers that classify before queue dispatch."""
    return specialist_queue_for_type(vuln_type)
