"""
Auth Discovery Agent Module

Discovers JWTs and session cookies from multiple sources:
- HTTP headers (Authorization, X-Auth-Token, etc.)
- Cookies (JWT cookies + session cookies)
- Web storage (localStorage, sessionStorage)
- HTML content (inline scripts, data attributes)
- JavaScript files (external .js files)

Phase: RECONNAISSANCE (Phase 1)

Modules:
    - core: PURE functions for JWT detection/validation, cookie analysis,
            auth header parsing, finding formatting, dedup, markdown report building
    - scanning: I/O functions for HTTP scanning, browser-based extraction,
                auto-registration, token extraction, artifact saving
    - agent: Thin orchestrator (AuthDiscoveryAgent class)

Usage:
    from bugtrace.agents.auth_discovery import AuthDiscoveryAgent

For backward compatibility:
    from bugtrace.agents.auth_discovery_agent import AuthDiscoveryAgent
"""

from bugtrace.agents.auth_discovery.core import (
    JWT_PATTERN,
    is_jwt,
    is_session_cookie,
    decode_jwt_parts,
    base64url_decode,
    find_jwt_context_in_html,
    is_duplicate_jwt,
    is_duplicate_cookie,
    format_jwt_finding,
    format_cookie_finding,
    build_markdown_report,
)

from bugtrace.agents.auth_discovery.scanning import (
    scan_url,
    extract_from_cookies,
    extract_from_storage,
    extract_from_html,
    extract_from_javascript,
    attempt_auto_registration,
)

from bugtrace.agents.auth_discovery.agent import AuthDiscoveryAgent

__all__ = [
    # Main class
    "AuthDiscoveryAgent",
    # Core (PURE)
    "JWT_PATTERN",
    "is_jwt",
    "is_session_cookie",
    "decode_jwt_parts",
    "base64url_decode",
    "find_jwt_context_in_html",
    "is_duplicate_jwt",
    "is_duplicate_cookie",
    "format_jwt_finding",
    "format_cookie_finding",
    "build_markdown_report",
    # Scanning (I/O)
    "scan_url",
    "extract_from_cookies",
    "extract_from_storage",
    "extract_from_html",
    "extract_from_javascript",
    "attempt_auto_registration",
]
