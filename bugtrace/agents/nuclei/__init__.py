"""
Nuclei Agent Module

Technology detection and vulnerability scanning using Nuclei.
Phase 1 of the Sequential Pipeline.

Modules:
    - core: PURE functions for result parsing, framework detection from HTML,
            vulnerable JS version detection, technology categorization
    - runner: I/O functions for Nuclei execution, HTML fetching, security header checks,
              cookie checks, GraphQL introspection, rate limiting, access control
    - agent: Thin orchestrator (NucleiAgent class)

Usage:
    from bugtrace.agents.nuclei import NucleiAgent

For backward compatibility:
    from bugtrace.agents.nuclei_agent import NucleiAgent
"""

from bugtrace.agents.nuclei.core import (
    load_vulnerable_js_libs,
    KNOWN_VULNERABLE_JS,
    SECURITY_HEADERS,
    categorize_tech_finding,
    detect_frameworks_from_html,
    detect_js_versions,
    extract_html_from_nuclei_response,
    check_header_missing,
    parse_cookie_issues,
    filter_fp_waf_matchers,
)

from bugtrace.agents.nuclei.runner import (
    fetch_html,
    check_security_headers,
    check_insecure_cookies,
    check_graphql_introspection,
    test_graphql_unauth_access,
    check_rate_limiting,
    check_access_control,
    verify_waf_detections,
    detect_frameworks_from_recon_urls,
)

from bugtrace.agents.nuclei.agent import NucleiAgent

__all__ = [
    # Main class
    "NucleiAgent",
    # Core (PURE)
    "load_vulnerable_js_libs",
    "KNOWN_VULNERABLE_JS",
    "SECURITY_HEADERS",
    "categorize_tech_finding",
    "detect_frameworks_from_html",
    "detect_js_versions",
    "extract_html_from_nuclei_response",
    "check_header_missing",
    "parse_cookie_issues",
    "filter_fp_waf_matchers",
    # Runner (I/O)
    "fetch_html",
    "check_security_headers",
    "check_insecure_cookies",
    "check_graphql_introspection",
    "test_graphql_unauth_access",
    "check_rate_limiting",
    "check_access_control",
    "verify_waf_detections",
    "detect_frameworks_from_recon_urls",
]
