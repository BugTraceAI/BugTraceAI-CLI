"""
IDOR Agent Module

This module provides IDOR (Insecure Direct Object Reference) vulnerability
detection and exploitation capabilities.

The IDORAgent class is the main entry point for IDOR scanning.

Modules:
    - types: IDORFinding dataclass, vulnerability constants
    - patterns: PURE: ID format detection, context inference, test ID generation
    - payloads: PURE: URL injection, path ID extraction
    - validation: PURE: differential analysis, finding validation, impact analysis
    - discovery: I/O: parameter discovery from URLs, paths, HTML forms
    - exploitation: I/O: access control testing, escalation, auth token handling
    - dedup: PURE: IDOR fingerprint dedup
    - agent: Thin orchestrator class

Usage:
    from bugtrace.agents.idor import IDORAgent

    agent = IDORAgent()
    result = await agent.check_url("http://example.com")

For backward compatibility, IDORAgent can also be imported from:
    from bugtrace.agents.idor_agent import IDORAgent
"""

# Re-export agent class
from bugtrace.agents.idor.agent import IDORAgent

# Re-export types
from bugtrace.agents.idor.types import (
    IDORFinding,
    SENSITIVE_MARKERS,
    USER_PATTERNS,
    PRIVILEGE_KEYWORDS_MAP,
    SPECIAL_MARKERS,
    PATH_INDICATORS,
)

# Re-export pure pattern functions
from bugtrace.agents.idor.patterns import (
    detect_id_format,
    infer_app_context,
    generate_horizontal_test_ids,
    is_special_account,
    detect_privilege_indicators,
    is_id_param,
    is_id_value,
)

# Re-export pure payload functions
from bugtrace.agents.idor.payloads import (
    inject_id,
    extract_path_id,
)

# Re-export pure validation functions
from bugtrace.agents.idor.validation import (
    validate_idor_finding,
    determine_validation_status,
    analyze_differential,
    analyze_response_diff,
    phase3_impact_analysis,
)

# Re-export pure dedup functions
from bugtrace.agents.idor.dedup import (
    generate_idor_fingerprint,
    fallback_fingerprint_dedup,
)

# Re-export I/O discovery functions
from bugtrace.agents.idor.discovery import (
    discover_idor_params,
)

# Re-export I/O exploitation functions
from bugtrace.agents.idor.exploitation import (
    test_custom_ids_python,
    phase1_retest,
    phase2_http_methods,
    phase4_horizontal_escalation,
    phase5_vertical_escalation,
    wait_for_auth_token,
    fetch_auth_headers,
)

__all__ = [
    # Main class
    "IDORAgent",
    # Types
    "IDORFinding",
    "SENSITIVE_MARKERS",
    "USER_PATTERNS",
    "PRIVILEGE_KEYWORDS_MAP",
    "SPECIAL_MARKERS",
    "PATH_INDICATORS",
    # Patterns (PURE)
    "detect_id_format",
    "infer_app_context",
    "generate_horizontal_test_ids",
    "is_special_account",
    "detect_privilege_indicators",
    "is_id_param",
    "is_id_value",
    # Payloads (PURE)
    "inject_id",
    "extract_path_id",
    # Validation (PURE)
    "validate_idor_finding",
    "determine_validation_status",
    "analyze_differential",
    "analyze_response_diff",
    "phase3_impact_analysis",
    # Dedup (PURE)
    "generate_idor_fingerprint",
    "fallback_fingerprint_dedup",
    # Discovery (I/O)
    "discover_idor_params",
    # Exploitation (I/O)
    "test_custom_ids_python",
    "phase1_retest",
    "phase2_http_methods",
    "phase4_horizontal_escalation",
    "phase5_vertical_escalation",
    "wait_for_auth_token",
    "fetch_auth_headers",
]
