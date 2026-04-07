"""
Validation Agent Module

AI-powered vulnerability validation using CDP events and vision analysis.

Modules:
    - core: PURE functions for validation strategy, evidence scoring, result analysis
    - browser: I/O layer for Playwright/CDP validation execution
    - agent: Thin orchestrator (AgenticValidator)

Usage:
    from bugtrace.agents.validation import AgenticValidator

For backward compatibility:
    from bugtrace.agents.agentic_validator import AgenticValidator
"""

from bugtrace.agents.validation.core import (
    ValidationCache,
    VerifierPool,
    detect_vuln_type,
    check_logs_for_execution,
    parse_vision_response,
    validate_alert_impact,
    construct_payload_url,
    generate_structural_key,
    generate_manual_review_brief,
    check_sql_errors,
    batch_filter_findings,
    XSS_PROMPT,
    SQLI_PROMPT,
    CSTI_PROMPT,
    GENERAL_PROMPT,
)

from bugtrace.agents.validation.browser import (
    execute_payload_optimized,
    generic_capture,
    validate_static_xss,
    call_vision_model,
)

from bugtrace.agents.validation.agent import AgenticValidator

__all__ = [
    # Main class
    "AgenticValidator",
    # Core types
    "ValidationCache",
    "VerifierPool",
    # Core pure functions
    "detect_vuln_type",
    "check_logs_for_execution",
    "parse_vision_response",
    "validate_alert_impact",
    "construct_payload_url",
    "generate_structural_key",
    "generate_manual_review_brief",
    "check_sql_errors",
    "batch_filter_findings",
    # Prompts
    "XSS_PROMPT",
    "SQLI_PROMPT",
    "CSTI_PROMPT",
    "GENERAL_PROMPT",
    # Browser I/O
    "execute_payload_optimized",
    "generic_capture",
    "validate_static_xss",
    "call_vision_model",
]
