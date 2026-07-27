"""
SQLMap Agent Module

Intelligent SQL Injection specialist using SQLMap as its primary tool,
with intelligent fallbacks and enhancement strategies.

Modules:
    - core: PURE functions for command building, result parsing, security validation,
            DB fingerprinting, WAF bypass strategy, evidence conversion, report building
    - runner: I/O layer for SQLMap Docker execution, process management, WAF detection
    - agent: Thin orchestrator (SQLMapAgent)

Usage:
    from bugtrace.agents.sqlmap import SQLMapAgent

For backward compatibility:
    from bugtrace.agents.sqlmap_agent import SQLMapAgent
"""

from bugtrace.agents.sqlmap.core import (
    # Data structures
    DBType,
    SQLMapConfig,
    SQLiEvidence,
    # Classes
    DBFingerprinter,
    WAFBypassStrategy,
    # Security validation (PURE)
    SAFE_COOKIE_VALUE_PATTERN,
    SAFE_HEADER_NAME_PATTERN,
    validate_cookie_value,
    validate_header,
    validate_post_data,
    strip_ansi_codes,
    # Command building (PURE)
    build_base_command,
    build_full_command,
    build_reproduction_command,
    build_docker_command,
    build_extraction_command,
    add_cookies_to_command,
    add_headers_to_command,
    add_tamper_scripts_to_command,
    is_likely_base64,
    # Result parsing (PURE)
    cache_key,
    parse_sqlmap_output,
    parse_extracted_data,
    process_sqlmap_output,
    check_sqlmap_error_patterns,
    check_critical_errors,
    # Evidence conversion (PURE)
    evidence_to_finding,
    build_evidence_description,
    build_evidence_details,
    # URL helpers (PURE)
    docker_url,
    extract_post_params,
    inject_probe_payload,
    # Default data (PURE)
    default_error_patterns,
    default_test_payloads,
    # Report building (PURE)
    build_report_header,
    build_report_findings,
    build_single_finding_report,
)

from bugtrace.agents.sqlmap.runner import (
    EnhancedSQLMapRunner,
    get_sqlmap_semaphore,
    detect_waf_async,
    get_smart_bypass_strategies,
)

from bugtrace.agents.sqlmap.agent import SQLMapAgent

__all__ = [
    # Main class
    "SQLMapAgent",
    # Data structures
    "DBType",
    "SQLMapConfig",
    "SQLiEvidence",
    # Core classes
    "DBFingerprinter",
    "WAFBypassStrategy",
    # Runner
    "EnhancedSQLMapRunner",
    # Security validation
    "SAFE_COOKIE_VALUE_PATTERN",
    "SAFE_HEADER_NAME_PATTERN",
    "validate_cookie_value",
    "validate_header",
    "validate_post_data",
    "strip_ansi_codes",
    # Command building
    "build_base_command",
    "build_full_command",
    "build_reproduction_command",
    "build_docker_command",
    "build_extraction_command",
    "add_cookies_to_command",
    "add_headers_to_command",
    "add_tamper_scripts_to_command",
    "is_likely_base64",
    # Result parsing
    "cache_key",
    "parse_sqlmap_output",
    "parse_extracted_data",
    "process_sqlmap_output",
    "check_sqlmap_error_patterns",
    "check_critical_errors",
    # Evidence conversion
    "evidence_to_finding",
    "build_evidence_description",
    "build_evidence_details",
    # URL helpers
    "docker_url",
    "extract_post_params",
    "inject_probe_payload",
    # Default data
    "default_error_patterns",
    "default_test_payloads",
    # Report building
    "build_report_header",
    "build_report_findings",
    "build_single_finding_report",
    # Runner I/O
    "get_sqlmap_semaphore",
    "detect_waf_async",
    "get_smart_bypass_strategies",
]
