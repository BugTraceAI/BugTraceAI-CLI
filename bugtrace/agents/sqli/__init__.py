"""
SQLi Agent Module

This module provides SQL Injection detection capabilities.

The SQLiAgent class is the main entry point for SQLi scanning.

Modules:
    - types: Data classes (SQLiFinding, SQLiConfidenceTier), constants
    - context: PURE confidence, prioritization, technique mapping
    - payloads: PURE payload generation, URL building, filter mutations
    - validation: PURE response analysis, SQLi confirmation, error extraction
    - discovery: I/O parameter discovery, SPA detection
    - exploitation: I/O payload sending, technique testing
    - dedup: PURE SQLi fingerprint deduplication
    - reporting: I/O save SQLi reports to filesystem
    - pipeline: ORCHESTRATION escalation levels, main exploit flow
    - agent: SQLiAgent thin orchestration class

Usage:
    from bugtrace.agents.sqli import SQLiAgent, SQLiFinding

    agent = SQLiAgent(url="http://example.com?id=1", param="id")
    result = await agent.run_loop()

For backward compatibility, SQLiAgent can also be imported from:
    from bugtrace.agents.sqli_agent import SQLiAgent
"""

# Re-export the main agent class
from bugtrace.agents.sqli.agent import SQLiAgent

# Re-export types
from bugtrace.agents.sqli.types import (
    SQLiFinding,
    SQLiConfidenceTier,
    DB_FINGERPRINTS,
    TECHNIQUE_DESCRIPTIONS,
    HIGH_PRIORITY_SQLI_PARAMS,
    MEDIUM_PRIORITY_PARAMS,
    OOB_PAYLOADS,
    FILTER_MUTATIONS,
)

# Re-export context functions (PURE)
from bugtrace.agents.sqli.context import (
    INFRASTRUCTURE_COOKIES,
    get_confidence_tier,
    determine_validation_status,
    should_stop_testing,
    prioritize_params,
    sqlmap_type_to_technique,
    get_sqlmap_technique_hint,
    get_technique_name,
    should_test_cookie,
    validate_sqli_finding,
    detect_dbms_from_output,
)

# Re-export payload functions (PURE)
from bugtrace.agents.sqli.payloads import (
    get_base_url,
    build_url_with_param,
    build_exploit_url,
    mutate_payload_for_filters,
    create_sleep_payload,
    verify_time_correlation,
    build_full_sqlmap_command,
    build_progressive_sqlmap_commands,
    generate_repro_steps,
    flatten_json,
    set_nested_value,
    extract_post_params,
    has_block_indicators,
)

# Re-export validation functions (PURE)
from bugtrace.agents.sqli.validation import (
    detect_database_type,
    extract_info_from_error,
    extract_tables_from_error,
    extract_columns_from_error,
    extract_paths_from_error,
    extract_db_version,
    is_boolean_vulnerable,
    parse_sqlmap_output,
    finding_to_dict,
    extract_finding_data,
    build_llm_prompt,
)

# Re-export discovery functions (I/O)
from bugtrace.agents.sqli.discovery import (
    discover_sqli_params,
    detect_and_resolve_spa_url,
)

# Re-export exploitation functions (I/O)
from bugtrace.agents.sqli.exploitation import (
    detect_filtered_chars,
    test_error_based,
    test_boolean_based,
    test_union_based,
    test_time_based,
    verify_time_based_triple,
    test_oob_sqli,
    test_json_body_injection,
    test_second_order_sqli,
    detect_prepared_statements,
    test_cookie_sqli,
    test_header_sqli,
    run_sqlmap_on_param,
    generate_llm_exploitation_explanation,
    escalation_l4_llm_bombing,
    escalation_l5_http_manipulator,
)

# Re-export dedup functions (PURE)
from bugtrace.agents.sqli.dedup import (
    generate_sqli_fingerprint,
    fallback_fingerprint_dedup,
)

# Re-export reporting functions (I/O)
from bugtrace.agents.sqli.reporting import (
    generate_specialist_report,
)

# Re-export pipeline functions (ORCHESTRATION)
from bugtrace.agents.sqli.pipeline import (
    sqli_escalation_pipeline,
    analyze_and_dedup_queue,
)

__all__ = [
    # Main class
    "SQLiAgent",
    # Types
    "SQLiFinding",
    "SQLiConfidenceTier",
    "DB_FINGERPRINTS",
    "TECHNIQUE_DESCRIPTIONS",
    "HIGH_PRIORITY_SQLI_PARAMS",
    "MEDIUM_PRIORITY_PARAMS",
    "OOB_PAYLOADS",
    "FILTER_MUTATIONS",
    # Context (PURE)
    "INFRASTRUCTURE_COOKIES",
    "get_confidence_tier",
    "determine_validation_status",
    "should_stop_testing",
    "prioritize_params",
    "sqlmap_type_to_technique",
    "get_sqlmap_technique_hint",
    "get_technique_name",
    "should_test_cookie",
    "validate_sqli_finding",
    "detect_dbms_from_output",
    # Payloads (PURE)
    "get_base_url",
    "build_url_with_param",
    "build_exploit_url",
    "mutate_payload_for_filters",
    "create_sleep_payload",
    "verify_time_correlation",
    "build_full_sqlmap_command",
    "build_progressive_sqlmap_commands",
    "generate_repro_steps",
    "flatten_json",
    "set_nested_value",
    "extract_post_params",
    "has_block_indicators",
    # Validation (PURE)
    "detect_database_type",
    "extract_info_from_error",
    "extract_tables_from_error",
    "extract_columns_from_error",
    "extract_paths_from_error",
    "extract_db_version",
    "is_boolean_vulnerable",
    "parse_sqlmap_output",
    "finding_to_dict",
    "extract_finding_data",
    "build_llm_prompt",
    # Discovery (I/O)
    "discover_sqli_params",
    "detect_and_resolve_spa_url",
    # Exploitation (I/O)
    "detect_filtered_chars",
    "test_error_based",
    "test_boolean_based",
    "test_union_based",
    "test_time_based",
    "verify_time_based_triple",
    "test_oob_sqli",
    "test_json_body_injection",
    "test_second_order_sqli",
    "detect_prepared_statements",
    "test_cookie_sqli",
    "test_header_sqli",
    "run_sqlmap_on_param",
    "generate_llm_exploitation_explanation",
    "escalation_l4_llm_bombing",
    "escalation_l5_http_manipulator",
    # Dedup (PURE)
    "generate_sqli_fingerprint",
    "fallback_fingerprint_dedup",
    # Reporting (I/O)
    "generate_specialist_report",
    # Pipeline (ORCHESTRATION)
    "sqli_escalation_pipeline",
    "analyze_and_dedup_queue",
]
