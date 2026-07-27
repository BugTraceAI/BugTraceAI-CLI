"""
SQLiAgent v3 - INTELLIGENT SQL Injection Specialist

REFACTORED: This module is now a backward-compatibility shim.
All logic has been moved to the bugtrace.agents.sqli package.

Usage:
    # Both of these work:
    from bugtrace.agents.sqli_agent import SQLiAgent
    from bugtrace.agents.sqli import SQLiAgent
"""

# Re-export everything from the new package for backward compatibility
from bugtrace.agents.sqli import (  # noqa: F401
    # Main class
    SQLiAgent,
    # Types
    SQLiFinding,
    SQLiConfidenceTier,
    DB_FINGERPRINTS,
    TECHNIQUE_DESCRIPTIONS,
    HIGH_PRIORITY_SQLI_PARAMS,
    MEDIUM_PRIORITY_PARAMS,
    OOB_PAYLOADS,
    FILTER_MUTATIONS,
    # Context (PURE)
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
    # Payloads (PURE)
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
    # Validation (PURE)
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
    # Discovery (I/O)
    discover_sqli_params,
    detect_and_resolve_spa_url,
    # Exploitation (I/O)
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
    # Dedup (PURE)
    generate_sqli_fingerprint,
    fallback_fingerprint_dedup,
    # Reporting (I/O)
    generate_specialist_report,
    # Pipeline (ORCHESTRATION)
    sqli_escalation_pipeline,
    analyze_and_dedup_queue,
)

# Also re-export the infrastructure cookie helper for backward compat
_load_infrastructure_cookies = None  # Removed, use load_infrastructure_cookies from context
INFRASTRUCTURE_COOKIES_data = INFRASTRUCTURE_COOKIES
_INFRASTRUCTURE_COOKIE_PREFIXES = None  # Available as module constant in context.py
