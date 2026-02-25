"""
Shared pure utility modules for BugTraceAI agents.

These modules contain pure functions with no side effects — they take inputs
and return outputs without mutating state or depending on class instances.
"""

from bugtrace.agents.shared.result_types import Ok, Err, Result, collect_results, safe_call
from bugtrace.agents.shared.http_attack import (
    build_attack_url,
    build_exploit_url,
    encode_for_url,
    fragment_build_url,
)
from bugtrace.agents.shared.payload_utils import (
    encode_for_html_attribute,
    encode_for_js_string,
    encode_for_script,
    prepare_payload,
    get_context_payload_map,
    replace_interactsh_placeholder,
)
from bugtrace.agents.shared.discovery import (
    extract_url_params,
    extract_form_params,
    extract_js_params,
    extract_anchor_params,
    extract_internal_urls,
    extract_all_param_metadata,
    merge_params,
    filter_excluded_params,
    prioritize_params,
    DEFAULT_EXCLUDED_PARAMS,
)
from bugtrace.agents.shared.deduplication import (
    generate_fingerprint,
    dedup_by_fingerprint,
    normalize_url_for_dedup,
    normalize_param_name,
    group_by_root_cause,
    get_fingerprint_fn,
    # Type-specific fingerprint generators
    xss_fingerprint,
    sqli_fingerprint,
    csti_fingerprint,
    lfi_fingerprint,
    rce_fingerprint,
    ssrf_fingerprint,
    idor_fingerprint,
    jwt_fingerprint,
    xxe_fingerprint,
    openredirect_fingerprint,
    header_injection_fingerprint,
    prototype_pollution_fingerprint,
    FINGERPRINT_REGISTRY,
)
from bugtrace.agents.shared.validation_utils import (
    has_interactsh_hit,
    has_dialog_detected,
    has_vision_proof,
    has_dom_mutation_proof,
    has_console_execution_proof,
    has_dangerous_unencoded_reflection,
    has_fragment_xss_with_screenshot,
    determine_validation_status,
    should_create_finding,
    check_reflection,
)
from bugtrace.agents.shared.confidence import (
    calculate_confidence,
    get_payload_impact_tier,
    should_stop_testing,
    HIGH_IMPACT_INDICATORS,
    MEDIUM_IMPACT_INDICATORS,
)
from bugtrace.agents.shared.context import (
    InjectionContext,
    check_contexts,
    prioritize_contexts,
    detect_injection_context,
    is_executable_in_html_context,
    is_executable_in_event_handler,
    is_executable_in_javascript_uri,
    is_executable_in_template,
    is_executable_in_js_string_breakout,
    detect_execution_context,
    requires_browser_validation,
    payload_reflects,
    detect_js_string_delimiter,
)

__all__ = [
    # Result types
    "Ok",
    "Err",
    "Result",
    "collect_results",
    "safe_call",
    # HTTP attack URL builders
    "build_attack_url",
    "build_exploit_url",
    "encode_for_url",
    "fragment_build_url",
    # Payload utilities
    "encode_for_html_attribute",
    "encode_for_js_string",
    "encode_for_script",
    "prepare_payload",
    "get_context_payload_map",
    "replace_interactsh_placeholder",
    # Parameter discovery
    "extract_url_params",
    "extract_form_params",
    "extract_js_params",
    "extract_anchor_params",
    "extract_internal_urls",
    "extract_all_param_metadata",
    "merge_params",
    "filter_excluded_params",
    "prioritize_params",
    "DEFAULT_EXCLUDED_PARAMS",
    # Deduplication
    "generate_fingerprint",
    "dedup_by_fingerprint",
    "normalize_url_for_dedup",
    "normalize_param_name",
    "group_by_root_cause",
    "get_fingerprint_fn",
    "xss_fingerprint",
    "sqli_fingerprint",
    "csti_fingerprint",
    "lfi_fingerprint",
    "rce_fingerprint",
    "ssrf_fingerprint",
    "idor_fingerprint",
    "jwt_fingerprint",
    "xxe_fingerprint",
    "openredirect_fingerprint",
    "header_injection_fingerprint",
    "prototype_pollution_fingerprint",
    "FINGERPRINT_REGISTRY",
    # Validation utilities
    "has_interactsh_hit",
    "has_dialog_detected",
    "has_vision_proof",
    "has_dom_mutation_proof",
    "has_console_execution_proof",
    "has_dangerous_unencoded_reflection",
    "has_fragment_xss_with_screenshot",
    "determine_validation_status",
    "should_create_finding",
    "check_reflection",
    # Confidence scoring
    "calculate_confidence",
    "get_payload_impact_tier",
    "should_stop_testing",
    "HIGH_IMPACT_INDICATORS",
    "MEDIUM_IMPACT_INDICATORS",
    # Context detection
    "InjectionContext",
    "check_contexts",
    "prioritize_contexts",
    "detect_injection_context",
    "is_executable_in_html_context",
    "is_executable_in_event_handler",
    "is_executable_in_javascript_uri",
    "is_executable_in_template",
    "is_executable_in_js_string_breakout",
    "detect_execution_context",
    "requires_browser_validation",
    "payload_reflects",
    "detect_js_string_delimiter",
]
