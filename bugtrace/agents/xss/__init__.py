"""
XSS Agent Module

This module provides XSS (Cross-Site Scripting) detection capabilities.

The XSSAgent class is the main entry point for XSS scanning.

Modules:
    - types: Data classes (XSSFinding, InjectionContext, etc.)
    - constants: Payloads and configuration values
    - discovery: Autonomous parameter discovery
    - bombardment: High-speed payload testing (Go fuzzer phases)
    - analysis: Reflection context detection
    - amplification: Visual payload generation and amplification
    - validation: Multi-level XSS validation pipeline
    - waf: Pure WAF detection and bypass functions
    - feedback: Pure feedback processing and variant generation
    - reporting: Phase report writing (I/O layer)
    - dom: DOM-based XSS detection, LLM analysis, and visual validation
    - stored: Stored XSS detection via form/API write-then-read
    - forms: POST parameter and HTML form XSS testing
    - fragment: Fragment-based XSS testing (hash-based DOM XSS)
    - llm_payloads: LLM-driven payload generation and analysis
    - http_sender: HTTP payload sending with WAF awareness (I/O)
    - reflection: Pure HTTP response reflection analysis
    - dedup: XSS finding deduplication (pure + I/O)
    - finding_builder: Pure finding construction and serialization
    - param_discovery: XSS-specific parameter discovery and prioritization

Usage:
    from bugtrace.agents.xss import XSSAgent, XSSFinding

    agent = XSSAgent(url="http://example.com", params=["q", "search"])
    findings = await agent.run()

For backward compatibility, XSSAgent can also be imported from:
    from bugtrace.agents.xss_agent import XSSAgent
"""

# Re-export types from the types module
from bugtrace.agents.xss.types import (
    InjectionContext,
    ValidationMethod,
    XSSFinding,
    ReflectionResult,
    PayloadTestResult,
)

# Re-export constants from the constants module
from bugtrace.agents.xss.constants import (
    PROBE_STRING,
    PROBE_STRING_SAFE,
    OMNIPROBE_PAYLOAD,
    GOLDEN_PAYLOADS,
    FRAGMENT_PAYLOADS,
    MAX_BYPASS_ATTEMPTS,
    VISUAL_MARKER,
    VISUAL_MARKER_ELEMENT_ID,
    INTERACTSH_PLACEHOLDER,
    HIGH_PRIORITY_PARAMS,
    CONTEXT_TYPES,
)

# Re-export discovery functions
from bugtrace.agents.xss.discovery import (
    discover_xss_params,
    extract_params_from_html,
)

# Re-export bombardment functions
from bugtrace.agents.xss.bombardment import (
    BombardmentConfig,
    phase1_omniprobe,
    phase2_seed_generation,
    phase3_amplification,
    phase4_mass_attack,
    run_full_bombardment,
)

# Re-export analysis functions
from bugtrace.agents.xss.analysis import (
    analyze_reflection_context,
    is_waf_blocked,
    detect_surviving_chars,
    find_reflection_context,
    filter_payloads_by_context,
    analyze_global_context,
    get_dom_snippet,
)

# Re-export amplification functions
from bugtrace.agents.xss.amplification import (
    JS_VISUAL_BACKTICK,
    JS_VISUAL_SINGLE,
    HTML_VISUAL,
    build_visual_payloads_from_breakouts,
    get_fallback_visual_payloads,
    generate_visual_payloads_llm,
    adapt_working_payloads_to_visual,
    amplify_visual_payloads,
)

# Re-export validation functions
from bugtrace.agents.xss.validation import (
    build_attack_url,
    validate_xss_multilevel,
    validate_http_reflection,
    validate_with_ai,
    validate_with_playwright,
    validate_visual_payload,
    run_vision_validation,
    process_vision_result,
    VISION_PROMPT,
)

# Re-export WAF bypass functions (pure)
from bugtrace.agents.xss.waf import (
    detect_payload_encoding,
    record_bypass_result,
    get_waf_optimized_payloads,
    bypass_try_waf_encoding,
    bypass_try_char_obfuscation,
    bypass_try_context_specific,
    bypass_try_universal_payloads,
    generate_bypass_variant,
)

# Re-export feedback/variant generation functions (pure)
from bugtrace.agents.xss.feedback import (
    extract_js_code,
    adapt_for_attribute,
    adapt_for_script,
    adapt_for_html,
    adapt_for_comment,
    adapt_for_style,
    adapt_to_context,
    encode_stripped_chars,
    generate_csp_bypass_payload,
    handle_waf_blocked,
    handle_context_mismatch,
    handle_encoding_stripped,
    handle_partial_reflection,
    handle_csp_blocked,
    handle_timing_issue,
    generate_variant_for_reason,
)

# Re-export reporting functions (I/O layer)
from bugtrace.agents.xss.reporting import (
    get_snippet,
    save_phase1_report,
    save_phase2_report,
    save_phase3_report,
    save_phase4_report,
)

# Re-export DOM XSS functions
from bugtrace.agents.xss.dom import (
    # Pure
    analyze_global_context as dom_analyze_global_context,
    build_dom_system_prompt,
    build_dom_user_prompt,
    extract_dom_around_reflection,
    parse_smart_analysis_response,
    extract_structured_payloads,
    parse_payload_block,
    replace_callback_urls,
    extract_payloads_by_patterns,
    log_generated_payloads,
    filter_dom_xss_false_positives,
    # I/O
    call_dom_llm,
    smart_dom_analysis,
    loop_test_dom_xss,
    validate_dom_xss_visually,
    try_alternative_dom_payloads,
)

# Re-export stored XSS functions
from bugtrace.agents.xss.stored import (
    extract_resource_id,
    check_stored_canary,
    build_stored_finding,
    test_stored_xss,
)

# Re-export form testing functions
from bugtrace.agents.xss.forms import (
    extract_form_data,
    build_post_finding,
    fetch_page_forms,
    send_post_request,
    test_post_params,
    discover_and_test_post_forms,
)

# Re-export fragment XSS functions
from bugtrace.agents.xss.fragment import (
    fragment_build_url,
    build_fragment_finding,
    test_fragment_xss,
)

# Re-export LLM payload generation functions
from bugtrace.agents.xss.llm_payloads import (
    build_analysis_system_prompt,
    parse_analysis_response,
    build_bypass_prompt,
    llm_analyze,
    llm_generate_bypass,
)

# Re-export HTTP sender functions (I/O + pure state)
from bugtrace.agents.xss.http_sender import (
    make_block_state,
    update_block_counter,
    should_enter_stealth_mode,
    handle_send_error,
    send_payload,
    fast_reflection_check,
    python_reflection_check,
)

# Re-export reflection analysis functions (pure)
from bugtrace.agents.xss.reflection import (
    can_confirm_from_http_response,
    is_executable_in_html_context,
    is_executable_in_event_handler,
    is_executable_in_javascript_uri,
    is_executable_in_template,
    detect_js_string_delimiter,
    is_executable_in_js_string_breakout,
    check_reflection,
    payload_reflects,
    detect_execution_context,
    requires_browser_validation,
)

# Re-export dedup functions (pure + I/O)
from bugtrace.agents.xss.dedup import (
    fallback_fingerprint_dedup,
    expand_wet_findings,
    merge_wet_metadata_into_dry,
    build_dedup_system_prompt,
    llm_analyze_and_dedup,
    load_recon_urls_with_params,
)

# Re-export finding builder functions (pure)
from bugtrace.agents.xss.finding_builder import (
    validate_before_emit,
    finding_to_dict,
    build_fragment_finding as fb_build_fragment_finding,
    update_learned_breakouts,
    add_safety_net_payloads,
)

# Re-export param discovery functions (pure + I/O)
from bugtrace.agents.xss.param_discovery import (
    HIGH_PRIORITY_PARAMS as PARAM_HIGH_PRIORITY,
    COMMON_VULN_PARAMS,
    prioritize_xss_params,
    discover_params,
    discover_xss_params_full,
)

# Import XSSAgent from the original file (will be migrated later)
# This maintains backward compatibility during the modularization process
from bugtrace.agents.xss_agent import XSSAgent

__all__ = [
    # Main class
    "XSSAgent",
    # Types
    "InjectionContext",
    "ValidationMethod",
    "XSSFinding",
    "ReflectionResult",
    "PayloadTestResult",
    # Constants
    "PROBE_STRING",
    "PROBE_STRING_SAFE",
    "OMNIPROBE_PAYLOAD",
    "GOLDEN_PAYLOADS",
    "FRAGMENT_PAYLOADS",
    "MAX_BYPASS_ATTEMPTS",
    "VISUAL_MARKER",
    "VISUAL_MARKER_ELEMENT_ID",
    "INTERACTSH_PLACEHOLDER",
    "HIGH_PRIORITY_PARAMS",
    "CONTEXT_TYPES",
    # Discovery
    "discover_xss_params",
    "extract_params_from_html",
    # Bombardment
    "BombardmentConfig",
    "phase1_omniprobe",
    "phase2_seed_generation",
    "phase3_amplification",
    "phase4_mass_attack",
    "run_full_bombardment",
    # Analysis
    "analyze_reflection_context",
    "is_waf_blocked",
    "detect_surviving_chars",
    "find_reflection_context",
    "filter_payloads_by_context",
    "analyze_global_context",
    "get_dom_snippet",
    # Amplification
    "JS_VISUAL_BACKTICK",
    "JS_VISUAL_SINGLE",
    "HTML_VISUAL",
    "build_visual_payloads_from_breakouts",
    "get_fallback_visual_payloads",
    "generate_visual_payloads_llm",
    "adapt_working_payloads_to_visual",
    "amplify_visual_payloads",
    # Validation
    "build_attack_url",
    "validate_xss_multilevel",
    "validate_http_reflection",
    "validate_with_ai",
    "validate_with_playwright",
    "validate_visual_payload",
    "run_vision_validation",
    "process_vision_result",
    "VISION_PROMPT",
    # WAF (pure)
    "detect_payload_encoding",
    "record_bypass_result",
    "get_waf_optimized_payloads",
    "bypass_try_waf_encoding",
    "bypass_try_char_obfuscation",
    "bypass_try_context_specific",
    "bypass_try_universal_payloads",
    "generate_bypass_variant",
    # Feedback (pure)
    "extract_js_code",
    "adapt_for_attribute",
    "adapt_for_script",
    "adapt_for_html",
    "adapt_for_comment",
    "adapt_for_style",
    "adapt_to_context",
    "encode_stripped_chars",
    "generate_csp_bypass_payload",
    "handle_waf_blocked",
    "handle_context_mismatch",
    "handle_encoding_stripped",
    "handle_partial_reflection",
    "handle_csp_blocked",
    "handle_timing_issue",
    "generate_variant_for_reason",
    # Reporting (I/O)
    "get_snippet",
    "save_phase1_report",
    "save_phase2_report",
    "save_phase3_report",
    "save_phase4_report",
    # DOM XSS
    "dom_analyze_global_context",
    "build_dom_system_prompt",
    "build_dom_user_prompt",
    "extract_dom_around_reflection",
    "parse_smart_analysis_response",
    "extract_structured_payloads",
    "parse_payload_block",
    "replace_callback_urls",
    "extract_payloads_by_patterns",
    "log_generated_payloads",
    "filter_dom_xss_false_positives",
    "call_dom_llm",
    "smart_dom_analysis",
    "loop_test_dom_xss",
    "validate_dom_xss_visually",
    "try_alternative_dom_payloads",
    # Stored XSS
    "extract_resource_id",
    "check_stored_canary",
    "build_stored_finding",
    "test_stored_xss",
    # Forms
    "extract_form_data",
    "build_post_finding",
    "fetch_page_forms",
    "send_post_request",
    "test_post_params",
    "discover_and_test_post_forms",
    # Fragment XSS
    "fragment_build_url",
    "build_fragment_finding",
    "test_fragment_xss",
    # LLM Payloads
    "build_analysis_system_prompt",
    "parse_analysis_response",
    "build_bypass_prompt",
    "llm_analyze",
    "llm_generate_bypass",
    # HTTP Sender (I/O + pure state)
    "make_block_state",
    "update_block_counter",
    "should_enter_stealth_mode",
    "handle_send_error",
    "send_payload",
    "fast_reflection_check",
    "python_reflection_check",
    # Reflection Analysis (pure)
    "can_confirm_from_http_response",
    "is_executable_in_html_context",
    "is_executable_in_event_handler",
    "is_executable_in_javascript_uri",
    "is_executable_in_template",
    "detect_js_string_delimiter",
    "is_executable_in_js_string_breakout",
    "check_reflection",
    "payload_reflects",
    "detect_execution_context",
    "requires_browser_validation",
    # Dedup (pure + I/O)
    "fallback_fingerprint_dedup",
    "expand_wet_findings",
    "merge_wet_metadata_into_dry",
    "build_dedup_system_prompt",
    "llm_analyze_and_dedup",
    "load_recon_urls_with_params",
    # Finding Builder (pure)
    "validate_before_emit",
    "finding_to_dict",
    "fb_build_fragment_finding",
    "update_learned_breakouts",
    "add_safety_net_payloads",
    # Param Discovery (pure + I/O)
    "PARAM_HIGH_PRIORITY",
    "COMMON_VULN_PARAMS",
    "prioritize_xss_params",
    "discover_params",
    "discover_xss_params_full",
]
