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
]
