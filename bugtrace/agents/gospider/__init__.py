"""
GoSpider Agent Module

Specialized URL discovery using GoSpider with intelligent
fallback discovery, extension filtering, and scope enforcement.

Modules:
    - core: PURE functions for URL filtering, scope checking, prioritization,
            extension filtering, JS URL extraction, OpenAPI path resolution,
            form parameter extraction helpers
    - agent: Thin orchestrator (GoSpiderAgent)

Usage:
    from bugtrace.agents.gospider import GoSpiderAgent

For backward compatibility:
    from bugtrace.agents.gospider_agent import GoSpiderAgent
"""

from bugtrace.agents.gospider.core import (
    # URL filtering
    should_analyze_url,
    is_in_scope,
    filter_and_prioritize_urls,
    # JavaScript extraction
    JS_URL_PATTERN,
    extract_js_urls,
    # Form parameter helpers
    SKIP_INPUT_TYPES,
    SKIP_INPUT_NAMES,
    SKIP_INPUT_TYPES_PW,
    SKIP_INPUT_NAMES_PW,
    build_param_url,
    should_skip_input,
    # OpenAPI
    OPENAPI_SPEC_PATHS,
    resolve_openapi_path,
    extract_openapi_urls,
)

from bugtrace.agents.gospider.agent import GoSpiderAgent

__all__ = [
    # Main class
    "GoSpiderAgent",
    # URL filtering
    "should_analyze_url",
    "is_in_scope",
    "filter_and_prioritize_urls",
    # JavaScript extraction
    "JS_URL_PATTERN",
    "extract_js_urls",
    # Form parameter helpers
    "SKIP_INPUT_TYPES",
    "SKIP_INPUT_NAMES",
    "SKIP_INPUT_TYPES_PW",
    "SKIP_INPUT_NAMES_PW",
    "build_param_url",
    "should_skip_input",
    # OpenAPI
    "OPENAPI_SPEC_PATHS",
    "resolve_openapi_path",
    "extract_openapi_urls",
]
