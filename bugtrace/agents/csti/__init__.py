"""
CSTI Agent Module

This module provides CSTI/SSTI (Client/Server-Side Template Injection) detection capabilities.

The CSTIAgent class is the main entry point for template injection scanning.

Modules:
    - types: CSTIFinding dataclass
    - engines: PURE template engine detection and classification
    - payloads: PURE payload library and impact classification
    - validation: PURE arithmetic eval, engine signatures, error matching
    - discovery: I/O CSTI-specific parameter discovery
    - exploitation: I/O payload sending, finding creation
    - dedup: PURE CSTI fingerprint deduplication
    - reporting: I/O specialist report writing
    - pipeline: ORCHESTRATION escalation levels L0-L6, validation pipeline

Usage:
    from bugtrace.agents.csti import CSTIAgent, CSTIFinding

    agent = CSTIAgent(url="http://example.com", params=[{"parameter": "q"}])
    result = await agent.run_loop()

For backward compatibility, CSTIAgent can also be imported from:
    from bugtrace.agents.csti_agent import CSTIAgent
"""

import asyncio
import time
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path

from bugtrace.agents.base import BaseAgent
from bugtrace.agents.mixins.tech_context import TechContextMixin
from bugtrace.core.ui import dashboard
from bugtrace.core.job_manager import JobStatus
from bugtrace.core.event_bus import EventType
from bugtrace.core.http_manager import http_manager, ConnectionProfile
from bugtrace.core.config import settings
from bugtrace.core.validation_status import ValidationStatus, requires_cdp_validation
from bugtrace.core.verbose_events import create_emitter
from bugtrace.schemas.validation_feedback import ValidationFeedback, FailureReason
from bugtrace.utils.logger import get_logger

# Re-export types
from bugtrace.agents.csti.types import CSTIFinding

# Re-export engine functions
from bugtrace.agents.csti.engines import (
    ENGINE_SIGNATURES,
    CLIENT_SIDE_ENGINES,
    fingerprint_engines,
    detect_engine_from_payload,
    classify_engine_type,
    is_client_side_engine,
    try_alternative_engine,
    encode_template_chars,
)

# Re-export payload data and functions
from bugtrace.agents.csti.payloads import (
    PAYLOAD_LIBRARY,
    HIGH_IMPACT_INDICATORS,
    MEDIUM_IMPACT_INDICATORS,
    HIGH_PRIORITY_PARAMS,
    get_payload_impact_tier,
    should_stop_testing,
    prioritize_params,
    prioritize_csti_params,
    build_l2_payload_list,
    get_universal_bypass_payloads,
)

# Re-export validation functions
from bugtrace.agents.csti.validation import (
    check_csti_confirmed,
    check_arithmetic_evaluation,
    check_string_multiplication,
    check_config_reflection,
    check_engine_signatures,
    check_error_signatures,
    validate_finding_before_emit,
)

# Re-export discovery functions
from bugtrace.agents.csti.discovery import (
    discover_csti_params,
    discover_all_params_sync,
    detect_engines_for_escalation,
)

# Re-export exploitation functions
from bugtrace.agents.csti.exploitation import (
    inject_param,
    create_finding,
    create_ambiguous_finding,
    generate_repro_steps,
    dict_to_finding,
    send_csti_payload_raw,
    get_encoded_payloads,
    test_post_injection,
    test_header_injection,
    fetch_page,
    get_baseline_content,
    check_light_reflection,
    test_api_ssti,
)

# Re-export dedup functions
from bugtrace.agents.csti.dedup import (
    generate_csti_fingerprint,
    fallback_fingerprint_dedup,
    normalize_csti_finding_params,
)

# Re-export reporting functions
from bugtrace.agents.csti.reporting import generate_specialist_report

# Re-export pipeline functions
from bugtrace.agents.csti.pipeline import (
    validate_csti,
    test_payload_with_validation,
    escalation_smart_probe,
    escalation_l0_wet_payload,
    escalation_l1_template_probe,
    escalation_l2_static_bombing,
    escalation_l3_llm_bombing,
    escalation_l4_http_manipulator,
    escalation_l5_browser,
    create_l6_cdp_finding,
    build_template_system_prompt,
    build_template_user_prompt,
    parse_llm_payloads,
    llm_smart_template_analysis,
    llm_analyze_and_dedup,
)


logger = get_logger("agents.csti")


# =========================================================================
# Legacy class kept for fingerprinting API compatibility
# =========================================================================

class TemplateEngineFingerprinter:
    """Detect which template engine is in use. Delegates to engines module."""

    ENGINE_SIGNATURES = ENGINE_SIGNATURES

    @classmethod
    def fingerprint(cls, html: str, headers: dict = None) -> List[str]:
        return fingerprint_engines(html, headers)


# =========================================================================
# CSTIAgent: canonical shell is csti.agent + csti_shell mixins (P4-CSTI-shell).
# Lazy import avoids cycles when pure submodules load during package init.
# =========================================================================

def __getattr__(name: str):
    if name == "CSTIAgent":
        from bugtrace.agents.csti.agent import CSTIAgent

        return CSTIAgent
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "CSTIAgent",
    "CSTIFinding",
    "TemplateEngineFingerprinter",
    "PAYLOAD_LIBRARY",
    "ENGINE_SIGNATURES",
]
