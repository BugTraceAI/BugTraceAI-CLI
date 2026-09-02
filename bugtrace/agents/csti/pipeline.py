"""
CSTI Pipeline facade — re-exports validation, escalation L0-L6, and LLM helpers.

Split modules:
  - pipeline_validation.py
  - pipeline_escalation.py
  - pipeline_llm.py
"""

from bugtrace.agents.csti.pipeline_validation import (
    validate_csti,
    test_payload_with_validation,
    escalation_smart_probe,
)
from bugtrace.agents.csti.pipeline_escalation import (
    escalation_l0_wet_payload,
    escalation_l1_template_probe,
    escalation_l2_static_bombing,
    escalation_l3_llm_bombing,
    escalation_l4_http_manipulator,
    escalation_l5_browser,
    create_l6_cdp_finding,
)
from bugtrace.agents.csti.pipeline_llm import (
    build_template_system_prompt,
    build_template_user_prompt,
    parse_llm_payloads,
    llm_smart_template_analysis,
    llm_analyze_and_dedup,
)

__all__ = [
    "validate_csti",
    "test_payload_with_validation",
    "escalation_smart_probe",
    "escalation_l0_wet_payload",
    "escalation_l1_template_probe",
    "escalation_l2_static_bombing",
    "escalation_l3_llm_bombing",
    "escalation_l4_http_manipulator",
    "escalation_l5_browser",
    "create_l6_cdp_finding",
    "build_template_system_prompt",
    "build_template_user_prompt",
    "parse_llm_payloads",
    "llm_smart_template_analysis",
    "llm_analyze_and_dedup",
]
