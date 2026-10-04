"""
SSRF specialist package.

Canonical shell: ``bugtrace.agents.ssrf.agent.SSRFAgent``.
Pure: ``bugtrace.agents.ssrf.detection``.

Backward compatible:

    from bugtrace.agents.ssrf import SSRFAgent
    from bugtrace.agents.ssrf_agent import SSRFAgent
"""

from bugtrace.agents.ssrf.agent import SSRFAgent
from bugtrace.agents.ssrf.detection import (
    is_time_based_confirmed,
    determine_validation_status,
    get_validation_status,
    generate_ssrf_fingerprint,
    fallback_fingerprint_dedup,
    validate_before_emit,
)

__all__ = [
    "SSRFAgent",
    "is_time_based_confirmed",
    "determine_validation_status",
    "get_validation_status",
    "generate_ssrf_fingerprint",
    "fallback_fingerprint_dedup",
    "validate_before_emit",
]
