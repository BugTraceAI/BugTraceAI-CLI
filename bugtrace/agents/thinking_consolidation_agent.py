"""ThinkingConsolidationAgent — compatibility facade.

Implementation lives in ``bugtrace.agents.consolidation`` (core/prompts/processing/agent).
Historical import path preserved for team flows and tests:

    from bugtrace.agents.thinking_consolidation_agent import ThinkingConsolidationAgent
"""

from bugtrace.agents.consolidation import (
    ThinkingConsolidationAgent,
    DeduplicationCache,
    FindingRecord,
    PrioritizedFinding,
    VULN_TYPE_TO_SPECIALIST,
    SEVERITY_PRIORITY,
    SPECIALIST_DESCRIPTIONS,
    classify_finding,
    calculate_priority,
)
from bugtrace.core.specialist_route_policy import classify_vuln_type

__all__ = [
    "ThinkingConsolidationAgent",
    "DeduplicationCache",
    "FindingRecord",
    "PrioritizedFinding",
    "VULN_TYPE_TO_SPECIALIST",
    "SEVERITY_PRIORITY",
    "SPECIALIST_DESCRIPTIONS",
    "classify_finding",
    "calculate_priority",
    "classify_vuln_type",
]
