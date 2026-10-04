"""RCEAgent — compatibility facade.

Implementation lives in ``bugtrace.agents.rce`` (agent + detection).

    from bugtrace.agents.rce_agent import RCEAgent
"""

from bugtrace.agents.rce.agent import RCEAgent
from bugtrace.agents.rce.detection import is_time_based_confirmed
from bugtrace.core.http_orchestrator import orchestrator

__all__ = ["RCEAgent", "is_time_based_confirmed", "orchestrator"]
