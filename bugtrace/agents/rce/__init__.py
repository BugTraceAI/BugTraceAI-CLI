"""
RCE specialist agent package.

Re-exports ``RCEAgent`` for backward compatibility so that
``from bugtrace.agents.rce_agent import RCEAgent``
continues to work after updating imports.
"""
from bugtrace.agents.rce.agent import RCEAgent
from bugtrace.agents.rce.detection import is_time_based_confirmed

__all__ = ["RCEAgent", "is_time_based_confirmed"]
