"""
RCE specialist agent package.

Re-exports ``RCEAgent`` for backward compatibility so that
``from bugtrace.agents.rce_agent import RCEAgent``
continues to work after updating imports.
"""
from bugtrace.agents.rce.agent import RCEAgent

__all__ = ["RCEAgent"]
