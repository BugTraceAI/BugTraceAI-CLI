"""LFIAgent — compatibility facade.

Implementation lives in ``bugtrace.agents.lfi`` (agent + detection).
This module preserves the historical import path:

    from bugtrace.agents.lfi_agent import LFIAgent
"""

from bugtrace.agents.lfi.agent import LFIAgent

__all__ = ["LFIAgent"]
