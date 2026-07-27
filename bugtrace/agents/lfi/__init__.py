"""
LFI specialist agent package.

Re-exports ``LFIAgent`` for backward compatibility so that
``from bugtrace.agents.lfi_agent import LFIAgent``
continues to work after updating imports.
"""
from bugtrace.agents.lfi.agent import LFIAgent

__all__ = ["LFIAgent"]
