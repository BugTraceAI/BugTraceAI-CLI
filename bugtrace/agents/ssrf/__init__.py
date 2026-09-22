"""
SSRF specialist agent package.

Re-exports ``SSRFAgent`` for backward compatibility so that
``from bugtrace.agents.ssrf_agent import SSRFAgent``
continues to work after updating imports.
"""
from bugtrace.agents.ssrf.agent import SSRFAgent

__all__ = ["SSRFAgent"]
