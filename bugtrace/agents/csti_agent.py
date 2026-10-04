"""CSTIAgent — compatibility facade (P4-CSTI-shell).

Canonical shell: ``bugtrace.agents.csti.agent.CSTIAgent``.
Finding type: ``bugtrace.agents.csti.types.CSTIFinding``.

Historical imports:

    from bugtrace.agents.csti_agent import CSTIAgent, CSTIFinding
"""

from __future__ import annotations

from bugtrace.agents.csti.agent import CSTIAgent
from bugtrace.agents.csti.types import CSTIFinding

__all__ = ["CSTIAgent", "CSTIFinding"]
