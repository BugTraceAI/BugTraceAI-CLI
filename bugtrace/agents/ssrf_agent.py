"""SSRFAgent — compatibility facade (P4-SSRF-2).

Canonical shell: ``bugtrace.agents.ssrf.agent.SSRFAgent``.
Pure helpers: ``bugtrace.agents.ssrf.detection``.

Historical import path used by team/CLI/smokes:

    from bugtrace.agents.ssrf_agent import SSRFAgent
    from bugtrace.agents.ssrf_agent import is_time_based_confirmed
"""

from __future__ import annotations

from bugtrace.agents.ssrf.agent import SSRFAgent
from bugtrace.agents.ssrf.detection import is_time_based_confirmed

__all__ = ["SSRFAgent", "is_time_based_confirmed"]
