"""OpenRedirectAgent — compatibility facade.

Implementation lives in ``bugtrace.agents.openredirect`` (agent + detection).
This module preserves the historical import path used by team flows and tests:

    from bugtrace.agents.openredirect_agent import OpenRedirectAgent
"""

from bugtrace.agents.openredirect.agent import OpenRedirectAgent

__all__ = ["OpenRedirectAgent"]
