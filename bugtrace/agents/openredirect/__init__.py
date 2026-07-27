"""
OpenRedirect specialist agent package.

Re-exports ``OpenRedirectAgent`` for backward compatibility so that
``from bugtrace.agents.openredirect_agent import OpenRedirectAgent``
continues to work after updating imports.
"""
from bugtrace.agents.openredirect.agent import OpenRedirectAgent

__all__ = ["OpenRedirectAgent"]
