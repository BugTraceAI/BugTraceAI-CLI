"""HeaderInjectionAgent — compatibility facade.

Implementation lives in ``bugtrace.agents.header_injection`` (agent + core + testing).

    from bugtrace.agents.header_injection_agent import HeaderInjectionAgent
"""

from bugtrace.agents.header_injection.agent import HeaderInjectionAgent

__all__ = ["HeaderInjectionAgent"]
