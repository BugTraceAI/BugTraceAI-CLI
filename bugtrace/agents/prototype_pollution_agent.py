"""PrototypePollutionAgent — compatibility facade.

Implementation lives in ``bugtrace.agents.prototype_pollution``
(core + testing + agent). Historical import path preserved:

    from bugtrace.agents.prototype_pollution_agent import PrototypePollutionAgent
"""

from bugtrace.agents.prototype_pollution.agent import PrototypePollutionAgent

__all__ = ["PrototypePollutionAgent"]
