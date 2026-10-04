"""DASTySASTAgent — compatibility facade.

Canonical: ``bugtrace.agents.analysis.agent.DASTySASTAgent``.
"""

from bugtrace.agents.analysis.agent import DASTySASTAgent
from bugtrace.core.http_orchestrator import orchestrator

__all__ = ["DASTySASTAgent", "orchestrator"]
