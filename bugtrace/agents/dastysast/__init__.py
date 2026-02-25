"""
DASTySAST Analysis Agent package.

Modular decomposition of the monolithic analysis_agent.py into
functional-programming-aligned submodules.

Re-exports DASTySASTAgent for backward compatibility:
    from bugtrace.agents.dastysast import DASTySASTAgent
"""
from bugtrace.agents.dastysast.agent import DASTySASTAgent

__all__ = ["DASTySASTAgent"]
