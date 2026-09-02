"""Team orchestration package (split from team.py monolith)."""
from bugtrace.core.config import settings
from bugtrace.core.team.orchestrator import TeamOrchestrator, run_agent_with_semaphore

__all__ = ["TeamOrchestrator", "run_agent_with_semaphore", "settings"]
