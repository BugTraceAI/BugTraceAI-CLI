"""SQLi/cookie/reflection probes — composed shell mixins."""

from __future__ import annotations

from bugtrace.agents.analysis_shell.reflection_probes import AnalysisReflectionProbesMixin
from bugtrace.agents.analysis_shell.sqli_probes import AnalysisSqliProbesMixin

__all__ = ["AnalysisProbesMixin"]


class AnalysisProbesMixin(AnalysisReflectionProbesMixin, AnalysisSqliProbesMixin):
    """Composite mixin for DASTySAST probe suite (reflection + SQLi/cookie)."""
    pass
