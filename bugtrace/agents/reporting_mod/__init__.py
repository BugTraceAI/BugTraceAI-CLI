"""
reporting_mod: Modular reporting subpackage.

Re-exports ReportingAgent for backward-compatible imports:
    from bugtrace.agents.reporting_mod import ReportingAgent
"""

from bugtrace.agents.reporting_mod.agent import ReportingAgent

__all__ = ["ReportingAgent"]
