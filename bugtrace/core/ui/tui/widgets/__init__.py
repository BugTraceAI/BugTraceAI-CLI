"""TUI Widget definitions.

Exports all custom widgets for the BugTraceAI TUI.
"""

from bugtrace.core.ui.tui.widgets.header import BugTraceHeader
from bugtrace.core.ui.tui.widgets.footer import BugTraceFooter
from bugtrace.core.ui.tui.widgets.pipeline import PipelineStatus
from bugtrace.core.ui.tui.widgets.activity import ActivityGraph
from bugtrace.core.ui.tui.widgets.metrics import SystemMetrics
from bugtrace.core.ui.tui.widgets.swarm import AgentSwarm
from bugtrace.core.ui.tui.widgets.payload_feed import PayloadFeed
from bugtrace.core.ui.tui.widgets.findings import FindingsSummary
from bugtrace.core.ui.tui.widgets.log_panel import LogPanel

__all__ = [
    "BugTraceHeader",
    "BugTraceFooter",
    "PipelineStatus",
    "ActivityGraph",
    "SystemMetrics",
    "AgentSwarm",
    "PayloadFeed",
    "FindingsSummary",
    "LogPanel",
]
