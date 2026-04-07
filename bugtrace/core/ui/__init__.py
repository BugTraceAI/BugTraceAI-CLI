"""BugTraceAI UI Module - Contains both legacy Rich dashboard and new Textual TUI."""

# Re-export legacy dashboard for backward compatibility
from bugtrace.core.ui_legacy import dashboard, Dashboard, DashboardHandler, SparklineBuffer

__all__ = ["dashboard", "Dashboard", "DashboardHandler", "SparklineBuffer"]
