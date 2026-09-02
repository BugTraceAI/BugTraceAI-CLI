"""
BugTraceAI v4.1 - Advanced Terminal Dashboard (legacy).

Thin shell — mixins under ``ui_legacy_shell``. Public: Dashboard, dashboard.
"""

from bugtrace.core.ui_legacy_shell.widgets import DashboardHandler, SparklineBuffer
from bugtrace.core.ui_legacy_shell.core import DashboardCoreMixin
from bugtrace.core.ui_legacy_shell.pipeline import DashboardPipelineMixin
from bugtrace.core.ui_legacy_shell.pages import DashboardPagesMixin
from bugtrace.core.ui_legacy_shell.chrome import DashboardChromeMixin


class Dashboard(
    DashboardCoreMixin,
    DashboardPipelineMixin,
    DashboardPagesMixin,
    DashboardChromeMixin,
):
    """Advanced multi-page terminal dashboard with animations and graphics."""

    PAGE_MAIN = 0
    PAGE_FINDINGS = 1
    PAGE_LOGS = 2
    PAGE_STATS = 3
    PAGE_AGENTS = 4
    PAGE_QUEUES = 5
    PAGE_CONFIG = 6

    # Spinner frames
    SPINNER_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    # Logo ASCII art with gradient colors
    LOGO_LINES = [
        "██████╗ ██╗   ██╗ ██████╗ ████████╗██████╗  █████╗  ██████╗███████╗     █████╗ ██╗",
        "██╔══██╗██║   ██║██╔════╝ ╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝    ██╔══██╗██║",
        "██████╔╝██║   ██║██║  ███╗   ██║   ██████╔╝███████║██║     █████╗      ███████║██║",
        "██╔══██╗██║   ██║██║   ██║   ██║   ██╔══██╗██╔══██║██║     ██╔══╝      ██╔══██║██║",
        "██████╔╝╚██████╔╝╚██████╔╝   ██║   ██║  ██║██║  ██║╚██████╗███████╗    ██║  ██║██║",
        "╚═════╝  ╚═════╝  ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝    ╚═╝  ╚═╝╚═╝",
    ]



# Global singleton
dashboard = Dashboard()

__all__ = ["Dashboard", "dashboard", "DashboardHandler", "SparklineBuffer"]
