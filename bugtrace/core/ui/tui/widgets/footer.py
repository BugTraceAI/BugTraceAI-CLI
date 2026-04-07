"""Custom footer widget for BugTraceAI TUI."""

from textual.widgets import Footer


class BugTraceFooter(Footer):
    """BugTraceAI customized footer widget.

    Extends the default Textual Footer with BugTraceAI styling.
    For now, uses default Footer behavior - will be customized in Phase 2.
    """

    DEFAULT_CSS = """
    BugTraceFooter {
        dock: bottom;
        height: 1;
    }
    """
