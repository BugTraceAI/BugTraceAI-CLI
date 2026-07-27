"""Custom header widget for BugTraceAI TUI."""

from textual.widgets import Header


class BugTraceHeader(Header):
    """BugTraceAI customized header widget.

    Extends the default Textual Header with BugTraceAI styling.
    For now, uses default Header behavior - will be customized in Phase 2.
    """

    DEFAULT_CSS = """
    BugTraceHeader {
        dock: top;
        height: 3;
        background: $surface;
        border-bottom: solid $primary;
    }
    """
