"""BugTraceAI Textual TUI Module.

This module provides the new Textual-based terminal user interface.
"""

__all__ = ["BugTraceApp"]


def __getattr__(name):
    # The scanner subprocess imports runner without loading Textual's renderer.
    if name == "BugTraceApp":
        from .app import BugTraceApp
        return BugTraceApp
    raise AttributeError(name)
