"""Shared pytest fixtures / markers for BugTraceAI-CLI.

Live tests (@pytest.mark.live) are skipped unless BUGTRACE_LIVE_TESTS=1, so the
default refactor loop never touches real networks or AWS accounts.
"""

import os

import pytest


def pytest_collection_modifyitems(config, items):
    """Skip @pytest.mark.live unless BUGTRACE_LIVE_TESTS=1."""
    if os.environ.get("BUGTRACE_LIVE_TESTS") == "1":
        return
    skip_live = pytest.mark.skip(reason="live test — set BUGTRACE_LIVE_TESTS=1 to run")
    for item in items:
        if "live" in item.keywords:
            item.add_marker(skip_live)
