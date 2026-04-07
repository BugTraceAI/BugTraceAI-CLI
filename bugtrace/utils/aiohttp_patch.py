"""
aiohttp Session Timeout Enforcement.

This module enforces default timeouts on aiohttp.ClientSession to prevent
hung connections (CLOSE_WAIT state).

The professional solution is to use HTTPClientManager from bugtrace.core.http_manager.
This patch serves as a safety net for any code that hasn't been migrated yet.

Usage:
    # Import at application startup to apply the patch
    import bugtrace.utils.aiohttp_patch  # noqa: F401

Migration Guide:
    Replace:
        async with aiohttp.ClientSession() as session:
            ...

    With:
        from bugtrace.core.http_manager import http_manager, ConnectionProfile
        async with http_manager.session(ConnectionProfile.STANDARD) as session:
            ...

Author: BugtraceAI Team
Date: 2026-01-31
"""

import aiohttp
import functools
import traceback
from bugtrace.utils.logger import get_logger

logger = get_logger("utils.aiohttp_patch")

# Default timeout for sessions that don't specify one
DEFAULT_TOTAL_TIMEOUT = 60.0
DEFAULT_CONNECT_TIMEOUT = 10.0

# Store original __init__
_original_init = aiohttp.ClientSession.__init__

# Track if we've logged migration warnings
_warned_locations = set()


@functools.wraps(_original_init)
def _patched_init(self, *args, **kwargs):
    """
    Patched ClientSession.__init__ that enforces timeout.

    If no timeout is specified, applies defaults and logs a migration warning.
    """
    timeout_arg = kwargs.get('timeout')

    if timeout_arg is None:
        # Apply default timeout
        kwargs['timeout'] = aiohttp.ClientTimeout(
            total=DEFAULT_TOTAL_TIMEOUT,
            connect=DEFAULT_CONNECT_TIMEOUT,
            sock_read=DEFAULT_TOTAL_TIMEOUT - 5,
            sock_connect=DEFAULT_CONNECT_TIMEOUT
        )

        # Log migration warning (once per call site)
        stack = traceback.extract_stack()
        if len(stack) >= 3:
            caller = stack[-3]  # The actual caller
            location = f"{caller.filename}:{caller.lineno}"

            if location not in _warned_locations:
                _warned_locations.add(location)
                logger.warning(
                    f"[aiohttp-patch] Session without timeout at {location}. "
                    f"Migrate to http_manager for proper connection management."
                )

    return _original_init(self, *args, **kwargs)


def apply_patch():
    """Apply the aiohttp timeout enforcement patch."""
    aiohttp.ClientSession.__init__ = _patched_init
    logger.info(
        f"[aiohttp-patch] Timeout enforcement active "
        f"(default: {DEFAULT_TOTAL_TIMEOUT}s total, {DEFAULT_CONNECT_TIMEOUT}s connect)"
    )


def remove_patch():
    """Remove the patch (for testing)."""
    aiohttp.ClientSession.__init__ = _original_init
    logger.info("[aiohttp-patch] Patch removed")


def get_unmigrated_locations() -> set:
    """Get set of file:line locations that need migration."""
    return _warned_locations.copy()


# Apply patch on import
apply_patch()
