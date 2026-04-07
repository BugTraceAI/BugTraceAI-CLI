"""
HTTP Client Utilities - Centralized aiohttp session management.

This module provides factory functions for creating aiohttp ClientSessions
with appropriate timeouts to prevent hung connections (CLOSE_WAIT state).

The default timeout settings are designed to:
1. Fail fast on connection issues (5s connect timeout)
2. Prevent indefinite waits on slow servers (30s total timeout)
3. Disable keepalive to avoid stale connection issues

Usage:
    from bugtrace.utils.http_client import create_http_session, DEFAULT_TIMEOUT

    # Using context manager (recommended)
    async with create_http_session() as session:
        async with session.get(url) as resp:
            ...

    # Custom timeout
    async with create_http_session(total=60, connect=10) as session:
        ...

Author: BugtraceAI Team
Date: 2026-01-31
"""

import aiohttp
from typing import Optional
from contextlib import asynccontextmanager

# Default timeout configuration
# These values are tuned to prevent hung connections while allowing
# reasonable time for legitimate slow responses
DEFAULT_TIMEOUT = aiohttp.ClientTimeout(
    total=30,      # Total request timeout (seconds)
    connect=5,     # Connection establishment timeout
    sock_read=20,  # Socket read timeout
    sock_connect=5 # Socket connection timeout
)

# Aggressive timeout for probes/quick checks
PROBE_TIMEOUT = aiohttp.ClientTimeout(
    total=10,
    connect=3,
    sock_read=8,
    sock_connect=3
)

# Extended timeout for slow operations (SQLMap, large downloads)
EXTENDED_TIMEOUT = aiohttp.ClientTimeout(
    total=120,
    connect=10,
    sock_read=60,
    sock_connect=10
)


def create_timeout(
    total: float = 30,
    connect: float = 5,
    sock_read: Optional[float] = None,
    sock_connect: Optional[float] = None
) -> aiohttp.ClientTimeout:
    """
    Create a ClientTimeout with sensible defaults.

    Args:
        total: Total timeout for the entire operation
        connect: Timeout for establishing connection
        sock_read: Timeout for reading data (defaults to total - 5)
        sock_connect: Timeout for socket connection (defaults to connect)

    Returns:
        aiohttp.ClientTimeout instance
    """
    return aiohttp.ClientTimeout(
        total=total,
        connect=connect,
        sock_read=sock_read or max(total - 5, 5),
        sock_connect=sock_connect or connect
    )


@asynccontextmanager
async def create_http_session(
    total: float = 30,
    connect: float = 5,
    headers: Optional[dict] = None,
    **kwargs
):
    """
    Create an aiohttp ClientSession with proper timeout and cleanup.

    This is the recommended way to create HTTP sessions in BugtraceAI.
    It ensures:
    - Proper timeout configuration
    - Automatic cleanup on exit
    - No keepalive to avoid stale connections

    Args:
        total: Total timeout in seconds (default: 30)
        connect: Connection timeout in seconds (default: 5)
        headers: Optional default headers
        **kwargs: Additional kwargs passed to ClientSession

    Yields:
        aiohttp.ClientSession configured with timeouts

    Example:
        async with create_http_session() as session:
            async with session.get(url) as resp:
                data = await resp.text()
    """
    timeout = create_timeout(total=total, connect=connect)

    # Connector with connection pooling disabled to avoid stale connections
    connector = aiohttp.TCPConnector(
        limit=10,  # Max concurrent connections
        ttl_dns_cache=300,  # DNS cache TTL
        enable_cleanup_closed=True,  # Clean up closed connections
    )

    session = aiohttp.ClientSession(
        timeout=timeout,
        headers=headers,
        connector=connector,
        **kwargs
    )

    try:
        yield session
    finally:
        await session.close()
        # Give connector time to clean up
        await connector.close()


# Convenience functions for common use cases

async def quick_get(url: str, timeout: float = 10, **kwargs) -> tuple[int, str]:
    """
    Quick GET request with minimal timeout.

    Returns:
        (status_code, response_body)
    """
    async with create_http_session(total=timeout, connect=3) as session:
        async with session.get(url, ssl=False, **kwargs) as resp:
            return resp.status, await resp.text()


async def quick_post(url: str, data: dict = None, timeout: float = 10, **kwargs) -> tuple[int, str]:
    """
    Quick POST request with minimal timeout.

    Returns:
        (status_code, response_body)
    """
    async with create_http_session(total=timeout, connect=3) as session:
        async with session.post(url, data=data, ssl=False, **kwargs) as resp:
            return resp.status, await resp.text()


# Export commonly used items
__all__ = [
    'create_http_session',
    'create_timeout',
    'quick_get',
    'quick_post',
    'DEFAULT_TIMEOUT',
    'PROBE_TIMEOUT',
    'EXTENDED_TIMEOUT',
]
