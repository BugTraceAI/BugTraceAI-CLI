"""
Centralized HTTP Client Manager for BugTraceAI.

This module provides backward-compatible access to the HTTP client system.
The actual implementation is now in http_orchestrator.py which provides:
- Destination-based routing (LLM, TARGET, SERVICE, PROBE)
- Retry policies with exponential backoff
- Circuit breakers per host
- Health monitoring and auto-recovery

For new code, prefer using the orchestrator directly:
    from bugtrace.core.http_orchestrator import orchestrator, DestinationType

Legacy usage (still supported):
    from bugtrace.core.http_manager import http_manager, ConnectionProfile

    async with http_manager.session() as session:
        async with session.get(url) as resp:
            data = await resp.text()

Author: BugtraceAI Team
Version: 2.5.0 (Orchestrator Backend)
Date: 2026-01-31
"""

import aiohttp
import asyncio
from enum import Enum
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass
from contextlib import asynccontextmanager
from bugtrace.utils.logger import get_logger

logger = get_logger("core.http_manager")


# =============================================================================
# Legacy ConnectionProfile (for backward compatibility)
# =============================================================================

class ConnectionProfile(Enum):
    """
    Connection profiles for different use cases.

    Note: This is maintained for backward compatibility.
    New code should use DestinationType from http_orchestrator.
    """
    PROBE = "probe"          # Fast checks, vulnerability probes
    STANDARD = "standard"    # Normal HTTP requests
    EXTENDED = "extended"    # Slow operations (SQLMap, large downloads)
    LLM = "llm"              # LLM API calls (OpenRouter, etc.)


@dataclass(frozen=True)
class ProfileConfig:
    """Configuration for a connection profile."""
    total: float           # Total request timeout
    connect: float         # Connection establishment timeout
    sock_read: float       # Socket read timeout
    sock_connect: float    # Socket connection timeout
    pool_size: int         # Max connections in pool
    keepalive: float       # Keepalive timeout (0 = disabled)

    def to_timeout(self) -> aiohttp.ClientTimeout:
        """Convert to aiohttp ClientTimeout."""
        return aiohttp.ClientTimeout(
            total=self.total,
            connect=self.connect,
            sock_read=self.sock_read,
            sock_connect=self.sock_connect
        )


# Profile configurations (kept for reference)
PROFILE_CONFIGS: Dict[ConnectionProfile, ProfileConfig] = {
    ConnectionProfile.PROBE: ProfileConfig(
        total=10.0,
        connect=3.0,
        sock_read=8.0,
        sock_connect=3.0,
        pool_size=20,
        keepalive=0
    ),
    ConnectionProfile.STANDARD: ProfileConfig(
        total=30.0,
        connect=5.0,
        sock_read=25.0,
        sock_connect=5.0,
        pool_size=50,
        keepalive=15.0
    ),
    ConnectionProfile.EXTENDED: ProfileConfig(
        total=120.0,
        connect=10.0,
        sock_read=60.0,
        sock_connect=10.0,
        pool_size=10,
        keepalive=30.0
    ),
    ConnectionProfile.LLM: ProfileConfig(
        total=120.0,
        connect=10.0,
        sock_read=110.0,
        sock_connect=10.0,
        pool_size=5,
        keepalive=60.0
    ),
}


# =============================================================================
# Import orchestrator (lazy to avoid circular imports)
# =============================================================================

def _get_orchestrator():
    """Lazy import of orchestrator."""
    from bugtrace.core.http_orchestrator import orchestrator, DestinationType
    return orchestrator, DestinationType


def _profile_to_destination(profile: ConnectionProfile):
    """Map ConnectionProfile to DestinationType."""
    _, DestinationType = _get_orchestrator()

    mapping = {
        ConnectionProfile.PROBE: DestinationType.PROBE,
        ConnectionProfile.STANDARD: DestinationType.TARGET,
        ConnectionProfile.EXTENDED: DestinationType.TARGET,
        ConnectionProfile.LLM: DestinationType.LLM,
    }
    return mapping.get(profile, DestinationType.TARGET)


# =============================================================================
# HTTPClientManager (Backward Compatible Wrapper)
# =============================================================================

class HTTPClientManager:
    """
    Centralized HTTP client manager with connection pooling and lifecycle management.

    This class now wraps the HTTPClientOrchestrator for backward compatibility.
    It provides the same API as before but routes to the new orchestrator system.

    For new code, prefer using the orchestrator directly:
        from bugtrace.core.http_orchestrator import orchestrator, DestinationType
    """

    _instance: Optional["HTTPClientManager"] = None
    _lock = asyncio.Lock()

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._started = False
        self._initialized = True
        logger.info("[HTTPClientManager] Initialized (orchestrator backend)")

    async def start(self) -> None:
        """
        Initialize all connection pools.

        Routes to orchestrator.start().
        """
        async with self._lock:
            if self._started:
                return

            orchestrator, _ = _get_orchestrator()
            await orchestrator.start()
            self._started = True
            logger.info("[HTTPClientManager] Started (via orchestrator)")

    async def shutdown(self) -> None:
        """
        Gracefully shutdown all connection pools.

        Routes to orchestrator.shutdown().
        """
        async with self._lock:
            if not self._started:
                return

            orchestrator, _ = _get_orchestrator()
            await orchestrator.shutdown()
            self._started = False
            logger.info("[HTTPClientManager] Shutdown complete (via orchestrator)")

    @asynccontextmanager
    async def session(
        self,
        profile: ConnectionProfile = ConnectionProfile.STANDARD,
        headers: Optional[Dict[str, str]] = None
    ):
        """
        Get a session for making HTTP requests.

        Routes to orchestrator.session().
        """
        orchestrator, _ = _get_orchestrator()
        dest = _profile_to_destination(profile)

        # Ensure orchestrator is started
        if not orchestrator._started:
            await orchestrator.start()

        async with orchestrator.session(dest) as session:
            yield session

    @asynccontextmanager
    async def isolated_session(
        self,
        profile: ConnectionProfile = ConnectionProfile.STANDARD,
        headers: Optional[Dict[str, str]] = None,
        **kwargs
    ):
        """
        Create an isolated session that's not part of the connection pool.

        Routes to orchestrator.isolated_session().
        """
        orchestrator, _ = _get_orchestrator()
        dest = _profile_to_destination(profile)

        async with orchestrator.isolated_session(dest, headers, **kwargs) as session:
            yield session

    async def get(
        self,
        url: str,
        profile: ConnectionProfile = ConnectionProfile.STANDARD,
        **kwargs
    ) -> Tuple[int, str]:
        """
        Perform a GET request with automatic retry.

        Routes to orchestrator.get().
        """
        orchestrator, _ = _get_orchestrator()
        dest = _profile_to_destination(profile)

        if not orchestrator._started:
            await orchestrator.start()

        return await orchestrator.get(url, dest, **kwargs)

    async def post(
        self,
        url: str,
        data: Any = None,
        json: Any = None,
        profile: ConnectionProfile = ConnectionProfile.STANDARD,
        **kwargs
    ) -> Tuple[int, str]:
        """
        Perform a POST request with automatic retry.

        Routes to orchestrator.post().
        """
        orchestrator, _ = _get_orchestrator()
        dest = _profile_to_destination(profile)

        if not orchestrator._started:
            await orchestrator.start()

        if data is not None:
            kwargs['data'] = data
        if json is not None:
            kwargs['json'] = json

        return await orchestrator.post(url, dest, **kwargs)

    async def head(
        self,
        url: str,
        profile: ConnectionProfile = ConnectionProfile.PROBE,
        **kwargs
    ) -> int:
        """
        Perform a HEAD request (for checking URLs).

        Routes to orchestrator.head().
        """
        orchestrator, _ = _get_orchestrator()
        dest = _profile_to_destination(profile)

        if not orchestrator._started:
            await orchestrator.start()

        return await orchestrator.head(url, dest, **kwargs)

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about current connections."""
        orchestrator, _ = _get_orchestrator()
        return orchestrator.get_health_report()


# =============================================================================
# Global Singleton Instance
# =============================================================================

http_manager = HTTPClientManager()


# =============================================================================
# Cleanup Registration
# =============================================================================

async def _cleanup_http_manager():
    """Called during application shutdown."""
    await http_manager.shutdown()


def register_shutdown_handler():
    """Register the cleanup handler with the event loop."""
    try:
        loop = asyncio.get_running_loop()
        # The Team orchestrator should call http_manager.shutdown() explicitly
    except RuntimeError:
        pass


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    'http_manager',
    'HTTPClientManager',
    'ConnectionProfile',
    'ProfileConfig',
    'PROFILE_CONFIGS',
]
