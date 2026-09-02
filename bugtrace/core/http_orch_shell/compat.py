"""HTTP orchestrator shell module — extracted for size policy."""

from __future__ import annotations

import aiohttp
import asyncio
import random
import time
from enum import Enum
from typing import Optional, Dict, Any, Tuple, Callable, List
from dataclasses import dataclass, field
from contextlib import asynccontextmanager
from collections import deque

from bugtrace.utils.logger import get_logger

logger = get_logger("core.http_orchestrator")

from bugtrace.core.http_orch_shell.types import DestinationType
from bugtrace.core.http_orch_shell.orchestrator_core import HTTPClientOrchestrator

_PROFILE_TO_DESTINATION = {
    "probe": DestinationType.PROBE,
    "standard": DestinationType.TARGET,
    "extended": DestinationType.TARGET,
    "llm": DestinationType.LLM,
}


class HTTPClientManagerCompat:
    """
    Compatibility wrapper for old http_manager API.

    Allows gradual migration from http_manager to orchestrator.
    """

    def __init__(self, orch: HTTPClientOrchestrator):
        self._orch = orch

    async def start(self):
        await self._orch.start()

    async def shutdown(self):
        await self._orch.shutdown()

    def _map_profile(self, profile) -> DestinationType:
        """Map ConnectionProfile to DestinationType."""
        if hasattr(profile, 'value'):
            profile_value = profile.value
        else:
            profile_value = str(profile)
        return _PROFILE_TO_DESTINATION.get(profile_value, DestinationType.TARGET)

    @asynccontextmanager
    async def session(self, profile=None, headers=None):
        dest = self._map_profile(profile) if profile else DestinationType.TARGET
        async with self._orch.session(dest) as session:
            yield session

    @asynccontextmanager
    async def isolated_session(self, profile=None, headers=None, **kwargs):
        dest = self._map_profile(profile) if profile else DestinationType.TARGET
        async with self._orch.isolated_session(dest, headers, **kwargs) as session:
            yield session

    async def get(self, url: str, profile=None, **kwargs) -> Tuple[int, str]:
        dest = self._map_profile(profile) if profile else DestinationType.TARGET
        return await self._orch.get(url, dest, **kwargs)

    async def post(self, url: str, data=None, json=None, profile=None, **kwargs) -> Tuple[int, str]:
        dest = self._map_profile(profile) if profile else DestinationType.TARGET
        if data:
            kwargs['data'] = data
        if json:
            kwargs['json'] = json
        return await self._orch.post(url, dest, **kwargs)

    async def head(self, url: str, profile=None, **kwargs) -> int:
        dest = self._map_profile(profile) if profile else DestinationType.PROBE
        return await self._orch.head(url, dest, **kwargs)

    def get_stats(self) -> Dict[str, Any]:
        return self._orch.get_health_report()

