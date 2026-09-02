"""LLM client shell mixin — extracted from llm_client for size policy."""

from __future__ import annotations

import os
import re
import time
import hashlib
import aiohttp
import json
import asyncio
import aiofiles
from typing import Optional, Dict, Any, List
from datetime import datetime
from tenacity import retry, stop_after_attempt, wait_exponential

from bugtrace.core.ui import dashboard
from bugtrace.utils.logger import get_logger
from bugtrace.core.config import settings
from bugtrace.core.http_orchestrator import orchestrator, DestinationType
from bugtrace.core.exceptions import (
    LLMError,
    LLMTimeoutError,
    LLMRateLimitError,
    LLMParseError,
    LLMServiceUnavailableError,
    NetworkError,
    TimeoutError as BugTraceTimeoutError,
    ConnectionError as BugTraceConnectionError,
    JSONParseError,
    is_transient,
)
from bugtrace.core.llm_shell.types import (
    LLMHealthState,
    CB_FAILURE_THRESHOLD,
    CB_COOLDOWN_SECONDS,
    CB_DEGRADED_DELAY,
    CB_SUCCESS_THRESHOLD,
    LLM_TOTAL_TIMEOUT,
    LLM_CONNECT_TIMEOUT,
    ModelMetrics,
    TokenUsageTracker,
    VULNERABILITY_SCHEMA,
    _ProviderRateLimiter,
    _parse_rpm,
    sanitize_text,
)

logger = get_logger("core.llm_client")


class LLMCacheMixin:
    def _get_cache_key(self, model: str, prompt: str) -> str:
        """Generate cache key from model and prompt."""
        return hashlib.sha256(f"{model}:{prompt}".encode()).hexdigest()

    def _cache_get(self, cache_key: str, ttl: int) -> Optional[str]:
        """Return cached response or evict stale entry."""
        cached = self.cache.get(cache_key)
        if cached is None:
            return None

        cached_response, timestamp = cached
        if time.time() - timestamp < ttl:
            return cached_response

        self.cache.pop(cache_key, None)
        return None

    def _cache_put(self, cache_key: str, response: str) -> None:
        """Store response while keeping cache bounded."""
        if len(self.cache) >= self.cache_max_entries:
            oldest_key = min(self.cache, key=lambda key: self.cache[key][1])
            self.cache.pop(oldest_key, None)
        self.cache[cache_key] = (response, time.time())

    async def generate_with_cache(
        self,
        prompt: str,
        module_name: str,
        model_override: Optional[str] = None,
        cache_ttl: Optional[int] = None,
        **kwargs
    ) -> Optional[str]:
        """Generate with response caching to avoid duplicate LLM calls.

        Args:
            prompt: The prompt to send
            module_name: Module identifier
            model_override: Optional specific model
            cache_ttl: Cache TTL in seconds (default: self.cache_ttl)
            **kwargs: Additional args passed to generate()

        Returns:
            LLM response (cached or fresh)
        """
        model = model_override or (self.models[0] if self.models else "unknown")
        cache_key = self._get_cache_key(model, prompt)
        ttl = cache_ttl or self.cache_ttl

        cached_response = self._cache_get(cache_key, ttl)
        if cached_response is not None:
            logger.debug(f"Cache hit for {module_name} ({model})")
            return cached_response

        # Generate fresh response
        response = await self.generate(
            prompt=prompt,
            module_name=module_name,
            model_override=model_override,
            **kwargs
        )

        # Cache valid responses
        if response:
            self._cache_put(cache_key, response)

        return response

    def clear_cache(self):
        """Clear all cached responses."""
        self.cache.clear()
        logger.info("LLM response cache cleared")
