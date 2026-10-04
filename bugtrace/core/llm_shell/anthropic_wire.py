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


class LLMAnthropicMixin:
    def _is_anthropic_model(self, model: str) -> bool:
        """Check if model should be routed to Anthropic API instead of OpenRouter."""
        if not settings.ANTHROPIC_OAUTH_ENABLED:
            return False
        return model.startswith("anthropic/")

    async def _ensure_anthropic_token(self) -> Optional[str]:
        """Lazy-load and auto-refresh Anthropic OAuth token."""
        import time as _time
        now = _time.time()
        if self._anthropic_token_cache and now < self._anthropic_token_expires:
            return self._anthropic_token_cache
        try:
            from bugtrace.core.anthropic_auth import get_valid_token
            token = await get_valid_token()
            if token:
                self._anthropic_token_cache = token
                self._anthropic_token_expires = now + 300  # Re-check every 5 min
            return token
        except Exception as e:
            logger.error(f"Anthropic token load failed: {e}")
            return None

    def _build_anthropic_headers(self, token: str, module_name: str) -> Dict[str, str]:
        """Build headers for direct Anthropic API calls (OAuth compatible)."""
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01",
            "anthropic-beta": "oauth-2025-04-20,interleaved-thinking-2025-05-14",
            "User-Agent": "claude-cli/2.1.2 (external, cli)",
        }

    def _build_anthropic_apikey_headers(self, api_key: str) -> Dict[str, str]:
        """Build headers for direct Anthropic API calls using an API key.

        API-key auth uses `x-api-key` — NOT `Authorization: Bearer` and NOT
        the OAuth beta header. This is the path for the `anthropic` provider
        preset (api_format=anthropic).
        """
        return {
            "x-api-key": api_key,
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01",
        }

    def _build_anthropic_payload(
        self,
        model: str,
        messages: List[Dict[str, str]],
        temperature: float,
        max_tokens: int,
        oauth: bool = True
    ) -> Dict[str, Any]:
        """Build Anthropic Messages API payload.

        Key differences from OpenAI format:
        - Model name without 'anthropic/' prefix
        - System prompt as top-level 'system' field, not in messages
        - Only 'user' and 'assistant' roles in messages array

        The Claude Code identity prefix is ONLY required for OAuth tokens
        (Pro/Max). With a real API key (`oauth=False`) it is omitted so the
        agent system prompt is used verbatim.
        """
        # Strip anthropic/ prefix
        anthropic_model = model.replace("anthropic/", "", 1)

        # Extract system prompt from messages
        system_text = None
        filtered_messages = []
        for msg in messages:
            if msg["role"] == "system":
                system_text = msg["content"]
            else:
                filtered_messages.append(msg)

        # Claude Code identity prefix — required ONLY for OAuth token acceptance.
        if oauth:
            cc_prefix = "You are Claude Code, Anthropic's official CLI for Claude."
            if system_text:
                system_text = f"{cc_prefix}\n\n{system_text}"
            else:
                system_text = cc_prefix

        payload = {
            "model": anthropic_model,
            "messages": filtered_messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        # Anthropic rejects `system: null` — only include when we have one.
        if system_text:
            payload["system"] = system_text

        return payload
