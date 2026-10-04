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


class LLMConnectivityMixin:
    async def verify_connectivity(self) -> bool:
        """
        Conducts a 'Startup Health Check' on configured models.
        Returns True if at least one model is responsive.
        Removes unresponsive models from self.models.
        """
        if not self.api_key:
            return False

        dashboard.log("Verifying AI Model Connectivity...", "INFO")

        # We'll test up to 3 models to avoid long startup times
        test_pool = self.models[:3]
        valid_models = []

        for model in test_pool:
            if await self._ping_model(model):
                valid_models.append(model)

        return self._report_connectivity_status(valid_models)

    async def _ping_model(self, model: str) -> bool:
        """Ping a single model to check connectivity."""
        dashboard.log(f"Pinging model: {model}...", "INFO")

        if self.api_format == 'anthropic':
            headers = self._build_anthropic_apikey_headers(self.api_key or "")
            payload = self._build_anthropic_payload(
                model, [{"role": "user", "content": "Ping"}],
                temperature=0.0, max_tokens=5, oauth=False
            )
        else:
            headers = self._build_headers("ping")
            payload = self._build_request_payload(
                model,
                [{"role": "user", "content": "Ping"}],
                temperature=0.0,
                max_tokens=5,
            )

        try:
            async with orchestrator.session(DestinationType.LLM) as session:
                async with session.post(self.base_url, headers=headers, json=payload, timeout=5) as resp:
                    return self._log_ping_result(model, resp.status)
        except Exception as e:
            dashboard.log(f"Model {model} unreachable: {e}. Check API key and limits.", "ERROR")
            return False

    def _log_ping_result(self, model: str, status: int) -> bool:
        """Log ping result and return success status."""
        if status == 200:
            dashboard.log(f"Model {model} is ONLINE.", "SUCCESS")
            return True

        dashboard.log(f"Model {model} failed health check ({status}). API Key may be invalid or out of credits.", "ERROR")
        return False

    def _report_connectivity_status(self, valid_models: list) -> bool:
        """Report overall connectivity status."""
        if valid_models:
            return True

        dashboard.log("CRITICAL: No AI models are responding.", "ERROR")
        return False
