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
from typing import Optional, Dict, Any, List, TYPE_CHECKING
from datetime import datetime
from tenacity import retry, stop_after_attempt, wait_exponential

from bugtrace.core.ui import dashboard
from bugtrace.utils.logger import get_logger
from bugtrace.core.http_orchestrator import orchestrator, DestinationType

if TYPE_CHECKING:
    from bugtrace.core.conversation_thread import ConversationThread
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


class LLMThreadMixin:
    async def _handle_thread_response(
        self,
        resp: aiohttp.ClientResponse,
        current_model: str,
        module_name: str,
        thread: "ConversationThread",
        prompt: str,
        is_anthropic: bool = False
    ) -> Optional[str]:
        """Process API response for threaded generation."""
        if resp.status == 200:
            data = await resp.json()
            if is_anthropic:
                content = data.get("content", [])
                text_parts = [b["text"] for b in content if b.get("type") == "text"]
                response_text = "\n".join(text_parts) if text_parts else ""
                if not response_text:
                    logger.warning(f"LLM Thread: Model {current_model} returned empty response.")
                    return None
            else:
                if 'choices' not in data or len(data['choices']) == 0:
                    logger.warning(f"LLM Thread: Model {current_model} returned empty response.")
                    return None
                response_text = data['choices'][0]['message']['content']

            thread.add_message("assistant", response_text)

            # Update telemetry
            self.req_count += 1
            dashboard.total_requests += 1
            if 'usage' in data:
                tokens = data['usage'].get('total_tokens', 0)
                cost = (tokens / 1_000_000) * 0.20
                dashboard.session_cost += cost

            if self.req_count % 10 == 0:
                asyncio.create_task(self.update_balance())

            await self._audit_log(module_name, current_model, f"[Thread: {thread.thread_id}] {prompt}", response_text)
            logger.info(f"LLM Thread Success: {current_model} for {module_name} (thread: {thread.thread_id})")
            return response_text

        elif resp.status == 429:
            logger.warning(f"LLM Thread: Model {current_model} rate limited (429). Shifting...")
        else:
            error_text = await resp.text()
            logger.error(f"LLM Thread: Model {current_model} failed ({resp.status}). Shifting...")

        return None

    async def _try_thread_models(
        self,
        models_to_try: List[str],
        headers: Dict[str, str],
        messages: List[Dict[str, str]],
        temperature: float,
        max_tokens: int,
        module_name: str,
        thread: "ConversationThread",
        prompt: str
    ) -> Optional[str]:
        """Try multiple models for threaded generation."""
        for current_model in models_to_try:
            result = await self._attempt_thread_model(
                current_model, headers, messages, temperature, max_tokens,
                module_name, thread, prompt
            )
            if result:
                return result

            await asyncio.sleep(0.5)
        return None

    async def _attempt_thread_model(
        self,
        current_model: str,
        headers: Dict[str, str],
        messages: List[Dict[str, str]],
        temperature: float,
        max_tokens: int,
        module_name: str,
        thread: "ConversationThread",
        prompt: str
    ) -> Optional[str]:
        """Attempt threaded generation with a single model."""
        is_anthropic = (self.api_format == 'anthropic')
        if is_anthropic:
            api_headers = self._build_anthropic_apikey_headers(self.api_key or "")
            payload = self._build_anthropic_payload(
                current_model, messages, temperature, max_tokens, oauth=False
            )
        else:
            api_headers = headers
            payload = self._build_request_payload(
                current_model,
                messages,
                temperature,
                max_tokens,
            )

        # Use orchestrator with LLM destination for proper timeout and lifecycle tracking
        try:
            async with orchestrator.session(DestinationType.LLM) as session:
                async with session.post(self.base_url, headers=api_headers, json=payload) as resp:
                    return await self._handle_thread_response(
                        resp, current_model, module_name, thread, prompt,
                        is_anthropic=is_anthropic
                    )
        except Exception as e:
            logger.error(f"LLM Thread Exception with {current_model}: {str(e)}", exc_info=True)
            return None

    async def generate_with_thread(
        self,
        prompt: str,
        thread: "ConversationThread",
        module_name: str,
        model_override: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2000
    ) -> Optional[str]:
        """Generate text using ConversationThread for persistent context."""
        from bugtrace.core.conversation_thread import ConversationThread

        # No global semaphore - each agent runs independently
        if not self.api_key:
            logger.warning(f"LLM Client: No API Key for {module_name}")
            return None

        thread.add_message("user", prompt)
        messages = thread.get_messages(format_for_api=True)
        models_to_try = [model_override] if model_override else self.models

        result = await self._try_thread_models(
            models_to_try, self._build_headers(module_name), messages,
            temperature, max_tokens, module_name, thread, prompt
        )

        if not result:
            logger.critical(f"LLM Client: All models exhausted for threaded generation in {module_name}")

        return result
