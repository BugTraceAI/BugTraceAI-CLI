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


class LLMStreamMixin:
    async def _process_stream_line(
        self,
        line: bytes,
        full_response: str,
        on_chunk: Optional[callable]
    ) -> tuple[str, Optional[str]]:
        """Process a single line from streaming response.

        Returns:
            Tuple of (updated_full_response, chunk_or_none)
        """
        line_str = line.decode('utf-8').strip()
        if not line_str or not line_str.startswith('data: '):
            return full_response, None

        data_str = line_str[6:]  # Remove 'data: ' prefix
        if data_str == '[DONE]':
            return full_response, None

        return self._extract_stream_chunk(data_str, full_response, on_chunk)

    def _extract_stream_chunk(
        self,
        data_str: str,
        full_response: str,
        on_chunk: Optional[callable]
    ) -> tuple[str, Optional[str]]:
        """Extract chunk from stream data."""
        try:
            data = json.loads(data_str)
            if 'choices' not in data or len(data['choices']) == 0:
                return full_response, None

            delta = data['choices'][0].get('delta', {})
            chunk = delta.get('content', '')

            if not chunk:
                return full_response, None

            full_response += chunk
            if on_chunk:
                on_chunk(chunk)
            return full_response, chunk

        except json.JSONDecodeError:
            return full_response, None

    async def _stream_response_content(
        self,
        resp: aiohttp.ClientResponse,
        full_response: str,
        on_chunk: Optional[callable]
    ):
        """Stream and yield response content line by line."""
        async for line in resp.content:
            full_response, chunk = await self._process_stream_line(
                line, full_response, on_chunk
            )
            if chunk:
                yield chunk, full_response
            else:
                yield None, full_response

    async def generate_stream(
        self,
        prompt: str,
        module_name: str,
        model_override: Optional[str] = None,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 1500,
        on_chunk: Optional[callable] = None
    ):
        """Generate with streaming response, yields chunks as they arrive."""
        # No global semaphore - each agent runs independently
        if not self.api_key:
            logger.warning(f"LLM Client: No API Key for streaming {module_name}")
            return

        model = model_override or (self.models[0] if self.models else None)
        if not model:
            logger.error("No model available for streaming")
            return

        headers = self._build_headers(module_name)
        messages = self._build_messages(prompt, system_prompt)
        payload = self._build_stream_payload(model, messages, temperature, max_tokens)

        async for chunk, full_response in self._execute_stream_request(
            headers, payload, on_chunk, module_name, model, prompt
        ):
            if chunk:
                yield chunk

    def _build_stream_payload(
        self,
        model: str,
        messages: List[Dict[str, str]],
        temperature: float,
        max_tokens: int
    ) -> Dict[str, Any]:
        """Build payload for streaming request."""
        payload = self._build_request_payload(
            model,
            messages,
            temperature,
            max_tokens,
        )
        payload["stream"] = True
        return payload

    async def _execute_stream_request(
        self,
        headers: Dict[str, str],
        payload: Dict[str, Any],
        on_chunk: Optional[callable],
        module_name: str,
        model: str,
        prompt: str
    ):
        """Execute streaming API request."""
        full_response = ""

        # Use orchestrator's isolated_session for streaming (LLM destination)
        try:
            async with orchestrator.isolated_session(DestinationType.LLM, headers) as session:
                resp = await session.post(self.base_url, headers=headers, json=payload)

                try:
                    async for chunk, full_response in self._handle_stream_response(
                        resp, full_response, on_chunk
                    ):
                        yield chunk, full_response
                finally:
                    await resp.close()

            await self._audit_log(module_name, model, prompt, full_response)
        except Exception as e:
            logger.error(f"Streaming error: {e}", exc_info=True)

    async def _handle_stream_response(
        self,
        resp: aiohttp.ClientResponse,
        full_response: str,
        on_chunk: Optional[callable]
    ):
        """Handle streaming response and yield chunks."""
        if resp.status != 200:
            error_text = await resp.text()
            logger.error(f"Stream error ({resp.status}): {error_text}")
            return

        async for chunk, full_response in self._stream_response_content(
            resp, full_response, on_chunk
        ):
            yield chunk, full_response
