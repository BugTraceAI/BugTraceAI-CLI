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


class LLMVisionMixin:
    async def analyze_visual(self, image_data: bytes, prompt: str, module_name: str = "Vision") -> Optional[str]:
        """
        Uses the specialized vision model (Qwen 3 VL or similar) to analyze screenshots.
        """
        import base64
        base64_image = base64.b64encode(image_data).decode('utf-8')

        headers = self._build_vision_headers(module_name)
        payload = self._build_vision_payload(prompt, base64_image)

        # Use orchestrator with LLM destination for proper timeout and lifecycle tracking
        try:
            async with orchestrator.session(DestinationType.LLM) as session:
                async with session.post(self.base_url, headers=headers, json=payload) as resp:
                    return await self._process_vision_response(resp, module_name, prompt)
        except Exception as e:
            logger.error(f"Visual Analysis failed: {e}", exc_info=True)
            await self._audit_log(f"Vision-{module_name}", settings.VISION_MODEL, prompt, f"ERROR: {str(e)}")
            return None

    def _build_vision_headers(self, module_name: str) -> Dict[str, str]:
        """Build headers for vision API request (provider-aware)."""
        return self._build_headers(module_name)

    def _build_vision_payload(self, prompt: str, base64_image: str) -> Dict[str, Any]:
        """Build payload for vision API request."""
        messages = [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": prompt},
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": f"data:image/jpeg;base64,{base64_image}"
                        },
                    },
                ],
            },
        ]
        payload = {
            "model": settings.VISION_MODEL,
            "messages": messages,
        }
        if self.provider_id == "openai" and settings.VISION_MODEL.startswith("gpt-5"):
            payload["max_completion_tokens"] = 1500
        else:
            payload["max_tokens"] = 1500
        if self.provider_id == "openrouter" and settings.OPENROUTER_ONLINE:
            payload["online"] = True
        return payload

    async def _process_vision_response(
        self,
        resp: aiohttp.ClientResponse,
        module_name: str,
        prompt: str
    ) -> Optional[str]:
        """Process vision API response."""
        if resp.status != 200:
            return None

        data = await resp.json()
        text = data['choices'][0]['message']['content']
        await self._audit_log(f"Vision-{module_name}", settings.VISION_MODEL, prompt, text)
        return text

    async def generate_with_image(self, prompt: str, image_path: str, model_override: str = None, module_name: str = "Vision", temperature: float = 0.3) -> str:
        """Generate LLM response with image input (vision model). Cost-conscious: Use sparingly."""
        import base64
        from pathlib import Path

        image_file = Path(image_path)
        if not image_file.exists():
            logger.error(f"[{module_name}] Image not found: {image_path}")
            return ""

        with open(image_path, 'rb') as f:
            image_data = base64.b64encode(f.read()).decode('utf-8')

        if self.api_format == 'anthropic':
            # Anthropic Messages API image schema: base64 source block
            messages = [{"role": "user", "content": [
                {"type": "text", "text": prompt},
                {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": image_data}},
            ]}]
        else:
            messages = [{"role": "user", "content": [{"type": "text", "text": prompt}, {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{image_data}"}}]}]

        # No global semaphore - each agent runs independently
        return await self._call_vision_api(messages, model_override, module_name, temperature)

    async def _call_vision_api(
        self,
        messages: List[Dict[str, Any]],
        model_override: Optional[str],
        module_name: str,
        temperature: float
    ) -> str:
        """Call vision API with image messages."""
        is_anthropic = (self.api_format == 'anthropic')
        model = model_override or settings.VALIDATION_VISION_MODEL
        if is_anthropic:
            headers = self._build_anthropic_apikey_headers(self.api_key or "")
            payload = {
                "model": model.replace("anthropic/", "", 1),
                "messages": messages,
                "temperature": temperature,
                "max_tokens": 100,
            }
        else:
            headers = self._build_headers(module_name)
            payload = self._build_request_payload(
                model,
                messages,
                temperature,
                max_tokens=100,
            )

        try:
            async with orchestrator.session(DestinationType.LLM) as session:
                async with session.post(self.base_url, headers=headers, json=payload) as resp:
                    return await self._extract_vision_result(resp, module_name, is_anthropic=is_anthropic)
        except Exception as e:
            logger.error(f"[{module_name}] Vision call failed: {e}", exc_info=True)
            return ""

    async def _extract_vision_result(self, resp: aiohttp.ClientResponse, module_name: str, is_anthropic: bool = False) -> str:
        """Extract result from vision API response."""
        if resp.status != 200:
            error_text = await resp.text()
            logger.error(f"[{module_name}] Vision API error ({resp.status}): {error_text}")
            return ""

        data = await resp.json()
        if is_anthropic:
            content = data.get("content", [])
            text_parts = [b["text"] for b in content if b.get("type") == "text"]
            result = "\n".join(text_parts) if text_parts else ""
        else:
            result = data.get("choices", [{}])[0].get("message", {}).get("content", "")
        logger.info(f"[{module_name}] Vision response: {result[:100]}")
        return result
