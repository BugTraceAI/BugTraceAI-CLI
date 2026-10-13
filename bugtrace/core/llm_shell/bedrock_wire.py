"""AWS Bedrock Converse transport used by the CLI LLM client.

The boto3 SDK is imported only when Bedrock is selected. Synchronous SDK calls
run in a worker thread so they do not block the async scan pipeline. Clients are
created per call so a provider/key change cannot reuse a client bound to older
credentials.
"""

from __future__ import annotations

import asyncio
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from bugtrace.core.config import settings
from bugtrace.core.exceptions import LLMRateLimitError, LLMTimeoutError
from bugtrace.utils.logger import get_logger

logger = get_logger("core.llm_client")

_IMAGE_FORMATS = {"png", "jpeg", "gif", "webp"}
_THROTTLE_CODES = {"ThrottlingException", "TooManyRequestsException"}
_TIMEOUT_CODES = {"ModelTimeoutException", "ReadTimeoutError", "ConnectTimeoutError"}


def bedrock_image_format(path: str) -> str:
    """Return a Bedrock-supported image format or reject unknown file types."""
    suffix = Path(path).suffix.lower().lstrip(".")
    if suffix == "jpg":
        suffix = "jpeg"
    if suffix not in _IMAGE_FORMATS:
        raise ValueError(f"Unsupported Bedrock image format: {suffix or 'unknown'}")
    return suffix


def bedrock_image_format_from_bytes(data: bytes) -> str:
    """Identify raw screenshot bytes for the Converse image format field."""
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        return "webp"
    raise ValueError("Unsupported Bedrock image bytes")


def build_converse_request(
    model: str,
    messages: List[Dict[str, Any]],
    temperature: float,
    max_tokens: int,
    image: Optional[bytes] = None,
    image_format: Optional[str] = None,
) -> Dict[str, Any]:
    """Translate the CLI's OpenAI-style messages into Converse input."""
    system_blocks: List[Dict[str, str]] = []
    converse_messages: List[Dict[str, Any]] = []

    for message in messages:
        role = message.get("role", "user")
        content = message.get("content", "")
        if isinstance(content, list):
            text = "\n".join(
                str(part.get("text", ""))
                for part in content
                if isinstance(part, dict) and part.get("type") == "text"
            )
        else:
            text = str(content)

        if role == "system":
            if text:
                system_blocks.append({"text": text})
            continue
        # Converse accepts only user/assistant roles. Tool messages are treated
        # as user context; this client currently does not expose tool-call blocks.
        converse_role = "assistant" if role == "assistant" else "user"
        converse_messages.append({"role": converse_role, "content": [{"text": text}]})

    if image is not None:
        if image_format not in _IMAGE_FORMATS:
            raise ValueError("A supported image_format is required when passing image bytes")
        image_block = {"image": {"format": image_format, "source": {"bytes": image}}}
        user_message = next((m for m in reversed(converse_messages) if m["role"] == "user"), None)
        if user_message is None:
            user_message = {"role": "user", "content": []}
            converse_messages.append(user_message)
        user_message["content"].append(image_block)

    request: Dict[str, Any] = {
        "modelId": model,
        "messages": converse_messages,
        "inferenceConfig": {"maxTokens": max_tokens, "temperature": temperature},
    }
    if system_blocks:
        request["system"] = system_blocks
    return request


def parse_converse_response(response: Dict[str, Any]) -> Tuple[str, Dict[str, int]]:
    """Extract text and normalize Bedrock token usage for existing telemetry."""
    output = response.get("output") or {}
    message = output.get("message") or {}
    blocks = message.get("content") or []
    text = "\n".join(
        str(block["text"])
        for block in blocks
        if isinstance(block, dict) and block.get("text")
    )
    usage = response.get("usage") or {}
    input_tokens = int(usage.get("inputTokens", 0) or 0)
    output_tokens = int(usage.get("outputTokens", 0) or 0)
    return text, {
        "prompt_tokens": input_tokens,
        "completion_tokens": output_tokens,
        "total_tokens": int(usage.get("totalTokens", input_tokens + output_tokens) or 0),
    }


class LLMBedrockMixin:
    def _bedrock_region(self) -> Optional[str]:
        """Use explicit BugTraceAI configuration, then let boto3 resolve AWS config."""
        region = (
            getattr(self, "bedrock_region", None)
            or getattr(settings, "BEDROCK_REGION", None)
            or os.environ.get("AWS_REGION")
            or os.environ.get("AWS_DEFAULT_REGION")
        )
        region = (region or "").strip()
        if region:
            return region
        return None

    def _bedrock_sync_converse(self, model: str, request: Dict[str, Any]) -> Dict[str, Any]:
        """Perform one synchronous Converse call; separated for hermetic tests."""
        import boto3
        from botocore.config import Config
        from bugtrace.core.llm_shell.types import LLM_CONNECT_TIMEOUT, LLM_TOTAL_TIMEOUT

        client_options: Dict[str, Any] = {
            "config": Config(
                connect_timeout=LLM_CONNECT_TIMEOUT,
                read_timeout=LLM_TOTAL_TIMEOUT,
                retries={"mode": "standard", "max_attempts": 2},
            )
        }
        region = self._bedrock_region()
        if region:
            client_options["region_name"] = region
        client = boto3.client("bedrock-runtime", **client_options)
        try:
            return client.converse(**request)
        finally:
            client.close()

    async def _bedrock_converse(
        self,
        model: str,
        request: Dict[str, Any],
    ) -> Tuple[Optional[Dict[str, Any]], float]:
        """Run Converse off-loop and translate retryable AWS errors."""
        started = time.monotonic()
        try:
            response = await asyncio.to_thread(self._bedrock_sync_converse, model, request)
            return response, (time.monotonic() - started) * 1000
        except Exception as exc:
            response = getattr(exc, "response", None)
            error = response.get("Error", {}) if isinstance(response, dict) else {}
            code = str(error.get("Code") or type(exc).__name__)
            latency_ms = (time.monotonic() - started) * 1000
            if code in _THROTTLE_CODES:
                raise LLMRateLimitError(
                    f"Bedrock throttled {model}", model=model, retry_after=5.0
                ) from None
            if code in _TIMEOUT_CODES or "Timeout" in type(exc).__name__:
                raise LLMTimeoutError(f"Bedrock timed out for {model}", model=model) from None
            logger.warning("Bedrock Converse failed for %s (%s)", model, code)
            return None, latency_ms

    async def _bedrock_request(
        self,
        model: str,
        messages: List[Dict[str, Any]],
        temperature: float,
        max_tokens: int,
        image: Optional[bytes] = None,
        image_format: Optional[str] = None,
    ) -> Tuple[Optional[Dict[str, Any]], float]:
        await self._rate_limit_acquire(self.provider_id)
        request = build_converse_request(
            model, messages, temperature, max_tokens, image=image, image_format=image_format
        )
        async with self._get_model_semaphore(model):
            return await self._bedrock_converse(model, request)

    async def _bedrock_generate(
        self,
        current_model: str,
        messages: List[Dict[str, Any]],
        module_name: str,
        prompt: str,
        temperature: float,
        max_tokens: int,
        model_override: Optional[str],
        system_prompt: Optional[str],
    ) -> Optional[str]:
        response, latency_ms = await self._bedrock_request(
            current_model, messages, temperature, max_tokens
        )
        if response is None:
            self._record_model_call(current_model, success=False, latency_ms=latency_ms)
            await self._audit_log(module_name, current_model, prompt, "ERROR: Bedrock Converse failed")
            return None

        text, usage = parse_converse_response(response)
        if not text:
            self._record_model_call(current_model, success=False, latency_ms=latency_ms)
            await self._audit_log(module_name, current_model, prompt, "ERROR: Bedrock returned empty content")
            return None

        result = await self._handle_refusal(
            text, current_model, model_override, prompt, module_name,
            system_prompt, temperature, max_tokens,
        )
        if result != text:
            return result

        self._record_model_call(current_model, success=True, latency_ms=latency_ms)
        await self._update_telemetry({"usage": usage}, current_model, module_name)
        await self._audit_log(module_name, current_model, prompt, text)
        logger.info("Bedrock Converse success: %s for %s", current_model, module_name)
        return text

    async def _bedrock_thread(
        self,
        current_model: str,
        messages: List[Dict[str, Any]],
        module_name: str,
        thread: Any,
        prompt: str,
        temperature: float,
        max_tokens: int,
    ) -> Optional[str]:
        response, latency_ms = await self._bedrock_request(
            current_model, messages, temperature, max_tokens
        )
        if response is None:
            await self._audit_log(module_name, current_model, f"[Thread: {thread.thread_id}] {prompt}",
                                  "ERROR: Bedrock Converse failed")
            return None
        text, usage = parse_converse_response(response)
        if not text:
            return None
        thread.add_message("assistant", text)
        self._record_model_call(current_model, success=True, latency_ms=latency_ms)
        await self._update_telemetry({"usage": usage}, current_model, module_name)
        await self._audit_log(module_name, current_model, f"[Thread: {thread.thread_id}] {prompt}", text)
        return text

    async def _bedrock_vision(
        self,
        image_data: bytes,
        prompt: str,
        module_name: str,
        model: str,
        image_format: str,
        max_tokens: int,
        temperature: float = 0.2,
    ) -> Optional[str]:
        response, latency_ms = await self._bedrock_request(
            model,
            [{"role": "user", "content": prompt}],
            temperature,
            max_tokens,
            image=image_data,
            image_format=image_format,
        )
        if response is None:
            self._record_model_call(model, success=False, latency_ms=latency_ms)
            await self._audit_log(f"Vision-{module_name}", model, prompt, "ERROR: Bedrock Converse failed")
            return None
        text, usage = parse_converse_response(response)
        if text:
            self._record_model_call(model, success=True, latency_ms=latency_ms)
            await self._update_telemetry({"usage": usage}, model, f"Vision-{module_name}")
            await self._audit_log(f"Vision-{module_name}", model, prompt, text)
            return text
        self._record_model_call(model, success=False, latency_ms=latency_ms)
        return None
