"""LLM client shell mixin — AWS Bedrock (Converse API via boto3).

Bedrock is NOT an HTTP-with-static-key endpoint like the other providers; it
requires boto3 (synchronous) against region-specific endpoints. This mixin runs
the boto3 `converse` call inside asyncio.to_thread while preserving the engine's
failover / circuit-breaker / telemetry / audit-log behaviour. Tests patch at the
`_get_bedrock_client` / `_bedrock_converse_call` boundary (never boto3 globally)
so the asyncio.to_thread wrapper is exercised.
"""

from __future__ import annotations

import os
import time
import asyncio
from typing import Optional, Dict, Any, List, Tuple

from bugtrace.utils.logger import get_logger
from bugtrace.core.config import settings
from bugtrace.core.exceptions import (
    LLMTimeoutError,
    LLMRateLimitError,
)

logger = get_logger("core.llm_client")

# Sentinel returned by _bedrock_converse_call to signal "shift to next model"
# (permanent-for-this-model failure that is neither a retryable rate-limit nor a
# timeout). The caller translates it to None/"" per fork.
_BEDROCK_SHIFT = object()

# boto3 ClientError codes grouped by how the engine should react.
_BEDROCK_THROTTLE_CODES = {"ThrottlingException", "TooManyRequestsException"}
_BEDROCK_TIMEOUT_CODES = {"ModelTimeoutException"}


def _bedrock_image_format(path: str) -> str:
    """Map a file extension to a Bedrock `converse` image format.

    `.png` -> 'png'; `.jpg`/`.jpeg` -> 'jpeg'; anything else -> 'png' (with a
    DEBUG log). Returns a bare format token (never a leading dot or a MIME type).
    """
    ext = os.path.splitext(str(path))[1].lower()
    if ext == ".png":
        return "png"
    if ext in (".jpg", ".jpeg"):
        return "jpeg"
    logger.debug(f"[Bedrock] Unknown image extension '{ext}' for {path}; defaulting to png")
    return "png"


class LLMBedrockMixin:
    def _get_bedrock_client(self, region: str):
        """Lazily build and cache a boto3 bedrock-runtime client, keyed by region.

        boto3 is imported lazily so a CLI without Bedrock selected never imports
        it. Auth is implicit and layered: when AWS_BEARER_TOKEN_BEDROCK is set,
        boto3 >= 1.34 auto-detects it as a bearer token; otherwise boto3's default
        credential chain (env keys / AWS_PROFILE / shared config / IAM role)
        applies. The adapter writes NO credential code and logs only the mode,
        never the secret.
        """
        cache = getattr(self, "_bedrock_client", None)
        if not isinstance(cache, dict):
            cache = {}
            self._bedrock_client = cache
        if region in cache:
            return cache[region]

        import boto3  # lazy — only when Bedrock is actually used

        mode = "bearer-token" if os.environ.get("AWS_BEARER_TOKEN_BEDROCK") else "default-credential-chain"
        logger.info(f"[Bedrock] Building bedrock-runtime client (region={region}, auth={mode})")
        client = boto3.client("bedrock-runtime", region_name=region)
        cache[region] = client
        return client

    def _build_bedrock_converse_args(
        self,
        model: str,
        messages: List[Dict[str, str]],
        temperature: float,
        max_tokens: int,
    ) -> Dict[str, Any]:
        """Pure transform: OpenAI-style messages -> boto3 `converse` kwargs.

        - A single `system` message becomes `system=[{"text": ...}]` (the kwarg
          is omitted entirely when absent — converse rejects an empty system).
        - Remaining {role, content} map to messages=[{role, content:[{text}]}].
        - inferenceConfig carries maxTokens + temperature.
        - modelId is the model verbatim (no prefix stripping).
        """
        system_text: Optional[str] = None
        converse_messages: List[Dict[str, Any]] = []
        for msg in messages:
            if msg.get("role") == "system":
                system_text = msg.get("content", "")
            else:
                converse_messages.append({
                    "role": msg.get("role"),
                    "content": [{"text": msg.get("content", "")}],
                })

        args: Dict[str, Any] = {
            "modelId": model,
            "messages": converse_messages,
            "inferenceConfig": {"maxTokens": max_tokens, "temperature": temperature},
        }
        if system_text:
            args["system"] = [{"text": system_text}]
        return args

    def _parse_bedrock_text(self, data: Dict[str, Any]) -> str:
        """Join the text blocks of a converse response (output.message.content[].text)."""
        content = (((data or {}).get("output") or {}).get("message") or {}).get("content") or []
        parts = [block.get("text", "") for block in content if isinstance(block, dict) and "text" in block]
        return "\n".join(p for p in parts if p)

    async def _bedrock_converse_call(
        self,
        model: str,
        converse_args: Dict[str, Any],
    ) -> Tuple[Any, float]:
        """Run the synchronous boto3 converse call off the event loop.

        Returns (data, latency_ms) on success. Translates boto3 errors:
          - throttle codes  -> raise LLMRateLimitError (main-fork backoff / shift)
          - timeout codes / ReadTimeoutError -> raise LLMTimeoutError
          - auth / validation / not-found codes -> return _BEDROCK_SHIFT sentinel
          - any other Exception -> return _BEDROCK_SHIFT sentinel

        Shared by all three forks so the boto3 seam lives in exactly one place.
        """
        from botocore.exceptions import ClientError, ReadTimeoutError, ConnectTimeoutError

        region = settings.BEDROCK_REGION or "us-east-1"
        client = self._get_bedrock_client(region)
        start_time = time.time()
        try:
            data = await asyncio.to_thread(lambda: client.converse(**converse_args))
            latency_ms = (time.time() - start_time) * 1000
            return data, latency_ms
        except ClientError as e:
            code = (e.response or {}).get("Error", {}).get("Code", "")
            if code in _BEDROCK_THROTTLE_CODES:
                logger.warning(f"[Bedrock] {model} throttled ({code}). Raising rate-limit.")
                raise LLMRateLimitError(
                    f"Bedrock throttled {model}",
                    model=model,
                    retry_after=5.0,
                ) from None
            if code in _BEDROCK_TIMEOUT_CODES:
                logger.warning(f"[Bedrock] {model} model timeout ({code}).")
                raise LLMTimeoutError(f"Bedrock model timeout {model}", model=model) from None
            logger.error(f"[Bedrock] {model} ClientError ({code}) in region {region}. Shifting.")
            return _BEDROCK_SHIFT, (time.time() - start_time) * 1000
        except (ReadTimeoutError, ConnectTimeoutError) as e:
            logger.warning(f"[Bedrock] {model} socket timeout: {e}")
            raise LLMTimeoutError(f"Bedrock socket timeout {model}", model=model) from None
        except Exception as e:
            logger.error(f"[Bedrock] {model} unexpected error: {e}", exc_info=True)
            return _BEDROCK_SHIFT, (time.time() - start_time) * 1000

    async def _bedrock_generate(
        self,
        current_model: str,
        messages: List[Dict[str, str]],
        module_name: str,
        prompt: str,
        temperature: float,
        max_tokens: int,
        model_override: Optional[str],
        system_prompt: Optional[str],
        provider_ctx: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """Main-fork Bedrock generation.

        Replicates the post-parse sequence of generate.py::_handle_api_response by
        hand (there is no aiohttp response object for Bedrock): credential guard ->
        rate-limit -> per-model semaphore -> converse -> empty-check -> refusal ->
        record success -> usage remap -> telemetry -> audit -> return text.
        Returns None to shift; raises LLMRateLimitError/LLMTimeoutError to retry.
        """
        from botocore.exceptions import NoCredentialsError, PartialCredentialsError

        converse_args = self._build_bedrock_converse_args(current_model, messages, temperature, max_tokens)

        await self._rate_limit_acquire((provider_ctx or {}).get('provider_id'))
        sem = self._get_model_semaphore(current_model)
        async with sem:
            try:
                result = await self._bedrock_converse_call(current_model, converse_args)
            except (NoCredentialsError, PartialCredentialsError) as e:
                logger.warning(f"[Bedrock] No credentials for {current_model}: {e}")
                await self._audit_log(module_name, current_model, prompt, "SKIPPED: no Bedrock credentials")
                return None

        if result[0] is _BEDROCK_SHIFT:
            latency_ms = result[1]
            self._record_model_call(current_model, success=False, latency_ms=latency_ms)
            await self._audit_log(module_name, current_model, prompt, "ERROR: Bedrock call failed")
            return None

        data, latency_ms = result
        text = self._parse_bedrock_text(data)
        if not text:
            self._record_model_call(current_model, success=False, latency_ms=latency_ms)
            logger.warning(f"[Bedrock] {current_model} returned empty/filtered output.")
            return None

        # Refusal check (same contract as _handle_api_response)
        refusal_result = await self._handle_refusal(
            text, current_model, model_override,
            prompt, module_name, system_prompt,
            temperature, max_tokens,
        )
        if refusal_result != text:
            return refusal_result

        # Success path
        self._record_model_call(current_model, success=True, latency_ms=latency_ms)
        usage = (data or {}).get("usage", {}) or {}
        telemetry_data = {
            "usage": {
                "prompt_tokens": usage.get("inputTokens", 0),
                "completion_tokens": usage.get("outputTokens", 0),
                "total_tokens": usage.get("totalTokens", 0),
            }
        }
        await self._update_telemetry(telemetry_data, current_model, module_name)
        await self._audit_log(module_name, current_model, prompt, text)
        logger.info(f"[Bedrock] Success: {current_model} for {module_name}")
        return text

    async def _bedrock_generate_with_image(
        self,
        prompt: str,
        raw_bytes: bytes,
        img_format: str,
        model_override: Optional[str],
        module_name: str,
        temperature: float,
    ) -> str:
        """Vision wrapper for generate_with_image (Fork 3a). Returns "" on failure.

        converse image blocks carry RAW bytes (not base64). modelId defaults to
        model_override or settings.VALIDATION_VISION_MODEL.
        """
        model = model_override or settings.VALIDATION_VISION_MODEL
        converse_args: Dict[str, Any] = {
            "modelId": model,
            "messages": [{
                "role": "user",
                "content": [
                    {"text": prompt},
                    {"image": {"format": img_format, "source": {"bytes": raw_bytes}}},
                ],
            }],
            "inferenceConfig": {"maxTokens": 100, "temperature": temperature},
        }
        try:
            result = await self._bedrock_converse_call(model, converse_args)
        except Exception as e:
            logger.error(f"[Bedrock] Vision call failed for {module_name}: {e}", exc_info=True)
            await self._audit_log(f"Vision-{module_name}", model, prompt, f"ERROR: {str(e)}")
            return ""
        if result[0] is _BEDROCK_SHIFT:
            await self._audit_log(f"Vision-{module_name}", model, prompt, "ERROR: Bedrock vision call failed")
            return ""
        data, _ = result
        text = self._parse_bedrock_text(data)
        await self._audit_log(f"Vision-{module_name}", model, prompt, text)
        logger.info(f"[Bedrock] Vision response: {text[:100]}")
        return text

    async def _bedrock_analyze_visual(
        self,
        image_data: bytes,
        prompt: str,
        module_name: str,
    ) -> Optional[str]:
        """Vision wrapper for analyze_visual (Fork 3b). Returns None on failure.

        The caller supplies in-memory bytes with no path, so format is fixed to
        'jpeg' (matching today's analyze_visual behaviour). modelId = VISION_MODEL.
        """
        model = settings.VISION_MODEL
        converse_args: Dict[str, Any] = {
            "modelId": model,
            "messages": [{
                "role": "user",
                "content": [
                    {"text": prompt},
                    {"image": {"format": "jpeg", "source": {"bytes": image_data}}},
                ],
            }],
            "inferenceConfig": {"maxTokens": 1500, "temperature": 0.3},
        }
        try:
            result = await self._bedrock_converse_call(model, converse_args)
        except Exception as e:
            logger.error(f"[Bedrock] Visual analysis failed: {e}", exc_info=True)
            await self._audit_log(f"Vision-{module_name}", model, prompt, f"ERROR: {str(e)}")
            return None
        if result[0] is _BEDROCK_SHIFT:
            await self._audit_log(f"Vision-{module_name}", model, prompt, "ERROR: Bedrock visual analysis failed")
            return None
        data, _ = result
        text = self._parse_bedrock_text(data)
        await self._audit_log(f"Vision-{module_name}", model, prompt, text)
        return text
