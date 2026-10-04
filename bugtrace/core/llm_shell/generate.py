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


class LLMGenerateMixin:
    async def _handle_refusal(
        self,
        text: Optional[str],
        current_model: str,
        model_override: Optional[str],
        prompt: str,
        module_name: str,
        system_prompt: Optional[str],
        temperature: float,
        max_tokens: int
    ) -> Optional[str]:
        """Handle LLM refusal and attempt fallback to uncensored model."""
        if not text:
            return text

        if not (any(phrase.lower() in text.lower() for phrase in self.REFUSAL_PHRASES) and len(text) < 300):
            return text

        logger.warning(f"LLM Refusal Detected from {current_model}: '...{text[:50]}...'")

        fallback_model = settings.MUTATION_MODEL
        if model_override != fallback_model:
            logger.info(f"Triggering Hybrid Resilience: Switching to Uncensored Model ({fallback_model})")
            return await self.generate(
                prompt, module_name,
                model_override=fallback_model,
                system_prompt=system_prompt,
                temperature=temperature,
                max_tokens=max_tokens
            )
        else:
            logger.error("Fallback Model also refused. Returning None to prevent crash.")
            return None

    async def _update_telemetry(self, data: Dict[str, Any], current_model: str, module_name: str):
        """Update dashboard telemetry and token tracking."""
        self.req_count += 1
        dashboard.total_requests += 1

        if 'usage' not in data:
            return

        input_tokens = data['usage'].get('prompt_tokens', 0)
        output_tokens = data['usage'].get('completion_tokens', 0)
        tokens = data['usage'].get('total_tokens', 0)

        self.token_tracker.record_usage(
            model=current_model,
            agent=module_name,
            input_tokens=input_tokens,
            output_tokens=output_tokens
        )

        cost = (tokens / 1_000_000) * 0.20
        dashboard.session_cost += cost

        if self.req_count % 10 == 0:
            asyncio.create_task(self.update_balance())

    async def _handle_api_response(
        self,
        resp: aiohttp.ClientResponse,
        current_model: str,
        module_name: str,
        prompt: str,
        latency_ms: float,
        model_override: Optional[str],
        system_prompt: Optional[str],
        temperature: float,
        max_tokens: int,
        is_anthropic: bool = False
    ) -> Optional[str]:
        """Process API response and handle errors/refusals."""
        if resp.status == 200:
            data = await resp.json()

            # Parse response based on provider
            if is_anthropic:
                # Anthropic Messages API: content[0].text
                content = data.get("content", [])
                if not content:
                    self._record_model_call(current_model, success=False, latency_ms=latency_ms)
                    logger.warning(f"Anthropic API: {current_model} returned empty content.")
                    return None
                # Extract text from content blocks (skip thinking blocks)
                text_parts = [block["text"] for block in content if block.get("type") == "text"]
                text = "\n".join(text_parts) if text_parts else ""
                if not text:
                    self._record_model_call(current_model, success=False, latency_ms=latency_ms)
                    logger.warning(f"Anthropic API: {current_model} returned no text content.")
                    return None
                # Map Anthropic usage fields for telemetry
                if "usage" in data:
                    data["usage"]["prompt_tokens"] = data["usage"].get("input_tokens", 0)
                    data["usage"]["completion_tokens"] = data["usage"].get("output_tokens", 0)
                    data["usage"]["total_tokens"] = data["usage"].get("prompt_tokens", 0) + data["usage"].get("completion_tokens", 0)
                logger.info(f"Anthropic API: Using {current_model} for {module_name}")
            else:
                # OpenRouter/OpenAI format: choices[0].message.content
                if 'choices' not in data or len(data['choices']) == 0:
                    self._record_model_call(current_model, success=False, latency_ms=latency_ms)
                    logger.warning(f"LLM Shift: Model {current_model} returned empty response.")
                    return None
                text = data['choices'][0]['message']['content']

            # Check for refusal
            result = await self._handle_refusal(
                text, current_model, model_override,
                prompt, module_name, system_prompt,
                temperature, max_tokens
            )
            if result != text:
                return result

            # Success path
            self._record_model_call(current_model, success=True, latency_ms=latency_ms)
            await self._update_telemetry(data, current_model, module_name)
            await self._audit_log(module_name, current_model, prompt, text)
            logger.info(f"LLM Shift Success: Using {current_model} for {module_name}")
            return text

        elif resp.status == 429:
            # Rate limited - raise typed exception for selective retry
            self._record_model_call(current_model, success=False, latency_ms=latency_ms)
            retry_after = resp.headers.get("Retry-After", "5")
            try:
                retry_seconds = float(retry_after)
            except ValueError:
                retry_seconds = 5.0
            logger.warning(f"LLM Shift: Model {current_model} rate limited (429). Retry-After: {retry_seconds}s")
            raise LLMRateLimitError(
                f"Rate limited by {current_model}",
                model=current_model,
                retry_after=retry_seconds
            )
        elif resp.status >= 500:
            # Server error - transient, allow model shifting
            self._record_model_call(current_model, success=False, latency_ms=latency_ms)
            error_text = await resp.text()
            await self._audit_log(module_name, current_model, prompt, f"ERROR: {resp.status} - {error_text}")
            logger.warning(f"LLM Shift: Model {current_model} server error ({resp.status}). Shifting...")
        else:
            # Client error (4xx except 429) - likely permanent
            self._record_model_call(current_model, success=False, latency_ms=latency_ms)
            error_text = await resp.text()
            await self._audit_log(module_name, current_model, prompt, f"ERROR: {resp.status} - {error_text}")
            logger.error(f"LLM Shift: Model {current_model} failed ({resp.status}). Reason: {error_text}. Shifting...")

        return None

    async def generate(
        self,
        prompt: str,
        module_name: str,
        model_override: Optional[str] = None,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 1500
    ) -> Optional[str]:
        """
        Generates text using Model Shifting with Circuit Breaker resilience.

        Circuit Breaker States:
        - HEALTHY: Normal operation
        - DEGRADED: Throttled requests (API unstable)
        - CRITICAL: Circuit OPEN - returns fallback responses

        If a model fails or is filtered, it 'shifts' to the next one in the list.
        """
        # No global semaphore - each agent runs independently
        # Rate limiting handled by retry with exponential backoff (tenacity)
        if not self.api_key and not settings.ANTHROPIC_OAUTH_ENABLED:
            logger.warning(f"LLM Client: No API Key found for {module_name}. Skipping generation.")
            await self._audit_log(module_name, "NONE", prompt, "SKIPPED: Missing API Key")
            return None

        # ========== Circuit Breaker Check ==========
        should_proceed, cb_status = self._check_circuit_breaker()

        if not should_proceed:
            # Circuit is OPEN - return fallback response
            fallback = self._get_fallback_response(prompt, system_prompt)
            await self._audit_log(
                module_name, "CIRCUIT_BREAKER",
                prompt, f"FALLBACK: {fallback}"
            )
            return fallback

        # Apply throttling if in DEGRADED state
        await self._apply_degraded_throttling()

        # ========== Normal Generation: Model Shifting + Provider Failover ==========
        messages = self._build_messages(prompt, system_prompt)

        # FIX: If model_override is provided, try it first but fall back to the rest.
        def _models_for(models: List[str]) -> List[str]:
            if model_override:
                return [model_override] + [m for m in models if m != model_override]
            return self._sort_models_by_availability(list(models))

        # Ordered attempts: primary provider first, then each failover provider (its own
        # base_url / key / headers / models). We only move to the next provider once the
        # current one's models are all exhausted — so a 403 key-limit no longer kills the call.
        attempts: List[Dict[str, Any]] = [{
            'provider_id': self.provider_id,
            'base_url': self.base_url,
            'headers': self._build_headers(module_name),
            'models': _models_for(self.models),
        }]
        for fp in self._failover_providers:
            attempts.append({
                'provider_id': fp['provider_id'],
                'base_url': fp['base_url'],
                'headers': self._build_headers_for(fp['api_key'], fp['headers'], fp['provider_id'], module_name),
                'models': _models_for(fp['models']),
            })

        try:
            for idx, attempt in enumerate(attempts):
                if not attempt['models']:
                    continue
                provider_ctx = {'provider_id': attempt['provider_id'], 'base_url': attempt['base_url']}
                result = await self._try_generate_with_models(
                    attempt['models'], attempt['headers'], messages, module_name, prompt,
                    temperature, max_tokens, model_override, system_prompt, provider_ctx
                )
                if result:
                    if idx > 0:
                        logger.warning(f"[Failover] Recovered for {module_name} on provider '{attempt['provider_id']}' (primary exhausted)")
                    self._record_circuit_success()
                    return result
                if idx + 1 < len(attempts):
                    logger.warning(f"[Failover] Provider '{attempt['provider_id']}' exhausted for {module_name} → trying '{attempts[idx + 1]['provider_id']}'")

            # All providers + models exhausted
            self._record_circuit_failure(Exception("All providers exhausted"))
            logger.critical(
                f"LLM Client: All providers exhausted for module {module_name}. "
                f"Circuit state: {self.health_state}"
            )

            # Return fallback instead of None to prevent crashes
            if self.health_state == LLMHealthState.CRITICAL:
                return self._get_fallback_response(prompt, system_prompt)

            return None

        except Exception as e:
            self._record_circuit_failure(e)
            logger.error(f"LLM Generate exception: {e}", exc_info=True)

            # If circuit just opened, return fallback
            if self.health_state == LLMHealthState.CRITICAL:
                return self._get_fallback_response(prompt, system_prompt)

            raise  # Let tenacity retry handle it

    async def generate_reporting_fallback(
        self,
        prompt: str,
        module_name: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.2,
        max_tokens: int = 1500,
    ) -> Optional[str]:
        """One-shot reporting/enrichment fallback to a SECONDARY provider preset
        (`settings.REPORTING_FAILOVER_PROVIDER`, default 'anthropic'), used only when the
        active provider's reporting call fails or degrades. Fully self-contained: loads the
        fallback provider's own preset (base_url, key from api_key_env, api_format,
        REPORTING_MODEL) and does NOT mutate the active provider or its circuit breaker.
        Scoped to the reporting phase — never used for scan-time generation. Never raises.
        """
        pid = (getattr(settings, "REPORTING_FAILOVER_PROVIDER", "anthropic") or "").strip().lower()
        if not pid or pid == self.provider_id:
            return None
        try:
            providers_dir = settings.BASE_DIR / "bugtrace" / "data" / "providers"
            preset = json.loads((providers_dir / f"{pid}.json").read_text(encoding="utf-8"))
        except Exception as e:
            logger.warning(f"[ReportingFailover] Could not load provider '{pid}': {e}")
            return None
        key = os.environ.get(preset.get("api_key_env", ""), "") if preset.get("api_key_env") else ""
        if not key:
            logger.warning(f"[ReportingFailover] Provider '{pid}' has no API key — skipping")
            return None
        models_cfg = preset.get("models", {}) or {}
        model = models_cfg.get("REPORTING_MODEL") or models_cfg.get("DEFAULT_MODEL") or ""
        base_url = preset.get("base_url", "")
        api_format = preset.get("api_format", "openai")
        if not model or not base_url:
            logger.warning(f"[ReportingFailover] Provider '{pid}' preset missing model/base_url")
            return None
        messages = self._build_messages(prompt, system_prompt)
        timeout = aiohttp.ClientTimeout(total=LLM_TOTAL_TIMEOUT, connect=LLM_CONNECT_TIMEOUT)
        try:
            if api_format == "anthropic":
                api_headers = self._build_anthropic_apikey_headers(key)
                api_payload = self._build_anthropic_payload(model, messages, temperature, max_tokens, oauth=False)
            else:
                api_headers = self._build_headers_for(key, preset.get("headers", {}) or {}, pid, module_name)
                api_payload = self._build_request_payload(model, messages, temperature, max_tokens)
            async with orchestrator.session(DestinationType.LLM) as session:
                async with session.post(base_url, headers=api_headers, json=api_payload, timeout=timeout) as resp:
                    if resp.status != 200:
                        logger.warning(f"[ReportingFailover] '{pid}' {model} HTTP {resp.status} for {module_name}")
                        return None
                    data = await resp.json()
                    if api_format == "anthropic":
                        parts = [b.get("text", "") for b in data.get("content", []) if b.get("type") == "text"]
                        text = "\n".join(p for p in parts if p)
                    else:
                        ch = data.get("choices", [])
                        text = ch[0].get("message", {}).get("content", "") if ch else ""
                    if text:
                        logger.info(f"[ReportingFailover] Recovered '{module_name}' via '{pid}' ({model})")
                    return text or None
        except Exception as e:
            logger.warning(f"[ReportingFailover] '{pid}' call failed for {module_name}: {e}")
            return None

    async def _try_generate_with_models(
        self,
        models_to_try: List[str],
        headers: Dict[str, str],
        messages: List[Dict[str, str]],
        module_name: str,
        prompt: str,
        temperature: float,
        max_tokens: int,
        model_override: Optional[str],
        system_prompt: Optional[str],
        provider_ctx: Optional[Dict[str, Any]] = None
    ) -> Optional[str]:
        """Try generation with each model in the list.

        For each model, attempts 3 retries with exponential backoff before shifting to next model.
        Handles typed exceptions for better retry logic. `provider_ctx` (base_url + provider_id)
        targets a specific provider for failover without mutating the shared client.
        """
        for current_model in models_to_try:
            # Skip models with zero available slots if others remain
            sem = self._get_model_semaphore(current_model)
            if sem._value <= 0 and current_model != models_to_try[-1]:
                logger.debug(f"[LoadBalancer] Skipping {current_model} (0 slots free), trying next model")
                continue

            # Try this model up to 3 times with exponential backoff
            for retry_attempt in range(3):
                try:
                    result = await self._attempt_model_generation(
                        current_model, headers, messages, module_name, prompt,
                        temperature, max_tokens, model_override, system_prompt, provider_ctx
                    )

                    if result:
                        if retry_attempt > 0:
                            logger.info(f"LLM Retry Success: {current_model} succeeded on attempt {retry_attempt + 1}")
                        return result

                except LLMTimeoutError as e:
                    # Transient timeout - retry with longer wait
                    if retry_attempt < 2:
                        wait_time = 2 ** (retry_attempt + 1)  # 2s, 4s, 8s for timeouts
                        logger.warning(
                            f"LLM Timeout {retry_attempt + 1}/3: {current_model}, "
                            f"waiting {wait_time}s before retry..."
                        )
                        await asyncio.sleep(wait_time)
                        continue
                    # After 3 timeouts, shift to next model
                    break

                except LLMRateLimitError as e:
                    # Rate limited - use retry_after if available, else longer backoff
                    retry_after = e.context.get("retry_after_seconds", 5)
                    logger.warning(f"LLM Rate Limited: {current_model}, waiting {retry_after}s...")
                    await asyncio.sleep(retry_after)
                    continue

                # If result is None (not an exception), wait before retrying
                if retry_attempt < 2:
                    wait_time = 2 ** retry_attempt  # 1s, 2s, 4s
                    logger.warning(
                        f"LLM Retry {retry_attempt + 1}/3: {current_model} failed, "
                        f"waiting {wait_time}s before retry..."
                    )
                    await asyncio.sleep(wait_time)

            # After 3 failed retries, shift to next model
            logger.warning(
                f"LLM Shift: {current_model} failed after 3 retries. "
                f"Shifting to next model..."
            )
            await asyncio.sleep(0.5)

        return None

    async def _attempt_model_generation(
        self,
        current_model: str,
        headers: Dict[str, str],
        messages: List[Dict[str, str]],
        module_name: str,
        prompt: str,
        temperature: float,
        max_tokens: int,
        model_override: Optional[str],
        system_prompt: Optional[str],
        provider_ctx: Optional[Dict[str, Any]] = None
    ) -> Optional[str]:
        """Attempt generation with a single model.

        Uses explicit timeouts (90s total, 10s connect) to prevent hanging.
        Routes anthropic/ models to Anthropic API, everything else to the active provider
        (or the failover provider in `provider_ctx`, when set).
        """
        # Routing precedence:
        #  1. api_format=='anthropic' provider  → Anthropic Messages API via x-api-key
        #  2. OAuth path (anthropic/ model + ANTHROPIC_OAUTH_ENABLED) → Bearer token
        #  3. everything else → OpenAI-format (OpenRouter/Z.ai)
        is_anthropic_apikey = (self.api_format == 'anthropic')
        is_anthropic = is_anthropic_apikey or self._is_anthropic_model(current_model)
        if is_anthropic_apikey:
            if not self.api_key:
                logger.warning(f"Anthropic API key unavailable, skipping {current_model}")
                return None
            api_url = (provider_ctx or {}).get('base_url') or self.base_url
            api_headers = self._build_anthropic_apikey_headers(self.api_key)
            api_payload = self._build_anthropic_payload(current_model, messages, temperature, max_tokens, oauth=False)
            # Per-provider request-rate gate (respects the preset's rate_limit)
            await self._rate_limit_acquire((provider_ctx or {}).get('provider_id'))
        elif is_anthropic:
            token = await self._ensure_anthropic_token()
            if not token:
                logger.warning(f"Anthropic OAuth token unavailable, skipping {current_model}")
                return None  # Triggers model shifting to next (OpenRouter) model
            api_url = "https://api.anthropic.com/v1/messages?beta=true"
            api_headers = self._build_anthropic_headers(token, module_name)
            api_payload = self._build_anthropic_payload(current_model, messages, temperature, max_tokens)
        else:
            api_url = (provider_ctx or {}).get('base_url') or self.base_url
            api_headers = headers
            api_payload = self._build_request_payload(current_model, messages, temperature, max_tokens)
            # Per-provider request-rate gate (provider HTTP path only; Anthropic is separate)
            await self._rate_limit_acquire((provider_ctx or {}).get('provider_id'))

        start_time = time.time()

        # Explicit timeout configuration for resilience
        timeout = aiohttp.ClientTimeout(
            total=LLM_TOTAL_TIMEOUT,
            connect=LLM_CONNECT_TIMEOUT
        )

        # Per-model concurrency limiter: wait for a slot before making the request
        sem = self._get_model_semaphore(current_model)
        try:
            async with sem:
                async with orchestrator.session(DestinationType.LLM) as session:
                    async with session.post(
                        api_url,
                        headers=api_headers,
                        json=api_payload,
                        timeout=timeout
                    ) as resp:
                        latency_ms = (time.time() - start_time) * 1000
                        return await self._handle_api_response(
                            resp, current_model, module_name, prompt,
                            latency_ms, model_override, system_prompt,
                            temperature, max_tokens,
                            is_anthropic=is_anthropic
                        )
        except asyncio.TimeoutError as e:
            # Transient: LLM request timed out - worth retrying
            latency_ms = (time.time() - start_time) * 1000
            self._record_model_call(current_model, success=False, latency_ms=latency_ms)
            await self._audit_log(module_name, current_model, prompt, f"TIMEOUT after {latency_ms:.0f}ms")
            logger.warning(f"LLM Shift Timeout with {current_model} after {latency_ms:.0f}ms")
            raise LLMTimeoutError(
                f"LLM request timed out after {latency_ms:.0f}ms",
                model=current_model,
                context={"latency_ms": latency_ms, "module": module_name},
                cause=e
            ) from None  # Suppress chained exception for cleaner logs
        except aiohttp.ClientConnectorError as e:
            # Transient: Network connection failed
            latency_ms = (time.time() - start_time) * 1000
            self._record_model_call(current_model, success=False, latency_ms=latency_ms)
            await self._audit_log(module_name, current_model, prompt, f"CONNECTION_ERROR: {str(e)}")
            logger.warning(f"LLM connection error with {current_model}: {e}")
            return None  # Allow model shifting
        except aiohttp.ClientError as e:
            # Transient: Other aiohttp errors (SSL, etc.)
            latency_ms = (time.time() - start_time) * 1000
            self._record_model_call(current_model, success=False, latency_ms=latency_ms)
            await self._audit_log(module_name, current_model, prompt, f"CLIENT_ERROR: {str(e)}")
            logger.warning(f"LLM client error with {current_model}: {e}")
            return None  # Allow model shifting
        except LLMError:
            # Re-raise typed LLM exceptions
            raise
        except Exception as e:
            # Catch-all for unexpected errors
            latency_ms = (time.time() - start_time) * 1000
            self._record_model_call(current_model, success=False, latency_ms=latency_ms)
            await self._audit_log(module_name, current_model, prompt, f"EXCEPTION: {str(e)}")
            logger.error(f"LLM Shift Exception with {current_model}: {str(e)}", exc_info=True)
            return None
