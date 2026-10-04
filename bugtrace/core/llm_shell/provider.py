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


class LLMProviderMixin:
    def _apply_provider_config(self, provider_cfg: Dict[str, Any], api_key: Optional[str] = None) -> None:
        """Apply every provider-derived attribute from a preset config dict.

        Single source of truth for provider-scoped state — called from __init__
        and from reconfigure_from_active_preset() (WEB provider switch) so the two
        can never drift. A partial hot-reload that forgets one field (e.g.
        api_format) is exactly the class of bug this consolidation prevents.
        """
        self.provider_id = settings.PROVIDER
        api_key_env = provider_cfg.get('api_key_env', 'OPENROUTER_API_KEY')
        # Resolve the key from THIS provider's env var — never fall back to another
        # provider's key (a stale OPENROUTER key must not leak into e.g. anthropic).
        self.api_key = api_key or os.environ.get(api_key_env) or getattr(settings, api_key_env, None)
        self.base_url = provider_cfg.get('base_url', "https://openrouter.ai/api/v1/chat/completions")
        # Provider wire format: "openai" (OpenRouter/Z.ai chat/completions) or "anthropic"
        # (Anthropic Messages API, x-api-key). Drives payload build + response parsing.
        self.api_format = provider_cfg.get('api_format', 'openai')

        # Priority list for Model Shifting
        self.models = [m.strip() for m in settings.PRIMARY_MODELS.split(",") if m.strip()]
        if not self.models:
            logger.critical("No PRIMARY_MODELS found in configuration. Please check bugtraceaicli.conf.")
            self.models = []
        if not self.api_key:
            logger.warning(f"{api_key_env} is not set. LLM features will be disabled.")

        # Provider custom headers (e.g., Accept-Language for Z.ai)
        self._provider_headers = provider_cfg.get('headers', {})

        # Per-model concurrency limiter (from preset). Reset semaphores — the model
        # set (and its per-model limits) may have changed on a provider switch.
        self._concurrency_cfg = provider_cfg.get('concurrency', {})
        self._model_semaphores: Dict[str, asyncio.Semaphore] = {}

        # ===== Provider failover chain + per-provider rate limiting =====
        # `failover` in the active preset lists provider ids to fall back to when the
        # primary's models are all exhausted (e.g. a 403 key-limit kills every model).
        self._failover_providers: List[Dict[str, Any]] = self._load_failover_providers(provider_cfg)
        self._rate_limiters: Dict[str, _ProviderRateLimiter] = {}
        self._register_rate_limiter(self.provider_id, provider_cfg.get('rate_limit'))
        for fp in self._failover_providers:
            self._register_rate_limiter(fp['provider_id'], fp.get('rate_limit'))
        if self._failover_providers:
            logger.info(f"[Failover] Provider chain: {self.provider_id} → {' → '.join(fp['provider_id'] for fp in self._failover_providers)}")

    def reconfigure_from_active_preset(self, api_key: Optional[str] = None) -> None:
        """Re-apply provider config after a runtime provider switch (WEB Provider tab).

        `settings.PROVIDER` and `settings._provider_config` must already reflect the
        new provider (the /api/provider route reloads the preset before calling this).
        Moves api_format, base_url, models, headers, concurrency, failover chain and
        rate limiters together so no attribute is left pointing at the old provider.
        """
        self._apply_provider_config(getattr(settings, '_provider_config', {}), api_key)
        logger.info(
            f"LLM client reconfigured for provider: {self.provider_id} "
            f"(api_format={self.api_format}, base_url={self.base_url})"
        )

    def _get_model_semaphore(self, model: str) -> asyncio.Semaphore:
        """Get or create a semaphore for the given model.

        Limits concurrent in-flight requests per model to prevent 429 avalanches.
        Concurrency limits are read from the provider preset's 'concurrency' map.
        """
        if model not in self._model_semaphores:
            limit = self._concurrency_cfg.get(model, self._concurrency_cfg.get('default', 999))
            self._model_semaphores[model] = asyncio.Semaphore(limit)
            if limit < 999:
                logger.debug(f"[Concurrency] Created semaphore for {model}: max {limit} concurrent")
        return self._model_semaphores[model]

    def _sort_models_by_availability(self, models: List[str]) -> List[str]:
        """Sort models by available semaphore slots (most available first).

        Distributes load across all models instead of always hitting the first one.
        Models with zero available slots go to the end.
        """
        def available_slots(model: str) -> int:
            sem = self._get_model_semaphore(model)
            return sem._value

        return sorted(models, key=available_slots, reverse=True)

    def _build_request_payload(
        self,
        model: str,
        messages: List[Dict[str, Any]],
        temperature: float,
        max_tokens: int
    ) -> Dict[str, Any]:
        """Build API request payload with common parameters."""
        payload = {
            "model": model,
            "messages": messages,
        }
        if self.provider_id == "openai" and model.startswith("gpt-5"):
            # GPT-5 chat completions use the completion-token parameter and
            # reject non-default temperature values at reasoning settings.
            payload["max_completion_tokens"] = max_tokens
        else:
            payload["temperature"] = temperature
            payload["max_tokens"] = max_tokens
        if self.provider_id == "openrouter" and settings.OPENROUTER_ONLINE:
            payload["online"] = True
        return payload

    def _build_headers(self, module_name: str) -> Dict[str, str]:
        """Build API request headers (provider-aware)."""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        # Apply provider custom headers (e.g., Accept-Language for Z.ai)
        if self._provider_headers:
            headers.update(self._provider_headers)
        # OpenRouter-specific headers
        if self.provider_id == "openrouter":
            headers["HTTP-Referer"] = "https://bugtraceai.com"
            headers["X-Title"] = f"Bugtrace-{module_name}"
        return headers

    def _build_headers_for(self, api_key: str, provider_headers: Dict[str, str], provider_id: str, module_name: str) -> Dict[str, str]:
        """Build headers for an arbitrary (failover) provider — no shared self.* mutation."""
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        if provider_headers:
            headers.update(provider_headers)
        if provider_id == "openrouter":
            headers["HTTP-Referer"] = "https://bugtraceai.com"
            headers["X-Title"] = f"Bugtrace-{module_name}"
        return headers

    def _load_failover_providers(self, provider_cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Load the provider preset(s) named in the active preset's `failover` list.

        Each entry resolves its own base_url, API key (from its api_key_env), headers,
        models and rate_limit. Providers without an available key are skipped (logged).
        """
        failover_ids = provider_cfg.get('failover', []) or []
        if not isinstance(failover_ids, list):
            return []
        providers_dir = settings.BASE_DIR / "bugtrace" / "data" / "providers"
        out: List[Dict[str, Any]] = []
        for pid in failover_ids:
            pid = str(pid).strip().lower()
            if not pid or pid == self.provider_id:
                continue
            try:
                preset = json.loads((providers_dir / f"{pid}.json").read_text(encoding="utf-8"))
            except Exception as e:
                logger.warning(f"[Failover] Could not load provider preset '{pid}': {e}")
                continue
            key_env = preset.get('api_key_env', '')
            key = os.environ.get(key_env, '') if key_env else ''
            if not key:
                logger.warning(f"[Failover] Provider '{pid}' skipped — no API key ({key_env or 'unset'})")
                continue
            models_str = (preset.get('models', {}) or {}).get('PRIMARY_MODELS', '') or ''
            models = [m.strip() for m in models_str.split(',') if m.strip()]
            if not models:
                logger.warning(f"[Failover] Provider '{pid}' skipped — no PRIMARY_MODELS in preset")
                continue
            out.append({
                'provider_id': pid,
                'base_url': preset.get('base_url'),
                'api_key': key,
                'headers': preset.get('headers', {}) or {},
                'models': models,
                'rate_limit': preset.get('rate_limit'),
            })
        return out

    def _register_rate_limiter(self, provider_id: str, rate_limit_cfg: Any) -> None:
        rpm = _parse_rpm(rate_limit_cfg)
        if rpm > 0 and provider_id not in self._rate_limiters:
            self._rate_limiters[provider_id] = _ProviderRateLimiter(rpm)
            logger.info(f"[RateLimit] Provider '{provider_id}' throttled to {rpm:g} req/min")

    async def _rate_limit_acquire(self, provider_id: Optional[str]) -> None:
        rl = self._rate_limiters.get(provider_id or self.provider_id)
        if rl is not None:
            await rl.acquire()

    def _build_messages(self, prompt: str, system_prompt: Optional[str] = None) -> List[Dict[str, str]]:
        """Build message array for API request."""
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        return messages
