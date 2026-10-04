"""Shared types/constants for LLM client shell."""

from __future__ import annotations

import os
import re
import time
import asyncio
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field

from bugtrace.utils.logger import get_logger
from bugtrace.core.config import settings

logger = get_logger("core.llm_client")


# ========== Circuit Breaker Constants ==========
class LLMHealthState:
    """Health states for LLM API circuit breaker."""
    HEALTHY = "HEALTHY"      # Normal operation
    DEGRADED = "DEGRADED"    # Slow down requests (API unstable)
    CRITICAL = "CRITICAL"    # Circuit OPEN - return fallbacks

# Circuit breaker configuration
CB_FAILURE_THRESHOLD = 3       # Consecutive failures to open circuit
CB_COOLDOWN_SECONDS = 60       # Time before attempting recovery (half-open)
CB_DEGRADED_DELAY = 2.0        # Delay between requests in DEGRADED state
CB_SUCCESS_THRESHOLD = 2       # Successes needed to recover from DEGRADED

# LLM Request Timeouts (seconds)
LLM_TOTAL_TIMEOUT = 90         # Total request timeout (non-streaming) — reasoning models need 30-60s
LLM_CONNECT_TIMEOUT = 15       # Connection establishment timeout


def sanitize_text(text: str) -> str:
    """Remove sensitive data from text before logging."""
    if not text:
        return text

    # Remove API keys and tokens
    text = re.sub(
        r'(api[_-]?key|token|secret|password|bearer|authorization)["\s:=]+([a-zA-Z0-9\-_]{20,})',
        r'\1: [REDACTED]',
        text,
        flags=re.IGNORECASE
    )

    # Remove URLs with embedded credentials
    text = re.sub(
        r'https?://[^:]+:[^@]+@',
        'https://[REDACTED]@',
        text
    )

    # Remove potential email addresses
    text = re.sub(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        '[EMAIL]',
        text
    )

    # Remove AWS-style keys
    text = re.sub(
        r'AKIA[0-9A-Z]{16}',
        '[AWS_KEY]',
        text
    )

    return text


@dataclass
class ModelMetrics:
    """Tracks performance metrics for a single model."""
    calls: int = 0
    successes: int = 0
    failures: int = 0
    total_latency_ms: float = 0.0

    @property
    def success_rate(self) -> float:
        return self.successes / self.calls if self.calls > 0 else 0.0

    @property
    def avg_latency_ms(self) -> float:
        return self.total_latency_ms / self.successes if self.successes > 0 else 0.0


class TokenUsageTracker:
    """Tracks token usage across models and agents with cost estimation."""

    # Pricing per 1M tokens — loaded from active provider preset, with fallbacks
    _FALLBACK_PRICING = {
        "google/gemini-2.5-flash-preview": {"input": 0.05, "output": 0.15},
        "google/gemini-3-flash-preview": {"input": 0.05, "output": 0.15},
        "moonshotai/kimi-k2-thinking": {"input": 0.40, "output": 1.75},
        "qwen/qwen-2.5-coder-32b-instruct": {"input": 0.20, "output": 0.60},
        "anthropic/claude-3-haiku": {"input": 0.25, "output": 1.25},
        "default": {"input": 0.50, "output": 1.50}
    }

    @classmethod
    def _get_pricing(cls) -> Dict[str, Dict[str, float]]:
        """Get pricing from active provider preset, falling back to hardcoded."""
        provider_cfg = getattr(settings, '_provider_config', {})
        provider_pricing = provider_cfg.get('pricing', {})
        merged = {**cls._FALLBACK_PRICING, **provider_pricing}
        if "default" not in merged:
            merged["default"] = {"input": 0.50, "output": 1.50}
        return merged

    PRICING = _FALLBACK_PRICING  # Class attribute for backward compat

    def __init__(self):
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.by_model: Dict[str, Dict[str, int]] = {}
        self.by_agent: Dict[str, Dict[str, int]] = {}

    def record_usage(self, model: str, agent: str, input_tokens: int, output_tokens: int):
        """Record token usage for a single LLM call."""
        self.total_input_tokens += input_tokens
        self.total_output_tokens += output_tokens

        # Track by model
        if model not in self.by_model:
            self.by_model[model] = {"input": 0, "output": 0}
        self.by_model[model]["input"] += input_tokens
        self.by_model[model]["output"] += output_tokens

        # Track by agent
        if agent not in self.by_agent:
            self.by_agent[agent] = {"input": 0, "output": 0}
        self.by_agent[agent]["input"] += input_tokens
        self.by_agent[agent]["output"] += output_tokens

    def estimate_cost(self) -> float:
        """Estimate total cost based on active provider pricing."""
        total_cost = 0.0
        pricing_table = self._get_pricing()
        for model, usage in self.by_model.items():
            pricing = pricing_table.get(model, pricing_table["default"])
            input_cost = (usage["input"] / 1_000_000) * pricing["input"]
            output_cost = (usage["output"] / 1_000_000) * pricing["output"]
            total_cost += input_cost + output_cost
        return total_cost

    def get_summary(self) -> Dict[str, Any]:
        """Get comprehensive usage summary."""
        return {
            "total_input": self.total_input_tokens,
            "total_output": self.total_output_tokens,
            "total": self.total_input_tokens + self.total_output_tokens,
            "by_model": self.by_model,
            "by_agent": self.by_agent,
            "estimated_cost": self.estimate_cost()
        }


# Response validation schemas
VULNERABILITY_SCHEMA = {
    "type": "object",
    "properties": {
        "vulnerable": {"type": "boolean"},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "vuln_type": {"type": "string"},
        "payload": {"type": "string"}
    },
    "required": ["vulnerable", "confidence"]
}


class _ProviderRateLimiter:
    """Per-provider request-rate gate (shared across all agents via the singleton client).

    Spaces requests to a provider at most `rpm` per minute by reserving evenly-spaced
    slots. Slots are reserved under a lock (cheap) and awaited outside it, so concurrent
    callers throttle correctly without serializing the whole client. Prevents the 429
    avalanches that free tiers (e.g. Z.ai ~10 RPM) hit when a scan fires 100+ calls.
    """

    def __init__(self, rpm: float):
        self.min_interval = 60.0 / rpm if rpm and rpm > 0 else 0.0
        self._lock = asyncio.Lock()
        self._next_allowed = 0.0

    async def acquire(self) -> None:
        if self.min_interval <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            slot = max(now, self._next_allowed)
            self._next_allowed = slot + self.min_interval
        wait = slot - time.monotonic()
        if wait > 0:
            await asyncio.sleep(wait)


def _parse_rpm(rate_limit_cfg: Any) -> float:
    """Extract requests-per-minute from a preset's `rate_limit` field (number or {rpm|requests_per_minute})."""
    if isinstance(rate_limit_cfg, (int, float)):
        return float(rate_limit_cfg)
    if isinstance(rate_limit_cfg, dict):
        for k in ("rpm", "requests_per_minute", "rpm_limit"):
            v = rate_limit_cfg.get(k)
            if isinstance(v, (int, float)):
                return float(v)
    return 0.0


