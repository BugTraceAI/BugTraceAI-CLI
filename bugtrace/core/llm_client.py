"""Centralized LLM client (thin shell).

Public API is unchanged: import from ``bugtrace.core.llm_client``.
Implementation lives in ``bugtrace.core.llm_shell`` mixins (size policy).
"""

from __future__ import annotations

from typing import Optional, Dict, Any, List

from bugtrace.core.config import settings
from bugtrace.core.llm_shell import (
    LLMHealthState,
    sanitize_text,
    ModelMetrics,
    TokenUsageTracker,
    VULNERABILITY_SCHEMA,
    LLMCircuitMixin,
    LLMConnectivityMixin,
    LLMProviderMixin,
    LLMAnthropicMixin,
    LLMGenerateMixin,
    LLMThreadMixin,
    LLMVisionMixin,
    LLMCacheMixin,
    LLMStreamMixin,
    LLMMiscMixin,
)

# Re-export for callers/tests that import symbols from this module
__all__ = [
    "LLMHealthState",
    "sanitize_text",
    "ModelMetrics",
    "TokenUsageTracker",
    "VULNERABILITY_SCHEMA",
    "LLMClient",
    "llm_client",
]


class LLMClient(
    LLMGenerateMixin,
    LLMThreadMixin,
    LLMVisionMixin,
    LLMStreamMixin,
    LLMCacheMixin,
    LLMProviderMixin,
    LLMAnthropicMixin,
    LLMCircuitMixin,
    LLMConnectivityMixin,
    LLMMiscMixin,
):
    """
    Centralized client for LLM interactions via OpenRouter.
    Implements 'Model Shifting' & 'Hybrid Resilience':
    1. Shifts to alternative models if primary fails (API errors).
    2. Shifts to Uncensored/Permissive models if Refusal/Censorship is detected.
    """

    REFUSAL_PHRASES = [
        "I cannot assist",
        "I cannot help",
        "illegal",
        "ethical guidelines",
        "harmful activity",
        "against my policy",
        "I cannot generate",
        "I can't provide",
        "security testing only",
    ]

    def __init__(self, api_key: Optional[str] = None):
        # Provider-aware initialization. ALL provider-scoped attributes are set in
        # _apply_provider_config so __init__ and the WEB provider switch
        # (reconfigure_from_active_preset) share ONE code path and never drift.
        self.req_count = 0

        # Anthropic OAuth token cache (lazy-loaded on first anthropic/ model call)
        self._anthropic_token_cache: Optional[str] = None
        self._anthropic_token_expires: float = 0

        self._apply_provider_config(getattr(settings, '_provider_config', {}), api_key)

        # TASK-130: Token usage tracking
        self.token_tracker = TokenUsageTracker()

        # TASK-131: Response cache {hash: (response, timestamp)}
        self.cache: Dict[str, tuple] = {}
        self.cache_ttl = 3600  # 1 hour default
        self.cache_max_entries = 1024

        # TASK-133: Model performance metrics
        self.model_metrics: Dict[str, ModelMetrics] = {}

        # Circuit Breaker State Tracking
        self.health_state = LLMHealthState.HEALTHY
        self.consecutive_errors = 0
        self.consecutive_successes = 0
        self.last_failure_time: float = 0
        self.circuit_open_until: float = 0


# Singleton instance
llm_client = LLMClient()
