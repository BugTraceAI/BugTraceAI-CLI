"""LLM client shell mixins — public surface stays bugtrace.core.llm_client."""

from bugtrace.core.llm_shell.types import (
    LLMHealthState,
    CB_FAILURE_THRESHOLD,
    CB_COOLDOWN_SECONDS,
    CB_DEGRADED_DELAY,
    CB_SUCCESS_THRESHOLD,
    LLM_TOTAL_TIMEOUT,
    LLM_CONNECT_TIMEOUT,
    sanitize_text,
    ModelMetrics,
    TokenUsageTracker,
    VULNERABILITY_SCHEMA,
    _ProviderRateLimiter,
    _parse_rpm,
)
from bugtrace.core.llm_shell.circuit import LLMCircuitMixin
from bugtrace.core.llm_shell.connectivity import LLMConnectivityMixin
from bugtrace.core.llm_shell.provider import LLMProviderMixin
from bugtrace.core.llm_shell.anthropic_wire import LLMAnthropicMixin
from bugtrace.core.llm_shell.generate import LLMGenerateMixin
from bugtrace.core.llm_shell.thread import LLMThreadMixin
from bugtrace.core.llm_shell.vision import LLMVisionMixin
from bugtrace.core.llm_shell.cache import LLMCacheMixin
from bugtrace.core.llm_shell.stream import LLMStreamMixin
from bugtrace.core.llm_shell.misc import LLMMiscMixin

__all__ = [
    "LLMHealthState",
    "sanitize_text",
    "ModelMetrics",
    "TokenUsageTracker",
    "VULNERABILITY_SCHEMA",
    "LLMCircuitMixin",
    "LLMConnectivityMixin",
    "LLMProviderMixin",
    "LLMAnthropicMixin",
    "LLMGenerateMixin",
    "LLMThreadMixin",
    "LLMVisionMixin",
    "LLMCacheMixin",
    "LLMStreamMixin",
    "LLMMiscMixin",
]
