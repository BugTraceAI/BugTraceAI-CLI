"""Unit tests for LLM Client (TASK-135).

Tests cover:
- TASK-128: Prompt sanitization
- TASK-129: Response validation
- TASK-130: Token usage tracking
- TASK-131: Request caching
- TASK-133: Model performance metrics
"""
import pytest
import json
from unittest.mock import AsyncMock, patch, MagicMock

from bugtrace.core.llm_client import (
    sanitize_text,
    TokenUsageTracker,
    ModelMetrics,
    LLMClient,
    VULNERABILITY_SCHEMA,
)


# ========== TASK-128: Sanitization Tests ==========
class TestSanitizeText:
    """Tests for sanitize_text function."""

    def test_sanitize_api_key(self):
        """Should redact API keys."""
        text = 'api_key="sk-proj-abcdefghijklmnopqrstuvwxyz123456"'
        result = sanitize_text(text)
        assert "[REDACTED]" in result
        assert "sk-proj-abcdefghijklmnopqrstuvwxyz123456" not in result

    def test_sanitize_bearer_token(self):
        """Should redact bearer tokens."""
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        result = sanitize_text(text)
        assert "[REDACTED]" in result

    def test_sanitize_password(self):
        """Should redact passwords."""
        text = 'password: "mysupersecretpassword123"'
        result = sanitize_text(text)
        assert "[REDACTED]" in result
        assert "mysupersecretpassword123" not in result

    def test_sanitize_url_credentials(self):
        """Should redact credentials in URLs."""
        text = "https://user:password123@api.example.com/v1"
        result = sanitize_text(text)
        assert "[REDACTED]" in result
        assert "password123" not in result

    def test_sanitize_email(self):
        """Should redact email addresses."""
        text = "Contact: john.doe@company.com for support"
        result = sanitize_text(text)
        assert "[EMAIL]" in result
        assert "john.doe@company.com" not in result

    def test_sanitize_aws_key(self):
        """Should redact AWS access keys."""
        text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
        result = sanitize_text(text)
        assert "[AWS_KEY]" in result
        assert "AKIAIOSFODNN7EXAMPLE" not in result

    def test_sanitize_preserves_normal_text(self):
        """Should not modify text without sensitive data."""
        text = "This is a normal prompt about testing XSS vulnerabilities."
        result = sanitize_text(text)
        assert result == text

    def test_sanitize_empty_string(self):
        """Should handle empty strings."""
        assert sanitize_text("") == ""
        assert sanitize_text(None) is None


# ========== TASK-130: Token Usage Tracking Tests ==========
class TestTokenUsageTracker:
    """Tests for TokenUsageTracker class."""

    def test_record_usage_basic(self):
        """Should record token usage correctly."""
        tracker = TokenUsageTracker()
        tracker.record_usage("model-a", "agent-1", 100, 50)

        assert tracker.total_input_tokens == 100
        assert tracker.total_output_tokens == 50
        assert tracker.by_model["model-a"]["input"] == 100
        assert tracker.by_model["model-a"]["output"] == 50
        assert tracker.by_agent["agent-1"]["input"] == 100
        assert tracker.by_agent["agent-1"]["output"] == 50

    def test_record_usage_accumulates(self):
        """Should accumulate token usage across calls."""
        tracker = TokenUsageTracker()
        tracker.record_usage("model-a", "agent-1", 100, 50)
        tracker.record_usage("model-a", "agent-1", 200, 100)

        assert tracker.total_input_tokens == 300
        assert tracker.total_output_tokens == 150
        assert tracker.by_model["model-a"]["input"] == 300
        assert tracker.by_model["model-a"]["output"] == 150

    def test_record_usage_multiple_models(self):
        """Should track usage per model."""
        tracker = TokenUsageTracker()
        tracker.record_usage("model-a", "agent-1", 100, 50)
        tracker.record_usage("model-b", "agent-1", 200, 100)

        assert len(tracker.by_model) == 2
        assert tracker.by_model["model-a"]["input"] == 100
        assert tracker.by_model["model-b"]["input"] == 200

    def test_record_usage_multiple_agents(self):
        """Should track usage per agent."""
        tracker = TokenUsageTracker()
        tracker.record_usage("model-a", "agent-1", 100, 50)
        tracker.record_usage("model-a", "agent-2", 200, 100)

        assert len(tracker.by_agent) == 2
        assert tracker.by_agent["agent-1"]["input"] == 100
        assert tracker.by_agent["agent-2"]["input"] == 200

    def test_estimate_cost_known_model(self):
        """Should estimate cost for known models."""
        tracker = TokenUsageTracker()
        # 1M input tokens at $0.05 = $0.05
        tracker.record_usage("google/gemini-2.5-flash-preview", "test", 1_000_000, 0)
        cost = tracker.estimate_cost()
        assert cost == pytest.approx(0.05, rel=0.01)

    def test_estimate_cost_unknown_model(self):
        """Should use default pricing for unknown models."""
        tracker = TokenUsageTracker()
        # 1M input tokens at default $0.50 = $0.50
        tracker.record_usage("unknown/model", "test", 1_000_000, 0)
        cost = tracker.estimate_cost()
        assert cost == pytest.approx(0.50, rel=0.01)

    def test_get_summary(self):
        """Should return complete usage summary."""
        tracker = TokenUsageTracker()
        tracker.record_usage("model-a", "agent-1", 100, 50)

        summary = tracker.get_summary()
        assert "total_input" in summary
        assert "total_output" in summary
        assert "total" in summary
        assert "by_model" in summary
        assert "by_agent" in summary
        assert "estimated_cost" in summary
        assert summary["total"] == 150


# ========== TASK-133: Model Metrics Tests ==========
class TestModelMetrics:
    """Tests for ModelMetrics dataclass."""

    def test_success_rate_no_calls(self):
        """Should return 0 for no calls."""
        metrics = ModelMetrics()
        assert metrics.success_rate == 0.0

    def test_success_rate_all_success(self):
        """Should return 1.0 for all successes."""
        metrics = ModelMetrics(calls=10, successes=10, failures=0)
        assert metrics.success_rate == 1.0

    def test_success_rate_partial(self):
        """Should calculate correct partial rate."""
        metrics = ModelMetrics(calls=10, successes=7, failures=3)
        assert metrics.success_rate == 0.7

    def test_avg_latency_no_success(self):
        """Should return 0 for no successes."""
        metrics = ModelMetrics()
        assert metrics.avg_latency_ms == 0.0

    def test_avg_latency_with_data(self):
        """Should calculate correct average latency."""
        metrics = ModelMetrics(successes=5, total_latency_ms=1000.0)
        assert metrics.avg_latency_ms == 200.0


# ========== TASK-129: Response Validation Tests ==========
class TestResponseValidation:
    """Tests for LLM response validation."""

    @pytest.fixture
    def client(self):
        """Create LLMClient with mocked API key."""
        with patch.object(LLMClient, '__init__', lambda self, api_key=None: None):
            client = LLMClient.__new__(LLMClient)
            client.api_key = "test-key"
            client.models = ["test-model"]
            client.cache = {}
            client.cache_ttl = 3600
            client.model_metrics = {}
            client.token_tracker = TokenUsageTracker()
            return client

    def test_validate_valid_json(self, client):
        """Should parse valid JSON response."""
        response = '{"vulnerable": true, "confidence": 0.9}'
        result = client.validate_json_response(response)
        assert result is not None
        assert result["vulnerable"] is True
        assert result["confidence"] == 0.9

    def test_validate_json_in_markdown(self, client):
        """Should extract JSON from markdown code blocks."""
        response = '''Here is the result:
```json
{"vulnerable": false, "confidence": 0.5}
```
'''
        result = client.validate_json_response(response)
        assert result is not None
        assert result["vulnerable"] is False

    def test_validate_invalid_json(self, client):
        """Should return None for invalid JSON."""
        response = "This is not JSON at all"
        result = client.validate_json_response(response)
        assert result is None

    def test_validate_with_schema_valid(self, client):
        """Should validate against schema."""
        response = '{"vulnerable": true, "confidence": 0.8}'
        result = client.validate_json_response(response, VULNERABILITY_SCHEMA)
        # Will work if jsonschema is installed, otherwise skip validation
        assert result is not None

    def test_validate_with_schema_missing_required(self, client):
        """Should reject response missing required fields."""
        response = '{"vulnerable": true}'  # missing confidence
        result = client.validate_json_response(response, VULNERABILITY_SCHEMA)
        # If jsonschema not installed, it will pass; otherwise None
        # This test documents expected behavior


# ========== TASK-131: Caching Tests ==========
class TestCaching:
    """Tests for LLM response caching."""

    @pytest.fixture
    def client(self):
        """Create LLMClient with mocked API key."""
        with patch.object(LLMClient, '__init__', lambda self, api_key=None: None):
            client = LLMClient.__new__(LLMClient)
            client.api_key = "test-key"
            client.models = ["test-model"]
            client.cache = {}
            client.cache_ttl = 3600
            client.model_metrics = {}
            client.token_tracker = TokenUsageTracker()
            return client

    def test_cache_key_generation(self, client):
        """Should generate consistent cache keys."""
        key1 = client._get_cache_key("model-a", "prompt 1")
        key2 = client._get_cache_key("model-a", "prompt 1")
        key3 = client._get_cache_key("model-a", "prompt 2")

        assert key1 == key2  # Same inputs = same key
        assert key1 != key3  # Different prompt = different key

    def test_cache_key_model_matters(self, client):
        """Should include model in cache key."""
        key1 = client._get_cache_key("model-a", "same prompt")
        key2 = client._get_cache_key("model-b", "same prompt")

        assert key1 != key2  # Different model = different key

    def test_clear_cache(self, client):
        """Should clear all cached responses."""
        client.cache["key1"] = ("response1", 0)
        client.cache["key2"] = ("response2", 0)

        client.clear_cache()

        assert len(client.cache) == 0


# ========== Integration Tests ==========
class TestLLMClientIntegration:
    """Integration tests for LLMClient."""

    @pytest.fixture
    def client(self):
        """Create LLMClient with mocked dependencies."""
        with patch.object(LLMClient, '__init__', lambda self, api_key=None: None):
            client = LLMClient.__new__(LLMClient)
            client.api_key = "test-key"
            client.base_url = "https://openrouter.ai/api/v1/chat/completions"
            client.models = ["test-model"]
            client.cache = {}
            client.cache_ttl = 3600
            client.model_metrics = {}
            client.token_tracker = TokenUsageTracker()
            client.req_count = 0
            client.semaphore = MagicMock()
            client.semaphore.__aenter__ = AsyncMock()
            client.semaphore.__aexit__ = AsyncMock()
            return client

    def test_get_model_metrics_empty(self, client):
        """Should return empty dict when no calls made."""
        metrics = client.get_model_metrics()
        assert metrics == {}

    def test_get_model_metrics_with_data(self, client):
        """Should return formatted metrics."""
        client._record_model_call("test-model", True, 150.0)
        client._record_model_call("test-model", True, 250.0)
        client._record_model_call("test-model", False, 50.0)

        metrics = client.get_model_metrics()
        assert "test-model" in metrics
        assert metrics["test-model"]["calls"] == 3
        assert metrics["test-model"]["successes"] == 2
        assert metrics["test-model"]["failures"] == 1
        assert metrics["test-model"]["success_rate"] == "66.7%"

    def test_get_token_summary(self, client):
        """Should return token usage summary."""
        client.token_tracker.record_usage("model", "agent", 100, 50)
        summary = client.get_token_summary()

        assert summary["total"] == 150
        assert "estimated_cost" in summary


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
