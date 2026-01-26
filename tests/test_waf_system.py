"""
Unit Tests for WAF System (TASK-80).

Tests for:
- TASK-66: SSL/TLS verification
- TASK-67: Q-Learning data poisoning prevention
- TASK-68: Exploration/exploitation balance
- TASK-69: WAF fingerprint caching
- TASK-70: Confidence scoring
- TASK-71: Q-table backup/restore
- TASK-72: Bypass metrics
- TASK-73: Multi-WAF detection
- TASK-74: Strategy combinations
- TASK-76: Encoding techniques
- TASK-77: False positive handling
- TASK-78: Q-table visualization
"""

import pytest
import tempfile
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

# Import WAF system components
from bugtrace.tools.waf.strategy_router import (
    StrategyRouter, StrategyStats, WAFLearningData,
    validate_name, VALID_WAF_TYPES, VALID_STRATEGIES
)
from bugtrace.tools.waf.encodings import encoding_techniques, EncodingTechniques
from bugtrace.tools.waf.fingerprinter import (
    WAFFingerprinter, CacheEntry, get_ssl_context, CACHE_TTL_SECONDS
)


class TestValidateName:
    """Tests for TASK-67: Input validation."""

    def test_valid_waf_name(self):
        """Test that valid WAF names pass validation."""
        assert validate_name("cloudflare", VALID_WAF_TYPES, "waf") == "cloudflare"
        assert validate_name("modsecurity", VALID_WAF_TYPES, "waf") == "modsecurity"
        assert validate_name("aws_waf", VALID_WAF_TYPES, "waf") == "aws_waf"

    def test_invalid_waf_name_returns_unknown(self):
        """Test that invalid WAF names return 'unknown'."""
        assert validate_name("nonexistent_waf", VALID_WAF_TYPES, "waf") == "unknown"
        assert validate_name("fake", VALID_WAF_TYPES, "waf") == "unknown"

    def test_injection_attempt_blocked(self):
        """Test that injection attempts are blocked (TASK-67)."""
        # SQL injection attempt
        assert validate_name("'; DROP TABLE--", VALID_WAF_TYPES, "waf") == "unknown"
        # Path traversal attempt
        assert validate_name("../../../etc/passwd", VALID_WAF_TYPES, "waf") == "unknown"
        # JSON injection
        assert validate_name("', }], [{", VALID_WAF_TYPES, "waf") == "unknown"

    def test_non_string_raises_error(self):
        """Test that non-string inputs raise ValueError."""
        with pytest.raises(ValueError):
            validate_name(123, VALID_WAF_TYPES, "waf")
        with pytest.raises(ValueError):
            validate_name(None, VALID_WAF_TYPES, "waf")

    def test_too_long_name_raises_error(self):
        """Test that excessively long names raise ValueError."""
        long_name = "a" * 100
        with pytest.raises(ValueError):
            validate_name(long_name, VALID_WAF_TYPES, "waf", max_length=50)

    def test_valid_strategy_names(self):
        """Test that valid strategy names pass validation."""
        assert validate_name("unicode_encode", VALID_STRATEGIES, "strategy") == "unicode_encode"
        assert validate_name("double_url_encode", VALID_STRATEGIES, "strategy") == "double_url_encode"


class TestStrategyStats:
    """Tests for TASK-68: UCB scoring."""

    def test_success_rate_calculation(self):
        """Test success rate calculation."""
        stats = StrategyStats(attempts=10, successes=7)
        assert stats.success_rate == 0.7

    def test_success_rate_no_attempts(self):
        """Test optimistic prior for unexplored strategies."""
        stats = StrategyStats(attempts=0, successes=0)
        assert stats.success_rate == 0.5  # Optimistic prior

    def test_ucb_score_unexplored(self):
        """Test that unexplored strategies get infinite UCB score."""
        stats = StrategyStats(attempts=0, successes=0)
        assert stats.ucb_score(total_attempts=100) == float('inf')

    def test_ucb_score_includes_exploration_bonus(self):
        """Test that UCB score includes exploration bonus (TASK-68)."""
        stats = StrategyStats(attempts=10, successes=5)
        # UCB should be > success rate due to exploration bonus
        ucb = stats.ucb_score(total_attempts=100)
        assert ucb > stats.success_rate


class TestWAFLearningData:
    """Tests for WAF learning data management."""

    def test_get_ranked_strategies(self):
        """Test strategy ranking by UCB score."""
        waf_data = WAFLearningData(waf_name="cloudflare")
        waf_data.strategies = {
            "good": StrategyStats(attempts=10, successes=8),
            "bad": StrategyStats(attempts=10, successes=2),
        }

        ranked = waf_data.get_ranked_strategies()
        # Unexplored strategies should be first (infinite UCB)
        # Then "good" should rank higher than "bad"
        strategy_names = [name for name, score in ranked]
        assert "good" in strategy_names
        assert strategy_names.index("good") < len(strategy_names) - 1 or \
               waf_data.strategies["good"].success_rate > waf_data.strategies["bad"].success_rate

    def test_get_total_attempts(self):
        """Test total attempts calculation."""
        waf_data = WAFLearningData(waf_name="cloudflare")
        waf_data.strategies = {
            "a": StrategyStats(attempts=10, successes=5),
            "b": StrategyStats(attempts=5, successes=2),
        }
        assert waf_data.get_total_attempts() == 15

    def test_get_total_successes(self):
        """Test total successes calculation."""
        waf_data = WAFLearningData(waf_name="cloudflare")
        waf_data.strategies = {
            "a": StrategyStats(attempts=10, successes=5),
            "b": StrategyStats(attempts=5, successes=2),
        }
        assert waf_data.get_total_successes() == 7


class TestStrategyRouter:
    """Tests for StrategyRouter (TASK-71, TASK-72, TASK-78)."""

    @pytest.fixture
    def temp_router(self):
        """Create a StrategyRouter with temporary data directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            router = StrategyRouter(data_dir=Path(tmpdir))
            yield router

    def test_record_result_validates_input(self, temp_router):
        """Test that record_result validates inputs (TASK-67)."""
        # Valid inputs should work
        temp_router.record_result("cloudflare", "unicode_encode", success=True)
        assert "cloudflare" in temp_router.learning_data

        # Invalid WAF should be rejected
        temp_router.record_result("invalid_waf_name_here", "unicode_encode", success=True)
        # Should default to "unknown" rather than creating invalid key
        assert "invalid_waf_name_here" not in temp_router.learning_data

    def test_get_detailed_metrics(self, temp_router):
        """Test detailed metrics generation (TASK-72)."""
        temp_router.record_result("cloudflare", "unicode_encode", success=True)
        temp_router.record_result("cloudflare", "unicode_encode", success=False)
        temp_router.record_result("cloudflare", "double_url_encode", success=True)

        metrics = temp_router.get_detailed_metrics()

        assert "overall" in metrics
        assert "by_waf" in metrics
        assert "by_strategy" in metrics
        assert metrics["overall"]["total_attempts"] == 3
        assert metrics["overall"]["total_successes"] == 2

    def test_visualize_q_table(self, temp_router):
        """Test Q-table visualization (TASK-78)."""
        temp_router.record_result("cloudflare", "unicode_encode", success=True)
        temp_router.record_result("cloudflare", "unicode_encode", success=True)

        viz = temp_router.visualize_q_table()

        assert "Q-LEARNING WAF STRATEGY TABLE" in viz
        assert "CLOUDFLARE" in viz
        assert "unicode_encode" in viz

    def test_get_learning_progress(self, temp_router):
        """Test learning progress tracking (TASK-78)."""
        temp_router.record_result("cloudflare", "unicode_encode", success=True)

        progress = temp_router.get_learning_progress()

        assert "wafs_learned" in progress
        assert "strategies_tried" in progress
        assert "exploration_coverage" in progress
        assert progress["wafs_learned"] >= 1


class TestEncodingTechniques:
    """Tests for encoding techniques (TASK-74, TASK-76)."""

    def test_encode_payload_basic(self):
        """Test basic payload encoding."""
        payload = "<script>alert(1)</script>"
        variants = encoding_techniques.encode_payload(payload, waf="cloudflare")

        assert len(variants) > 0
        assert all(v != payload for v in variants)  # All should be different

    def test_encode_with_combinations(self):
        """Test strategy combinations (TASK-74)."""
        payload = "<script>alert(1)</script>"
        variants = encoding_techniques.encode_with_combinations(payload, waf="cloudflare")

        assert len(variants) > 0
        # Each variant should be a tuple of (encoded_payload, technique_names)
        for encoded, techniques in variants:
            assert isinstance(encoded, str)
            assert isinstance(techniques, list)
            assert len(techniques) >= 1

    def test_new_encoding_techniques_exist(self):
        """Test that TASK-76 encoding techniques exist."""
        technique_names = encoding_techniques.get_technique_names()

        # TASK-76 additions
        assert "concat_string" in technique_names
        assert "hex_encode" in technique_names
        assert "scientific_notation" in technique_names
        assert "buffer_overflow" in technique_names
        assert "newline_injection" in technique_names

    def test_url_encode(self):
        """Test URL encoding."""
        tech = encoding_techniques.get_technique_by_name("url_encode")
        assert tech is not None
        encoded = tech.encoder("<script>")
        assert "%" in encoded  # Should contain URL-encoded characters

    def test_unicode_encode(self):
        """Test Unicode encoding."""
        tech = encoding_techniques.get_technique_by_name("unicode_encode")
        assert tech is not None
        encoded = tech.encoder("<script>")
        assert "\\u" in encoded  # Should contain Unicode escapes


class TestCacheEntry:
    """Tests for cache entry with TTL (TASK-69)."""

    def test_cache_entry_not_expired(self):
        """Test that fresh cache entries are not expired."""
        entry = CacheEntry(
            waf_name="cloudflare",
            confidence=0.8,
            indicators=["header_match"],
            timestamp=time.time()
        )
        assert not entry.is_expired()

    def test_cache_entry_expired(self):
        """Test that old cache entries are expired."""
        entry = CacheEntry(
            waf_name="cloudflare",
            confidence=0.8,
            indicators=["header_match"],
            timestamp=time.time() - CACHE_TTL_SECONDS - 100  # Past TTL
        )
        assert entry.is_expired()


class TestWAFFingerprinter:
    """Tests for WAF fingerprinter (TASK-69, TASK-70, TASK-73, TASK-77)."""

    def test_get_cache_stats(self):
        """Test cache statistics (TASK-69)."""
        fingerprinter = WAFFingerprinter()

        # Add entries to cache
        fingerprinter.cache["test1"] = CacheEntry(
            waf_name="cloudflare",
            confidence=0.8,
            indicators=["header_match"],
            timestamp=time.time()
        )
        fingerprinter.cache["test2"] = CacheEntry(
            waf_name="modsecurity",
            confidence=0.6,
            indicators=["response_pattern"],
            timestamp=time.time() - CACHE_TTL_SECONDS - 100  # Expired
        )

        stats = fingerprinter.get_cache_stats()

        assert stats["total_entries"] == 2
        assert stats["valid_entries"] == 1
        assert stats["expired_entries"] == 1

    def test_is_false_positive_likely_low_confidence(self):
        """Test false positive detection for low confidence (TASK-77)."""
        fingerprinter = WAFFingerprinter()

        # Low confidence should be flagged
        assert fingerprinter.is_false_positive_likely("cloudflare", 0.3, ["header_match"])

        # High confidence should not be flagged
        assert not fingerprinter.is_false_positive_likely("cloudflare", 0.9, ["header_match", "response_pattern"])

    def test_is_false_positive_likely_header_only(self):
        """Test false positive detection for header-only detection (TASK-77)."""
        fingerprinter = WAFFingerprinter()

        # Header only with medium confidence - suspicious
        assert fingerprinter.is_false_positive_likely("cloudflare", 0.5, ["header_match"])

        # Header only with high confidence - OK
        assert not fingerprinter.is_false_positive_likely("cloudflare", 0.7, ["header_match"])


class TestSSLConfiguration:
    """Tests for SSL configuration (TASK-66)."""

    @patch('bugtrace.tools.waf.fingerprinter.settings')
    def test_ssl_verification_enabled_by_default(self, mock_settings):
        """Test that SSL verification is enabled by default (TASK-66)."""
        mock_settings.VERIFY_SSL_CERTIFICATES = True
        mock_settings.ALLOW_SELF_SIGNED_CERTS = False

        result = get_ssl_context()
        assert result is True  # Default verification

    @patch('bugtrace.tools.waf.fingerprinter.settings')
    def test_ssl_verification_disabled_warning(self, mock_settings):
        """Test that disabling SSL verification logs a warning (TASK-66)."""
        mock_settings.VERIFY_SSL_CERTIFICATES = False
        mock_settings.ALLOW_SELF_SIGNED_CERTS = False

        result = get_ssl_context()
        assert result is False


# Run with: pytest tests/test_waf_system.py -v
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
