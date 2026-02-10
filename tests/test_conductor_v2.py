"""
Unit Tests for Conductor V2 - Checkpoint Manager
=================================================

Tests for context management, shared context, agent prompts, and integrity verification.

NOTE: Validation tests removed (2026-02-04).
Specialists now self-validate via BaseAgent.emit_finding()

Run with: pytest tests/test_conductor_v2.py -v
"""

import pytest
import time
from bugtrace.core.conductor import ConductorV2


@pytest.fixture
def conductor():
    """Create fresh Conductor V2 instance for each test."""
    return ConductorV2()


# ============================================================================
# CONTEXT REFRESH TESTS
# ============================================================================

def test_context_refresh(conductor):
    """Context refresh should clear cache."""
    # Load some context
    conductor.get_context("context")
    assert len(conductor.context_cache) >= 0  # May be 0 if file doesn't exist

    # Add something to cache manually
    conductor.context_cache["test_key"] = "test_value"
    assert len(conductor.context_cache) > 0

    # Refresh
    conductor.refresh_context()

    assert len(conductor.context_cache) == 0
    assert conductor.stats["context_refreshes"] == 1


def test_auto_refresh_check(conductor):
    """Auto-refresh should trigger after interval."""
    # Simulate old refresh time
    conductor.last_refresh = time.time() - 400  # 6.6 minutes ago

    # Check refresh
    conductor.check_refresh_needed()

    assert conductor.stats["context_refreshes"] == 1


def test_auto_refresh_not_needed(conductor):
    """Auto-refresh should NOT trigger if recent."""
    conductor.last_refresh = time.time()  # Just now

    conductor.check_refresh_needed()

    assert conductor.stats["context_refreshes"] == 0


def test_get_context_caching(conductor):
    """Context should be cached after first load."""
    # First load (from disk)
    content1 = conductor.get_context("context")

    # Modify cache
    conductor.context_cache["context"] = "modified_content"

    # Second load (from cache)
    content2 = conductor.get_context("context")

    assert content2 == "modified_content"


def test_get_context_force_refresh(conductor):
    """Force refresh should bypass cache."""
    # Load and modify cache
    conductor.get_context("context")
    conductor.context_cache["context"] = "modified_content"

    # Force refresh should reload from disk
    content = conductor.get_context("context", force_refresh=True)

    # Should NOT be the modified content (unless disk also has it)
    assert content != "modified_content" or content == ""


# ============================================================================
# AGENT PROMPT GENERATION TESTS
# ============================================================================

def test_get_agent_prompt_recon(conductor):
    """Agent prompt for recon should load correct file."""
    prompt = conductor.get_agent_prompt("recon", {"target": "example.com"})

    assert isinstance(prompt, str)
    assert len(prompt) > 0
    assert "target" in prompt.lower()


def test_get_agent_prompt_exploit(conductor):
    """Agent prompt for exploit should include task context."""
    task_context = {
        "url": "https://example.com",
        "input_name": "search"
    }

    prompt = conductor.get_agent_prompt("exploit", task_context)

    assert "example.com" in prompt
    assert "search" in prompt


def test_get_agent_prompt_unknown_agent(conductor):
    """Unknown agent should get fallback prompt."""
    prompt = conductor.get_agent_prompt("unknown-agent")

    assert "unknown-agent" in prompt.lower()


def test_get_agent_prompt_with_none_context(conductor):
    """Agent prompt should work without task context."""
    prompt = conductor.get_agent_prompt("exploit", None)

    assert isinstance(prompt, str)
    assert len(prompt) > 0


def test_get_full_system_prompt(conductor):
    """Full system prompt should combine all protocol files."""
    prompt = conductor.get_full_system_prompt()

    assert isinstance(prompt, str)
    # Should contain some structure markers even if files are empty
    assert "Security Rules" in prompt or len(prompt) > 0


# ============================================================================
# SHARED CONTEXT TESTS
# ============================================================================

def test_share_context_new_key(conductor):
    """Sharing context with new key should set value."""
    conductor.share_context("new_key", "test_value")

    assert conductor.shared_context["new_key"] == "test_value"


def test_share_context_list_append(conductor):
    """Sharing context to existing list should append."""
    # discovered_urls is initialized as list
    conductor.share_context("discovered_urls", "https://example.com/page1")
    conductor.share_context("discovered_urls", "https://example.com/page2")

    assert len(conductor.shared_context["discovered_urls"]) == 2
    assert "https://example.com/page1" in conductor.shared_context["discovered_urls"]
    assert "https://example.com/page2" in conductor.shared_context["discovered_urls"]


def test_share_context_list_extend(conductor):
    """Sharing context with list value should extend existing list."""
    conductor.share_context("discovered_urls", ["url1", "url2"])
    conductor.share_context("discovered_urls", ["url3", "url4"])

    assert len(conductor.shared_context["discovered_urls"]) == 4


def test_get_shared_context_all(conductor):
    """Getting shared context without key should return copy of all."""
    conductor.share_context("discovered_urls", "test_url")

    context = conductor.get_shared_context()

    assert isinstance(context, dict)
    assert "discovered_urls" in context
    assert "test_url" in context["discovered_urls"]

    # Should be a copy, not the original
    context["new_key"] = "new_value"
    assert "new_key" not in conductor.shared_context


def test_get_shared_context_specific_key(conductor):
    """Getting shared context with key should return that value."""
    conductor.share_context("discovered_urls", "test_url")

    urls = conductor.get_shared_context("discovered_urls")

    assert isinstance(urls, list)
    assert "test_url" in urls


def test_get_shared_context_missing_key(conductor):
    """Getting shared context with missing key should return None."""
    result = conductor.get_shared_context("nonexistent_key")

    assert result is None


def test_get_context_summary_empty(conductor):
    """Context summary should handle empty context."""
    summary = conductor.get_context_summary()

    assert summary == "No shared context yet"


def test_get_context_summary_with_data(conductor):
    """Context summary should show counts."""
    conductor.share_context("discovered_urls", "url1")
    conductor.share_context("discovered_urls", "url2")
    conductor.share_context("confirmed_vulns", {"type": "XSS"})

    summary = conductor.get_context_summary()

    assert "URLs discovered: 2" in summary
    assert "Confirmed vulns: 1" in summary


# ============================================================================
# INTEGRITY VERIFICATION TESTS
# ============================================================================

def test_verify_integrity_discovery_pass(conductor):
    """Discovery phase should pass when all URLs accounted for."""
    expected = {"urls_count": 5}
    actual = {"dast_reports_count": 4, "errors": 1}

    result = conductor.verify_integrity("discovery", expected, actual)

    assert result == True
    assert conductor.stats["integrity_passes"] == 1


def test_verify_integrity_discovery_fail(conductor):
    """Discovery phase should fail when URLs missing."""
    expected = {"urls_count": 5}
    actual = {"dast_reports_count": 2, "errors": 1}  # Missing 2

    result = conductor.verify_integrity("discovery", expected, actual)

    assert result == False
    assert conductor.stats["integrity_failures"] == 1


def test_verify_integrity_strategy_pass(conductor):
    """Strategy phase should pass when WET items <= raw findings."""
    expected = {"raw_findings_count": 10}
    actual = {"wet_queue_count": 8}

    result = conductor.verify_integrity("strategy", expected, actual)

    assert result == True


def test_verify_integrity_strategy_fail_hallucination(conductor):
    """Strategy phase should fail when WET items > raw findings (hallucination)."""
    expected = {"raw_findings_count": 5}
    actual = {"wet_queue_count": 10}  # More than input = hallucination

    result = conductor.verify_integrity("strategy", expected, actual)

    assert result == False
    assert conductor.stats["integrity_failures"] == 1


def test_verify_integrity_strategy_100_percent_filtration(conductor):
    """Strategy phase should warn but pass on 100% filtration."""
    expected = {"raw_findings_count": 10}
    actual = {"wet_queue_count": 0}  # All filtered

    result = conductor.verify_integrity("strategy", expected, actual)

    # Warning only, not failure
    assert result == True


def test_verify_integrity_exploitation_pass(conductor):
    """Exploitation phase should pass when DRY items <= WET items."""
    expected = {"wet_processed": 10}
    actual = {"dry_generated": 8}

    result = conductor.verify_integrity("exploitation", expected, actual)

    assert result == True
    assert conductor.stats["integrity_passes"] == 1


def test_verify_integrity_exploitation_fail_hallucination(conductor):
    """Exploitation phase should fail when DRY items > WET items (hallucination)."""
    expected = {"wet_processed": 5}
    actual = {"dry_generated": 10}  # Inventing findings!

    result = conductor.verify_integrity("exploitation", expected, actual)

    assert result == False
    assert conductor.stats["integrity_failures"] == 1


def test_verify_integrity_unknown_phase(conductor):
    """Unknown phase should pass (with warning)."""
    result = conductor.verify_integrity("unknown_phase", {}, {})

    assert result == True  # Unknown phases pass


# ============================================================================
# STATISTICS TESTS
# ============================================================================

def test_statistics_initial(conductor):
    """Initial statistics should be zero."""
    stats = conductor.get_statistics()

    assert stats["context_refreshes"] == 0
    assert stats["integrity_passes"] == 0
    assert stats["integrity_failures"] == 0


def test_statistics_after_operations(conductor):
    """Statistics should track operations."""
    # Refresh context
    conductor.refresh_context()
    conductor.refresh_context()

    # Run integrity checks
    conductor.verify_integrity("discovery", {"urls_count": 1}, {"dast_reports_count": 1, "errors": 0})
    conductor.verify_integrity("discovery", {"urls_count": 5}, {"dast_reports_count": 1, "errors": 0})

    stats = conductor.get_statistics()

    assert stats["context_refreshes"] == 2
    assert stats["integrity_passes"] == 1
    assert stats["integrity_failures"] == 1
    assert "last_refresh" in stats


# ============================================================================
# PROTOCOL FILE TESTS
# ============================================================================

def test_ensure_protocol_exists(conductor):
    """Conductor should create protocol directory."""
    import os

    assert os.path.exists(conductor.PROTOCOL_DIR)
    assert os.path.isdir(conductor.PROTOCOL_DIR)


def test_load_file_unknown_key(conductor):
    """Loading unknown key should return empty string."""
    content = conductor._load_file("nonexistent_key")

    assert content == ""


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
