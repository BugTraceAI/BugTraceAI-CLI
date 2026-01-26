"""
Unit Tests for Conductor V2
============================

Tests for validation, payload checking, FP detection, and context refresh.

Run with: pytest tests/test_conductor_v2.py -v
"""

import pytest
import os
import time
from datetime import datetime
from bugtrace.core.conductor import ConductorV2


@pytest.fixture
def conductor():
    """Create fresh Conductor V2 instance for each test."""
    return ConductorV2()


@pytest.fixture
def sample_xss_finding():
    """Sample XSS finding with complete evidence."""
    return {
        "finding_id": "xss_test_001",
        "type": "XSS",
        "url": "https://example.com/search?q=test",
        "payload": "<script>alert(document.domain)</script>",
        "confidence": 0.8,
        "evidence": {
            "alert_triggered": True,
            "screenshot": "/tmp/screenshot.png",
            "request": "GET /search?q=... HTTP/1.1",
            "response": {
                "status_code": 200,
                "body": "Results for <script>alert(document.domain)</script>",
                "headers": {}
            }
        }
    }


@pytest.fixture
def sample_sqli_finding():
    """Sample SQLi finding with error-based proof."""
    return {
        "finding_id": "sqli_test_001",
        "type": "SQLi",
        "url": "https://example.com/product?id=1",
        "payload": "' OR '1'='1",
        "confidence": 0.85,
        "evidence": {
            "error_message": "MySQL syntax error near ''1'='1'",
            "response": {
                "status_code": 500,
                "body": "Database error: MySQL syntax error",
                "headers": {}
            }
        }
    }


# ============================================================================
# VALIDATION TESTS
# ============================================================================

def test_validate_finding_xss_pass(conductor, sample_xss_finding):
    """Valid XSS finding should pass validation."""
    is_valid, reason = conductor.validate_finding(sample_xss_finding)
    
    assert is_valid == True
    assert reason == "Validation passed"
    assert conductor.stats["findings_passed"] == 1


def test_validate_finding_xss_low_confidence(conductor, sample_xss_finding):
    """XSS with low confidence should be rejected."""
    sample_xss_finding["confidence"] = 0.5
    
    is_valid, reason = conductor.validate_finding(sample_xss_finding)
    
    assert is_valid == False
    assert "Confidence" in reason
    assert conductor.stats["findings_blocked"] == 1


def test_validate_finding_xss_no_alert(conductor, sample_xss_finding):
    """XSS without alert triggered should be rejected."""
    sample_xss_finding["evidence"]["alert_triggered"] = False
    
    is_valid, reason = conductor.validate_finding(sample_xss_finding)
    
    assert is_valid == False
    assert "alert execution" in reason.lower()


def test_validate_finding_xss_no_screenshot(conductor, sample_xss_finding):
    """XSS without screenshot should be rejected."""
    del sample_xss_finding["evidence"]["screenshot"]
    
    is_valid, reason = conductor.validate_finding(sample_xss_finding)
    
    assert is_valid == False
    assert "screenshot" in reason.lower()


def test_validate_finding_sqli_pass(conductor, sample_sqli_finding):
    """Valid SQLi finding should pass validation."""
    is_valid, reason = conductor.validate_finding(sample_sqli_finding)
    
    assert is_valid == True
    assert reason == "Validation passed"


def test_validate_finding_sqli_no_evidence(conductor, sample_sqli_finding):
    """SQLi without error/time/data should be rejected."""
    del sample_sqli_finding["evidence"]["error_message"]
    
    is_valid, reason = conductor.validate_finding(sample_sqli_finding)
    
    assert is_valid == False
    assert "proof" in reason.lower()


def test_validate_finding_sqli_only_status_code(conductor, sample_sqli_finding):
    """SQLi with only 500 status code (no error) should be rejected."""
    del sample_sqli_finding["evidence"]["error_message"]
    sample_sqli_finding["evidence"]["status_code"] = 500
    
    is_valid, reason = conductor.validate_finding(sample_sqli_finding)
    
    assert is_valid == False
    assert "proof" in reason.lower()  # Fixed: matches actual message


# ============================================================================
# PAYLOAD VALIDATION TESTS
# ============================================================================

def test_validate_payload_xss_valid(conductor):
    """Valid XSS payload should pass."""
    payload = "<script>alert(document.domain)</script>"
    
    is_valid = conductor.validate_payload(payload, "XSS")
    
    assert is_valid == True


def test_validate_payload_xss_conversational(conductor):
    """XSS payload with conversational text should fail."""
    payload = "Here is a payload: <script>alert(1)</script>"
    
    is_valid = conductor.validate_payload(payload, "XSS")
    
    assert is_valid == False


def test_validate_payload_xss_no_attack_chars(conductor):
    """XSS payload without attack chars should fail."""
    payload = "test value"
    
    is_valid = conductor.validate_payload(payload, "XSS")
    
    assert is_valid == False


def test_validate_payload_sqli_valid(conductor):
    """Valid SQLi payload should pass."""
    payload = "' OR '1'='1"
    
    is_valid = conductor.validate_payload(payload, "SQLi")
    
    assert is_valid == True


def test_validate_payload_sqli_no_sql_syntax(conductor):
    """SQLi payload without SQL syntax should fail."""
    payload = "test"
    
    is_valid = conductor.validate_payload(payload, "SQLi")
    
    assert is_valid == False


def test_validate_payload_too_long(conductor):
    """Payload > 500 chars should fail."""
    payload = "A" * 501
    
    is_valid = conductor.validate_payload(payload, "XSS")
    
    assert is_valid == False


# ============================================================================
# FALSE POSITIVE DETECTION TESTS
# ============================================================================

def test_check_false_positive_waf_block(conductor, sample_xss_finding):
    """WAF block (403 + cloudflare) should be detected as FP."""
    sample_xss_finding["evidence"]["response"] = {
        "status_code": 403,
        "body": "Blocked by Cloudflare",
        "headers": {"CF-RAY": "12345"}
    }
    
    is_fp, pattern = conductor.check_false_positive(sample_xss_finding)
    
    assert is_fp == True
    assert pattern == "WAF_BLOCK"


def test_check_false_positive_404(conductor, sample_xss_finding):
    """404 Not Found should be detected as FP."""
    sample_xss_finding["evidence"]["response"] = {
        "status_code": 404,
        "body": "404 Not Found",
        "headers": {}
    }
    
    is_fp, pattern = conductor.check_false_positive(sample_xss_finding)
    
    assert is_fp == True
    assert pattern == "GENERIC_404"


def test_check_false_positive_captcha(conductor, sample_xss_finding):
    """CAPTCHA page should be detected as FP."""
    sample_xss_finding["evidence"]["response"] = {
        "status_code": 200,
        "body": "Please complete the reCAPTCHA below",
        "headers": {}
    }
    
    is_fp, pattern = conductor.check_false_positive(sample_xss_finding)
    
    assert is_fp == True
    assert pattern == "CAPTCHA"


def test_check_false_positive_rate_limit(conductor, sample_xss_finding):
    """Rate limiting should be detected as FP."""
    sample_xss_finding["evidence"]["response"] = {
        "status_code": 429,
        "body": "Too many requests, slow down",
        "headers": {}
    }
    
    is_fp, pattern = conductor.check_false_positive(sample_xss_finding)
    
    assert is_fp == True
    assert pattern == "RATE_LIMIT"


def test_check_false_positive_no_match(conductor, sample_xss_finding):
    """Valid response should not match FP patterns."""
    is_fp, pattern = conductor.check_false_positive(sample_xss_finding)
    
    assert is_fp == False
    assert pattern is None


# ============================================================================
# CONTEXT REFRESH TESTS
# ============================================================================

def test_context_refresh(conductor):
    """Context refresh should clear cache."""
    # Load some context
    conductor.get_context("context")
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


# ============================================================================
# STATISTICS TESTS
# ============================================================================

def test_statistics_tracking(conductor, sample_xss_finding):
    """Statistics should track validations."""
    # Run some validations
    conductor.validate_finding(sample_xss_finding)
    
    sample_xss_finding["confidence"] = 0.3
    conductor.validate_finding(sample_xss_finding)
    
    stats = conductor.get_statistics()
    
    assert stats["validations_run"] == 2
    assert stats["findings_passed"] == 1
    assert stats["findings_blocked"] == 1
    assert stats["validation_pass_rate"] == 0.5


def test_fp_pattern_statistics(conductor, sample_xss_finding):
    """FP blocks should be tracked by pattern."""
    # Trigger WAF block
    sample_xss_finding["evidence"]["response"] = {
        "status_code": 403,
        "body": "Cloudflare",
        "headers": {}
    }
    
    conductor.validate_finding(sample_xss_finding)
    
    stats = conductor.get_statistics()
    
    assert "WAF_BLOCK" in stats["fp_blocks_by_pattern"]
    assert stats["fp_blocks_by_pattern"]["WAF_BLOCK"] == 1


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

def test_full_validation_workflow(conductor, sample_xss_finding):
    """Complete validation workflow from finding to stats."""
    # Valid finding
    is_valid, reason = conductor.validate_finding(sample_xss_finding)
    assert is_valid == True
    
    # Invalid payload
    sample_xss_finding["payload"] = "Here is a test"
    is_valid, reason = conductor.validate_finding(sample_xss_finding)
    assert is_valid == False
    
    # WAF block
    sample_xss_finding["payload"] = "<script>alert(1)</script>"
    sample_xss_finding["evidence"]["response"]["status_code"] = 403
    sample_xss_finding["evidence"]["response"]["body"] = "Blocked"
    is_valid, reason = conductor.validate_finding(sample_xss_finding)
    assert is_valid == False
    
    # Check stats
    stats = conductor.get_statistics()
    assert stats["validations_run"] == 3
    assert stats["findings_passed"] == 1
    assert stats["findings_blocked"] == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
