#!/usr/bin/env python3
"""
Unit tests for OpenRedirectAgent

Tests:
- Hunter phase: Parameter, path, JavaScript, and header vector discovery
- Auditor phase: Payload testing and validation logic
- Integration: Full run_loop execution

Requires: Mock server running on http://127.0.0.1:5080
"""

import asyncio
import pytest
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch, MagicMock

# Add bugtrace to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from bugtrace.agents.openredirect_agent import OpenRedirectAgent
from bugtrace.agents.openredirect_payloads import (
    REDIRECT_PARAMS, RANKED_PAYLOADS, JS_REDIRECT_PATTERNS,
    get_payloads_for_tier
)


class TestHunterPhase:
    """Tests for Hunter phase - vector discovery."""

    def test_discover_param_vectors_existing(self):
        """Hunter identifies redirect params in existing URL."""
        agent = OpenRedirectAgent("http://test.com/page?redirect=http://other.com&q=search")
        vectors = agent._discover_param_vectors()

        # Should find 'redirect' param
        redirect_vectors = [v for v in vectors if v.get("param") == "redirect"]
        assert len(redirect_vectors) >= 1, "Should detect 'redirect' parameter"
        assert redirect_vectors[0]["confidence"] == "HIGH"

    def test_discover_param_vectors_heuristic(self):
        """Hunter uses heuristics for redirect-like params."""
        agent = OpenRedirectAgent("http://test.com?returnUrl=http://other.com")
        vectors = agent._discover_param_vectors()

        # Should find 'returnUrl' via heuristic (contains 'return')
        assert any(v.get("param") == "returnUrl" for v in vectors)

    def test_discover_param_vectors_agent_input(self):
        """Hunter includes params provided via agent constructor."""
        agent = OpenRedirectAgent("http://test.com", params=["custom_redirect", "target"])
        vectors = agent._discover_param_vectors()

        assert any(v.get("param") == "custom_redirect" for v in vectors)
        assert any(v.get("param") == "target" for v in vectors)

    def test_discover_path_vectors(self):
        """Hunter identifies path-based redirect patterns."""
        agent = OpenRedirectAgent("http://test.com/redirect/external")
        vectors = agent._discover_path_vectors()

        assert len(vectors) >= 1, "Should detect /redirect/ path pattern"
        assert vectors[0]["type"] == "PATH"

    def test_discover_path_vectors_goto(self):
        """Hunter identifies /goto/ path pattern."""
        agent = OpenRedirectAgent("http://test.com/goto/http://evil.com")
        vectors = agent._discover_path_vectors()

        assert any(v.get("pattern_matched", "").startswith("/goto") for v in vectors)

    def test_analyze_javascript_redirects(self):
        """Hunter detects JavaScript redirect patterns."""
        agent = OpenRedirectAgent("http://test.com")

        html = '''
        <script>
        var url = getParam('next');
        window.location = url;
        </script>
        '''
        vectors = agent._analyze_javascript_redirects(html)

        assert len(vectors) >= 1, "Should detect window.location pattern"
        assert vectors[0]["type"] == "JAVASCRIPT"

    def test_analyze_javascript_location_href(self):
        """Hunter detects location.href patterns."""
        agent = OpenRedirectAgent("http://test.com")

        html = '<script>location.href = "http://redirect.com";</script>'
        vectors = agent._analyze_javascript_redirects(html)

        assert len(vectors) >= 1
        assert any("location" in v.get("pattern_name", "").lower() for v in vectors)

    def test_analyze_meta_refresh(self):
        """Hunter detects meta refresh tags."""
        agent = OpenRedirectAgent("http://test.com")

        html = '''
        <html>
        <head>
        <meta http-equiv="refresh" content="0;url=http://redirect.com">
        </head>
        </html>
        '''
        vectors = agent._analyze_meta_refresh(html)

        assert len(vectors) >= 1, "Should detect meta refresh"
        assert vectors[0]["type"] == "META_REFRESH"
        assert "redirect.com" in vectors[0]["redirect_url"]


class TestAuditorPhase:
    """Tests for Auditor phase - payload testing and validation."""

    def test_is_external_redirect_protocol_relative(self):
        """Auditor correctly identifies protocol-relative redirects."""
        agent = OpenRedirectAgent("http://test.com")

        assert agent._is_external_redirect("//evil.com", "//evil.com") is True

    def test_is_external_redirect_full_url(self):
        """Auditor correctly identifies full URL redirects."""
        agent = OpenRedirectAgent("http://test.com")

        assert agent._is_external_redirect("https://evil.com/path", "evil.com") is True

    def test_is_external_redirect_internal(self):
        """Auditor correctly identifies internal redirects as safe."""
        agent = OpenRedirectAgent("http://test.com")

        # Same host = internal = safe
        assert agent._is_external_redirect("http://test.com/page", "test") is False
        # Relative = internal = safe
        assert agent._is_external_redirect("/dashboard", "/dashboard") is False

    def test_is_external_redirect_subdomain(self):
        """Auditor handles subdomain correctly."""
        agent = OpenRedirectAgent("http://test.com")

        # Subdomain of original = internal
        assert agent._is_external_redirect("http://sub.test.com/page", "sub") is False
        # Different domain = external
        assert agent._is_external_redirect("http://test.com.evil.com/page", "evil") is True

    def test_get_technique_name(self):
        """Auditor assigns correct technique names."""
        agent = OpenRedirectAgent("http://test.com")

        assert agent._get_technique_name("//evil.com") == "protocol_relative"
        assert agent._get_technique_name("trusted@evil.com") == "whitelist_bypass_userinfo"
        assert agent._get_technique_name("%2f%2fevil.com") == "encoding_bypass"
        assert agent._get_technique_name("javascript:alert(1)") == "javascript_protocol"


class TestPayloadLibrary:
    """Tests for payload library module."""

    def test_redirect_params_count(self):
        """Payload library has sufficient redirect parameters."""
        assert len(REDIRECT_PARAMS) >= 100, "Should have 100+ redirect params"

    def test_ranked_payloads_tiers(self):
        """Payload library has all required tiers."""
        assert "basic" in RANKED_PAYLOADS
        assert "encoding" in RANKED_PAYLOADS
        assert "whitelist" in RANKED_PAYLOADS
        assert "advanced" in RANKED_PAYLOADS

    def test_get_payloads_for_tier_substitution(self):
        """get_payloads_for_tier substitutes placeholders correctly."""
        payloads = get_payloads_for_tier("basic", "attacker.com")

        assert len(payloads) > 0
        assert all("attacker.com" in p for p in payloads)
        assert not any("{attacker}" in p for p in payloads)

    def test_get_payloads_whitelist_tier(self):
        """Whitelist tier payloads include trusted domain."""
        payloads = get_payloads_for_tier("whitelist", "attacker.com", "trusted.com")

        assert len(payloads) > 0
        # Should have both attacker and trusted domains
        assert any("attacker.com" in p and "trusted.com" in p for p in payloads)


class TestIntegration:
    """Integration tests requiring mock server."""

    @pytest.fixture
    def mock_response(self):
        """Create mock aiohttp response."""
        mock = MagicMock()
        mock.status = 302
        mock.headers = {"Location": "http://evil.com/redirect"}
        mock.version = MagicMock(major=1, minor=1)
        mock.text = AsyncMock(return_value="<html></html>")
        return mock

    @pytest.mark.asyncio
    async def test_run_loop_returns_dict(self):
        """Agent run_loop returns proper structure."""
        agent = OpenRedirectAgent("http://test.com?url=test", params=["url"])

        # Mock the HTTP calls
        with patch.object(agent, '_hunter_phase', new_callable=AsyncMock) as mock_hunter:
            with patch.object(agent, '_auditor_phase', new_callable=AsyncMock) as mock_auditor:
                mock_hunter.return_value = []
                mock_auditor.return_value = []

                result = await agent.run_loop()

        assert "status" in result
        assert "vulnerable" in result
        assert "findings" in result
        assert "findings_count" in result

    @pytest.mark.asyncio
    async def test_hunter_phase_calls_all_discovery_methods(self):
        """Hunter phase calls all discovery methods."""
        agent = OpenRedirectAgent("http://test.com?redirect=test")

        with patch.object(agent, '_discover_param_vectors', return_value=[]) as mock_params:
            with patch.object(agent, '_discover_path_vectors', return_value=[]) as mock_paths:
                with patch.object(agent, '_discover_content_vectors', new_callable=AsyncMock, return_value=[]) as mock_content:
                    await agent._hunter_phase()

        mock_params.assert_called_once()
        mock_paths.assert_called_once()
        mock_content.assert_called_once()


def run_tests():
    """Run all tests."""
    print("\n" + "="*60)
    print("OpenRedirectAgent Unit Tests")
    print("="*60 + "\n")

    # Run pytest with verbose output
    pytest.main([__file__, "-v", "--tb=short"])


if __name__ == "__main__":
    run_tests()
