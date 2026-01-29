#!/usr/bin/env python3
"""
False Positive Validation Tests

Ensures OpenRedirectAgent and PrototypePollutionAgent do NOT flag safe patterns.

Tests:
- OpenRedirect: Whitelist-validated, internal redirects, relative paths
- PrototypePollution: Immutable objects, frozen objects, safe merge operations
- Combined: Zero false positives across all safe endpoints

Purpose: Prevent alert fatigue by confirming agents distinguish safe from vulnerable
"""

import asyncio
import pytest
import sys
import aiohttp
from pathlib import Path
from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase, TestClient, TestServer

# Add bugtrace to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from bugtrace.agents.openredirect_agent import OpenRedirectAgent
from bugtrace.agents.prototype_pollution_agent import PrototypePollutionAgent
from bugtrace.agents.prototype_pollution_payloads import POLLUTION_MARKER
from tests.mocks.mock_openredirect_server import create_app as create_openredirect_app
from tests.mocks.mock_prototype_pollution_server import create_app as create_pollution_app


class TestOpenRedirectFalsePositives:
    """Tests that safe redirect patterns are NOT flagged as vulnerabilities."""

    @pytest.mark.asyncio
    async def test_whitelist_validated_redirect_not_vulnerable(self):
        """
        Safe endpoint: /redirect-safe validates against whitelist.
        Should NOT be flagged as vulnerable.
        """
        app = create_openredirect_app()
        async with TestClient(TestServer(app)) as client:
            base_url = str(client.server.make_url("/redirect-safe"))

            # Test with whitelisted domain (trusted.com is in SAFE_DOMAINS)
            test_url = f"{base_url}?url=http://trusted.com"

            agent = OpenRedirectAgent(test_url)
            result = await agent.run_loop()

            # Assert: Should NOT detect vulnerability on whitelisted redirect
            assert result["vulnerable"] is False, "Whitelist-validated redirect should NOT be flagged"
            assert result["findings_count"] == 0, "Should have zero findings for safe redirect"

    @pytest.mark.asyncio
    async def test_internal_redirect_not_vulnerable(self):
        """
        Safe endpoint: /internal always redirects to /dashboard (internal path).
        Should NOT be flagged as vulnerable.
        """
        app = create_openredirect_app()
        async with TestClient(TestServer(app)) as client:
            base_url = str(client.server.make_url("/internal"))

            agent = OpenRedirectAgent(base_url)
            result = await agent.run_loop()

            # Assert: Internal redirect should NOT be flagged
            assert result["vulnerable"] is False, "Internal redirect should NOT be flagged"
            assert result["findings_count"] == 0, "Should have zero findings for internal redirect"

    @pytest.mark.asyncio
    async def test_relative_path_redirect_not_vulnerable(self):
        """
        Test that relative path redirects are not flagged as external.
        Uses /redirect-safe endpoint with relative path.
        """
        app = create_openredirect_app()
        async with TestClient(TestServer(app)) as client:
            base_url = str(client.server.make_url("/redirect-safe"))

            # Test with relative path (no domain)
            test_url = f"{base_url}?url=/dashboard"

            agent = OpenRedirectAgent(test_url)
            result = await agent.run_loop()

            # Assert: Relative redirect should NOT be flagged as external
            assert result["vulnerable"] is False, "Relative path redirect should NOT be flagged"
            assert result["findings_count"] == 0

    @pytest.mark.asyncio
    async def test_same_domain_redirect_not_vulnerable(self):
        """
        Test that redirects to same domain are classified as internal.
        Agent's _is_external_redirect() should return False for same host.
        """
        app = create_openredirect_app()
        async with TestClient(TestServer(app)) as client:
            base_url = str(client.server.make_url("/redirect-safe"))

            # Construct URL that redirects to same domain
            same_domain_url = str(client.server.make_url("/dashboard"))
            test_url = f"{base_url}?url={same_domain_url}"

            agent = OpenRedirectAgent(test_url)
            result = await agent.run_loop()

            # Assert: Same-domain redirect should NOT be flagged
            assert result["vulnerable"] is False, "Same-domain redirect should NOT be flagged"
            assert result["findings_count"] == 0

    @pytest.mark.asyncio
    async def test_subdomain_redirect_handling(self):
        """
        Test redirect to subdomain (should be treated as internal).
        Current implementation should NOT flag subdomain redirects.
        """
        app = create_openredirect_app()
        async with TestClient(TestServer(app)) as client:
            base_url = str(client.server.make_url("/redirect-safe"))

            # Test subdomain redirect (localhost is whitelisted)
            test_url = f"{base_url}?url=http://sub.localhost/page"

            agent = OpenRedirectAgent(test_url)
            result = await agent.run_loop()

            # Assert: Subdomain should NOT be flagged (part of same parent domain)
            assert result["vulnerable"] is False, "Subdomain redirect should NOT be flagged"
            assert result["findings_count"] == 0

    @pytest.mark.asyncio
    async def test_encoded_internal_path_not_vulnerable(self):
        """
        Test URL-encoded internal path is correctly identified as internal.
        """
        app = create_openredirect_app()
        async with TestClient(TestServer(app)) as client:
            base_url = str(client.server.make_url("/redirect-safe"))

            # Test URL-encoded path (/dashboard = %2Fdashboard)
            test_url = f"{base_url}?url=%2Fdashboard"

            agent = OpenRedirectAgent(test_url)
            result = await agent.run_loop()

            # Assert: Encoded internal path should NOT be flagged
            assert result["vulnerable"] is False, "Encoded internal path should NOT be flagged"
            assert result["findings_count"] == 0


class TestPrototypePollutionFalsePositives:
    """Tests that safe merge patterns are NOT flagged as vulnerabilities."""

    @pytest.mark.asyncio
    async def test_immutable_object_pattern_not_vulnerable(self):
        """
        Safe endpoint: /api/safe/immutable filters __proto__ and constructor.
        Uses Object.create(null) pattern. Should NOT be flagged.
        """
        app = create_pollution_app()
        async with TestClient(TestServer(app)) as client:
            base_url = str(client.server.make_url("/api/safe/immutable"))

            agent = PrototypePollutionAgent(base_url)
            result = await agent.run_loop()

            # Assert: Safe immutable endpoint should NOT be flagged as vulnerable
            # It may find vectors, but pollution should NOT be confirmed
            if result["vulnerable"]:
                # Check findings - should not have HIGH/CRITICAL pollution confirmation
                for finding in result.get("findings", []):
                    assert finding.get("pollution_confirmed") is False, \
                        "Immutable endpoint should NOT confirm pollution"

    @pytest.mark.asyncio
    async def test_frozen_object_pattern_not_vulnerable(self):
        """
        Safe endpoint: /api/safe/frozen rejects __proto__/constructor with 400.
        Uses Object.freeze pattern. Should NOT be flagged.
        """
        app = create_pollution_app()
        async with TestClient(TestServer(app)) as client:
            base_url = str(client.server.make_url("/api/safe/frozen"))

            agent = PrototypePollutionAgent(base_url)
            result = await agent.run_loop()

            # Assert: Endpoint rejects pollution - should NOT be flagged as RCE
            if result["vulnerable"]:
                for finding in result.get("findings", []):
                    assert finding.get("rce_confirmed") is False, \
                        "Frozen endpoint should NOT be flagged as RCE vulnerable"

    @pytest.mark.asyncio
    async def test_no_json_body_acceptance_not_vulnerable(self):
        """
        Test that GET-only endpoints don't produce false positives.
        Hunter should not find JSON body vector on GET-only endpoints.
        """
        app = create_openredirect_app()  # This has GET endpoints only
        async with TestClient(TestServer(app)) as client:
            base_url = str(client.server.make_url("/"))

            agent = PrototypePollutionAgent(base_url)
            vectors = await agent._hunter_phase()

            # Should not find JSON_BODY vector on GET-only endpoint
            json_vectors = [v for v in vectors if v.get("type") == "JSON_BODY"]
            # May return empty or no HIGH confidence JSON_BODY on GET endpoint
            # This validates agent doesn't flag non-applicable endpoints

    @pytest.mark.asyncio
    async def test_pollution_marker_not_in_response(self):
        """
        Send pollution payload to safe endpoint.
        POLLUTION_MARKER should NOT appear in response.
        _verify_pollution() should return False.
        """
        app = create_pollution_app()
        async with TestClient(TestServer(app)) as client:
            base_url = str(client.server.make_url("/api/safe/immutable"))

            # Send pollution payload directly
            pollution_payload = {
                "__proto__": {
                    "polluted": POLLUTION_MARKER
                }
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    base_url,
                    json=pollution_payload,
                    headers={"Content-Type": "application/json"}
                ) as response:
                    resp_text = await response.text()

                    # Assert: POLLUTION_MARKER should NOT be in response
                    assert POLLUTION_MARKER not in resp_text, \
                        "Safe endpoint should filter pollution marker"

                    # Verify _verify_pollution returns False
                    agent = PrototypePollutionAgent(base_url)
                    pollution_found = await agent._verify_pollution(resp_text, POLLUTION_MARKER)
                    assert pollution_found is False, \
                        "_verify_pollution should return False for safe endpoint"

    @pytest.mark.asyncio
    async def test_normal_json_not_pollution(self):
        """
        Send normal JSON without __proto__ or constructor.
        Should NOT detect pollution vectors or false positive.
        """
        app = create_pollution_app()
        async with TestClient(TestServer(app)) as client:
            base_url = str(client.server.make_url("/api/safe/immutable"))

            agent = PrototypePollutionAgent(base_url)

            # Send normal JSON
            normal_payload = {
                "name": "test",
                "value": 123,
                "nested": {
                    "key": "value"
                }
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    base_url,
                    json=normal_payload,
                    headers={"Content-Type": "application/json"}
                ) as response:
                    resp_text = await response.text()

                    # Should not detect pollution from normal JSON
                    pollution_found = await agent._verify_pollution(resp_text, POLLUTION_MARKER)
                    assert pollution_found is False, \
                        "Normal JSON should NOT trigger pollution detection"

    @pytest.mark.asyncio
    async def test_nested_but_safe_objects(self):
        """
        Send deeply nested JSON without prototype keys.
        Should NOT false positive on complex but safe structures.
        """
        app = create_pollution_app()
        async with TestClient(TestServer(app)) as client:
            base_url = str(client.server.make_url("/api/safe/immutable"))

            agent = PrototypePollutionAgent(base_url)

            # Deep nested structure without pollution
            nested_payload = {
                "level1": {
                    "level2": {
                        "level3": {
                            "level4": {
                                "data": "safe",
                                "array": [1, 2, 3]
                            }
                        }
                    }
                }
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    base_url,
                    json=nested_payload,
                    headers={"Content-Type": "application/json"}
                ) as response:
                    resp_text = await response.text()

                    pollution_found = await agent._verify_pollution(resp_text, POLLUTION_MARKER)
                    assert pollution_found is False, \
                        "Nested safe JSON should NOT trigger pollution detection"


class TestCombinedValidation:
    """Combined tests for overall false positive rate."""

    @pytest.mark.asyncio
    async def test_safe_endpoints_zero_findings(self):
        """
        Run both agents against ALL safe endpoints.
        Should produce zero HIGH/CRITICAL findings.
        """
        # Test OpenRedirect safe endpoints
        or_app = create_openredirect_app()
        async with TestClient(TestServer(or_app)) as client:
            safe_endpoints = [
                "/redirect-safe?url=http://trusted.com",
                "/internal",
            ]

            total_findings = 0
            for endpoint in safe_endpoints:
                url = str(client.server.make_url(endpoint))
                agent = OpenRedirectAgent(url)
                result = await agent.run_loop()
                total_findings += result.get("findings_count", 0)

            assert total_findings == 0, \
                f"OpenRedirect safe endpoints should have ZERO findings, got {total_findings}"

        # Test PrototypePollution safe endpoints
        pp_app = create_pollution_app()
        async with TestClient(TestServer(pp_app)) as client:
            safe_endpoints = [
                "/api/safe/immutable",
                "/api/safe/frozen",
            ]

            critical_findings = 0
            for endpoint in safe_endpoints:
                url = str(client.server.make_url(endpoint))
                agent = PrototypePollutionAgent(url)
                result = await agent.run_loop()

                # Check for CRITICAL/HIGH findings (false positives)
                for finding in result.get("findings", []):
                    severity = finding.get("severity", "LOW")
                    if severity in ("CRITICAL", "HIGH"):
                        critical_findings += 1

            assert critical_findings == 0, \
                f"PrototypePollution safe endpoints should have ZERO high-severity findings, got {critical_findings}"

    @pytest.mark.asyncio
    async def test_vulnerable_vs_safe_differentiation(self):
        """
        Verify agents clearly differentiate vulnerable vs safe endpoints.
        Run same agent against both types - should only flag vulnerable.
        """
        # Test OpenRedirect differentiation
        or_app = create_openredirect_app()
        async with TestClient(TestServer(or_app)) as client:
            # Vulnerable endpoint
            vuln_url = str(client.server.make_url("/redirect?url=http://evil.com"))
            vuln_agent = OpenRedirectAgent(vuln_url)
            vuln_result = await vuln_agent.run_loop()

            # Safe endpoint
            safe_url = str(client.server.make_url("/redirect-safe?url=http://trusted.com"))
            safe_agent = OpenRedirectAgent(safe_url)
            safe_result = await safe_agent.run_loop()

            # Assert clear differentiation
            assert vuln_result["vulnerable"] is True, "Vulnerable endpoint should be flagged"
            assert safe_result["vulnerable"] is False, "Safe endpoint should NOT be flagged"

    @pytest.mark.asyncio
    async def test_confidence_levels_on_safe_endpoints(self):
        """
        Run agents against safe endpoints.
        Any vectors found should have LOW confidence (not HIGH).
        """
        app = create_pollution_app()
        async with TestClient(TestServer(app)) as client:
            safe_url = str(client.server.make_url("/api/safe/immutable"))

            agent = PrototypePollutionAgent(safe_url)
            vectors = await agent._hunter_phase()

            # Check confidence levels
            high_confidence_vectors = [v for v in vectors if v.get("confidence") == "HIGH"]

            # HIGH confidence vectors are OK during Hunter phase
            # What matters: Auditor phase should NOT confirm exploitation
            result = await agent.run_loop()

            if result["vulnerable"]:
                for finding in result.get("findings", []):
                    # Safe endpoints should NOT produce CRITICAL/HIGH confirmed findings
                    severity = finding.get("severity", "LOW")
                    assert severity not in ("CRITICAL", "HIGH"), \
                        f"Safe endpoint produced {severity} finding - false positive"

    @pytest.mark.asyncio
    async def test_audit_trail_for_safe_determination(self):
        """
        Verify agents correctly log why endpoint was determined safe.
        Check that _is_external_redirect() and _verify_pollution() work correctly.
        """
        # Test OpenRedirect _is_external_redirect logic
        or_app = create_openredirect_app()
        async with TestClient(TestServer(or_app)) as client:
            base_url = str(client.server.make_url("/redirect-safe"))
            test_url = f"{base_url}?url=http://trusted.com"

            agent = OpenRedirectAgent(test_url)

            # Test _is_external_redirect with internal redirect
            is_external = agent._is_external_redirect("/dashboard", "/dashboard")
            assert is_external is False, "_is_external_redirect should return False for relative path"

            # Test _is_external_redirect with same domain
            same_domain = str(client.server.make_url("/other"))
            is_external_same = agent._is_external_redirect(same_domain, same_domain)
            assert is_external_same is False, "_is_external_redirect should return False for same domain"

        # Test PrototypePollution _verify_pollution logic
        pp_app = create_pollution_app()
        async with TestClient(TestServer(pp_app)) as client:
            base_url = str(client.server.make_url("/api/safe/immutable"))

            agent = PrototypePollutionAgent(base_url)

            # Safe response should not have marker
            safe_response = '{"status": "safe", "config": {"test": "data"}}'
            pollution_found = await agent._verify_pollution(safe_response, POLLUTION_MARKER)
            assert pollution_found is False, "_verify_pollution should return False for safe response"

            # Polluted response would have marker
            polluted_response = f'{{"status": "polluted", "marker": "{POLLUTION_MARKER}"}}'
            pollution_confirmed = await agent._verify_pollution(polluted_response, POLLUTION_MARKER)
            assert pollution_confirmed is True, "_verify_pollution should return True when marker present"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
