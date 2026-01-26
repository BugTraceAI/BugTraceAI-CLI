"""
Test finding conversion and description generation.
Run with: python -m pytest tests/test_finding_conversion.py -v
"""
import pytest
import sys
sys.path.insert(0, '.')

from bugtrace.core.database import _evidence_to_description
from bugtrace.agents.reporting import ReportingAgent


class TestEvidenceToDescription:
    """Test the _evidence_to_description helper function."""

    def test_csti_dict_evidence(self):
        """CSTI with dict evidence should produce readable description."""
        finding = {
            "type": "CSTI",
            "parameter": "HEADER:User-Agent",
            "payload": "{{7*7}}",
            "evidence": {"proof": "Found via Header injection"}
        }
        result = _evidence_to_description(finding)

        # Should NOT contain raw dict syntax
        assert "{'proof'" not in result
        assert "{\"proof\"" not in result

        # Should be readable
        assert "CSTI" in result or "Template Injection" in result
        assert "HEADER:User-Agent" in result or "User-Agent" in result
        print(f"CSTI description: {result}")

    def test_sqli_dict_evidence(self):
        """SQLi with dict evidence should produce readable description."""
        finding = {
            "type": "SQLI",
            "parameter": "category",
            "payload": "' OR '1'='1",
            "evidence": {
                "db_type": "PostgreSQL",
                "injection_type": "boolean-based blind"
            }
        }
        result = _evidence_to_description(finding)

        # Should NOT contain raw dict syntax
        assert "{'db_type'" not in result

        # Should be readable
        assert "SQL" in result
        print(f"SQLi description: {result}")

    def test_string_description_priority(self):
        """If description is a proper string, use it directly."""
        finding = {
            "type": "XSS",
            "description": "This is a proper human-readable description.",
            "evidence": {"some": "dict"}
        }
        result = _evidence_to_description(finding)
        assert result == "This is a proper human-readable description."

    def test_string_evidence(self):
        """String evidence should pass through."""
        finding = {
            "type": "XSS",
            "evidence": "Found reflected XSS in search parameter."
        }
        result = _evidence_to_description(finding)
        assert result == "Found reflected XSS in search parameter."

    def test_fallback_when_no_evidence(self):
        """Should generate fallback description when no evidence."""
        finding = {
            "type": "LFI",
            "parameter": "file"
        }
        result = _evidence_to_description(finding)
        assert "LFI" in result
        assert "file" in result


class TestReportingAgentCurl:
    """Test curl command generation."""

    def setup_method(self):
        """Create a minimal ReportingAgent."""
        self.agent = ReportingAgent.__new__(ReportingAgent)

    def test_csti_header_curl(self):
        """CSTI header injection should generate curl with -H flag."""
        finding = {
            "type": "CSTI",
            "url": "https://example.com/page",
            "parameter": "HEADER:User-Agent",
            "payload": "{{7*7}}"
        }
        result = self.agent._generate_curl(finding)

        assert "curl" in result
        assert "-H" in result
        assert "User-Agent" in result
        assert "{{7*7}}" in result
        print(f"CSTI curl: {result}")

    def test_csti_post_curl(self):
        """CSTI POST should generate curl with -d flag."""
        finding = {
            "type": "CSTI",
            "url": "https://example.com/page",
            "parameter": "POST:search",
            "payload": "{{7*7}}"
        }
        result = self.agent._generate_curl(finding)

        assert "curl" in result
        assert "-X POST" in result or "-d" in result
        print(f"CSTI POST curl: {result}")

    def test_sqli_sqlmap(self):
        """SQLi should generate sqlmap command."""
        finding = {
            "type": "SQLI",
            "url": "https://example.com/products?id=1",
            "parameter": "id"
        }
        result = self.agent._generate_curl(finding)

        assert "sqlmap" in result
        assert "-p id" in result
        print(f"SQLi command: {result}")

    def test_xss_browser_url(self):
        """XSS should generate browser-friendly URL."""
        finding = {
            "type": "XSS",
            "url": "https://example.com/search?q=test",
            "parameter": "q",
            "payload": "<script>alert(1)</script>"
        }
        result = self.agent._generate_curl(finding)

        assert "example.com" in result
        assert "Open in browser" in result or "XSS" in result
        print(f"XSS reproduction: {result}")

    def test_reproduction_priority(self):
        """If reproduction is provided, use it directly."""
        finding = {
            "type": "SQLI",
            "url": "https://example.com/page",
            "parameter": "id",
            "reproduction": "sqlmap -u 'https://example.com/page?id=1' -p id --batch --dbs --technique=U"
        }
        result = self.agent._generate_curl(finding)

        # Should use the provided reproduction command exactly
        assert result == finding["reproduction"]


if __name__ == "__main__":
    # Run tests
    print("=" * 60)
    print("Testing _evidence_to_description")
    print("=" * 60)

    test_evidence = TestEvidenceToDescription()
    test_evidence.test_csti_dict_evidence()
    test_evidence.test_sqli_dict_evidence()
    test_evidence.test_string_description_priority()
    test_evidence.test_string_evidence()
    test_evidence.test_fallback_when_no_evidence()

    print("\n" + "=" * 60)
    print("Testing _generate_curl")
    print("=" * 60)

    test_curl = TestReportingAgentCurl()
    test_curl.setup_method()
    test_curl.test_csti_header_curl()
    test_curl.test_csti_post_curl()
    test_curl.test_sqli_sqlmap()
    test_curl.test_xss_browser_url()
    test_curl.test_reproduction_priority()

    print("\n" + "=" * 60)
    print("ALL TESTS PASSED!")
    print("=" * 60)
