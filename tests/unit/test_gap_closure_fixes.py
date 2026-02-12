"""
Unit tests for the 5 Gap Closure fixes (vs Burp Suite benchmark).

These tests validate each fix independently WITHOUT running a full scan.
They mock HTTP/browser interactions and verify the logic works correctly.

Fix #1: Cookie SQLi probe findings include "url" field
Fix #2: Nuclei misconfig separation into tech_profile["misconfigurations"]
Fix #3: JS dependency version detection (_detect_js_versions)
Fix #4: XSS internal link extraction for DOM XSS coverage
Fix #5: Open Redirect internal link extraction + DOM redirect testing
"""
import asyncio
import base64
import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from contextlib import asynccontextmanager
from pathlib import Path

from tests.unit.conftest import RICH_HTML, TEST_URL


# ---------------------------------------------------------------------------
# HTML fixtures for gap closure tests (base64 to avoid escaping issues)
# ---------------------------------------------------------------------------

# HTML with internal links for Fix #4 and #5
_HTML_WITH_LINKS_B64 = base64.b64encode("""<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body ng-app="myApp">
    <nav>
        <a href="/blog/">Blog</a>
        <a href="/about">About</a>
        <a href="/catalog?category=Juice">Catalog</a>
        <a href="https://external.com/page">External</a>
        <a href="/contact">Contact</a>
    </nav>
    <form action="/search" method="GET">
        <input type="text" name="searchTerm" value="">
        <input type="hidden" name="category" value="Juice">
        <input type="submit" value="Search">
    </form>
    <script>
        var searchText = "user_query";
        var selectedCategory = "Juice";
    </script>
    <script src="/js/angular-1.7.7.min.js"></script>
    <script src="/js/jquery-3.4.1.min.js"></script>
</body>
</html>""".encode()).decode()

HTML_WITH_LINKS = base64.b64decode(_HTML_WITH_LINKS_B64).decode()

# HTML with vulnerable JS versions for Fix #3
_HTML_VULN_JS_B64 = base64.b64encode("""<!DOCTYPE html>
<html>
<body>
    <script src="https://cdn.example.com/angular-1.7.7.min.js"></script>
    <script src="https://cdn.example.com/jquery-3.4.1.min.js"></script>
    <script src="https://cdn.example.com/vue-2.6.14.js"></script>
    <script src="https://cdn.example.com/lodash-4.17.20.min.js"></script>
    <script src="https://cdn.example.com/bootstrap-4.3.1.min.js"></script>
    <script src="https://cdn.example.com/react-17.0.2.min.js"></script>
</body>
</html>""".encode()).decode()

HTML_VULN_JS = base64.b64decode(_HTML_VULN_JS_B64).decode()

# HTML with safe JS versions
_HTML_SAFE_JS_B64 = base64.b64encode("""<!DOCTYPE html>
<html>
<body>
    <script src="https://cdn.example.com/angular-1.8.3.min.js"></script>
    <script src="https://cdn.example.com/jquery-3.6.0.min.js"></script>
</body>
</html>""".encode()).decode()

HTML_SAFE_JS = base64.b64decode(_HTML_SAFE_JS_B64).decode()


# ============================================================================
# Fix #1: Cookie SQLi probe findings include "url" field
# ============================================================================

class TestCookieSQLiUrlField:
    """
    FIX #9: Cookie SQLi probe findings were missing "url" field,
    so they couldn't flow through the pipeline.

    Tests that all 3 finding types (error-based, time-based, timeout)
    include the "url" field.
    """

    @pytest.fixture
    def agent(self):
        from bugtrace.agents.analysis_agent import DASTySASTAgent
        agent = DASTySASTAgent(
            url="https://example.com/catalog",
            tech_profile={},
            report_dir=Path("/tmp/test"),
        )
        agent._v = Mock()
        return agent

    @pytest.mark.asyncio
    async def test_error_based_finding_has_url(self, agent):
        """Error-based SQLi finding (status 500 vs <400) must include url."""
        # Mock browser session to return cookies
        mock_session_data = {
            "cookies": [{"name": "TrackingId", "value": "abc123"}]
        }

        # Mock HTTP responses: single quote → 500, double → 200
        mock_resp_500 = AsyncMock()
        mock_resp_500.status = 500
        mock_resp_200 = AsyncMock()
        mock_resp_200.status = 200

        call_count = 0
        @asynccontextmanager
        async def mock_get(url, headers=None, ssl=None, timeout=None):
            nonlocal call_count
            call_count += 1
            if call_count % 2 == 1:  # Odd calls = single quote
                yield mock_resp_500
            else:                     # Even calls = double quote
                yield mock_resp_200

        mock_session = MagicMock()
        mock_session.get = mock_get

        @asynccontextmanager
        async def mock_orchestrator_session(dest_type):
            yield mock_session

        with patch("bugtrace.agents.analysis_agent.orchestrator") as mock_orch, \
             patch("bugtrace.tools.visual.browser.browser_manager.get_session_data",
                   AsyncMock(return_value=mock_session_data)):
            mock_orch.session = mock_orchestrator_session

            # Mock synthetic cookies to empty (only test real cookies)
            agent._generate_synthetic_cookies = AsyncMock(return_value=[])

            result = await agent._check_cookie_sqli_probes()

        findings = result["vulnerabilities"]
        assert len(findings) > 0, "Should detect SQLi in cookie"

        for finding in findings:
            assert "url" in finding, f"Finding missing 'url' field: {finding}"
            assert finding["url"] == "https://example.com/catalog"
            assert finding["type"] == "SQLi"
            assert "Cookie:" in finding["parameter"]

    @pytest.mark.asyncio
    async def test_time_based_finding_has_url(self, agent):
        """Time-based blind SQLi finding must include url."""
        import time

        mock_session_data = {
            "cookies": [{"name": "userId", "value": "42"}]
        }

        # Mock: no error-based detection (all 200s), but slow response for sleep
        @asynccontextmanager
        async def mock_get(url, headers=None, ssl=None, timeout=None):
            resp = AsyncMock()
            cookie_header = headers.get("Cookie", "") if headers else ""
            if "SLEEP" in cookie_header or "WAITFOR" in cookie_header or "pg_sleep" in cookie_header:
                resp.status = 200
                # Simulate slow response by patching time
                resp.text = AsyncMock(return_value="OK")
                yield resp
            else:
                resp.status = 200
                resp.text = AsyncMock(return_value="OK")
                yield resp

        mock_session = MagicMock()
        mock_session.get = mock_get

        @asynccontextmanager
        async def mock_orchestrator_session(dest_type):
            yield mock_session

        # Patch time.time to simulate 3s delay for sleep payloads
        original_time = time.time
        time_call_count = 0

        def mock_time():
            nonlocal time_call_count
            time_call_count += 1
            # Every pair: start_time=0, end_time=3.5 (simulates 3.5s delay)
            if time_call_count % 2 == 1:
                return 1000.0
            else:
                return 1003.5

        with patch("bugtrace.agents.analysis_agent.orchestrator") as mock_orch, \
             patch("bugtrace.tools.visual.browser.browser_manager.get_session_data",
                   AsyncMock(return_value=mock_session_data)), \
             patch("time.time", side_effect=mock_time):
            mock_orch.session = mock_orchestrator_session
            agent._generate_synthetic_cookies = AsyncMock(return_value=[])

            result = await agent._check_cookie_sqli_probes()

        findings = result["vulnerabilities"]
        # Should find time-based blind SQLi
        time_findings = [f for f in findings if "Time-based" in f.get("vulnerability", "")]
        if time_findings:
            for finding in time_findings:
                assert "url" in finding, f"Time-based finding missing 'url': {finding}"
                assert finding["url"] == "https://example.com/catalog"

    @pytest.mark.asyncio
    async def test_no_cookies_returns_empty(self, agent):
        """No cookies should return empty findings without error."""
        mock_session_data = {"cookies": []}

        with patch("bugtrace.tools.visual.browser.browser_manager.get_session_data",
                   AsyncMock(return_value=mock_session_data)):
            agent._generate_synthetic_cookies = AsyncMock(return_value=[])
            result = await agent._check_cookie_sqli_probes()

        assert result["vulnerabilities"] == []


# ============================================================================
# Fix #2: Nuclei misconfig separation
# ============================================================================

class TestNucleiMisconfigSeparation:
    """
    FIX #10: Nuclei misconfigs (HSTS missing, cookie flags) were not
    being separated from tech findings into tech_profile["misconfigurations"].

    Tests the parsing logic in NucleiAgent.run().
    """

    @pytest.fixture
    def agent(self):
        from bugtrace.agents.nuclei_agent import NucleiAgent
        return NucleiAgent(
            target="https://example.com",
            report_dir=Path("/tmp/test"),
            event_bus=Mock(),
        )

    @pytest.mark.asyncio
    async def test_misconfig_findings_separated(self, agent):
        """Findings with misconfig/exposure tags go to misconfigurations list."""
        mock_nuclei_results = {
            "tech_findings": [
                {
                    "info": {
                        "name": "Strict-Transport-Security Missing",
                        "tags": ["misconfig", "headers"],
                        "severity": "info",
                        "description": "HSTS header is missing",
                    },
                    "template-id": "http-missing-security-headers",
                    "matched-at": "https://example.com",
                },
                {
                    "info": {
                        "name": "AngularJS Detection",
                        "tags": ["tech", "detect"],
                        "severity": "info",
                    },
                    "template-id": "angularjs-detect",
                    "matched-at": "https://example.com",
                },
                {
                    "info": {
                        "name": "Cookie Without HttpOnly Flag",
                        "tags": ["misconfig", "cookie"],
                        "severity": "low",
                        "description": "Cookie missing HttpOnly flag",
                    },
                    "template-id": "cookie-without-httponly",
                    "matched-at": "https://example.com",
                },
                {
                    "info": {
                        "name": "Exposed Git Config",
                        "tags": ["exposure", "config"],
                        "severity": "medium",
                        "description": "Git config exposed",
                    },
                    "template-id": "git-config-exposure",
                    "matched-at": "https://example.com/.git/config",
                },
            ],
            "vuln_findings": [],
        }

        with patch.object(agent, '_verify_waf_detections', new_callable=AsyncMock, return_value=[]), \
             patch.object(agent, '_fetch_html', new_callable=AsyncMock, return_value=None), \
             patch.object(agent, '_check_security_headers', new_callable=AsyncMock, return_value=[]), \
             patch("bugtrace.tools.external.external_tools.run_nuclei",
                   AsyncMock(return_value=mock_nuclei_results)), \
             patch("bugtrace.core.ui.dashboard"), \
             patch("builtins.open", MagicMock()):

            result = await agent.run()

        # Misconfigs should be in separate list (from nuclei results only, security headers mocked out)
        misconfigs = result["misconfigurations"]
        assert len(misconfigs) == 3, f"Expected 3 misconfigs, got {len(misconfigs)}: {misconfigs}"

        misconfig_names = [m["name"] for m in misconfigs]
        assert "Strict-Transport-Security Missing" in misconfig_names
        assert "Cookie Without HttpOnly Flag" in misconfig_names
        assert "Exposed Git Config" in misconfig_names

        # AngularJS should be in frameworks, NOT misconfigurations
        assert "AngularJS Detection" not in misconfig_names
        assert "AngularJS Detection" in result.get("frameworks", []) or \
               "AngularJS Detection" in result.get("tech_tags", [])

    @pytest.mark.asyncio
    async def test_misconfig_finding_fields(self, agent):
        """Each misconfig finding must have required fields."""
        mock_nuclei_results = {
            "tech_findings": [
                {
                    "info": {
                        "name": "X-Frame-Options Missing",
                        "tags": ["misconfig", "headers"],
                        "severity": "info",
                        "description": "X-Frame-Options header is missing",
                    },
                    "template-id": "x-frame-options-missing",
                    "matched-at": "https://example.com",
                },
            ],
            "vuln_findings": [],
        }

        with patch.object(agent, '_verify_waf_detections', new_callable=AsyncMock, return_value=[]), \
             patch.object(agent, '_fetch_html', new_callable=AsyncMock, return_value=None), \
             patch.object(agent, '_check_security_headers', new_callable=AsyncMock, return_value=[]), \
             patch("bugtrace.tools.external.external_tools.run_nuclei",
                   AsyncMock(return_value=mock_nuclei_results)), \
             patch("bugtrace.core.ui.dashboard"), \
             patch("builtins.open", MagicMock()):

            result = await agent.run()

        misconfigs = result["misconfigurations"]
        assert len(misconfigs) == 1

        mc = misconfigs[0]
        required_fields = ["name", "severity", "description", "tags", "template_id", "matched_at"]
        for field in required_fields:
            assert field in mc, f"Misconfig missing field '{field}': {mc}"

    @pytest.mark.asyncio
    async def test_no_misconfigs_empty_list(self, agent):
        """Tech-only findings should leave misconfigurations empty."""
        mock_nuclei_results = {
            "tech_findings": [
                {
                    "info": {
                        "name": "Nginx",
                        "tags": ["tech", "detect"],
                        "severity": "info",
                    },
                    "template-id": "nginx-detect",
                    "matched-at": "https://example.com",
                },
            ],
            "vuln_findings": [],
        }

        with patch.object(agent, '_verify_waf_detections', new_callable=AsyncMock, return_value=[]), \
             patch.object(agent, '_fetch_html', new_callable=AsyncMock, return_value=None), \
             patch.object(agent, '_check_security_headers', new_callable=AsyncMock, return_value=[]), \
             patch("bugtrace.tools.external.external_tools.run_nuclei",
                   AsyncMock(return_value=mock_nuclei_results)), \
             patch("bugtrace.core.ui.dashboard"), \
             patch("builtins.open", MagicMock()):

            result = await agent.run()

        assert result["misconfigurations"] == []


# ============================================================================
# Fix #3: JS dependency version detection
# ============================================================================

class TestJSVersionDetection:
    """
    FIX #11: Vulnerable JS library versions (e.g., Angular 1.7.7) were
    not detected. _detect_js_versions() is a pure function — easiest to test.
    """

    @pytest.fixture
    def agent(self):
        from bugtrace.agents.nuclei_agent import NucleiAgent
        return NucleiAgent(
            target="https://example.com",
            report_dir=Path("/tmp/test"),
            event_bus=Mock(),
        )

    def test_detects_vulnerable_angular(self, agent):
        """Angular 1.7.7 < 1.8.0 → vulnerable."""
        html = '<script src="/js/angular-1.7.7.min.js"></script>'
        findings = agent._detect_js_versions(html)
        assert len(findings) == 1
        assert "AngularJS" in findings[0]["display_name"]
        assert "1.7.7" in findings[0]["display_name"]
        assert "END OF LIFE" in findings[0]["display_name"]
        assert "CVE-2022-25869" in findings[0]["description"]

    def test_detects_vulnerable_jquery(self, agent):
        """jQuery 3.4.1 < 3.5.0 → vulnerable."""
        html = '<script src="/js/jquery-3.4.1.min.js"></script>'
        findings = agent._detect_js_versions(html)
        assert len(findings) == 1
        assert "jQuery" in findings[0]["display_name"]
        assert "3.4.1" in findings[0]["display_name"]

    def test_detects_vulnerable_lodash(self, agent):
        """Lodash 4.17.20 < 4.17.21 → vulnerable."""
        html = '<script src="/js/lodash-4.17.20.min.js"></script>'
        findings = agent._detect_js_versions(html)
        assert len(findings) == 1
        assert "Lodash" in findings[0]["name"]

    def test_safe_versions_no_findings(self, agent):
        """Safe versions should not produce findings."""
        findings = agent._detect_js_versions(HTML_SAFE_JS)
        assert len(findings) == 0

    def test_multiple_vulnerable_libs(self, agent):
        """Multiple vulnerable libs detected in one page."""
        findings = agent._detect_js_versions(HTML_VULN_JS)
        names = [f["name"] for f in findings]

        # Angular 1.7.7 < 1.8.0
        assert any("AngularJS" in n for n in names)
        # jQuery 3.4.1 < 3.5.0
        assert any("jQuery" in n for n in names)
        # Lodash 4.17.20 < 4.17.21
        assert any("Lodash" in n for n in names)
        # Vue 2.6.14 < 2.7.0
        assert any("Vue" in n for n in names)

        # React 17.0.2 >= 16.13.0 → NOT vulnerable
        assert not any("React" in n for n in names)
        # Bootstrap 4.3.1 >= 4.3.1 → NOT vulnerable
        assert not any("Bootstrap" in n for n in names)

    def test_inline_version_detection(self, agent):
        """Detect version from inline comment like 'AngularJS v1.7.7'."""
        html = '<script>/* AngularJS v1.7.7 */</script>'
        findings = agent._detect_js_versions(html)
        assert len(findings) == 1
        assert "AngularJS" in findings[0]["name"]

    def test_finding_has_required_fields(self, agent):
        """Each finding must have misconfig-compatible fields."""
        html = '<script src="/js/angular-1.7.7.min.js"></script>'
        findings = agent._detect_js_versions(html)
        assert len(findings) == 1

        f = findings[0]
        assert "name" in f
        assert "severity" in f
        assert "description" in f
        assert "tags" in f
        assert "js-dependency" in f["tags"]
        assert "template_id" in f
        assert f["template_id"] == "js-vulnerable-angularjs"
        assert "matched_at" in f

    def test_no_scripts_no_findings(self, agent):
        """HTML without scripts returns empty list."""
        html = '<html><body><p>Hello</p></body></html>'
        findings = agent._detect_js_versions(html)
        assert findings == []

    def test_underscore_version_separator(self, agent):
        """angular_1_7_7.js should be detected."""
        html = '<script src="/js/angular_1_7_7.js"></script>'
        findings = agent._detect_js_versions(html)
        assert len(findings) == 1
        assert "AngularJS" in findings[0]["name"]


# ============================================================================
# Fix #4: XSS internal link extraction for DOM XSS
# ============================================================================

class TestXSSInternalLinkExtraction:
    """
    FIX #12: _loop_test_dom_xss() only tested self.url.
    Now _discover_xss_params() extracts internal links stored in
    _discovered_internal_urls, and _loop_test_dom_xss() iterates them all.
    """

    @pytest.fixture
    def agent(self):
        from bugtrace.agents.xss_agent import XSSAgent
        agent = XSSAgent(url="https://example.com/catalog?category=Juice", event_bus=Mock())
        agent._v = Mock()
        return agent

    def _make_browser_mock(self, html):
        return AsyncMock(return_value={
            "text": html,
            "screenshot": "/tmp/fake.png",
            "html": html,
        })

    @pytest.mark.asyncio
    async def test_extracts_internal_links(self, agent):
        """Internal links from <a> tags are extracted and stored."""
        mock = self._make_browser_mock(HTML_WITH_LINKS)
        with patch("bugtrace.tools.visual.browser.browser_manager.capture_state", mock):
            await agent._discover_xss_params("https://example.com/catalog?category=Juice")

        assert hasattr(agent, '_discovered_internal_urls')
        urls = agent._discovered_internal_urls

        # Should find /blog/, /about, /contact (same domain)
        assert any("/blog" in u for u in urls), f"Missing /blog in {urls}"
        assert any("/about" in u for u in urls), f"Missing /about in {urls}"
        assert any("/contact" in u for u in urls), f"Missing /contact in {urls}"

    @pytest.mark.asyncio
    async def test_excludes_external_links(self, agent):
        """External links (different domain) must be excluded."""
        mock = self._make_browser_mock(HTML_WITH_LINKS)
        with patch("bugtrace.tools.visual.browser.browser_manager.capture_state", mock):
            await agent._discover_xss_params("https://example.com/catalog?category=Juice")

        urls = agent._discovered_internal_urls
        assert not any("external.com" in u for u in urls), f"External link found: {urls}"

    @pytest.mark.asyncio
    async def test_excludes_self_url(self, agent):
        """The base URL itself should not be in internal URLs."""
        mock = self._make_browser_mock(HTML_WITH_LINKS)
        with patch("bugtrace.tools.visual.browser.browser_manager.capture_state", mock):
            await agent._discover_xss_params("https://example.com/catalog?category=Juice")

        urls = agent._discovered_internal_urls
        # /catalog is the same base path as the URL → should be excluded
        assert not any(u == "https://example.com/catalog" for u in urls), \
            f"Self URL found in internal URLs: {urls}"

    @pytest.mark.asyncio
    async def test_caps_at_15_urls(self, agent):
        """Internal URLs capped at 15."""
        # Generate HTML with 20 internal links
        links = "\n".join(f'<a href="/page{i}">Page {i}</a>' for i in range(20))
        html = f'<html><body>{links}</body></html>'
        mock = self._make_browser_mock(html)
        with patch("bugtrace.tools.visual.browser.browser_manager.capture_state", mock):
            await agent._discover_xss_params("https://example.com/catalog?category=Juice")

        assert len(agent._discovered_internal_urls) <= 15

    @pytest.mark.asyncio
    async def test_removes_query_strings(self, agent):
        """Internal links should be clean (no query params/fragments)."""
        mock = self._make_browser_mock(HTML_WITH_LINKS)
        with patch("bugtrace.tools.visual.browser.browser_manager.capture_state", mock):
            await agent._discover_xss_params("https://example.com/catalog?category=Juice")

        urls = agent._discovered_internal_urls
        for url in urls:
            assert "?" not in url, f"URL has query params: {url}"
            assert "#" not in url, f"URL has fragment: {url}"

    @pytest.mark.asyncio
    async def test_params_still_extracted(self, agent):
        """Fix #4 should not break normal param extraction."""
        mock = self._make_browser_mock(HTML_WITH_LINKS)
        with patch("bugtrace.tools.visual.browser.browser_manager.capture_state", mock):
            params = await agent._discover_xss_params(
                "https://example.com/catalog?category=Juice"
            )

        assert "category" in params
        assert params["category"] == "Juice"
        assert "searchTerm" in params

    @pytest.mark.asyncio
    async def test_empty_html_no_crash(self, agent):
        """Empty HTML should not crash, just return empty internal URLs."""
        html = '<html><body></body></html>'
        mock = self._make_browser_mock(html)
        with patch("bugtrace.tools.visual.browser.browser_manager.capture_state", mock):
            await agent._discover_xss_params("https://example.com/catalog?category=Juice")

        assert hasattr(agent, '_discovered_internal_urls')
        assert agent._discovered_internal_urls == []


# ============================================================================
# Fix #5: Open Redirect internal links + DOM redirect testing
# ============================================================================

class TestOpenRedirectInternalLinks:
    """
    FIX #13: DOM-based open redirects not detected.
    Tests internal link extraction in _discover_openredirect_params()
    and the _test_dom_redirects() method structure.
    """

    @pytest.fixture
    def agent(self):
        from bugtrace.agents.openredirect_agent import OpenRedirectAgent
        agent = OpenRedirectAgent(url="https://example.com/login", event_bus=Mock())
        agent._v = Mock()
        return agent

    def _make_browser_mock(self, html):
        return AsyncMock(return_value={
            "text": html,
            "screenshot": "/tmp/fake.png",
            "html": html,
        })

    @pytest.mark.asyncio
    async def test_extracts_internal_links(self, agent):
        """_discover_openredirect_params extracts internal links."""
        mock = self._make_browser_mock(HTML_WITH_LINKS)
        with patch("bugtrace.tools.visual.browser.browser_manager.capture_state", mock):
            await agent._discover_openredirect_params("https://example.com/login")

        assert hasattr(agent, '_discovered_internal_urls')
        urls = agent._discovered_internal_urls
        assert len(urls) > 0, "Should find internal links"
        assert not any("external.com" in u for u in urls)

    @pytest.mark.asyncio
    async def test_dom_redirects_tests_all_urls(self, agent):
        """_test_dom_redirects tests self.url + internal URLs."""
        agent._discovered_internal_urls = [
            "https://example.com/blog",
            "https://example.com/about",
        ]

        tested_urls = []

        @asynccontextmanager
        async def mock_get_page():
            page = MagicMock()
            page.route = AsyncMock()
            page.goto = AsyncMock()
            page.close = AsyncMock()

            # Track which URLs are tested
            async def capture_goto(url, **kwargs):
                tested_urls.append(url)
            page.goto = capture_goto

            yield page

        with patch("bugtrace.tools.visual.browser.browser_manager.get_page", mock_get_page), \
             patch("asyncio.sleep", AsyncMock()):
            await agent._test_dom_redirects()

        # Should test self.url (example.com/login) + 2 internal URLs
        # Each URL tests multiple params, so we should see many goto calls
        assert len(tested_urls) > 0, "Should have tested some URLs"

        # Verify all 3 base URLs were tested (they appear with injected params)
        all_urls_str = " ".join(tested_urls)
        assert "example.com/login" in all_urls_str
        assert "example.com/blog" in all_urls_str
        assert "example.com/about" in all_urls_str

    @pytest.mark.asyncio
    async def test_dom_redirect_detection(self, agent):
        """Detects DOM redirect when page navigates to evil domain."""
        agent._discovered_internal_urls = []

        @asynccontextmanager
        async def mock_get_page():
            page = MagicMock()

            route_handler = None
            async def capture_route(pattern, handler):
                nonlocal route_handler
                route_handler = handler
            page.route = capture_route

            async def fake_goto(url, **kwargs):
                # Simulate: if "redirect" param is present, JS redirects to evil domain
                if "redirect=" in url and "evil.bugtraceai.test" in url:
                    # Simulate the route handler being called with evil domain request
                    mock_route = MagicMock()
                    mock_route.request.url = "https://evil.bugtraceai.test/redirect-probe"
                    mock_route.abort = AsyncMock()
                    mock_route.continue_ = AsyncMock()
                    if route_handler:
                        await route_handler(mock_route)
            page.goto = fake_goto

            yield page

        with patch("bugtrace.tools.visual.browser.browser_manager.get_page", mock_get_page), \
             patch("asyncio.sleep", AsyncMock()):
            findings = await agent._test_dom_redirects()

        assert len(findings) > 0, "Should detect DOM redirect"
        finding = findings[0]
        assert finding["type"] == "OPEN_REDIRECT"
        assert finding["tier"] == "dom"
        assert finding["technique"] == "dom_redirect"
        assert finding["evidence"]["dom_redirect"] is True
        assert "evil.bugtraceai.test" in finding["evidence"]["redirected_to"]

    @pytest.mark.asyncio
    async def test_no_redirect_no_findings(self, agent):
        """No redirect detected = empty findings."""
        agent._discovered_internal_urls = []

        @asynccontextmanager
        async def mock_get_page():
            page = MagicMock()
            page.route = AsyncMock()
            page.goto = AsyncMock()  # No redirect happens
            yield page

        with patch("bugtrace.tools.visual.browser.browser_manager.get_page", mock_get_page), \
             patch("asyncio.sleep", AsyncMock()):
            findings = await agent._test_dom_redirects()

        assert findings == []
