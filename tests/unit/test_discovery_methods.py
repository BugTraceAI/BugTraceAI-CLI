"""
Unit tests for the 13 specialist autonomous discovery methods.

These methods are the most critical code paths in the pipeline — if a discovery
method has a bug, vulnerabilities are silently missed with zero warning.

Zero production code changes — only tests.
"""
import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from contextlib import asynccontextmanager

from tests.unit.conftest import RICH_HTML, MINIMAL_HTML, EMPTY_HTML, TEST_URL


# ============================================================================
# Category A: Dict[str, str] — 10 specialists
# ============================================================================


class TestHeaderInjectionDiscovery:
    """HeaderInjectionAgent._discover_header_params — simplest (no filtering)."""

    @pytest.fixture
    def agent(self):
        from bugtrace.agents.header_injection_agent import HeaderInjectionAgent
        return HeaderInjectionAgent(url="", event_bus=Mock())

    @pytest.mark.asyncio
    async def test_extracts_url_params(self, agent, mock_browser_rich):
        result = await agent._discover_header_params(TEST_URL)
        assert "category" in result
        assert result["category"] == "Juice"
        assert "sort" in result
        assert result["sort"] == "asc"

    @pytest.mark.asyncio
    async def test_extracts_html_form_params(self, agent, mock_browser_rich):
        result = await agent._discover_header_params(TEST_URL)
        assert "searchTerm" in result
        assert "comment" in result

    @pytest.mark.asyncio
    async def test_empty_html_graceful(self, agent, mock_browser_empty):
        result = await agent._discover_header_params(TEST_URL)
        assert "category" in result
        assert "sort" in result
        assert "searchTerm" not in result

    @pytest.mark.asyncio
    async def test_excludes_submit_buttons(self, agent, mock_browser_rich):
        result = await agent._discover_header_params(TEST_URL)
        assert "go" not in result
        assert "cancel" not in result

    @pytest.mark.asyncio
    async def test_includes_csrf_tokens(self, agent, mock_browser_rich):
        result = await agent._discover_header_params(TEST_URL)
        assert "csrf_token" in result


class TestSQLiDiscovery:
    """SQLiAgent._discover_sqli_params — includes CSRF tokens."""

    @pytest.fixture
    def agent(self):
        from bugtrace.agents.sqli_agent import SQLiAgent
        return SQLiAgent(url="", event_bus=Mock())

    @pytest.mark.asyncio
    async def test_extracts_url_params(self, agent, mock_browser_rich):
        result = await agent._discover_sqli_params(TEST_URL)
        assert "category" in result
        assert result["category"] == "Juice"
        assert "sort" in result

    @pytest.mark.asyncio
    async def test_extracts_html_form_params(self, agent, mock_browser_rich):
        result = await agent._discover_sqli_params(TEST_URL)
        assert "searchTerm" in result
        assert "comment" in result

    @pytest.mark.asyncio
    async def test_empty_html_graceful(self, agent, mock_browser_empty):
        result = await agent._discover_sqli_params(TEST_URL)
        assert "category" in result
        assert "searchTerm" not in result

    @pytest.mark.asyncio
    async def test_excludes_submit_buttons(self, agent, mock_browser_rich):
        result = await agent._discover_sqli_params(TEST_URL)
        assert "go" not in result
        assert "cancel" not in result

    @pytest.mark.asyncio
    async def test_includes_csrf_tokens(self, agent, mock_browser_rich):
        result = await agent._discover_sqli_params(TEST_URL)
        assert "csrf_token" in result


class TestSSRFDiscovery:
    """SSRFAgent._discover_ssrf_params — excludes CSRF (not token), logs URL-like params."""

    @pytest.fixture
    def agent(self):
        from bugtrace.agents.ssrf_agent import SSRFAgent
        return SSRFAgent(url="", event_bus=Mock())

    @pytest.mark.asyncio
    async def test_extracts_url_params(self, agent, mock_browser_rich):
        result = await agent._discover_ssrf_params(TEST_URL)
        assert "category" in result
        assert "sort" in result

    @pytest.mark.asyncio
    async def test_extracts_html_form_params(self, agent, mock_browser_rich):
        result = await agent._discover_ssrf_params(TEST_URL)
        assert "searchTerm" in result

    @pytest.mark.asyncio
    async def test_empty_html_graceful(self, agent, mock_browser_empty):
        result = await agent._discover_ssrf_params(TEST_URL)
        assert "category" in result
        assert "searchTerm" not in result

    @pytest.mark.asyncio
    async def test_excludes_submit_buttons(self, agent, mock_browser_rich):
        result = await agent._discover_ssrf_params(TEST_URL)
        assert "go" not in result

    @pytest.mark.asyncio
    async def test_excludes_csrf_but_keeps_non_csrf_tokens(self, agent, mock_browser_rich):
        """SSRF checks 'csrf' not in name, but 'upload_token' has no 'csrf' — should be kept."""
        result = await agent._discover_ssrf_params(TEST_URL)
        assert "csrf_token" not in result
        assert "upload_token" in result

    @pytest.mark.asyncio
    async def test_discovers_url_like_params(self, agent, mock_browser_rich):
        result = await agent._discover_ssrf_params(TEST_URL)
        assert "callback" in result
        assert "redirect_url" in result


class TestCSTIDiscovery:
    """CSTIAgent._discover_csti_params — excludes CSRF+token, fingerprints template engines."""

    @pytest.fixture
    def agent(self):
        from bugtrace.agents.csti_agent import CSTIAgent
        return CSTIAgent(url="", event_bus=Mock())

    @pytest.mark.asyncio
    async def test_extracts_url_params(self, agent, mock_browser_rich):
        result = await agent._discover_csti_params(TEST_URL)
        assert "category" in result
        assert result["category"] == "Juice"

    @pytest.mark.asyncio
    async def test_extracts_html_form_params(self, agent, mock_browser_rich):
        result = await agent._discover_csti_params(TEST_URL)
        assert "searchTerm" in result
        assert "comment" in result
        assert "template" in result

    @pytest.mark.asyncio
    async def test_empty_html_graceful(self, agent, mock_browser_empty):
        result = await agent._discover_csti_params(TEST_URL)
        assert "category" in result
        assert "searchTerm" not in result

    @pytest.mark.asyncio
    async def test_excludes_submit_buttons(self, agent, mock_browser_rich):
        result = await agent._discover_csti_params(TEST_URL)
        assert "go" not in result

    @pytest.mark.asyncio
    async def test_excludes_csrf_and_token(self, agent, mock_browser_rich):
        result = await agent._discover_csti_params(TEST_URL)
        assert "csrf_token" not in result
        assert "upload_token" not in result


class TestXSSDiscovery:
    """XSSAgent._discover_xss_params — JS variables, excludes CSRF+token."""

    @pytest.fixture
    def agent(self):
        from bugtrace.agents.xss_agent import XSSAgent
        return XSSAgent(url="", event_bus=Mock())

    @pytest.mark.asyncio
    async def test_extracts_url_params(self, agent, mock_browser_rich):
        result = await agent._discover_xss_params(TEST_URL)
        assert "category" in result
        assert result["category"] == "Juice"
        assert "sort" in result

    @pytest.mark.asyncio
    async def test_extracts_html_form_params(self, agent, mock_browser_rich):
        result = await agent._discover_xss_params(TEST_URL)
        assert "searchTerm" in result
        assert "comment" in result

    @pytest.mark.asyncio
    async def test_empty_html_graceful(self, agent, mock_browser_empty):
        result = await agent._discover_xss_params(TEST_URL)
        assert "category" in result
        assert "searchTerm" not in result

    @pytest.mark.asyncio
    async def test_excludes_submit_buttons(self, agent, mock_browser_rich):
        result = await agent._discover_xss_params(TEST_URL)
        assert "go" not in result

    @pytest.mark.asyncio
    async def test_excludes_csrf_and_token(self, agent, mock_browser_rich):
        result = await agent._discover_xss_params(TEST_URL)
        assert "csrf_token" not in result
        assert "upload_token" not in result

    @pytest.mark.asyncio
    async def test_extracts_js_variables(self, agent, mock_browser_rich):
        result = await agent._discover_xss_params(TEST_URL)
        assert "searchText" in result
        assert result["searchText"] == "user_query"
        assert "selectedCategory" in result

    @pytest.mark.asyncio
    async def test_filters_short_js_variable_names(self, agent, mock_browser_rich):
        """JS var 'x' (len<=2) should be filtered out."""
        result = await agent._discover_xss_params(TEST_URL)
        assert "x" not in result


class TestRCEDiscovery:
    """RCEAgent._discover_rce_params — command keyword prioritization."""

    @pytest.fixture
    def agent(self):
        from bugtrace.agents.rce_agent import RCEAgent
        return RCEAgent(url="", event_bus=Mock())

    @pytest.mark.asyncio
    async def test_extracts_url_params(self, agent, mock_browser_rich):
        result = await agent._discover_rce_params(TEST_URL)
        assert "category" in result
        assert "sort" in result

    @pytest.mark.asyncio
    async def test_extracts_html_form_params(self, agent, mock_browser_rich):
        result = await agent._discover_rce_params(TEST_URL)
        assert "searchTerm" in result

    @pytest.mark.asyncio
    async def test_empty_html_graceful(self, agent, mock_browser_empty):
        result = await agent._discover_rce_params(TEST_URL)
        assert "category" in result

    @pytest.mark.asyncio
    async def test_excludes_submit_buttons(self, agent, mock_browser_rich):
        result = await agent._discover_rce_params(TEST_URL)
        assert "go" not in result

    @pytest.mark.asyncio
    async def test_prioritizes_command_params(self, agent, mock_browser_rich):
        """cmd, exec_target should appear before non-command params."""
        result = await agent._discover_rce_params(TEST_URL)
        keys = list(result.keys())
        cmd_idx = keys.index("cmd")
        exec_idx = keys.index("exec_target")
        # These should be in the first few positions
        assert cmd_idx < len(keys) // 2
        assert exec_idx < len(keys) // 2


class TestLFIDiscovery:
    """LFIAgent._discover_lfi_params — file extension detection, priority ordering."""

    @pytest.fixture
    def agent(self):
        from bugtrace.agents.lfi_agent import LFIAgent
        return LFIAgent(url="", event_bus=Mock())

    @pytest.mark.asyncio
    async def test_extracts_url_params(self, agent, mock_browser_rich):
        result = await agent._discover_lfi_params(TEST_URL)
        assert "category" in result
        assert "sort" in result

    @pytest.mark.asyncio
    async def test_extracts_html_form_params(self, agent, mock_browser_rich):
        result = await agent._discover_lfi_params(TEST_URL)
        assert "searchTerm" in result

    @pytest.mark.asyncio
    async def test_empty_html_graceful(self, agent, mock_browser_empty):
        result = await agent._discover_lfi_params(TEST_URL)
        assert "category" in result

    @pytest.mark.asyncio
    async def test_excludes_submit_buttons(self, agent, mock_browser_rich):
        result = await agent._discover_lfi_params(TEST_URL)
        assert "go" not in result

    @pytest.mark.asyncio
    async def test_excludes_csrf_and_token(self, agent, mock_browser_rich):
        result = await agent._discover_lfi_params(TEST_URL)
        assert "csrf_token" not in result
        assert "upload_token" not in result

    @pytest.mark.asyncio
    async def test_prioritizes_file_path_params(self, agent, mock_browser_rich):
        """file_path and template should appear before searchTerm."""
        result = await agent._discover_lfi_params(TEST_URL)
        keys = list(result.keys())
        assert "file_path" in keys
        assert "template" in keys
        file_idx = keys.index("file_path")
        search_idx = keys.index("searchTerm")
        assert file_idx < search_idx

    @pytest.mark.asyncio
    async def test_detects_file_extension_values(self, agent, mock_browser_rich):
        """file_path with value 'header.php' should be detected."""
        result = await agent._discover_lfi_params(TEST_URL)
        assert result.get("file_path") == "header.php"


class TestOpenRedirectDiscovery:
    """OpenRedirectAgent._discover_openredirect_params — redirect priority, token filtering."""

    @pytest.fixture
    def agent(self):
        from bugtrace.agents.openredirect_agent import OpenRedirectAgent
        return OpenRedirectAgent(url="", event_bus=Mock())

    @pytest.mark.asyncio
    async def test_extracts_url_params(self, agent, mock_browser_rich):
        result = await agent._discover_openredirect_params(TEST_URL)
        assert "category" in result
        assert "sort" in result

    @pytest.mark.asyncio
    async def test_extracts_html_form_params(self, agent, mock_browser_rich):
        result = await agent._discover_openredirect_params(TEST_URL)
        assert "searchTerm" in result

    @pytest.mark.asyncio
    async def test_empty_html_graceful(self, agent, mock_browser_empty):
        result = await agent._discover_openredirect_params(TEST_URL)
        assert "category" in result

    @pytest.mark.asyncio
    async def test_excludes_submit_buttons(self, agent, mock_browser_rich):
        result = await agent._discover_openredirect_params(TEST_URL)
        assert "go" not in result

    @pytest.mark.asyncio
    async def test_prioritizes_redirect_params(self, agent, mock_browser_rich):
        """redirect_url and callback should appear before searchTerm."""
        result = await agent._discover_openredirect_params(TEST_URL)
        keys = list(result.keys())
        redirect_idx = keys.index("redirect_url")
        callback_idx = keys.index("callback")
        search_idx = keys.index("searchTerm")
        assert redirect_idx < search_idx
        assert callback_idx < search_idx

    @pytest.mark.asyncio
    async def test_token_filtering_logic(self, agent, mock_browser_rich):
        """Params with 'token' excluded UNLESS they also contain 'redirect'."""
        result = await agent._discover_openredirect_params(TEST_URL)
        # csrf_token has 'token' but no 'redirect' → excluded
        assert "csrf_token" not in result
        # upload_token has 'token' but no 'redirect' → excluded
        assert "upload_token" not in result


class TestIDORDiscovery:
    """IDORAgent._discover_idor_params — path segments, UUIDs, hidden inputs."""

    @pytest.fixture
    def agent(self):
        from bugtrace.agents.idor_agent import IDORAgent
        return IDORAgent(url="", event_bus=Mock())

    @pytest.mark.asyncio
    async def test_extracts_url_params(self, agent, mock_browser_rich):
        result = await agent._discover_idor_params(TEST_URL)
        assert "category" in result
        assert "sort" in result

    @pytest.mark.asyncio
    async def test_empty_html_graceful(self, agent, mock_browser_empty):
        result = await agent._discover_idor_params(TEST_URL)
        assert "category" in result

    @pytest.mark.asyncio
    async def test_extracts_numeric_path_segments(self, agent, mock_browser_empty):
        """URL /users/123/profile → users_id: '123'."""
        url = "https://example.com/users/123/profile"
        result = await agent._discover_idor_params(url)
        assert "users_id" in result
        assert result["users_id"] == "123"

    @pytest.mark.asyncio
    async def test_extracts_uuid_path_segments(self, agent, mock_browser_empty):
        """URL /orders/<uuid>/detail → orders_id."""
        url = "https://example.com/orders/a1b2c3d4-e5f6-7890-abcd-ef1234567890/detail"
        result = await agent._discover_idor_params(url)
        assert "orders_id" in result
        assert result["orders_id"] == "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

    @pytest.mark.asyncio
    async def test_extracts_hash_path_segments(self, agent, mock_browser_empty):
        """URL /files/<md5>/view → files_hash."""
        url = "https://example.com/files/abcdef1234567890abcdef1234567890ab/view"
        result = await agent._discover_idor_params(url)
        assert "files_hash" in result

    @pytest.mark.asyncio
    async def test_hidden_inputs_with_id_values(self, agent, mock_browser_rich):
        """user_id (hidden, value=42) should be included."""
        result = await agent._discover_idor_params(TEST_URL)
        assert "user_id" in result
        assert result["user_id"] == "42"


class TestPrototypePollutionDiscovery:
    """PrototypePollutionAgent._discover_prototype_pollution_params — JSON probe, _accepts_json key."""

    @pytest.fixture
    def agent(self):
        from bugtrace.agents.prototype_pollution_agent import PrototypePollutionAgent
        return PrototypePollutionAgent(url="", event_bus=Mock())

    @pytest.mark.asyncio
    async def test_extracts_url_params(self, agent, mock_browser_rich):
        with patch.object(agent, "_probe_json_acceptance", new_callable=AsyncMock, return_value=False):
            result = await agent._discover_prototype_pollution_params(TEST_URL)
        assert "category" in result
        assert "sort" in result

    @pytest.mark.asyncio
    async def test_extracts_html_form_params(self, agent, mock_browser_rich):
        with patch.object(agent, "_probe_json_acceptance", new_callable=AsyncMock, return_value=False):
            result = await agent._discover_prototype_pollution_params(TEST_URL)
        assert "searchTerm" in result

    @pytest.mark.asyncio
    async def test_empty_html_graceful(self, agent, mock_browser_empty):
        with patch.object(agent, "_probe_json_acceptance", new_callable=AsyncMock, return_value=False):
            result = await agent._discover_prototype_pollution_params(TEST_URL)
        assert "category" in result

    @pytest.mark.asyncio
    async def test_excludes_submit_buttons(self, agent, mock_browser_rich):
        with patch.object(agent, "_probe_json_acceptance", new_callable=AsyncMock, return_value=False):
            result = await agent._discover_prototype_pollution_params(TEST_URL)
        assert "go" not in result

    @pytest.mark.asyncio
    async def test_excludes_csrf_and_token(self, agent, mock_browser_rich):
        with patch.object(agent, "_probe_json_acceptance", new_callable=AsyncMock, return_value=False):
            result = await agent._discover_prototype_pollution_params(TEST_URL)
        assert "csrf_token" not in result
        assert "upload_token" not in result

    @pytest.mark.asyncio
    async def test_json_acceptance_true(self, agent, mock_browser_rich):
        with patch.object(agent, "_probe_json_acceptance", new_callable=AsyncMock, return_value=True):
            result = await agent._discover_prototype_pollution_params(TEST_URL)
        assert "_accepts_json" in result
        assert result["_accepts_json"] == "true"

    @pytest.mark.asyncio
    async def test_json_acceptance_false(self, agent, mock_browser_rich):
        with patch.object(agent, "_probe_json_acceptance", new_callable=AsyncMock, return_value=False):
            result = await agent._discover_prototype_pollution_params(TEST_URL)
        assert "_accepts_json" not in result


# ============================================================================
# Category B: List[Dict] — 2 specialists (endpoint discovery)
# ============================================================================


class TestXXEDiscovery:
    """XXEAgent._discover_xxe_params — discovers XML upload endpoints."""

    @pytest.fixture
    def agent(self):
        from bugtrace.agents.xxe_agent import XXEAgent
        return XXEAgent(url="http://test.com/page", event_bus=Mock())

    @pytest.mark.asyncio
    async def test_discovers_xml_file_upload(self, agent, mock_browser_rich):
        result = await agent._discover_xxe_params(TEST_URL)
        xml_endpoints = [ep for ep in result if ep.get("type") == "file_upload_xml"]
        assert len(xml_endpoints) >= 1
        assert ".xml" in xml_endpoints[0].get("accept", "").lower()

    @pytest.mark.asyncio
    async def test_endpoint_url_resolved(self, agent, mock_browser_rich):
        """Action URLs should be resolved relative to base URL."""
        result = await agent._discover_xxe_params(TEST_URL)
        for ep in result:
            assert ep["url"].startswith("http")

    @pytest.mark.asyncio
    async def test_empty_html_fallback(self, agent):
        """Empty HTML should return fallback XML endpoint."""
        mock = AsyncMock(return_value={"text": "", "screenshot": "", "html": ""})
        with patch("bugtrace.tools.visual.browser.browser_manager.capture_state", mock):
            result = await agent._discover_xxe_params(TEST_URL)
        assert len(result) >= 1
        assert result[0]["type"] == "xml_endpoint"
        assert result[0]["method"] == "POST"

    @pytest.mark.asyncio
    async def test_returns_list(self, agent, mock_browser_rich):
        result = await agent._discover_xxe_params(TEST_URL)
        assert isinstance(result, list)


class TestFileUploadDiscovery:
    """FileUploadAgent._discover_upload_forms — file inputs, dropzones, all_fields."""

    @pytest.fixture
    def agent(self):
        from bugtrace.agents.fileupload_agent import FileUploadAgent
        return FileUploadAgent(url="http://test.com/page")

    @pytest.mark.asyncio
    async def test_discovers_file_input_forms(self, agent, mock_browser_rich):
        result = await agent._discover_upload_forms()
        assert len(result) >= 1
        # Should find the upload form with file inputs
        upload_forms = [f for f in result if not f.get("dropzone")]
        assert len(upload_forms) >= 1

    @pytest.mark.asyncio
    async def test_file_input_metadata(self, agent, mock_browser_rich):
        result = await agent._discover_upload_forms()
        upload_form = [f for f in result if not f.get("dropzone")][0]
        file_inputs = upload_form["file_inputs"]
        assert len(file_inputs) >= 1
        fi = file_inputs[0]
        assert "name" in fi
        assert "accept" in fi
        assert "multiple" in fi
        assert "required" in fi

    @pytest.mark.asyncio
    async def test_all_fields_populated(self, agent, mock_browser_rich):
        """all_fields should include hidden and text inputs from the form."""
        result = await agent._discover_upload_forms()
        upload_form = [f for f in result if not f.get("dropzone")][0]
        all_fields = upload_form.get("all_fields", {})
        assert "upload_token" in all_fields
        assert "description" in all_fields

    @pytest.mark.asyncio
    async def test_discovers_dropzones(self, agent, mock_browser_rich):
        result = await agent._discover_upload_forms()
        dropzones = [f for f in result if f.get("dropzone")]
        assert len(dropzones) >= 1
        assert "/api/upload/drop" in dropzones[0]["action"]

    @pytest.mark.asyncio
    async def test_empty_html_returns_empty_list(self, agent, mock_browser_empty):
        result = await agent._discover_upload_forms()
        assert result == []


# ============================================================================
# Category C: List[Tuple[str, str]] — JWTAgent (token discovery)
# ============================================================================


class TestJWTDiscovery:
    """JWTAgent._discover_tokens — JWT regex from URL, cookies, localStorage, body."""

    SAMPLE_JWT = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
        ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )

    @pytest.fixture
    def agent(self):
        from bugtrace.agents.jwt_agent import JWTAgent
        return JWTAgent(event_bus=Mock())

    def _make_mock_page(self, url="http://example.com/", body_text="", cookies=None):
        """Create a mocked Playwright page for JWT discovery."""
        page = AsyncMock()
        page.url = url
        page.goto = AsyncMock()
        page.content = AsyncMock(return_value=body_text)
        page.evaluate = AsyncMock(return_value=body_text)
        page.on = Mock()
        ctx = AsyncMock()
        ctx.cookies = AsyncMock(return_value=cookies or [])
        page.context = ctx
        return page

    @pytest.mark.asyncio
    async def test_discovers_url_param_token(self, agent):
        """JWT in URL query string should be found."""
        url_with_jwt = f"http://example.com/api?token={self.SAMPLE_JWT}"
        mock_page = self._make_mock_page(url=url_with_jwt)

        @asynccontextmanager
        async def fake_get_page():
            yield mock_page

        with patch("bugtrace.tools.visual.browser.browser_manager.get_page", fake_get_page):
            result = await agent._discover_tokens(url_with_jwt)

        tokens = [t for t, loc in result]
        assert self.SAMPLE_JWT in tokens

    @pytest.mark.asyncio
    async def test_empty_page_returns_empty(self, agent):
        """No JWTs anywhere → empty list."""
        mock_page = self._make_mock_page(body_text="<html><body>No tokens here</body></html>")

        @asynccontextmanager
        async def fake_get_page():
            yield mock_page

        url = "http://example.com/page"
        with patch("bugtrace.tools.visual.browser.browser_manager.get_page", fake_get_page):
            result = await agent._discover_tokens(url)

        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_deduplicates_tokens(self, agent):
        """Same JWT found in multiple locations → only one entry."""
        url_with_jwt = f"http://example.com/api?token={self.SAMPLE_JWT}"
        body_with_jwt = f"<html><body>Token: {self.SAMPLE_JWT}</body></html>"
        mock_page = self._make_mock_page(url=url_with_jwt, body_text=body_with_jwt)

        @asynccontextmanager
        async def fake_get_page():
            yield mock_page

        with patch("bugtrace.tools.visual.browser.browser_manager.get_page", fake_get_page):
            result = await agent._discover_tokens(url_with_jwt)

        tokens = [t for t, loc in result]
        # Should be deduplicated — same JWT counted once
        assert tokens.count(self.SAMPLE_JWT) <= 1

    @pytest.mark.asyncio
    async def test_returns_list_of_tuples(self, agent):
        """Return type should be List[Tuple[str, str]]."""
        mock_page = self._make_mock_page()

        @asynccontextmanager
        async def fake_get_page():
            yield mock_page

        url = "http://example.com/"
        with patch("bugtrace.tools.visual.browser.browser_manager.get_page", fake_get_page):
            result = await agent._discover_tokens(url)

        assert isinstance(result, list)
        for item in result:
            assert isinstance(item, tuple)
            assert len(item) == 2
