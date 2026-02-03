"""
Unit tests for XSS HTTP-First Validation (Phase 15).

Tests the new HTTP response analysis methods that reduce Playwright usage by ~90%.
"""
import pytest
from bugtrace.agents.xss_agent import XSSAgent


class TestDetectExecutionContext:
    """Tests for _detect_execution_context() method."""

    @pytest.fixture
    def agent(self):
        """Create XSSAgent instance for testing."""
        return XSSAgent(url="https://example.com")

    def test_script_block_detection(self, agent):
        """Payload inside script tags should return 'script_block'."""
        html = '<html><script>var x = "PAYLOAD123";</script></html>'
        assert agent._detect_execution_context("PAYLOAD123", html) == "script_block"

    def test_script_block_multiline(self, agent):
        """Script block detection works across multiple lines."""
        html = '''<script>
            var data = {
                value: "PAYLOAD456"
            };
        </script>'''
        assert agent._detect_execution_context("PAYLOAD456", html) == "script_block"

    def test_script_block_with_attributes(self, agent):
        """Script block with type and src attributes."""
        html = '<script type="text/javascript" src="main.js">var x = "ATTRPAYLOAD";</script>'
        assert agent._detect_execution_context("ATTRPAYLOAD", html) == "script_block"

    def test_event_handler_detection(self, agent):
        """Payload in event handler should return 'event_handler'."""
        html = '<img src="x" onerror="PAYLOAD789">'
        assert agent._detect_execution_context("PAYLOAD789", html) == "event_handler"

    def test_event_handler_onclick(self, agent):
        """onclick handler detection."""
        html = '<button onclick="CLICKPAYLOAD">Click</button>'
        assert agent._detect_execution_context("CLICKPAYLOAD", html) == "event_handler"

    def test_event_handler_onload(self, agent):
        """onload handler detection."""
        html = '<body onload="LOADPAYLOAD">'
        assert agent._detect_execution_context("LOADPAYLOAD", html) == "event_handler"

    def test_event_handler_onmouseover(self, agent):
        """onmouseover handler detection."""
        html = '<div onmouseover="HOVERPAYLOAD">Hover me</div>'
        assert agent._detect_execution_context("HOVERPAYLOAD", html) == "event_handler"

    def test_javascript_uri_href(self, agent):
        """Payload in javascript: href should return 'javascript_uri'."""
        html = '<a href="javascript:URIPAYLOAD">Link</a>'
        assert agent._detect_execution_context("URIPAYLOAD", html) == "javascript_uri"

    def test_javascript_uri_src(self, agent):
        """Payload in javascript: src should return 'javascript_uri'."""
        html = '<iframe src="javascript:SRCPAYLOAD"></iframe>'
        assert agent._detect_execution_context("SRCPAYLOAD", html) == "javascript_uri"

    def test_javascript_uri_action(self, agent):
        """Payload in javascript: action should return 'javascript_uri'."""
        html = '<form action="javascript:ACTIONPAYLOAD"></form>'
        assert agent._detect_execution_context("ACTIONPAYLOAD", html) == "javascript_uri"

    def test_template_expression_angular(self, agent):
        """Angular-style {{}} template detection."""
        html = '<div>{{ANGULARPAYLOAD}}</div>'
        assert agent._detect_execution_context("ANGULARPAYLOAD", html) == "template_expression"

    def test_template_expression_literal(self, agent):
        """Template literal ${} detection."""
        html = '<div>${LITERALPAYLOAD}</div>'
        assert agent._detect_execution_context("LITERALPAYLOAD", html) == "template_expression"

    def test_no_context_html_body(self, agent):
        """Payload in HTML body (not executable) returns None."""
        html = '<div>Hello BODYPAYLOAD world</div>'
        assert agent._detect_execution_context("BODYPAYLOAD", html) is None

    def test_no_context_attribute(self, agent):
        """Payload in non-event attribute returns None."""
        html = '<input value="ATTRPAYLOAD">'
        assert agent._detect_execution_context("ATTRPAYLOAD", html) is None

    def test_no_context_html_comment(self, agent):
        """Payload in HTML comment returns None (not executable)."""
        html = '<!-- COMMENTPAYLOAD -->'
        assert agent._detect_execution_context("COMMENTPAYLOAD", html) is None

    def test_priority_script_over_event(self, agent):
        """Script block has higher priority than event handler."""
        html = '''
        <script>var x = "DUALPAYLOAD";</script>
        <img onerror="DUALPAYLOAD">
        '''
        assert agent._detect_execution_context("DUALPAYLOAD", html) == "script_block"

    def test_priority_event_over_javascript_uri(self, agent):
        """Event handler has higher priority than javascript URI."""
        html = '''
        <img onerror="MIXEDPAYLOAD">
        <a href="javascript:MIXEDPAYLOAD">Link</a>
        '''
        assert agent._detect_execution_context("MIXEDPAYLOAD", html) == "event_handler"

    def test_payload_not_found(self, agent):
        """Returns None when payload is not in response."""
        html = '<html><body>No payload here</body></html>'
        assert agent._detect_execution_context("MISSINGPAYLOAD", html) is None


class TestCanConfirmFromHttpResponse:
    """Tests for _can_confirm_from_http_response() method."""

    @pytest.fixture
    def agent(self):
        """Create XSSAgent instance for testing."""
        return XSSAgent(url="https://example.com")

    def test_confirms_html_tag_injection(self, agent):
        """Should confirm XSS when payload creates a new HTML tag with JS execution."""
        # Payload that injects a new tag with event handler
        html = '<div><img src=x onerror=alert(1)></div>'
        evidence = {}
        result = agent._can_confirm_from_http_response("<img src=x onerror=alert(1)>", html, evidence)

        assert result is True
        assert evidence["http_confirmed"] is True
        assert evidence["execution_context"] == "html_tag"
        assert evidence["validation_method"] == "http_response_analysis"

    def test_rejects_payload_in_js_string_literal(self, agent):
        """Payload inside JS string literal is NOT executable (just data)."""
        # Payload reflected inside quotes in JS - not exploitable
        html = '<script>var x = "CONFIRMPAYLOAD";</script>'
        evidence = {}
        result = agent._can_confirm_from_http_response("CONFIRMPAYLOAD", html, evidence)

        # Should NOT confirm - payload is data, not code
        assert result is False

    def test_confirms_event_handler(self, agent):
        """Should confirm XSS when payload is in event handler."""
        html = '<img onerror="EVENTPAYLOAD">'
        evidence = {}
        result = agent._can_confirm_from_http_response("EVENTPAYLOAD", html, evidence)

        assert result is True
        assert evidence["execution_context"] == "event_handler"

    def test_confirms_javascript_uri(self, agent):
        """Should confirm XSS when payload is in javascript URI."""
        html = '<a href="javascript:JSPAYLOAD">Click</a>'
        evidence = {}
        result = agent._can_confirm_from_http_response("JSPAYLOAD", html, evidence)

        assert result is True
        assert evidence["execution_context"] == "javascript_uri"

    def test_template_expression_needs_browser(self, agent):
        """Template expressions need browser evaluation, not HTTP confirmation."""
        # Template expressions like {{payload}} need Angular/Vue to evaluate
        # HTTP analysis cannot confirm execution - needs browser
        html = '<div>{{TEMPLATEPAYLOAD}}</div>'
        evidence = {}
        result = agent._can_confirm_from_http_response("TEMPLATEPAYLOAD", html, evidence)

        # Should NOT confirm from HTTP - requires browser to evaluate template
        assert result is False

    def test_rejects_body_reflection(self, agent):
        """Should NOT confirm when payload is just in body text."""
        html = '<div>Your input: TEXTPAYLOAD</div>'
        evidence = {}
        result = agent._can_confirm_from_http_response("TEXTPAYLOAD", html, evidence)

        assert result is False
        # http_confirmed is set to False on rejection
        assert evidence.get("http_confirmed") is False

    def test_rejects_attribute_reflection(self, agent):
        """Should NOT confirm when payload is in non-event attribute."""
        html = '<input name="field" value="VALUEPAYLOAD">'
        evidence = {}
        result = agent._can_confirm_from_http_response("VALUEPAYLOAD", html, evidence)

        assert result is False

    def test_rejects_missing_payload(self, agent):
        """Should NOT confirm when payload is not in response."""
        html = '<html><body>No payload</body></html>'
        evidence = {}
        result = agent._can_confirm_from_http_response("MISSINGPAYLOAD", html, evidence)

        assert result is False

    def test_evidence_populated_on_success(self, agent):
        """Evidence dict should have all required fields on success."""
        # Use a payload that actually creates executable context (HTML tag injection)
        html = '<div><svg onload=alert(1)></div>'
        evidence = {}
        result = agent._can_confirm_from_http_response("<svg onload=alert(1)>", html, evidence)

        assert result is True
        assert "http_confirmed" in evidence
        assert evidence["http_confirmed"] is True
        assert "execution_context" in evidence
        assert "validation_method" in evidence


class TestRequiresBrowserValidation:
    """Tests for _requires_browser_validation() method."""

    @pytest.fixture
    def agent(self):
        """Create XSSAgent instance for testing."""
        return XSSAgent(url="https://example.com")

    # DOM sink patterns in payload
    def test_requires_browser_location_hash(self, agent):
        """DOM-based XSS via location.hash needs browser."""
        payload = "location.hash.slice(1)"
        html = "<html></html>"
        assert agent._requires_browser_validation(payload, html) is True

    def test_requires_browser_location_search(self, agent):
        """DOM-based XSS via location.search needs browser."""
        payload = "location.search.substring(1)"
        html = "<html></html>"
        assert agent._requires_browser_validation(payload, html) is True

    def test_requires_browser_document_url(self, agent):
        """DOM-based XSS via document.URL needs browser."""
        payload = "document.URL.split('#')[1]"
        html = "<html></html>"
        assert agent._requires_browser_validation(payload, html) is True

    def test_requires_browser_document_referrer(self, agent):
        """DOM-based XSS via document.referrer needs browser."""
        payload = "document.referrer"
        html = "<html></html>"
        assert agent._requires_browser_validation(payload, html) is True

    def test_requires_browser_postmessage(self, agent):
        """postMessage sink needs browser."""
        payload = "postMessage(data, '*')"
        html = "<html></html>"
        assert agent._requires_browser_validation(payload, html) is True

    def test_requires_browser_innerhtml(self, agent):
        """innerHTML sink needs browser."""
        payload = "element.innerHTML = input"
        html = "<html></html>"
        assert agent._requires_browser_validation(payload, html) is True

    def test_requires_browser_outerhtml(self, agent):
        """outerHTML sink needs browser."""
        payload = "element.outerHTML = data"
        html = "<html></html>"
        assert agent._requires_browser_validation(payload, html) is True

    def test_requires_browser_document_write(self, agent):
        """document.write sink needs browser."""
        payload = "document.write(userInput)"
        html = "<html></html>"
        assert agent._requires_browser_validation(payload, html) is True

    # Interaction patterns
    def test_requires_browser_autofocus_onfocus(self, agent):
        """autofocus + onfocus combination needs browser."""
        payload = '<input autofocus onfocus="alert(1)">'
        html = "<html></html>"
        assert agent._requires_browser_validation(payload, html) is True

    def test_requires_browser_onfocus_autofocus(self, agent):
        """onfocus + autofocus (reversed order) needs browser."""
        payload = '<input onfocus="alert(1)" autofocus>'
        html = "<html></html>"
        assert agent._requires_browser_validation(payload, html) is True

    def test_requires_browser_onblur(self, agent):
        """onblur handler needs browser (focus loss)."""
        payload = '<input onblur="alert(1)">'
        html = "<html></html>"
        assert agent._requires_browser_validation(payload, html) is True

    def test_requires_browser_onmouseover(self, agent):
        """onmouseover handler needs browser (mouse interaction)."""
        payload = '<div onmouseover="alert(1)">Hover</div>'
        html = "<html></html>"
        assert agent._requires_browser_validation(payload, html) is True

    def test_requires_browser_onmouseenter(self, agent):
        """onmouseenter handler needs browser (mouse interaction)."""
        payload = '<div onmouseenter="alert(1)">Enter</div>'
        html = "<html></html>"
        assert agent._requires_browser_validation(payload, html) is True

    # Complex sink patterns in response
    def test_requires_browser_eval_in_response(self, agent):
        """Complex sink (eval) in response needs browser."""
        payload = "harmless"
        html = '<script>eval(userInput);</script>'
        assert agent._requires_browser_validation(payload, html) is True

    def test_requires_browser_function_in_response(self, agent):
        """Complex sink (Function constructor) in response needs browser."""
        payload = "harmless"
        html = '<script>new Function("return " + data)();</script>'
        assert agent._requires_browser_validation(payload, html) is True

    def test_requires_browser_settimeout_string(self, agent):
        """setTimeout with string argument in response needs browser."""
        payload = "harmless"
        html = '<script>setTimeout("doSomething()", 1000);</script>'
        assert agent._requires_browser_validation(payload, html) is True

    def test_requires_browser_setinterval_string(self, agent):
        """setInterval with string argument in response needs browser."""
        payload = "harmless"
        html = '<script>setInterval("refresh()", 5000);</script>'
        assert agent._requires_browser_validation(payload, html) is True

    # Cases NOT requiring browser
    def test_no_browser_simple_script(self, agent):
        """Simple reflected script does NOT need browser (HTTP confirms)."""
        payload = '<script>alert(1)</script>'
        html = "<html></html>"
        assert agent._requires_browser_validation(payload, html) is False

    def test_no_browser_onerror(self, agent):
        """Simple onerror does NOT need browser (HTTP confirms)."""
        payload = '<img onerror="alert(1)">'
        html = "<html></html>"
        assert agent._requires_browser_validation(payload, html) is False

    def test_no_browser_onclick(self, agent):
        """Simple onclick does NOT need browser (HTTP confirms)."""
        payload = '<button onclick="alert(1)">Click</button>'
        html = "<html></html>"
        assert agent._requires_browser_validation(payload, html) is False

    def test_no_browser_javascript_uri(self, agent):
        """javascript: URI does NOT need browser (HTTP confirms)."""
        payload = 'javascript:alert(1)'
        html = "<html></html>"
        assert agent._requires_browser_validation(payload, html) is False

    def test_no_browser_svg_onload(self, agent):
        """SVG onload does NOT need browser (HTTP confirms)."""
        payload = '<svg onload="alert(1)">'
        html = "<html></html>"
        assert agent._requires_browser_validation(payload, html) is False

    def test_no_browser_img_src_error(self, agent):
        """img with invalid src does NOT need browser (HTTP confirms)."""
        payload = '<img src=x onerror="alert(1)">'
        html = "<html></html>"
        assert agent._requires_browser_validation(payload, html) is False


class TestValidateIntegration:
    """Integration tests for the refactored _validate() flow."""

    @pytest.fixture
    def agent(self):
        """Create XSSAgent instance for testing."""
        return XSSAgent(url="https://example.com")

    def test_methods_exist(self, agent):
        """Verify all HTTP-first validation methods exist."""
        assert hasattr(agent, '_detect_execution_context')
        assert hasattr(agent, '_can_confirm_from_http_response')
        assert hasattr(agent, '_requires_browser_validation')
        assert hasattr(agent, '_validate')

    def test_methods_callable(self, agent):
        """Verify all methods are callable."""
        assert callable(getattr(agent, '_detect_execution_context'))
        assert callable(getattr(agent, '_can_confirm_from_http_response'))
        assert callable(getattr(agent, '_requires_browser_validation'))
        assert callable(getattr(agent, '_validate'))

    def test_http_confirmation_sets_evidence(self, agent):
        """HTTP confirmation should populate evidence dict correctly."""
        # Use a truly executable payload (HTML tag injection)
        html = '<div><img src=x onerror=alert(1)></div>'
        evidence = {}
        result = agent._can_confirm_from_http_response("<img src=x onerror=alert(1)>", html, evidence)

        assert result is True
        assert evidence["http_confirmed"] is True
        assert evidence["execution_context"] == "html_tag"
        assert evidence["validation_method"] == "http_response_analysis"

    def test_browser_gate_works_correctly(self, agent):
        """Browser gate should distinguish DOM-based from reflected XSS."""
        # DOM-based needs browser
        dom_payload = "location.hash.slice(1)"
        assert agent._requires_browser_validation(dom_payload, "") is True

        # Reflected does NOT need browser
        reflected_payload = '<script>alert(1)</script>'
        assert agent._requires_browser_validation(reflected_payload, "") is False

    def test_context_detection_priority(self, agent):
        """Verify context detection follows priority order."""
        # Script block should take priority
        html = '<script>var x = "PAYLOAD";</script><img onerror="PAYLOAD">'
        context = agent._detect_execution_context("PAYLOAD", html)
        assert context == "script_block"
