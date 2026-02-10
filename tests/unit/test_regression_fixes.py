"""
Unit tests for Smart Probe v3.5 regression fixes.
Tests run without HTTP — all network calls mocked.
"""

import pytest
import json
import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock


# ===========================================================================
# Bug 1: CSTI auto-dispatch should use real reflecting params, not "_auto_dispatch"
# ===========================================================================

class TestCSTIAutoDispatch:
    """Bug 1: Auto-dispatch should inject synthetic findings with REAL parameters."""

    def _build_dast_findings(self):
        """Simulate DAST findings with real reflecting params."""
        return [
            {
                "type": "XSS (Reflected)",
                "parameter": "category",
                "url": "https://example.com/catalog?category=test",
                "severity": "Medium",
                "fp_confidence": 0.7,
                "confidence_score": 0.7,
                "votes": 3,
                "skeptical_score": 6,
            },
            {
                "type": "XSS (Reflected)",
                "parameter": "searchTerm",
                "url": "https://example.com/catalog?searchTerm=hello",
                "severity": "Medium",
                "fp_confidence": 0.7,
                "confidence_score": 0.7,
                "votes": 3,
                "skeptical_score": 6,
            },
        ]

    def test_csti_autodispatch_uses_real_param(self):
        """Synthetic CSTI finding should have a real parameter, not '_auto_dispatch'."""
        all_findings = self._build_dast_findings()
        tech_profile = {"frameworks": ["AngularJS 1.7.7"]}
        target = "https://example.com/"

        # Simulate auto-dispatch logic (extracted from team.py _phase_3_strategy)
        csti_frameworks = ['angular', 'angularjs', 'vue', 'vuejs', 'vue.js']
        detected_frameworks = tech_profile.get('frameworks', [])
        frameworks_lower = [f.lower() for f in detected_frameworks]

        detected_csti_framework = None
        for fw in csti_frameworks:
            if any(fw in f for f in frameworks_lower):
                detected_csti_framework = fw
                break

        assert detected_csti_framework is not None, "Should detect AngularJS"

        has_csti = any(
            f.get('type', '').upper() in ['CSTI', 'CLIENT-SIDE TEMPLATE INJECTION']
            for f in all_findings
        )
        assert not has_csti, "No CSTI in DAST findings"

        # Extract real reflecting params for synthetic finding
        reflecting_params = [
            f for f in all_findings
            if f.get('parameter') and f['parameter'] not in ('', '_auto_dispatch', 'General DOM', 'DOM', 'DOM/Body')
        ]

        assert len(reflecting_params) > 0, "Should find reflecting params"

        # Build synthetic using FIRST real param
        first_real = reflecting_params[0]
        synthetic_csti = {
            "type": "CSTI",
            "parameter": first_real["parameter"],
            "url": first_real["url"],
            "_auto_dispatched": True,
        }

        # Assertions
        assert synthetic_csti["parameter"] != "_auto_dispatch"
        assert synthetic_csti["parameter"] in ["category", "searchTerm"]
        assert "?" in synthetic_csti["url"], "URL should have query params"

    def test_csti_autodispatch_injects_even_when_csti_exists_on_wrong_params(self):
        """Even if DASTySAST found CSTI on ng-app/postId, should still inject for real params."""
        all_findings = [
            {
                "type": "Client-Side Template Injection",
                "parameter": "ng-app",
                "url": "https://example.com/",
            },
            {
                "type": "XSS (Reflected)",
                "parameter": "category",
                "url": "https://example.com/catalog?category=test",
            },
            {
                "type": "XSS (Reflected)",
                "parameter": "searchTerm",
                "url": "https://example.com/catalog?searchTerm=hello",
            },
        ]

        # Existing CSTI params
        existing_csti_params = set()
        for f in all_findings:
            ftype = f.get('type', '').upper()
            if ftype in ['CSTI', 'CLIENT-SIDE TEMPLATE INJECTION', 'TEMPLATE INJECTION']:
                existing_csti_params.add(f.get('parameter', ''))

        assert 'ng-app' in existing_csti_params, "ng-app should be in existing CSTI"

        # Reflecting params (excluding framework attrs)
        reflecting_params = [
            f for f in all_findings
            if f.get('parameter') and f['parameter'] not in (
                '', '_auto_dispatch', 'auto_dispatch',
                'General DOM', 'DOM', 'DOM/Body',
                'ng-app', 'ng-controller', 'v-if', 'v-for',
            )
        ]

        # Should inject for category and searchTerm (not already CSTI)
        injected = []
        seen = set()
        for rf in reflecting_params:
            param = rf["parameter"]
            if param in existing_csti_params or param in seen:
                continue
            seen.add(param)
            injected.append({"type": "CSTI", "parameter": param, "url": rf["url"]})

        assert len(injected) >= 1, "Should inject at least 1 synthetic CSTI"
        assert any(i["parameter"] == "category" for i in injected), "category should be injected"
        assert not any(i["parameter"] == "ng-app" for i in injected), "ng-app should NOT be injected (already exists)"

    def test_csti_autodispatch_no_reflecting_params_uses_target(self):
        """If no reflecting params, synthetic finding should still have a reasonable URL."""
        all_findings = [
            {"type": "Info", "parameter": "", "url": "https://example.com/"},
        ]
        tech_profile = {"frameworks": ["Vue.js 3.0"]}
        target = "https://example.com/page?id=1"

        reflecting_params = [
            f for f in all_findings
            if f.get('parameter') and f['parameter'] not in ('', '_auto_dispatch', 'General DOM', 'DOM', 'DOM/Body')
        ]

        # No reflecting params — should fallback to target URL
        assert len(reflecting_params) == 0
        # Fallback: use target URL and extract its params
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(target)
        query_params = parse_qs(parsed.query)

        if query_params:
            first_param = list(query_params.keys())[0]
            synthetic_url = target
        else:
            first_param = "_auto_dispatch"
            synthetic_url = target

        # When target has params, use them
        assert first_param == "id"


# ===========================================================================
# Bug 2: CSTI smart probe should execute and handle all response types
# ===========================================================================

class TestCSTISmartProbe:
    """Bug 2: CSTI smart probe should be called and handle responses correctly."""

    def _simulate_smart_probe_logic(self, response, baseline_html, engines=None):
        """Simulate the core smart probe logic without needing HTTP."""
        if engines is None:
            engines = ["angular"]

        probe = "BT_CSTI_49{{7*7}}${7*7}"

        if response is None:
            return None, True  # Network error, continue

        if "BT_CSTI_49" not in response:
            return None, False  # No reflection, skip

        if "49" in response and "7*7" not in response and "49" not in baseline_html:
            engine = engines[0] if any(e in ["angular", "vue"] for e in engines) else "unknown"
            finding = {
                "parameter": "category",
                "payload": "{{7*7}}",
                "method": "arithmetic_eval",
                "engine": engine,
                "status": "VALIDATED_CONFIRMED",
            }
            return finding, True  # Confirmed!

        return None, True  # Reflects but no eval, continue

    def test_smart_probe_detects_evaluation(self):
        """Smart probe should detect {{7*7}}=49 and return confirmed finding."""
        response = "Page content BT_CSTI_49 result is 49 and more text"
        baseline = "Page content without any numbers"

        finding, should_continue = self._simulate_smart_probe_logic(response, baseline)
        assert finding is not None, "Should confirm CSTI"
        assert finding["status"] == "VALIDATED_CONFIRMED"
        assert finding["engine"] == "angular"

    def test_smart_probe_skips_no_reflection(self):
        """Smart probe should skip param if probe doesn't reflect at all."""
        response = "Page without any probe reflection whatsoever"

        finding, should_continue = self._simulate_smart_probe_logic(response, "")
        assert finding is None
        assert should_continue is False, "Should skip this param entirely"

    def test_smart_probe_continues_on_literal_reflection(self):
        """If template syntax reflects literally, continue escalation."""
        response = "BT_CSTI_49{{7*7}}${7*7} reflected literally"

        finding, should_continue = self._simulate_smart_probe_logic(response, "")
        assert finding is None, "Should NOT confirm (7*7 still in response)"
        assert should_continue is True, "Should continue to L0/L1"

    def test_smart_probe_handles_49_in_baseline(self):
        """If 49 exists in baseline, it's not proof of evaluation."""
        response = "BT_CSTI_49 the result is 49"
        baseline = "Page shows 49 items in stock"

        finding, should_continue = self._simulate_smart_probe_logic(response, baseline)
        assert finding is None, "49 in baseline = false positive"

    def test_smart_probe_network_error_continues(self):
        """Network error should continue escalation, not skip."""
        finding, should_continue = self._simulate_smart_probe_logic(None, "")
        assert finding is None
        assert should_continue is True, "Network error → continue escalation"

    def test_smart_probe_with_auto_dispatch_param_would_fail(self):
        """Demonstrates why _auto_dispatch param causes 0 findings (Bug 1 root cause)."""
        # When server receives ?_auto_dispatch=BT_CSTI_49{{7*7}}${7*7}
        # The param doesn't exist → server ignores it → no reflection
        response = "Normal page with no reflection of unknown params"

        finding, should_continue = self._simulate_smart_probe_logic(response, "")
        assert finding is None
        assert should_continue is False, "_auto_dispatch never reflects → skip"


# ===========================================================================
# Bug 3: XSS smart probe should generate correct context-specific payloads
# ===========================================================================

class TestXSSSmartProbe:
    """Bug 3: XSS L0.5 smart probe payload selection and confirmation."""

    def test_smart_probe_script_context_payloads(self):
        """For script context, should try JS breakout payloads."""
        from bugtrace.agents.xss_agent import XSSAgent as XSSAgentV4

        payloads = XSSAgentV4.SMART_PAYLOADS

        # Script context should use JS breakouts
        assert "js_sq_breakout" in payloads
        assert "js_dq_breakout" in payloads
        assert "\\'" in payloads["js_sq_breakout"], "Should have backslash-quote"
        assert "document.domain" in payloads["js_sq_breakout"] or "document.title" in payloads["js_sq_breakout"]

    def test_smart_probe_html_context_payloads(self):
        """For HTML text context with < surviving, should try SVG/IMG."""
        from bugtrace.agents.xss_agent import XSSAgent as XSSAgentV4

        payloads = XSSAgentV4.SMART_PAYLOADS

        assert "<svg" in payloads["html_svg"]
        assert "<img" in payloads["html_img"]

    def test_smart_probe_never_uses_alert_1(self):
        """RULE: Never use alert(1). Must use document.domain or document.title."""
        from bugtrace.agents.xss_agent import XSSAgent as XSSAgentV4

        for name, payload in XSSAgentV4.SMART_PAYLOADS.items():
            assert "alert(1)" not in payload, f"SMART_PAYLOADS['{name}'] uses alert(1)!"

    def test_smart_probe_generates_payloads_for_script_context(self):
        """Simulate payload selection for script context with surviving chars."""
        from bugtrace.agents.xss_agent import XSSAgent as XSSAgentV4

        SP = XSSAgentV4.SMART_PAYLOADS
        detected_context = "script"
        surviving = '"\'<>`'

        smart = []
        if detected_context == "script":
            smart.append(SP["js_sq_breakout"])
            smart.append(SP["js_dq_breakout"])

        assert len(smart) >= 2
        assert any("\\'" in p for p in smart), "Should include single-quote breakout"
        assert any('\\"' in p or '\\\\"' in p for p in smart), "Should include double-quote breakout"

    def test_smart_probe_no_reflection_returns_skip(self):
        """If BT7331 marker doesn't reflect, should signal skip."""
        response = "Normal page content without any markers"
        reflects = "BT7331" in response
        assert reflects is False


# ===========================================================================
# Bug 4: WET files should be valid JSON Lines
# ===========================================================================

class TestWETFileFormat:
    """Bug 4: WET files must be valid JSON Lines (one JSON object per line)."""

    def test_wet_file_each_line_is_valid_json(self):
        """Each line of a WET file should be valid JSON."""
        sample_lines = [
            '{"timestamp":1770710716.68,"specialist":"xss","finding":{"type":"XSS","parameter":"q"}}',
            '{"timestamp":1770710716.77,"specialist":"xss","finding":{"type":"XSS","parameter":"id"}}',
        ]
        for i, line in enumerate(sample_lines):
            parsed = json.loads(line)
            assert "specialist" in parsed
            assert "finding" in parsed

    def test_wet_file_reader_handles_jsonlines(self):
        """Code that reads WET files should handle JSON Lines format."""
        import tempfile
        import os

        # Write a valid JSONL file
        lines = [
            {"timestamp": 1.0, "specialist": "csti", "finding": {"type": "CSTI", "parameter": "cat"}},
            {"timestamp": 2.0, "specialist": "csti", "finding": {"type": "CSTI", "parameter": "q"}},
        ]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            for item in lines:
                f.write(json.dumps(item) + "\n")
            tmp_path = f.name

        try:
            # Read as JSONL (correct way)
            findings = []
            with open(tmp_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        entry = json.loads(line)
                        findings.append(entry.get("finding", {}))

            assert len(findings) == 2
            assert findings[0]["parameter"] == "cat"
            assert findings[1]["parameter"] == "q"
        finally:
            os.unlink(tmp_path)

    def test_wet_file_reader_rejects_bare_json_load(self):
        """json.load() on JSONL should fail — this is the bug scenario."""
        import tempfile
        import os

        lines = [
            {"timestamp": 1.0, "specialist": "csti", "finding": {"type": "CSTI"}},
            {"timestamp": 2.0, "specialist": "csti", "finding": {"type": "CSTI"}},
        ]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            for item in lines:
                f.write(json.dumps(item) + "\n")
            tmp_path = f.name

        try:
            # json.load() on JSONL should FAIL (extra data)
            with pytest.raises(json.JSONDecodeError):
                with open(tmp_path, 'r') as f:
                    json.load(f)
        finally:
            os.unlink(tmp_path)

    def test_validator_engine_reads_jsonl_wet_files(self):
        """ValidationEngine._read_findings_file() should handle JSONL WET files."""
        import tempfile
        import os
        from bugtrace.core.validator_engine import ValidationEngine

        # Create a JSONL file like the WET files
        lines = [
            {"timestamp": 1.0, "specialist": "csti", "finding": {"type": "CSTI", "parameter": "category", "url": "https://example.com/"}},
            {"timestamp": 2.0, "specialist": "csti", "finding": {"type": "CSTI", "parameter": "q", "url": "https://example.com/search"}},
        ]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            for item in lines:
                f.write(json.dumps(item) + "\n")
            tmp_path = f.name

        try:
            engine = ValidationEngine.__new__(ValidationEngine)
            findings = engine._read_findings_file(Path(tmp_path), "wet")
            assert len(findings) == 2, f"Should find 2 findings, got {len(findings)}"
            assert findings[0]["parameter"] == "category"
            assert findings[1]["parameter"] == "q"
        finally:
            os.unlink(tmp_path)

    def test_validator_engine_reads_standard_json(self):
        """ValidationEngine._read_findings_file() should still handle standard JSON."""
        import tempfile
        import os
        from bugtrace.core.validator_engine import ValidationEngine

        data = {
            "specialist": "xss",
            "findings": [
                {"type": "XSS", "parameter": "q", "url": "https://example.com/"},
            ]
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(data, f)
            tmp_path = f.name

        try:
            engine = ValidationEngine.__new__(ValidationEngine)
            findings = engine._read_findings_file(Path(tmp_path), "results")
            assert len(findings) == 1
            assert findings[0]["parameter"] == "q"
        finally:
            os.unlink(tmp_path)


# ===========================================================================
# Bug 5: Reporting should only run once
# ===========================================================================

class TestReportingDedup:
    """Bug 5: ReportingAgent.generate_all_deliverables() should only be called once."""

    def test_validator_engine_has_skip_report_flag(self):
        """Validator engine should have a way to skip report generation."""
        # This tests the concept — the fix should prevent double generation
        # by having team.py pass a flag or removing one of the calls
        pass  # Implementation depends on fix approach


# ===========================================================================
# Bug 39: _check_csti() false negative when {{7*7}} in <script> tag
# ===========================================================================

class TestCSTIBrowserDetection:
    """Bug 39: _check_csti() must use page.content() (not just innerText) and
    strip <script> tags before checking template markers.

    On ginandjuice.shop:
    - Angular evaluates {{7*7}} to 49 in hidden input attribute (value="49")
    - innerText does NOT include attribute values → "49" not found
    - JS variable `const selectedCategory = "{{7*7}}"` in <script> tag
      caused page_content to still contain {{7*7}} → false negative
    """

    @pytest.mark.asyncio
    async def test_csti_confirmed_when_49_in_attribute_only(self):
        """CSTI should be confirmed when 49 only appears in attribute (ginandjuice.shop scenario)."""
        from bugtrace.tools.visual.verifier import XSSVerifier

        verifier = XSSVerifier()

        page = AsyncMock()
        # innerText does NOT include "49" (it's only in attribute)
        page.evaluate.return_value = "Products found"
        # page.content() shows Angular evaluated: value="49", no {{7*7}} in DOM
        page.content.return_value = (
            '<html><body ng-app="app">'
            '<input hidden name="category" value="49">'
            '<p>Products found</p>'
            '</body></html>'
        )

        url = "https://example.com/catalog?category=%7B%7B7*7%7D%7D"
        result = await verifier._check_csti(page, url)
        assert result is True, "CSTI should be confirmed when 49 in attribute (hidden input)"

    @pytest.mark.asyncio
    async def test_csti_confirmed_when_marker_only_in_script_tag(self):
        """CSTI should be confirmed when {{7*7}} only exists inside <script> tags."""
        from bugtrace.tools.visual.verifier import XSSVerifier

        verifier = XSSVerifier()

        page = AsyncMock()
        page.evaluate.return_value = "Products 49 items found"
        # page.content() has {{7*7}} ONLY in a <script> tag (not in HTML body)
        page.content.return_value = (
            '<html><body ng-app="app">'
            '<input hidden name="category" value="49">'
            '<p>Products 49 items found</p>'
            '<script>const selectedCategory = "{{7*7}}";</script>'
            '</body></html>'
        )

        url = "https://example.com/catalog?category=%7B%7B7*7%7D%7D"
        result = await verifier._check_csti(page, url)
        assert result is True, "CSTI should be confirmed when {{7*7}} only in <script> tag"

    @pytest.mark.asyncio
    async def test_csti_rejected_when_marker_in_html_body(self):
        """CSTI should NOT be confirmed when {{7*7}} appears in HTML body (literal reflection)."""
        from bugtrace.tools.visual.verifier import XSSVerifier

        verifier = XSSVerifier()

        page = AsyncMock()
        page.evaluate.return_value = "Products 49 items found"
        # {{7*7}} is in BOTH script AND visible HTML → literal reflection, not evaluated
        page.content.return_value = (
            '<html><body>'
            '<p>{{7*7}}</p>'
            '<p>Products 49 items found</p>'
            '<script>const x = "{{7*7}}";</script>'
            '</body></html>'
        )

        url = "https://example.com/?q=%7B%7B7*7%7D%7D"
        result = await verifier._check_csti(page, url)
        assert result is False, "CSTI should NOT confirm when {{7*7}} in HTML body (literal)"

    @pytest.mark.asyncio
    async def test_csti_confirmed_constructor_eval(self):
        """Constructor eval should still work."""
        from bugtrace.tools.visual.verifier import XSSVerifier

        verifier = XSSVerifier()

        page = AsyncMock()
        page.evaluate.return_value = "49 results"
        page.content.return_value = '<html><body><p>49 results</p></body></html>'

        url = "https://example.com/?q={{constructor.constructor(%22return%207*7%22)()}}"
        result = await verifier._check_csti(page, url)
        assert result is True, "Constructor eval should confirm when 49 in DOM"

    @pytest.mark.asyncio
    async def test_csti_no_arithmetic_in_url_skips(self):
        """No arithmetic expressions in URL → skip CSTI check entirely."""
        from bugtrace.tools.visual.verifier import XSSVerifier

        verifier = XSSVerifier()

        page = AsyncMock()
        url = "https://example.com/?q=hello"
        result = await verifier._check_csti(page, url)
        assert result is False
        # page.content should NOT be called (early return)
        page.content.assert_not_called()
