"""
ReportValidator: Post-Scan Report Validation Agent

This agent takes a completed BugTraceAI report and validates each finding by:
1. Reading the report (engagement_data.json)
2. For each finding with a POC:
   - Open browser to the vulnerable URL
   - Execute the payload
   - Take screenshots
   - Use Vision LLM to analyze results
   - DELEGATE TO SPECIALIZED AGENTS if needed:
     * SQLMapAgent for SQL Injection
     * Nuclei for CVE-based checks
     * XSS Agent for complex XSS
   - Mark finding as VERIFIED or UNVERIFIED
3. Generate an updated report with validation status

Browser Automation Options:
- Playwright (default)
- Chrome DevTools MCP (future integration)

This gives the validator "browser subagent superpowers" - the ability to
browse, click, scroll, reason, and delegate to specialized tools.
"""

import asyncio
import json
import base64
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime


from loguru import logger

from bugtrace.agents.base import BaseAgent
from bugtrace.tools.visual.browser import browser_manager
from bugtrace.core.config import settings
from bugtrace.core.llm_client import LLMClient
# Specialized agent imports for delegation
from bugtrace.agents.sqlmap_agent import SQLMapAgent
from bugtrace.tools.external import external_tools


@dataclass
class ValidationResult:
    """Result of validating a single finding."""
    finding_id: str
    validated: bool
    confidence: float
    evidence: str
    screenshot_path: Optional[str]
    method: str
    

class ReportValidator(BaseAgent):
    """
    Post-scan report validator with full browser automation capabilities.
    
    This is the "final boss" validation - takes the report and personally
    verifies each POC like a human pentester would.
    """
    
    def __init__(self, event_bus=None):
        super().__init__("ReportValidator", "POC Verification Specialist", event_bus, agent_id="report_validator")
        self.llm = LLMClient()
        self.validation_results: List[ValidationResult] = []
        
    async def run_loop(self):
        """Not used - this agent is triggered after scan completion."""
        pass
    
    async def validate_report(
        self, 
        report_dir: Path,
        max_findings: int = 20
    ) -> Dict[str, Any]:
        """
        Main entry point: Take a report directory and validate all findings.
        
        Args:
            report_dir: Path to report folder (contains engagement_data.json)
            max_findings: Maximum findings to validate (to control cost/time)
            
        Returns:
            Validation summary with updated findings
        """
        self.think(f"Starting report validation for: {report_dir}")
        
        # 1. Load the report
        engagement_file = report_dir / "engagement_data.json"
        if not engagement_file.exists():
            raise FileNotFoundError(f"No engagement_data.json in {report_dir}")
            
        with open(engagement_file) as f:
            report_data = json.load(f)
            
        findings = report_data.get("findings", [])
        self.think(f"Loaded {len(findings)} findings from report")
        
        # 2. Filter to findings worth validating
        candidates = self._get_validation_candidates(findings, max_findings)
        self.think(f"Selected {len(candidates)} findings for validation")
        
        # 3. Validate each finding
        validated_findings = []
        for i, finding in enumerate(findings):
            if finding in candidates:
                self.think(f"Validating {i+1}/{len(candidates)}: {finding.get('title', 'Unknown')[:50]}")
                validated = await self._validate_single_finding(finding, report_dir)
                validated_findings.append(validated)
            else:
                validated_findings.append(finding)
                
        # 4. Update report
        report_data["findings"] = validated_findings
        report_data["validation_summary"] = self._generate_summary()
        
        # 5. Save updated report
        output_file = report_dir / "engagement_data_validated.json"
        with open(output_file, "w") as f:
            json.dump(report_data, f, indent=2, default=str)
            
        self.think(f"Validation complete! Results saved to {output_file}")
        
        return report_data
    
    def _get_validation_candidates(
        self, 
        findings: List[Dict], 
        max_count: int
    ) -> List[Dict]:
        """
        Select which findings to validate based on:
        - Not already validated
        - Has URL and/or payload
        - Higher severity first
        """
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        
        candidates = []
        for f in findings:
            if f.get("validated"):
                continue
            if not f.get("url") and not f.get("metadata", {}).get("url"):
                continue
            candidates.append(f)
            
        # Sort by severity
        candidates.sort(key=lambda x: severity_order.get(x.get("severity", "INFO").upper(), 5))
        
        return candidates[:max_count]
    
    async def _validate_single_finding(
        self, 
        finding: Dict[str, Any],
        report_dir: Path
    ) -> Dict[str, Any]:
        """
        Validate a single finding using browser automation + vision.
        
        This is where the "superpowers" happen:
        1. Navigate to URL with payload
        2. Capture screenshot
        3. Ask Vision LLM to analyze
        4. DELEGATE TO SPECIALIZED AGENTS if vision is inconclusive
        5. Update finding with results
        """
        vuln_type = self._detect_vuln_type(finding)
        url = finding.get("url") or finding.get("metadata", {}).get("url")
        payload = self._extract_payload(finding)
        parameter = finding.get("parameter") or finding.get("metadata", {}).get("parameter")
        
        if not url:
            return finding
            
        try:
            # STEP 1: Browser Automation
            screenshot_path, browser_logs, basic_triggered = await self._browser_test(
                url, payload, vuln_type, report_dir
            )
            
            # STEP 2: Check if basic test succeeded
            if basic_triggered:
                finding["validated"] = True
                finding["validation_method"] = "ReportValidator + Browser Alert"
                finding["validation_confidence"] = 1.0
                finding["screenshot_path"] = str(screenshot_path) if screenshot_path else None
                
                self.validation_results.append(ValidationResult(
                    finding_id=finding.get("id", "unknown"),
                    validated=True,
                    confidence=1.0,
                    evidence="Alert/error triggered in browser",
                    screenshot_path=str(screenshot_path) if screenshot_path else None,
                    method="Browser Alert Detection"
                ))
                return finding
                
            # STEP 3: Vision Analysis
            vision_result = {"success": False, "confidence": 0}
            if screenshot_path and Path(screenshot_path).exists():
                vision_result = await self._vision_analysis(
                    screenshot_path, vuln_type, url, payload
                )
                
                if vision_result.get("success") and vision_result.get("confidence", 0) >= 0.7:
                    finding["validated"] = True
                    finding["validation_method"] = "ReportValidator + Vision LLM"
                    finding["validation_confidence"] = vision_result.get("confidence")
                    finding["validation_evidence"] = vision_result.get("evidence")
                    finding["screenshot_path"] = str(screenshot_path)
                    
                    self.validation_results.append(ValidationResult(
                        finding_id=finding.get("id", "unknown"),
                        validated=True,
                        confidence=vision_result.get("confidence", 0),
                        evidence=vision_result.get("evidence", ""),
                        screenshot_path=str(screenshot_path),
                        method="Vision LLM Analysis"
                    ))
                    return finding
            
            # STEP 4: DELEGATE TO SPECIALIZED AGENTS if inconclusive
            # This is the key enhancement - using the right tool for the job
            
            if vuln_type == "sqli" and not finding.get("validated"):
                self.think(f"Vision inconclusive for SQLi, delegating to SQLMapAgent...")
                sqlmap_result = await self._delegate_to_sqlmap(url, parameter, report_dir)
                
                if sqlmap_result.get("validated"):
                    finding["validated"] = True
                    finding["validation_method"] = "ReportValidator -> SQLMapAgent"
                    finding["validation_confidence"] = 1.0
                    finding["validation_evidence"] = sqlmap_result.get("evidence")
                    finding["reproduction"] = sqlmap_result.get("reproduction")
                    
                    self.validation_results.append(ValidationResult(
                        finding_id=finding.get("id", "unknown"),
                        validated=True,
                        confidence=1.0,
                        evidence=sqlmap_result.get("evidence", "SQLMap confirmed"),
                        screenshot_path=str(screenshot_path) if screenshot_path else None,
                        method="SQLMapAgent Delegation"
                    ))
                    return finding
            
            # If we get here, validation was inconclusive
            if screenshot_path:
                finding["screenshot_path"] = str(screenshot_path)
            finding["validation_attempted"] = True
            finding["validation_notes"] = vision_result.get("evidence", "Inconclusive - all methods tried")
            
            self.validation_results.append(ValidationResult(
                finding_id=finding.get("id", "unknown"),
                validated=False,
                confidence=vision_result.get("confidence", 0),
                evidence=vision_result.get("evidence", ""),
                screenshot_path=str(screenshot_path) if screenshot_path else None,
                method="All Methods Inconclusive"
            ))
                
        except Exception as e:
            logger.error(f"Validation failed for {finding.get('title')}: {e}")
            finding["validation_error"] = str(e)
            
        return finding
    
    async def _delegate_to_sqlmap(
        self,
        url: str,
        parameter: Optional[str],
        report_dir: Path
    ) -> Dict[str, Any]:
        """
        Delegate SQL injection validation to SQLMapAgent.
        
        This runs actual sqlmap commands against the target to confirm SQLi.
        """
        self.think(f"Running SQLMap validation on {url} (param: {parameter})")
        
        try:
            # If we have a specific parameter, use it
            params = [parameter] if parameter else []
            
            # If no parameter specified, try to extract from URL
            if not params:
                import urllib.parse as urlparse
                from urllib.parse import parse_qs
                parsed = urlparse.urlparse(url)
                if parsed.query:
                    params = list(parse_qs(parsed.query).keys())
            
            if not params:
                return {"validated": False, "evidence": "No parameters to test"}
            
            # Run SQLMap via the SQLMapAgent
            sqlmap_agent = SQLMapAgent(url, params, report_dir)
            result = await sqlmap_agent.run()
            
            if result.get("findings"):
                # SQLMap found something!
                first_finding = result["findings"][0]
                return {
                    "validated": True,
                    "evidence": first_finding.get("evidence", "SQLMap confirmed vulnerability"),
                    "reproduction": first_finding.get("reproduction", f"sqlmap -u '{url}' --batch")
                }
            else:
                return {"validated": False, "evidence": "SQLMap did not confirm vulnerability"}
                
        except Exception as e:
            logger.error(f"SQLMap delegation failed: {e}")
            return {"validated": False, "evidence": f"SQLMap error: {e}"}
    
    async def _browser_test(
        self,
        url: str,
        payload: Optional[str],
        vuln_type: str,
        report_dir: Path
    ) -> Tuple[Optional[Path], List[str], bool]:
        """
        Execute browser-based testing.
        
        This includes:
        - Navigating to URL
        - Injecting payloads
        - Checking for alerts/errors
        - Capturing screenshots
        """
        logs = []
        triggered = False
        screenshot_path = None
        
        # Construct target URL with payload
        target_url = self._construct_test_url(url, payload)
        
        async with browser_manager.get_page() as page:
            try:
                # Setup XSS detection for XSS vulnerabilities
                if vuln_type == "xss":
                    async def on_alert(msg):
                        nonlocal triggered
                        triggered = True
                        logs.append(f"ALERT TRIGGERED: {msg}")
                        
                    await page.expose_function("bugtrace_alert", on_alert)
                    await page.add_init_script("""
                        window.alert = function(msg) {
                            // Visual proof
                            const div = document.createElement('div');
                            div.id = 'xss-proof';
                            div.style.cssText = 'position:fixed;top:20px;left:50%;transform:translateX(-50%);z-index:999999;background:#dc2626;color:white;padding:20px;border-radius:8px;font-size:20px;font-weight:bold;';
                            div.innerText = '⚠️ XSS VERIFIED: ' + msg;
                            document.body.appendChild(div);
                            // Callback
                            window.bugtrace_alert(msg);
                        };
                    """)
                
                # Navigate
                logs.append(f"Navigating to: {target_url}")
                await page.goto(target_url, wait_until="domcontentloaded", timeout=30000)
                await page.wait_for_timeout(3000)  # Wait for JS execution
                
                # For SQLi, check page content for errors
                if vuln_type == "sqli":
                    content = await page.content()
                    sql_indicators = [
                        "sql syntax", "mysql", "postgresql", "sqlite",
                        "ora-", "microsoft sql", "syntax error"
                    ]
                    for indicator in sql_indicators:
                        if indicator in content.lower():
                            triggered = True
                            logs.append(f"SQL indicator found: {indicator}")
                            break
                
                # Capture screenshot
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                screenshot_path = report_dir / "validation_screenshots" / f"validate_{timestamp}.png"
                screenshot_path.parent.mkdir(parents=True, exist_ok=True)
                await page.screenshot(path=str(screenshot_path))
                logs.append(f"Screenshot captured: {screenshot_path}")
                
            except Exception as e:
                logs.append(f"Browser error: {e}")
                logger.error(f"Browser test failed: {e}")
                
        return screenshot_path, logs, triggered
    
    async def _vision_analysis(
        self,
        screenshot_path: Path,
        vuln_type: str,
        url: str,
        payload: Optional[str]
    ) -> Dict[str, Any]:
        """
        Use Vision LLM to analyze screenshot and determine if vulnerability is real.
        
        This is the "AI reasoning" superpower - the ability to see and understand
        what's in the screenshot.
        """
        # Build context-aware prompt
        prompt = self._build_vision_prompt(vuln_type, url, payload)
        
        try:
            # Use the LLMClient's generate_with_image method
            response = await self.llm.generate_with_image(
                prompt=prompt,
                image_path=str(screenshot_path),
                model_override="google/gemini-2.0-flash-001",
                module_name="ReportValidator",
                temperature=0.1
            )
            
            return self._parse_vision_response(response)
            
        except Exception as e:
            logger.error(f"Vision analysis failed: {e}")
            return {"success": False, "confidence": 0, "evidence": str(e)}
    
    def _build_vision_prompt(
        self, 
        vuln_type: str, 
        url: str, 
        payload: Optional[str]
    ) -> str:
        """Build the appropriate prompt for vision analysis."""
        
        if not self.system_prompt:
             # Fallback context if no system prompt loaded
             return f"Analyze this screenshot for {vuln_type} success. URL: {url}, Payload: {payload}"

        prompt_sections = self.system_prompt.split("## ")
        section_name = ""
        if vuln_type == "xss":
            section_name = "XSS Vision Analysis Prompt"
        elif vuln_type == "sqli":
            section_name = "SQLi Vision Analysis Prompt"
        else:
            section_name = "General Vision Analysis Prompt"

        target_prompt = ""
        for section in prompt_sections:
            if section.startswith(section_name):
                target_prompt = section.replace(section_name, "").strip()
                break
        
        if not target_prompt:
            target_prompt = self.system_prompt # Fallback

        return target_prompt.format(
            url=url,
            payload=payload or "N/A"
        )
    
    def _parse_vision_response(self, response: str) -> Dict[str, Any]:
        """Parse JSON response from vision model."""
        import re
        
        try:
            # Find JSON in response
            json_match = re.search(r'\{[^{}]*\}', response, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
        except json.JSONDecodeError:
            pass
            
        # Fallback parsing
        return {
            "success": "success" in response.lower() and "true" in response.lower(),
            "confidence": 0.5,
            "evidence": response[:500]
        }
    
    def _construct_test_url(self, url: str, payload: Optional[str]) -> str:
        """Construct URL with payload injected."""
        if not payload or payload in url:
            return url
            
        import urllib.parse as urlparse
        from urllib.parse import urlencode, parse_qs
        
        parsed = urlparse.urlparse(url)
        if parsed.query:
            qs = parse_qs(parsed.query, keep_blank_values=True)
            # Inject payload into first parameter
            for k in qs:
                qs[k] = [payload]
                break
            new_query = urlencode(qs, doseq=True)
            return urlparse.urlunparse(parsed._replace(query=new_query))
        else:
            return f"{url}?test={payload}"
    
    def _extract_payload(self, finding: Dict[str, Any]) -> Optional[str]:
        """Extract payload from finding data."""
        # Try direct payload field
        payload = finding.get("payload")
        if payload:
            return payload
            
        # Try metadata
        payload = finding.get("metadata", {}).get("payload")
        if payload:
            return payload
            
        # Try evidence
        for ev in finding.get("evidence", []):
            if isinstance(ev, dict):
                content = ev.get("content", "")
                if "payload" in content.lower():
                    # Simple extraction - could be improved
                    return content.split(":")[-1].strip() if ":" in content else None
                    
        return None
    
    def _detect_vuln_type(self, finding: Dict[str, Any]) -> str:
        """Detect vulnerability type from finding."""
        title = finding.get("title", "").upper()
        ftype = finding.get("type", "").upper()
        
        if "XSS" in title or "CROSS-SITE" in title or "XSS" in ftype:
            return "xss"
        elif "SQL" in title or "SQLI" in ftype:
            return "sqli"
        elif "SSRF" in title:
            return "ssrf"
        elif "CRLF" in title or "HEADER" in title:
            return "crlf"
        else:
            return "general"
    
    def _generate_summary(self) -> Dict[str, Any]:
        """Generate validation summary statistics."""
        total = len(self.validation_results)
        validated = sum(1 for r in self.validation_results if r.validated)
        
        return {
            "total_validated": total,
            "confirmed": validated,
            "unconfirmed": total - validated,
            "confirmation_rate": validated / total if total > 0 else 0,
            "methods_used": list(set(r.method for r in self.validation_results)),
            "timestamp": datetime.now().isoformat()
        }


# Convenience function to validate a report
async def validate_report(report_path: str, max_findings: int = 20) -> Dict[str, Any]:
    """
    Standalone function to validate a BugTraceAI report.
    
    Usage:
        from bugtrace.agents.report_validator import validate_report
        result = await validate_report("reports/ginandjuice.shop_20260107/")
    """
    validator = ReportValidator()
    return await validator.validate_report(Path(report_path), max_findings)


# CLI entry point for standalone validation
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python -m bugtrace.agents.report_validator <report_dir>")
        sys.exit(1)
        
    report_dir = sys.argv[1]
    result = asyncio.run(validate_report(report_dir))
    
    summary = result.get("validation_summary", {})
    print(f"\n✅ Validation Complete!")
    print(f"   Confirmed: {summary.get('confirmed', 0)}/{summary.get('total_validated', 0)}")
    print(f"   Rate: {summary.get('confirmation_rate', 0)*100:.1f}%")
