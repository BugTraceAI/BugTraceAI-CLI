"""
External Tools Skills - Docker-based external tool wrappers.

Contains:
    - SQLMapSkill: SQLMap Docker wrapper for SQLi confirmation
    - NucleiSkill: Nuclei template-based scanning
    - GoSpiderSkill: Deep crawling
    - MutationSkill: AI-powered payload mutation for WAF bypass
"""

import asyncio
from typing import Dict, Any
from .base import BaseSkill
from bugtrace.utils.logger import get_logger

logger = get_logger("skills.external_tools")


class SQLMapSkill(BaseSkill):
    """SQLMap skill - heavy SQLi confirmation using SQLMap via Docker."""
    
    description = "Confirm SQL injection using SQLMap (requires Docker)"
    
    async def execute(self, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        from bugtrace.tools.external import external_tools
        from bugtrace.tools.visual.browser import browser_manager
        
        findings = []
        
        try:
            # Get session cookies if available
            cookies = None
            try:
                session_data = await browser_manager.get_session_data()
                cookies = session_data.get("cookies", [])
            except Exception as e:
                logger.debug(f"Session data fetch failed: {e}")
            
            result = await external_tools.run_sqlmap(
                url, 
                cookies,
                target_param=params.get("parameter")
            )
            
            if result:
                if isinstance(result, dict):
                    repro_cmd = result.get("reproduction_command", f"sqlmap -u '{url}' --batch --dbs")
                    findings.append({
                        "type": "SQLi",
                        "url": url,
                        "tool": "sqlmap",
                        "parameter": result.get("parameter"),
                        "payload": result.get("type", "SQLi"),
                        "evidence": f"SQLMap Command: {repro_cmd}\n\nEvidence: {result.get('output_snippet', 'Confirmed')}",
                        "validated": True,
                        "reproduction_command": repro_cmd,
                        "severity": "CRITICAL",
                        "description": f"SQL Injection confirmed by SQLMap. Parameter: {result.get('parameter', 'unknown')}. Injection type: {result.get('type', 'unknown')}",
                        "reproduction": repro_cmd
                    })
                else:
                    findings.append({
                        "type": "SQLi",
                        "url": url,
                        "tool": "sqlmap",
                        "evidence": "SQLMap confirmed SQL Injection",
                        "validated": True,
                        "severity": "CRITICAL",
                        "description": "SQL Injection vulnerability confirmed by SQLMap automated scanner.",
                        "reproduction": f"sqlmap -u '{url}' --batch --dbs"
                    })
                
                self.master.thread.record_payload_attempt("SQLi", "sqlmap", success=True)
                logger.info(f"[{self.master.name}] ✅ SQLMap confirmed SQLi")
                
        except Exception as e:
            logger.error(f"SQLMap skill failed: {e}")
        
        return {
            "success": True,
            "findings": findings,
            "sqli_found": len(findings) > 0
        }


class NucleiSkill(BaseSkill):
    """Nuclei skill - template-based vulnerability scanning via Docker."""
    
    description = "Run Nuclei template scan for known CVEs and vulnerabilities"
    
    async def execute(self, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        from bugtrace.tools.external import external_tools
        from bugtrace.tools.visual.browser import browser_manager
        
        findings = []
        
        try:
            # Get session cookies if available
            cookies = None
            try:
                session_data = await browser_manager.get_session_data()
                cookies = session_data.get("cookies", [])
            except Exception as e:

                logger.debug(f"Session data fetch failed: {e}")
            
            nuclei_results = await external_tools.run_nuclei(url, cookies)
            
            if nuclei_results:
                for result in nuclei_results:
                    template_id = result.get("template-id", "unknown")
                    matched_url = result.get("matched-at", url)
                    info = result.get("info", {})
                    findings.append({
                        "type": info.get("name", "Nuclei Finding"),
                        "url": matched_url,
                        "tool": "nuclei",
                        "template_id": template_id,
                        "severity": info.get("severity", "INFO").upper(),
                        "validated": True,
                        "description": f"Vulnerability detected by Nuclei template '{template_id}'. {info.get('description', '')}",
                        "reproduction": f"nuclei -u '{matched_url}' -t {template_id}"
                    })
                
                logger.info(f"[{self.master.name}] ✅ Nuclei found {len(findings)} issues")
                
        except Exception as e:
            logger.error(f"Nuclei skill failed: {e}")
        
        return {
            "success": True,
            "findings": findings,
            "nuclei_findings": len(findings)
        }


class GoSpiderSkill(BaseSkill):
    """GoSpider skill - deep crawling using GoSpider via Docker."""
    
    description = "Run GoSpider for deep crawling and endpoint discovery"
    
    async def execute(self, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        from bugtrace.tools.external import external_tools
        from bugtrace.tools.visual.browser import browser_manager
        
        urls_found = []
        
        try:
            # Get session cookies if available
            cookies = None
            try:
                session_data = await browser_manager.get_session_data()
                cookies = session_data.get("cookies", [])
            except Exception as e:

                logger.debug(f"Session data fetch failed: {e}")
            
            spider_urls = await external_tools.run_gospider(url, cookies)
            
            if spider_urls:
                urls_found = spider_urls
                # Update master's metadata with discovered URLs
                self.master.thread.update_metadata("spider_urls", spider_urls)
                logger.info(f"[{self.master.name}] ✅ GoSpider found {len(urls_found)} URLs")
                
        except Exception as e:
            logger.error(f"GoSpider skill failed: {e}")
        
        return {
            "success": True,
            "urls_found": urls_found,
            "count": len(urls_found)
        }


class MutationSkill(BaseSkill):
    """Mutation skill - AI-powered payload mutation for WAF bypass."""
    
    description = "Use LLM to mutate blocked payloads for WAF evasion"
    
    async def execute(self, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        from bugtrace.tools.exploitation.mutation import mutation_engine
        from bugtrace.tools.visual.browser import browser_manager

        findings = []
        base_payload = params.get("payload", "<script>alert(1)</script>")
        target_param = params.get("parameter", "test")

        try:
            mutations = await mutation_engine.mutate(base_payload, strategies=["encode", "polyglot", "obfuscate"])
            if mutations:
                findings = await self._test_mutations_with_browser(browser_manager, url, target_param, mutations)
        except Exception as e:
            logger.error(f"Mutation skill failed: {e}")

        return {
            "success": True,
            "mutations_tested": len(mutations) if 'mutations' in dir() else 0,
            "findings": findings,
            "bypass_found": len(findings) > 0
        }

    async def _test_mutations_with_browser(self, browser_manager, url: str, target_param: str, mutations: list) -> list:
        """Test mutations with browser to detect XSS."""
        findings = []

        async with browser_manager.get_page() as page:
            self._alert_detected = False
            page.on("dialog", self._handle_alert_dialog)

            for mutation in mutations[:10]:
                finding = await self._test_single_mutation(page, url, target_param, mutation)
                if finding:
                    findings.append(finding)
                    logger.info(f"[{self.master.name}] ✅ Mutation bypass successful!")
                    break

        return findings

    async def _handle_alert_dialog(self, dialog):
        """Handle browser alert dialog."""
        self._alert_detected = True
        await dialog.dismiss()

    async def _test_single_mutation(self, page, url: str, target_param: str, mutation: str):
        """Test a single mutation payload."""
        test_url = self._build_mutation_test_url(url, target_param, mutation)
        self._alert_detected = False

        try:
            await page.goto(test_url, wait_until="domcontentloaded", timeout=8000)
            await asyncio.sleep(1)

            if self._alert_detected:
                return await self._create_mutation_finding(page, url, target_param, mutation, test_url)

        except Exception as e:
            logger.debug(f"Mutation test failed for payload: {e}")

        return None

    def _build_mutation_test_url(self, url: str, target_param: str, mutation: str) -> str:
        """Build test URL with mutated payload."""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        parsed = urlparse(url)
        url_params = parse_qs(parsed.query)
        url_params[target_param] = [mutation]

        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, urlencode(url_params, doseq=True), parsed.fragment
        ))

    async def _create_mutation_finding(self, page, url: str, target_param: str, mutation: str, test_url: str) -> dict:
        """Create finding dict for successful mutation."""
        from bugtrace.core.config import settings

        screenshot_path = str(settings.LOG_DIR / f"{self.master.thread.thread_id}_mutation.png")
        await page.screenshot(path=screenshot_path)

        self.master.thread.record_payload_attempt("XSS", mutation, success=True)

        return {
            "type": "XSS",
            "url": url,
            "parameter": target_param,
            "param": target_param,
            "payload": mutation,
            "screenshot": screenshot_path,
            "validated": True,
            "alert_triggered": True,
            "severity": "HIGH",
            "note": "WAF bypass via mutation",
            "description": f"Cross-Site Scripting (XSS) confirmed via WAF bypass mutation. Alert dialog triggered in browser. Parameter: {target_param}",
            "reproduction": f"# Open in browser:\n{test_url}"
        }
