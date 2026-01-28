"""
Infrastructure Skills - Infrastructure-level vulnerability testing.

Contains:
    - HeaderInjectionSkill: CRLF and header injection
    - PrototypePollutionSkill: Client-side prototype pollution
"""

from typing import Dict, Any
from .base import BaseSkill
from bugtrace.utils.logger import get_logger

logger = get_logger("skills.infrastructure")


class HeaderInjectionSkill(BaseSkill):
    """Header Injection skill - tests for CRLF and header injection vulnerabilities."""
    
    description = "Test HTTP Header Injection and CRLF injection"
    
    async def execute(self, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        from bugtrace.tools.exploitation.header_injection import header_detector
        
        findings = []
        
        try:
            result = await header_detector.check(url)
            
            if result:
                # Result can be string or tuple (message, screenshot)
                if isinstance(result, tuple):
                    message, screenshot = result
                else:
                    message, screenshot = result, None
                
                finding = {
                    "type": "Header Injection",
                    "url": url,
                    "evidence": message,
                    "validated": True,
                    "severity": "MEDIUM",
                    "description": f"HTTP Header Injection (CRLF) vulnerability detected. Attacker can inject arbitrary headers into the HTTP response, potentially leading to XSS, cache poisoning, or session fixation. Evidence: {message[:200] if message else 'N/A'}",
                    "reproduction": f"curl -I '{url}%0d%0aX-Injected:%20true' | grep -i x-injected"
                }
                
                if screenshot:
                    finding["screenshot"] = screenshot
                    
                findings.append(finding)
                
                self.master.thread.record_payload_attempt("Header Injection", "auto-detect", success=True)
                logger.info(f"[{self.master.name}] ✅ Header Injection detected")
                
        except Exception as e:
            logger.debug(f"Header Injection test failed: {e}")
        
        return {
            "success": True,
            "findings": findings,
            "header_injection_found": len(findings) > 0
        }


class PrototypePollutionSkill(BaseSkill):
    """Prototype Pollution skill - tests for client-side prototype pollution."""
    
    description = "Test for Client-Side Prototype Pollution vulnerabilities"
    
    async def execute(self, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        from bugtrace.tools.visual.browser import browser_manager

        findings = []

        # Prototype pollution payloads in various formats
        pp_payloads = [
            "__proto__[test]=polluted",
            "constructor[prototype][test]=polluted",
            "__proto__.test=polluted",
        ]

        try:
            findings = await self._test_payloads_with_browser(browser_manager, url, pp_payloads)
        except Exception as e:
            logger.error(f"Prototype Pollution skill failed: {e}")

        return {
            "success": True,
            "findings": findings,
            "proto_pollution_found": len(findings) > 0
        }

    async def _test_payloads_with_browser(self, browser_manager, url: str, pp_payloads: list) -> list:
        """Test all payloads with browser."""
        findings = []

        async with browser_manager.get_page() as page:
            for payload in pp_payloads:
                finding = await self._test_prototype_pollution(page, url, payload)
                if finding:
                    findings.append(finding)
                    logger.info(f"[{self.master.name}] ✅ Prototype Pollution confirmed")
                    break

        return findings

    async def _test_prototype_pollution(self, page, url: str, payload: str):
        """Test a single prototype pollution payload."""
        test_url = f"{url}{'&' if '?' in url else '?'}{payload}"

        try:
            await page.goto(test_url, wait_until="domcontentloaded", timeout=8000)

            # Check if prototype was polluted
            is_polluted = await page.evaluate("() => ({}).test === 'polluted'")

            if is_polluted:
                from bugtrace.core.config import settings
                screenshot_path = str(settings.LOG_DIR / f"{self.master.thread.thread_id}_proto.png")
                await page.screenshot(path=screenshot_path)

                self.master.thread.record_payload_attempt("Prototype Pollution", payload, success=True)

                return {
                    "type": "Prototype Pollution",
                    "url": url,
                    "payload": payload,
                    "screenshot": screenshot_path,
                    "validated": True,
                    "severity": "MEDIUM"
                }

        except Exception as e:
            logger.debug(f"Prototype pollution test failed for {payload}: {e}")

        return None
