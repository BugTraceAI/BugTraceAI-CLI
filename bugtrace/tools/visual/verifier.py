"""
Browser Verification Module - CDP + Playwright Hybrid.

Provides robust XSS verification using multiple methods:
1. CDP (Chrome DevTools Protocol) - Primary, more reliable
2. Playwright - Fallback if CDP fails

Author: BugtraceAI Team
Date: 2026-01-08
"""

import os
import asyncio
from typing import Tuple, List, Optional, Dict, Any
from pathlib import Path
from dataclasses import dataclass

from bugtrace.utils.logger import get_logger
from bugtrace.core.config import settings

logger = get_logger("tools.browser_verifier")


@dataclass
class VerificationResult:
    """Result of XSS verification."""
    success: bool
    method: str  # "cdp", "playwright", or "none"
    screenshot_path: Optional[str] = None
    console_logs: List[Dict] = None
    details: Dict[str, Any] = None
    error: Optional[str] = None


class XSSVerifier:
    """
    Hybrid XSS Verifier using CDP (primary) and Playwright (fallback).
    
    CDP provides more reliable detection through:
    - Direct console.log monitoring
    - DOM inspection without race conditions
    - Network request visibility
    
    Playwright is used as fallback when CDP is unavailable.
    """
    
    # XSS MARKER
    XSS_MARKER = "BUGTRACE-XSS-CONFIRMED"
    
    def __init__(self, headless: bool = True, prefer_cdp: bool = False):
        self.headless = headless
        self.prefer_cdp = prefer_cdp
        self._cdp_available = None  # Lazy check
        
    async def _check_cdp_available(self) -> bool:
        """Check if CDP client can be initialized."""
        if not self.prefer_cdp:
            return False

        if self._cdp_available is not None:
            return self._cdp_available
            
        try:
            from bugtrace.core.cdp_client import CDPClient
            # Quick test to see if Chrome is available
            cdp = CDPClient(headless=True)
            chrome_path = cdp._find_chrome()
            self._cdp_available = chrome_path is not None
            logger.info(f"CDP available: {self._cdp_available}")
        except Exception as e:
            logger.warning(f"CDP not available: {e}")
            self._cdp_available = False
            
        return self._cdp_available
    
    async def verify_xss(
        self,
        url: str,
        screenshot_dir: Optional[str] = None,
        timeout: float = 15.0,
        expected_marker: Optional[str] = None
    ) -> VerificationResult:
        """
        Verify XSS at URL using best available method.
        
        Args:
            url: URL with XSS payload to verify
            screenshot_dir: Directory to save evidence screenshots
            timeout: Time to wait for XSS execution
            
        Returns:
            VerificationResult with outcome and evidence
        """
        # Try CDP first if preferred and available
        if self.prefer_cdp and await self._check_cdp_available():
            result = await self._verify_with_cdp(url, screenshot_dir, timeout, expected_marker)
            if result.success or result.error is None:
                return result
            # If CDP failed, fall through to Playwright
            logger.warning("CDP verification failed, trying Playwright...")
        
        # Fallback to Playwright
        return await self._verify_with_playwright(url, screenshot_dir, timeout, expected_marker)
    
    async def _verify_with_cdp(
        self,
        url: str,
        screenshot_dir: Optional[str],
        timeout: float,
        expected_marker: Optional[str] = None
    ) -> VerificationResult:
        """Verify XSS using CDP."""
        try:
            from bugtrace.core.cdp_client import CDPClient

            async with CDPClient(headless=self.headless) as cdp:
                return await self._execute_cdp_validation(cdp, url, screenshot_dir, timeout, expected_marker)

        except Exception as e:
            logger.error(f"CDP verification error: {e}", exc_info=True)
            return VerificationResult(
                success=False,
                method="cdp",
                error=str(e)
            )

    async def _execute_cdp_validation(self, cdp, url: str, screenshot_dir: Optional[str],
                                       timeout: float, expected_marker: Optional[str]) -> VerificationResult:
        """Execute CDP validation with timeout protection."""
        # Wrap with timeout to prevent infinite hangs from alert() popups
        try:
            result = await asyncio.wait_for(
                cdp.validate_xss(
                    url=url,
                    xss_marker=self.XSS_MARKER,
                    timeout=timeout,
                    screenshot_dir=screenshot_dir,
                    expected_marker=expected_marker
                ),
                timeout=timeout + 30.0  # Extra 30s for CDP overhead
            )
        except asyncio.TimeoutError:
            logger.error(f"CDP validation timed out after {timeout + 30}s - likely alert() popup hang", exc_info=True)
            return VerificationResult(
                success=False,
                method="cdp",
                error=f"Timeout after {timeout + 30}s - alert() popup likely blocked CDP"
            )

        return VerificationResult(
            success=result.success,
            method="cdp",
            screenshot_path=result.screenshot_path,
            console_logs=result.console_logs,
            details=result.data,
            error=result.error
        )
    
    async def _verify_with_playwright(
        self,
        url: str,
        screenshot_dir: Optional[str],
        timeout: float,
        expected_marker: Optional[str] = None
    ) -> VerificationResult:
        """Verify XSS using Playwright (fallback)."""
        from playwright.async_api import async_playwright

        browser = None
        context = None
        page = None

        try:
            async with async_playwright() as p:
                result = await self._run_playwright_verification(
                    p, url, screenshot_dir, timeout, expected_marker
                )
                browser, context, page = result.get("browser_refs", (None, None, None))
                return result.get("verification_result")

        except Exception as e:
            logger.error(f"Playwright critical error: {e}", exc_info=True)
            return VerificationResult(success=False, method="playwright", error=str(e))
        finally:
            await self._cleanup_browser(page, context, browser)

    async def _run_playwright_verification(self, p, url: str, screenshot_dir: Optional[str],
                                             timeout: float, expected_marker: Optional[str]) -> dict:
        """Run Playwright verification workflow."""
        browser, context, page = await self._setup_browser(p, url)
        console_logs = []
        dialog_detected = await self._setup_page_handlers(page, console_logs)

        await self._navigate_to_url(page, url)
        await asyncio.sleep(min(timeout, 5.0))

        if not dialog_detected[0]:
            early_result = await self._simulate_user_interactions(page, url, console_logs, dialog_detected)
            if early_result:
                return {
                    "verification_result": early_result,
                    "browser_refs": (browser, context, page)
                }

        xss_confirmed, evaluation_data = await self._evaluate_xss_indicators(
            page, url, dialog_detected[0], console_logs, expected_marker
        )

        impact_data = await self._extract_impact_data(page, url, xss_confirmed)
        screenshot_path = await self._capture_screenshot(page, screenshot_dir, xss_confirmed)

        result = self._build_verification_result(
            xss_confirmed, screenshot_path, console_logs,
            dialog_detected[0], evaluation_data, impact_data
        )

        return {
            "verification_result": result,
            "browser_refs": (browser, context, page)
        }

    def _build_verification_result(self, xss_confirmed, screenshot_path, console_logs,
                                   dialog_detected, evaluation_data, impact_data) -> VerificationResult:
        """Build final verification result."""
        return VerificationResult(
            success=xss_confirmed,
            method="playwright",
            screenshot_path=screenshot_path,
            console_logs=console_logs,
            details={
                "dialog_detected": dialog_detected,
                "marker_found": evaluation_data.get("marker_found", False),
                "impact_data": impact_data
            }
        )

    async def _setup_browser(self, p, url: str):
        """Setup browser, context and page."""
        logger.info(f"[{url}] Launching browser...")
        browser = await p.chromium.launch(headless=self.headless)
        context = await browser.new_context(viewport={"width": 1280, "height": 720})
        page = await context.new_page()
        return browser, context, page

    async def _setup_page_handlers(self, page, console_logs: List):
        """Setup console logging and dialog handlers."""
        page.on("console", lambda msg: console_logs.append({
            "type": msg.type,
            "text": msg.text,
            "source": "playwright"
        }))

        dialog_detected = [False]  # Use list for mutability in closure
        async def handle_dialog(dialog):
            dialog_detected[0] = True
            await dialog.dismiss()

        page.on("dialog", handle_dialog)
        return dialog_detected

    async def _navigate_to_url(self, page, url: str):
        """Navigate to target URL."""
        try:
            logger.info(f"[{url}] Navigating to target...")
            await page.goto(url, timeout=20000, wait_until="load")
        except Exception as e:
            logger.warning(f"Playwright navigation warning: {e}")

    async def _simulate_user_interactions(self, page, url: str, console_logs: List, dialog_detected: List):
        """Simulate user interactions to trigger XSS."""
        try:
            logger.info(f"[{url}] 🖱️ Simulating User Interactions...")

            # Try focus events
            if await self._simulate_focus_events(page, dialog_detected):
                return self._make_early_result(console_logs)

            # Try hover events
            if await self._simulate_hover_events(page, dialog_detected):
                return self._make_early_result(console_logs)

            # Try click events
            if await self._simulate_click_events(page, url, dialog_detected):
                return self._make_early_result(console_logs)
        except Exception as e:
            logger.warning(f"Interaction simulation error: {e}")

        return None

    async def _simulate_focus_events(self, page, dialog_detected: List) -> bool:
        """Simulate focus events on inputs."""
        inputs = await page.query_selector_all("input, textarea, select")
        for i, inp in enumerate(inputs[:5]):
            if dialog_detected[0]:
                return True
            if not await inp.is_visible():
                continue

            await self._trigger_focus_event(page, inp, i)

        return dialog_detected[0]

    async def _trigger_focus_event(self, page, element, index: int):
        """Trigger focus event on a single element."""
        try:
            logger.debug(f"Forcing focus on input {index}")
            await page.evaluate('''(el) => {
                el.focus();
                el.dispatchEvent(new FocusEvent('focus', { bubbles: true }));
                el.dispatchEvent(new FocusEvent('focusin', { bubbles: true }));
            }''', element)
            await asyncio.sleep(0.8)
        except Exception as e:
            logger.debug(f"Focus event failed: {e}")

    async def _simulate_hover_events(self, page, dialog_detected: List) -> bool:
        """Simulate hover events on elements."""
        candidates = await page.query_selector_all("img, div, span, a, label")
        for i, cand in enumerate(candidates[:10]):
            if dialog_detected[0]:
                return True
            try:
                if await cand.is_visible():
                    await cand.hover(timeout=500)
            except Exception as e:
                logger.debug(f"Hover action failed: {e}")
        return dialog_detected[0]

    async def _simulate_click_events(self, page, url: str, dialog_detected: List) -> bool:
        """Simulate click events on clickable elements."""
        clickable_selectors = [
            "a[href^='javascript:']", "button[onclick]", "div[onclick]",
            "input[type='submit']", "a:has-text('Back')",
            "button:has-text('Back')", ".back-button"
        ]

        for selector in clickable_selectors:
            if dialog_detected[0]:
                return True
            elements = await page.query_selector_all(selector)
            if await self._click_elements(elements, url, selector, dialog_detected):
                return True
        return dialog_detected[0]

    async def _click_elements(self, elements, url: str, selector: str, dialog_detected: List) -> bool:
        """Click elements and check for dialog detection."""
        for i, elem in enumerate(elements[:3]):
            if dialog_detected[0]:
                return True
            try:
                if await elem.is_visible():
                    logger.info(f"[{url}] Clicking: {selector} [{i}]")
                    await elem.click(timeout=1000)
                    await asyncio.sleep(1.0)
            except Exception as e:
                logger.debug(f"Element click failed: {e}")
        return dialog_detected[0]

    def _make_early_result(self, console_logs: List) -> VerificationResult:
        """Create early success result for user interaction."""
        return VerificationResult(
            success=True,
            method="playwright",
            screenshot_path=None,
            console_logs=console_logs,
            details={"dialog_detected": True, "trigger": "user_interaction"}
        )

    async def _evaluate_xss_indicators(self, page, url: str, dialog_detected: bool,
                                      console_logs: List, expected_marker: Optional[str]) -> Tuple[bool, Dict]:
        """Evaluate all XSS indicators in the page."""
        if dialog_detected:
            return True, {}

        try:
            marker_found = await self._check_expected_marker(page, expected_marker)
            xss_in_dom = await self._check_xss_in_dom(page)
            xss_var_confirmed = await self._check_window_variable(page, url)
            csti_confirmed = await self._check_csti(page, url)
            visual_confirmed = await self._check_visual_defacement(page, url)
            xss_in_console = self._check_console_logs(console_logs)

            xss_confirmed = (marker_found or xss_in_dom or xss_in_console or
                           csti_confirmed or visual_confirmed or xss_var_confirmed)

            return xss_confirmed, {"marker_found": marker_found}
        except Exception as e:
            logger.debug(f"DOM evaluation failed: {e}")
            return False, {}

    async def _check_expected_marker(self, page, expected_marker: Optional[str]) -> bool:
        """Check if expected marker exists."""
        if expected_marker:
            return await page.evaluate(f'document.getElementById("{expected_marker}") !== null')
        return False

    async def _check_xss_in_dom(self, page) -> bool:
        """Check for XSS markers in DOM."""
        if await page.evaluate(f'document.body.innerHTML.includes("{self.XSS_MARKER}")'):
            return True
        return await page.evaluate('document.body.innerHTML.includes("XSS-HACKED")')

    async def _check_window_variable(self, page, url: str) -> bool:
        """Check for XSS_CONFIRMED window variable."""
        xss_var = await page.evaluate('window.XSS_CONFIRMED === true')
        if xss_var:
            logger.info(f"[{url}] Window variable XSS_CONFIRMED found!")
        return xss_var

    async def _check_csti(self, page, url: str) -> bool:
        """Check for CSTI arithmetic expression evaluation."""
        if "{{7*7}}" in url:
            page_content = await page.content()
            if "49" in page_content and "{{7*7}}" not in page_content:
                logger.info(f"[{url}] CSTI Confirmed: Expression evaluated to 49!")
                return True
        return False

    async def _check_visual_defacement(self, page, url: str) -> bool:
        """Check for visual defacement markers."""
        try:
            pwn_elements = await page.evaluate('''() => {
                const allElements = document.querySelectorAll('[id*="bt-pwn"]');
                return allElements.length;
            }''')
            if pwn_elements > 0:
                logger.info(f"[{url}] Visual Defacement Confirmed (count: {pwn_elements})!")
                return True
        except Exception as e:
            logger.debug(f"Visual defacement check failed: {e}")
            if await self._check_specific_pwn_ids(page, url):
                return True

        return await self._check_text_based_markers(page, url)

    async def _check_specific_pwn_ids(self, page, url: str) -> bool:
        """Check for specific bt-pwn ID variants."""
        for pwn_id in ["#bt-pwn", "#bt-pwn-l8", "#bt-pwn-l7"]:
            if await page.locator(pwn_id).count() > 0:
                logger.info(f"[{url}] Visual Defacement Confirmed: '{pwn_id}' element found!")
                return True
        return False

    async def _check_text_based_markers(self, page, url: str) -> bool:
        """Check for text-based defacement markers."""
        markers = ["HACKED BY BUGTRACEAI", "FRAGMENT XSS", "MXSS DETECTED",
                  "XSS DETECTED", "PWNED BY BUGTRACE"]

        for marker in markers:
            if await page.locator(f"div:has-text('{marker}')").count() > 0:
                if await self._check_marker_divs(page, url, marker):
                    return True
        return False

    async def _check_marker_divs(self, page, url: str, marker: str) -> bool:
        """Check divs containing marker for XSS confirmation."""
        pwn_divs = await page.locator(f"div:has-text('{marker}')").all()
        for div in pwn_divs:
            style = await div.get_attribute("style")
            div_id = await div.get_attribute("id")
            if (style and "background:red" in style) or (div_id and "bt-pwn" in div_id):
                logger.info(f"[{url}] Visual Defacement Confirmed: '{marker}' banner!")
                return True
        return False

    def _check_console_logs(self, console_logs: List) -> bool:
        """Check console logs for XSS markers."""
        return any((self.XSS_MARKER in log.get("text", "") or
                   "XSS-VERIFIED" in log.get("text", "")) for log in console_logs)

    async def _extract_impact_data(self, page, url: str, xss_confirmed: bool) -> Dict:
        """Extract impact data if XSS is confirmed."""
        if not xss_confirmed:
            return {}

        try:
            impact_data = await page.evaluate('''() => {
                return {
                    cookie_count: document.cookie ? document.cookie.split(';').length : 0,
                    cookies: document.cookie,
                    origin: window.origin,
                    localStorageKeys: Object.keys(localStorage),
                    sessionStorageKeys: Object.keys(sessionStorage),
                    has_sensitive_tokens: (document.cookie + JSON.stringify(localStorage)).match(/token|jwt|session|auth|key/i) !== null
                }
            }''')

            has_storage_access = (impact_data.get('cookies') or impact_data.get('localStorageKeys'))
            is_sandboxed = impact_data.get('origin') == "null" or not has_storage_access

            if is_sandboxed:
                logger.warning(f"[{url}] ⚠️ XSS confirmed but SANDBOXED. Impact is LOW.")

            if impact_data.get('has_sensitive_tokens'):
                logger.success(f"[{url}] 💰 CRITICAL IMPACT: Sensitive tokens found!")

            impact_data['is_sandboxed'] = is_sandboxed
            return impact_data
        except Exception as e:
            logger.warning(f"Impact extraction failed: {e}")
            return {}

    async def _capture_screenshot(self, page, screenshot_dir: Optional[str], xss_confirmed: bool) -> Optional[str]:
        """Capture screenshot as evidence."""
        if not screenshot_dir:
            return None

        import time
        prefix = "playwright_xss" if xss_confirmed else "repro_attempt"
        screenshot_path = f"{screenshot_dir}/{prefix}_{int(time.time())}_{os.getpid()}.png"

        try:
            await page.screenshot(path=screenshot_path, timeout=5000)
            return screenshot_path
        except Exception as e:
            logger.warning(f"Screenshot failed: {e}")
            return None

    async def _cleanup_browser(self, page, context, browser):
        """Clean up browser resources."""
        for resource, name in [(page, "Page"), (context, "Context"), (browser, "Browser")]:
            if not resource:
                continue
            await self._close_resource(resource, name)

    async def _close_resource(self, resource, name: str):
        """Close a browser resource with error handling."""
        try:
            await resource.close()
        except Exception as e:
            logger.debug(f"{name} close error: {e}")


# Convenience function
async def verify_xss(
    url: str,
    screenshot_dir: Optional[str] = None,
    timeout: float = 15.0,
    expected_marker: Optional[str] = None
) -> VerificationResult:
    """
    Quick XSS verification using best available method.
    
    Example:
        result = await verify_xss("http://vuln.site/?q=<script>console.log('BUGTRACE-XSS-CONFIRMED')</script>")
        if result.success:
            print(f"XSS confirmed via {result.method}")
    """
    verifier = XSSVerifier(headless=settings.HEADLESS_BROWSER)
    return await verifier.verify_xss(url, screenshot_dir)
