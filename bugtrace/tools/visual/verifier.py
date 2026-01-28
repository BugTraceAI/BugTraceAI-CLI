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
                    logger.error(f"CDP validation timed out after {timeout + 30}s - likely alert() popup hang")
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
                
        except Exception as e:
            logger.error(f"CDP verification error: {e}")
            return VerificationResult(
                success=False,
                method="cdp",
                error=str(e)
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
                logger.info(f"[{url}] Launching browser...")
                browser = await p.chromium.launch(headless=self.headless)
                context = await browser.new_context(
                    viewport={"width": 1280, "height": 720}
                )
                page = await context.new_page()
                
                # Track console logs
                console_logs = []
                page.on("console", lambda msg: console_logs.append({
                    "type": msg.type,
                    "text": msg.text,
                    "source": "playwright"
                }))
                
                def _make_result():
                     # Helper to return early if interaction succeeded
                     return VerificationResult(
                        success=True,
                        method="playwright",
                        screenshot_path=None, 
                        console_logs=console_logs,
                        details={"dialog_detected": True, "trigger": "user_interaction"}
                    )
                
                # Track dialogs (alerts)
                dialog_detected = False
                async def handle_dialog(dialog):
                    nonlocal dialog_detected
                    dialog_detected = True
                    await dialog.dismiss()
                    
                page.on("dialog", handle_dialog)
                
                # Navigate
                try:
                    logger.info(f"[{url}] Navigating to target...")
                    await page.goto(url, timeout=20000, wait_until="load")
                except Exception as e:
                    logger.warning(f"Playwright navigation warning: {e}")
                
                # Wait for initial execution
                wait_time = min(timeout, 5.0)
                logger.debug(f"[{url}] Waiting {wait_time}s for execution...")
                await asyncio.sleep(wait_time)

                # CLICK/FOCUS/HOVER SIMULATION (Enhanced Interaction)
                if not dialog_detected:
                    try:
                        logger.info(f"[{url}] 🖱️ Simulating User Interactions (Focus/Hover) for Attribute Execution...")
                        
                        # 1. Focus inputs (for onfocus/autofocus payloads)
                        # Use JavaScript to force the focus event because headless Chrome
                        # doesn't always dispatch onfocus via Playwright's .focus()
                        inputs = await page.query_selector_all("input, textarea, select")
                        for i, inp in enumerate(inputs[:5]):
                            if await inp.is_visible():
                                try:
                                    logger.debug(f"Forcing focus on input {i} via JS dispatchEvent")
                                    # Force the onfocus event with JavaScript
                                    await page.evaluate('''(el) => {
                                        el.focus();
                                        el.dispatchEvent(new FocusEvent('focus', { bubbles: true }));
                                        el.dispatchEvent(new FocusEvent('focusin', { bubbles: true }));
                                    }''', inp)
                                    await asyncio.sleep(0.8)
                                    if dialog_detected: break
                                except Exception as e:
                                    logger.debug(f"Focus event failed: {e}")
                        
                        if dialog_detected: return _make_result()

                        # 2. Hover elements (for onmouseover)
                        # We hover over elements that might be the injection point (labels, images, divs)
                        candidates = await page.query_selector_all("img, div, span, a, label")
                        for i, cand in enumerate(candidates[:10]): # Limit to 10
                            try:
                                if await cand.is_visible():
                                    await cand.hover(timeout=500)
                                    if dialog_detected: break
                            except Exception as e:
                                logger.debug(f"Hover action failed: {e}")
                            
                        if dialog_detected: return _make_result()

                        # 3. Click Simulation (DOM XSS / onclick)
                        clickable_selectors = [
                            "a[href^='javascript:']",
                            "button[onclick]", 
                            "div[onclick]",
                            "input[type='submit']",
                            "a:has-text('Back')",
                            "button:has-text('Back')",
                            ".back-button"
                        ]

                        for selector in clickable_selectors:
                            elements = await page.query_selector_all(selector)
                            for i, elem in enumerate(elements[:3]): # Limit to first 3 to avoid infinite loops
                                try:
                                    if await elem.is_visible():
                                        logger.info(f"[{url}] Clicking suspected element: {selector} [{i}]")
                                        await elem.click(timeout=1000)
                                        await asyncio.sleep(1.0) # Wait for event handler
                                        if dialog_detected:
                                            break
                                except Exception as click_err:
                                    pass
                            if dialog_detected:
                                break
                    except Exception as e:
                        logger.warning(f"Interaction simulation error: {e}")
                
                # Eval finished, return the helper at the end was here.
                pass
                
                # Evaluation
                xss_confirmed = dialog_detected
                xss_in_dom = False
                xss_in_console = False
                marker_found = False
                
                if not xss_confirmed:
                    try:
                        # Check marker in DOM
                        if expected_marker:
                            marker_found = await page.evaluate(f'document.getElementById("{expected_marker}") !== null')
                        
                        xss_in_dom = await page.evaluate(f'document.body.innerHTML.includes("{self.XSS_MARKER}")')
                        
                        # NEW: Check for XSS-HACKED (DOM Modification method)
                        if not xss_in_dom:
                            xss_in_dom = await page.evaluate('document.body.innerHTML.includes("XSS-HACKED")')
                            
                        # NEW: Check for window variable (Method 3)
                        xss_var_confirmed = await page.evaluate('window.XSS_CONFIRMED === true')
                        if xss_var_confirmed:
                             logger.info(f"[{url}] Window variable XSS_CONFIRMED found!")
                        
                        # CSTI Arithmetic Check (e.g. {{7*7}} -> 49)
                        csti_confirmed = False
                        if "{{7*7}}" in url:
                            page_content = await page.content()
                            # We check if 49 is present but {{7*7}} is NOT present (meaning it was evaluated)
                            # Or if 49 appears in a context that suggests evaluation
                            if "49" in page_content and "{{7*7}}" not in page_content:
                                csti_confirmed = True
                                logger.info(f"[{url}] CSTI Confirmed: Expression evaluated to 49!")

                        # Visual Defacement Check (Robust ID-based)
                        # Supports multiple markers: #bt-pwn, #bt-pwn-l8, etc.
                        visual_confirmed = False
                        
                        # Check 1: Any element with ID containing "bt-pwn" (covers all variants)
                        # This catches: #bt-pwn, #bt-pwn-l8, #bt-pwn-l7, etc.
                        try:
                            pwn_elements = await page.evaluate('''() => {
                                const allElements = document.querySelectorAll('[id*="bt-pwn"]');
                                return allElements.length;
                            }''')
                            if pwn_elements > 0:
                                visual_confirmed = True
                                logger.info(f"[{url}] Visual Defacement Confirmed: bt-pwn element found (count: {pwn_elements})!")
                        except Exception as e:
                            logger.debug(f"Visual defacement check failed: {e}")
                            # Fallback to specific ID checks
                            if await page.locator("#bt-pwn").count() > 0:
                                visual_confirmed = True
                                logger.info(f"[{url}] Visual Defacement Confirmed: '#bt-pwn' element found!")
                            elif await page.locator("#bt-pwn-l8").count() > 0:
                                visual_confirmed = True
                                logger.info(f"[{url}] Visual Defacement Confirmed: '#bt-pwn-l8' element found!")
                            elif await page.locator("#bt-pwn-l7").count() > 0:
                                visual_confirmed = True
                                logger.info(f"[{url}] Visual Defacement Confirmed: '#bt-pwn-l7' element found!")
                        
                        # Check 2: Text-based markers (multiple variations)
                        # Supports: "HACKED BY BUGTRACEAI", "FRAGMENT XSS", "MXSS DETECTED", etc.
                        if not visual_confirmed:
                            defacement_markers = [
                                "HACKED BY BUGTRACEAI",
                                "FRAGMENT XSS",
                                "MXSS DETECTED",
                                "XSS DETECTED", 
                                "PWNED BY BUGTRACE"
                            ]
                            
                            for marker in defacement_markers:
                                if await page.locator(f"div:has-text('{marker}')").count() > 0:
                                    # Found div with marker text - confirm it's not just reflection
                                    pwn_divs = await page.locator(f"div:has-text('{marker}')").all()
                                    for div in pwn_divs:
                                        # Check if it has our style attributes
                                        style = await div.get_attribute("style")
                                        div_id = await div.get_attribute("id")
                                        
                                        # Confirmed if it has red background style OR bt-pwn ID
                                        if (style and "background:red" in style) or (div_id and "bt-pwn" in div_id):
                                            visual_confirmed = True
                                            logger.info(f"[{url}] Visual Defacement Confirmed: '{marker}' banner found!")
                                            break
                                
                                if visual_confirmed:
                                    break


                        # Check console
                        xss_in_console = any((self.XSS_MARKER in log.get("text", "") or "XSS-VERIFIED" in log.get("text", "")) for log in console_logs)
                        
                        xss_confirmed = marker_found or xss_in_dom or xss_in_console or csti_confirmed or visual_confirmed or xss_var_confirmed
                    except Exception as eval_err:
                        logger.debug(f"DOM evaluation failed: {eval_err}")

                # IMPACT EXTRACTION (Advanced analysis)
                impact_data = {}
                if xss_confirmed:
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
                        
                        # IMPACT ASSESSMENT
                        has_storage_access = (impact_data.get('cookies') or impact_data.get('localStorageKeys'))
                        is_sandboxed = False
                        
                        # Check for sandbox (null origin or no storage access)
                        if impact_data.get('origin') == "null" or not has_storage_access:
                            is_sandboxed = True
                            logger.warning(f"[{url}] ⚠️ XSS confirmed but appears SANDBOXED (No storage access/Null origin). Impact is LOW.")
                            
                        if impact_data.get('has_sensitive_tokens'):
                            logger.success(f"[{url}] 💰 CRITICAL IMPACT: Sensitive tokens found in storage!")
                            
                        # Add sandbox status to details
                        impact_data['is_sandboxed'] = is_sandboxed
                        
                    except Exception as impact_err:
                        logger.warning(f"Impact extraction failed: {impact_err}")

                # Screenshot
                screenshot_path = None
                if screenshot_dir:
                    import time
                    prefix = "playwright_xss" if xss_confirmed else "repro_attempt"
                    screenshot_path = f"{screenshot_dir}/{prefix}_{int(time.time())}_{os.getpid()}.png"
                    try:
                        await page.screenshot(path=screenshot_path, timeout=5000)
                    except Exception as s_err:
                        logger.warning(f"Screenshot failed: {s_err}")
                
                return VerificationResult(
                    success=xss_confirmed,
                    method="playwright",
                    screenshot_path=screenshot_path,
                    console_logs=console_logs,
                    details={
                        "dialog_detected": dialog_detected,
                        "marker_found": marker_found,
                        "impact_data": impact_data
                    }
                )
                
        except Exception as e:
            logger.error(f"Playwright critical error: {e}")
            return VerificationResult(success=False, method="playwright", error=str(e))
        finally:
            try:
                if page: await page.close()
            except Exception as e:
                logger.debug(f"Page/Context/Browser close error: {e}")
            try:
                if context: await context.close()
            except Exception as e:
                logger.debug(f"Context close error: {e}")
            try:
                if browser: await browser.close()
            except Exception as e:
                logger.debug(f"Context close error: {e}")


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
