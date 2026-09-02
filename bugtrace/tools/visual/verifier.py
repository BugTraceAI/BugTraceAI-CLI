"""
Browser Verification Module - CDP + Playwright Hybrid.

Provides robust XSS verification using multiple methods:
1. CDP (Chrome DevTools Protocol) - Primary, more reliable
2. Playwright - Fallback if CDP fails

Author: BugtraceAI Team
Date: 2026-01-08
"""

import os
import re
import asyncio
from typing import Tuple, List, Optional, Dict, Any
from pathlib import Path
from dataclasses import dataclass

from bugtrace.utils.logger import get_logger
from bugtrace.core.config import settings

logger = get_logger("tools.browser_verifier")


from bugtrace.tools.visual.verifier_evidence import (
    _MARKER_EVIDENCE_NODE_LIMIT,
    _MARKER_EVIDENCE_JS,
    _POC_ELEMENT_ID_HINTS,
    _DEFACEMENT_TEXT_MARKERS,
    _BANNER_STYLE_TOKENS,
    _MIN_BANNER_STYLE_TOKENS,
    _SOURCE_SYNTAX_CHARS,
    _JS_STRING_DELIMITERS,
    _ECHO_DATA_BOUNDARY,
    _ECHO_LITERAL_SCAN_WINDOW,
    _JS_ESCAPE_RE,
    _OVERLAY_MIN_VIEWPORT_COVERAGE,
    _OVERLAY_MAX_TEXT_SHARE,
    _OCCLUSION_MAX_ROUNDS,
    _OCCLUSION_SAMPLE_COLS,
    _OCCLUSION_SAMPLE_ROWS,
    _OCCLUSION_TIMEOUT_S,
    _STACKING_RESET_DECLARATIONS,
    _BANNER_LOCK_DECLARATIONS,
    _NEUTRALIZE_OCCLUDERS_JS,
    decode_js_escapes,
    decoded_payload_sources,
    normalize_style,
    _node_attrs,
    has_poc_element_id,
    has_banner_style,
    marker_sent_as_string_literal,
    is_execution_evidence,
    node_execution_evidence,
    evaluate_marker_evidence,
    payload_carries_marker,
    VerificationResult,
)
from bugtrace.tools.visual.verifier_checks import VerifierChecksMixin


class XSSVerifier(VerifierChecksMixin):
    """
    Hybrid XSS Verifier using CDP (primary) and Playwright (fallback).
    
    CDP provides more reliable detection through:
    - Direct console.log monitoring
    - DOM inspection without race conditions
    - Network request visibility
    
    Playwright is used as fallback when CDP is unavailable.
    """
    
    # XSS MARKER
    XSS_MARKER = "HACKED BY BUGTRACEAI"
    
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
        expected_marker: Optional[str] = None,
        max_level: int = 4
    ) -> VerificationResult:
        """
        Verify XSS at URL using best available method up to max_level.
        
        Args:
            url: URL with XSS payload to verify
            screenshot_dir: Directory to save evidence screenshots
            timeout: Time to wait for XSS execution
            max_level: Maximum level to try (3=Playwright, 4=CDP)
            
        Returns:
            VerificationResult with outcome and evidence
        """
        # Level 3: Try Playwright first (Lighter, handles most cases)
        if max_level >= 3:
            result = await self._verify_with_playwright(url, screenshot_dir, timeout, expected_marker)
            if result.success:
                return result

        # Level 4: If Playwright failed or was inconclusive, try CDP as a specialized fallback
        if max_level >= 4 and self.prefer_cdp and await self._check_cdp_available():
            logger.info("Playwright inconclusive (L3), attempting deep validation via CDP (L4)...")
            cdp_result = await self._verify_with_cdp(url, screenshot_dir, timeout, expected_marker)
            if cdp_result.success:
                return cdp_result
        
        # If we only wanted L3 and it failed, or L3 and L4 both failed
        return result if max_level >= 3 else VerificationResult(success=False, method="none", error="Level limit reached")
    
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
                    timeout=min(timeout, 5.0), # Cap execution wait at 5s to leave room for setup
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
            alert_message=result.alert_message,
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

        # FIX: Increased navigation timeout
        await self._navigate_to_url(page, url, timeout=60000)  # Changed from default 20s
        
        # FIX: Increased wait time for payload execution
        await asyncio.sleep(min(timeout, 8.0))  # Changed from 5.0 to 8.0

        if not dialog_detected[0]:
            early_result = await self._simulate_user_interactions(page, url, console_logs, dialog_detected)
            if early_result:
                # Capture evidence screenshot before returning early
                screenshot_path = await self._capture_screenshot(page, screenshot_dir, True)
                early_result.screenshot_path = screenshot_path
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
            dialog_detected[0], dialog_detected[1] if len(dialog_detected) > 1 else None,
            evaluation_data, impact_data
        )

        return {
            "verification_result": result,
            "browser_refs": (browser, context, page)
        }

    def _build_verification_result(self, xss_confirmed, screenshot_path, console_logs,
                                   dialog_detected, dialog_message, evaluation_data, impact_data) -> VerificationResult:
        """Build final verification result."""
        return VerificationResult(
            success=xss_confirmed,
            method="playwright",
            screenshot_path=screenshot_path,
            console_logs=console_logs,
            alert_message=dialog_message,
            details={
                "dialog_detected": dialog_detected,
                "marker_found": evaluation_data.get("marker_found", False),
                "impact_data": impact_data
            }
        )

    async def _setup_browser(self, p, url: str):
        """Setup browser, context and page."""
        logger.info(f"[{url}] Launching browser...")
        browser = await p.chromium.launch(
            headless=self.headless,
            # --disable-dev-shm-usage: use /tmp instead of the tiny 64MB /dev/shm in Docker,
            # which otherwise exhausts and wedges the renderer (screenshot/close hang forever).
            args=['--no-sandbox', '--disable-dev-shm-usage', '--disable-setuid-sandbox'],
        )
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

        dialog_detected = [False, None]  # Use list for mutability in closure: [triggered, message]
        async def handle_dialog(dialog):
            dialog_detected[0] = True
            dialog_detected[1] = dialog.message
            await dialog.dismiss()
 
        page.on("dialog", handle_dialog)
        return dialog_detected

    async def _navigate_to_url(self, page, url: str, timeout: int = 60000):
        """
        Navigate to target URL.
        
        FIX: Increased default timeout from 20s to 60s.
        """
        try:
            logger.info(f"[{url}] Navigating to target...")
            # FIX: Increased timeout and use domcontentloaded for faster initial load
            await page.goto(url, timeout=timeout, wait_until="domcontentloaded")
            # Wait for network to settle after initial load
            await page.wait_for_load_state("networkidle", timeout=30000)
        except Exception as e:
            logger.warning(f"Playwright navigation warning: {e}")
            # Fallback: try with just 'load' event
            try:
                await page.goto(url, timeout=timeout, wait_until="load")
            except Exception as fallback_e:
                logger.error(f"Navigation failed completely: {fallback_e}")

    async def _capture_screenshot(self, page, screenshot_dir: Optional[str], xss_confirmed: bool) -> Optional[str]:
        """Capture screenshot as evidence."""
        if not screenshot_dir:
            return None

        # Every detection probe has already read the DOM by now, so clearing site
        # chrome here can only change the IMAGE, never the verdict. Run it for the
        # failed attempts too: a `repro_attempt` shot of a consent modal tells the
        # triager nothing either.
        await self._neutralize_occluders(page)

        import time
        prefix = "playwright_xss" if xss_confirmed else "repro_attempt"
        screenshot_path = f"{screenshot_dir}/{prefix}_{int(time.time())}_{os.getpid()}.png"

        # FIX: Retry logic with increased timeout
        max_retries = 3
        for attempt in range(max_retries):
            try:
                # FIX: Increased timeout from 5s to 15s
                await page.screenshot(path=screenshot_path, timeout=15000, full_page=False)
                logger.info(f"Playwright screenshot captured: {screenshot_path}")
                return screenshot_path
            except Exception as e:
                if attempt == max_retries - 1:
                    logger.warning(f"Screenshot failed after {max_retries} attempts: {e}")
                    return None
                logger.warning(f"Screenshot attempt {attempt + 1} failed, retrying...: {e}")
                await asyncio.sleep(1.0 * (attempt + 1))
        
        return None

    async def _cleanup_browser(self, page, context, browser):
        """Clean up browser resources."""
        for resource, name in [(page, "Page"), (context, "Context"), (browser, "Browser")]:
            if not resource:
                continue
            await self._close_resource(resource, name)

    async def _close_resource(self, resource, name: str):
        """Close a browser resource with a HARD timeout.

        A wedged chromium (e.g. /dev/shm exhausted) makes resource.close() block
        forever waiting for a CDP ack that never comes. Because this runs inside a
        finally during cancellation it cannot be cancelled again, so an unbounded
        close() freezes the whole scan. Bound it: a dead browser degrades to a
        logged warning instead of an eternal hang.
        """
        try:
            await asyncio.wait_for(resource.close(), timeout=5.0)
        except asyncio.TimeoutError:
            logger.warning(f"{name} close timed out after 5s (browser wedged); abandoning it")
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
