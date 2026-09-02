"""
DOM XSS Detector using Playwright headless browser.

Monitors JavaScript execution for dangerous sink usage and
detects when user-controlled input reaches executable contexts.

Split: ``dom_xss_types``, ``dom_xss_scripts``, ``dom_xss_scan``.
"""

import asyncio  # used by detect_dom_xss_batch (wait_for / TimeoutError); dropped in the peel
from typing import List, Dict, Optional, Any
from playwright.async_api import async_playwright, Page, Browser, ConsoleMessage
from bugtrace.utils.logger import get_logger

from bugtrace.tools.headless.dom_xss_types import (
    DOMXSSFinding,
    DOM_REDIRECT_PARAMS,
    DOM_SEARCH_PARAMS,
    DOM_SINK_PARAMS,
)
from bugtrace.tools.headless.dom_xss_scripts import DOMXSSScriptsMixin
from bugtrace.tools.headless.dom_xss_scan import DOMXSSScanMixin

logger = get_logger("tools.dom_xss")


class DOMXSSDetector(DOMXSSScriptsMixin, DOMXSSScanMixin):
    """
    Headless browser-based DOM XSS detector.

    Uses Playwright to:
    1. Inject monitoring scripts that hook dangerous sinks
    2. Load pages with XSS payloads in various sources
    3. Detect when payloads reach dangerous sinks
    4. Confirm execution via alert/error interception
    """

    def __init__(self, timeout: int = 10000):
        self.timeout = timeout
        self.browser: Optional[Browser] = None
        self.playwright = None
        self.findings: List[DOMXSSFinding] = []

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, *args):
        await self.stop()

    async def start(self):
        """Start the headless browser."""
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(
            headless=True,
            args=[
                "--disable-web-security",  # Allow cross-origin for testing
                "--disable-features=IsolateOrigins,site-per-process",
            ]
        )
        logger.info("[DOMXSSDetector] Headless browser started")

    async def stop(self):
        """Stop the headless browser."""
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()
        logger.info("[DOMXSSDetector] Headless browser stopped")




async def detect_dom_xss(url: str, timeout: int = 10000,
                         discovered_params: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Convenience function for XSSAgent integration.

    Args:
        url: URL to scan for DOM XSS
        timeout: Browser timeout in ms
        discovered_params: Optional param names from specialist discovery.
                          Enables testing ?back=CANARY, ?searchTerm=CANARY etc.
    """
    async with DOMXSSDetector(timeout=timeout) as detector:
        findings = await detector.scan(url, discovered_params=discovered_params)

    return [
        {
            "vulnerability_type": "DOM_XSS",
            "url": f.url,
            "payload": f.payload,
            "sink": f.sink,
            "source": f.source,
            "evidence": f.evidence,
            "severity": f.severity,
            "status": "VALIDATED_CONFIRMED",
            "validated": True
        }
        for f in findings
    ]


async def detect_dom_xss_batch(urls: List[str], timeout: int = 10000,
                               discovered_params: Optional[List[str]] = None,
                               per_url_timeout: float = 180.0) -> List[Dict[str, Any]]:
    """Scan MANY urls reusing a SINGLE headless browser.

    ``detect_dom_xss`` launches AND closes Chromium on every call — a ~1-2s cold
    start per URL that dominated slow scans (the browser was restarted for each of
    N URLs). This opens ONE browser for the whole batch; each url still gets its own
    isolated context (created + torn down inside ``scan()``'s finally), and a per-url
    timeout/exception SKIPS that url without tearing the shared browser down.

    Returns the same flat list of finding-dicts as ``detect_dom_xss``.
    """
    all_findings: List[Dict[str, Any]] = []
    async with DOMXSSDetector(timeout=timeout) as detector:  # one browser for all urls
        for url in urls:
            try:
                findings = await asyncio.wait_for(
                    detector.scan(url, discovered_params=discovered_params),
                    timeout=per_url_timeout,
                )
            except asyncio.TimeoutError:
                logger.warning(f"[DOMXSSDetector] scan timeout ({per_url_timeout:.0f}s) for {url}, skipping")
                continue
            except Exception as e:
                logger.debug(f"[DOMXSSDetector] scan failed for {url}: {e}")
                continue
            for f in findings:
                all_findings.append({
                    "vulnerability_type": "DOM_XSS",
                    "url": f.url,
                    "payload": f.payload,
                    "sink": f.sink,
                    "source": f.source,
                    "evidence": f.evidence,
                    "severity": f.severity,
                    "status": "VALIDATED_CONFIRMED",
                    "validated": True,
                })
    return all_findings
