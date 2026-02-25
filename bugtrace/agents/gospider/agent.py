"""
GoSpider Agent

Thin orchestrator for URL discovery using GoSpider.
Delegates pure logic to core.py, performs I/O (GoSpider execution,
Playwright crawling, HTTP requests) directly.

Extracted from gospider_agent.py for modularity.
"""

import re
from typing import List, Dict, Any, Set
from loguru import logger
from urllib.parse import urlparse, urljoin
from pathlib import Path

from bugtrace.agents.base import BaseAgent
from bugtrace.core.config import settings

from bugtrace.agents.gospider.core import (
    should_analyze_url,
    is_in_scope,
    filter_and_prioritize_urls,
    extract_js_urls,
    extract_openapi_urls,
    resolve_openapi_path,
    build_param_url,
    should_skip_input,
    SKIP_INPUT_TYPES,
    SKIP_INPUT_NAMES,
    SKIP_INPUT_TYPES_PW,
    SKIP_INPUT_NAMES_PW,
    OPENAPI_SPEC_PATHS,
)


class GoSpiderAgent(BaseAgent):
    """
    Specialized Agent for URL Discovery using GoSpider.
    Phase 1 of the Sequential Pipeline.

    Features:
    - URL discovery via GoSpider with full feature utilization:
      * -a: Wayback Machine, CommonCrawl, VirusTotal, AlienVault
      * --sitemap: Parse sitemap.xml
      * --js: JavaScript link extraction (default)
    - Form parameter extraction (input names from HTML forms)
    - JavaScript URL extraction (parameterized URLs in JS code)
    - Extension filtering (excludes .js, .css, .jpg, etc.)
    - Scope enforcement (same domain only)
    - Priority-based URL ordering

    IMPROVED 2026-01-30: Extract ALL testable parameters, not just URLs.
    """

    def __init__(
        self,
        target: str,
        report_dir: Path,
        max_depth: int = 2,
        max_urls: int = 10,
        event_bus: Any = None,
    ):
        super().__init__("GoSpiderAgent", "URL Discovery", event_bus=event_bus, agent_id="gospider_agent")
        self.target = target
        self.report_dir = report_dir
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.target_domain = urlparse(target).hostname.lower() if urlparse(target).hostname else ""

        # Load extension filters from config
        self.exclude_extensions = [ext.strip().lower() for ext in settings.CRAWLER_EXCLUDE_EXTENSIONS.split(",") if ext.strip()]
        self.include_extensions = [ext.strip().lower() for ext in settings.CRAWLER_INCLUDE_EXTENSIONS.split(",") if ext.strip()]

    # =====================================================================
    # RUN METHODS
    # =====================================================================

    async def run_loop(self):  # I/O
        await self.run()

    async def run(self) -> List[str]:  # I/O
        """Runs GoSpider and returns a prioritized, filtered list of URLs."""
        from bugtrace.core.ui import dashboard

        dashboard.current_agent = self.name
        dashboard.log(f"[{self.name}] Starting URL discovery (max_depth={self.max_depth}, max_urls={self.max_urls})...", "INFO")

        try:
            # Discover URLs
            gospider_urls = await self._discover_urls()
            if not gospider_urls:
                dashboard.log(f"[{self.name}] No URLs discovered. Using target URL.", "WARN")
                return [self.target]

            # Filter, prioritize and limit (delegates to PURE function)
            from bugtrace.utils.prioritizer import URLPrioritizer

            final_urls = filter_and_prioritize_urls(
                gospider_urls=gospider_urls,
                target=self.target,
                max_urls=self.max_urls,
                exclude_extensions=self.exclude_extensions,
                include_extensions=self.include_extensions,
                prioritizer_fn=URLPrioritizer.prioritize,
                dashboard=dashboard,
                agent_name=self.name,
            )

            # Save artifact
            urls_path = self.report_dir / "urls.txt"
            with open(urls_path, "w") as f:
                f.write("\n".join(final_urls))

            dashboard.log(f"[{self.name}] Discovered {len(final_urls)} prioritized URLs (filtered from {len(gospider_urls)} raw).", "SUCCESS")
            return final_urls

        except Exception as e:
            logger.error(f"GoSpiderAgent failed: {e}", exc_info=True)
            dashboard.log(f"[{self.name}] Error: {e}", "ERROR")
            return [self.target]

    # =====================================================================
    # URL DISCOVERY (I/O)
    # =====================================================================

    async def _discover_urls(self) -> List[str]:  # I/O
        """Run GoSpider and fallback discovery if needed."""
        from bugtrace.tools.external import external_tools
        from bugtrace.core.ui import dashboard

        # Pass max_urls to support early exit (optimization)
        gospider_urls = await external_tools.run_gospider(
            self.target,
            depth=self.max_depth,
            max_urls=self.max_urls,
        )

        # If GoSpider only returns 1 URL (the target itself), trigger fallback
        if len(gospider_urls) <= 1:
            dashboard.log(f"[{self.name}] GoSpider returned only {len(gospider_urls)} URL(s). Activating fallback link discovery...", "WARN")
            fallback_urls = await self._fallback_discovery()
            gospider_urls = list(set(gospider_urls + fallback_urls))

        return gospider_urls

    # =====================================================================
    # FALLBACK DISCOVERY (I/O)
    # =====================================================================

    async def _fallback_discovery(self) -> List[str]:  # I/O
        """
        Comprehensive fallback discovery if GoSpider fails.
        Extracts URLs AND parameters from forms, JavaScript, and API specs.
        """
        import httpx
        from bugtrace.core.ui import dashboard

        discovered: Set[str] = set()
        discovered.add(self.target)

        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=15.0, verify=False) as client:
                # Parse main page
                await self._fallback_parse_page(client, self.target, discovered)

                # Probe for OpenAPI/Swagger specs (REST API autodiscovery)
                api_urls = await self._discover_from_openapi(client)
                discovered.update(api_urls)

            # Try Playwright for JS-heavy sites
            js_urls = await self._crawl_with_playwright(self.target)
            discovered.update(js_urls)

            logger.info(f"[{self.name}] Fallback discovered {len(discovered)} URLs with params")
            return list(discovered)
        except Exception as e:
            logger.error(f"Fallback discovery failed: {e}", exc_info=True)
            return [self.target]

    async def _discover_from_openapi(self, client) -> Set[str]:  # I/O
        """
        Probe well-known OpenAPI/Swagger endpoints and extract API URLs.
        Works generically for any REST API with standard documentation.
        """
        from bugtrace.core.ui import dashboard

        parsed_target = urlparse(self.target)
        base = f"{parsed_target.scheme}://{parsed_target.netloc}"

        spec_data = None
        for path in OPENAPI_SPEC_PATHS:
            try:
                resp = await client.get(f"{base}{path}", timeout=5.0)
                if resp.status_code == 200:
                    content_type = resp.headers.get("content-type", "")
                    if "json" in content_type or resp.text.strip().startswith("{"):
                        spec_data = resp.json()
                        logger.info(f"[{self.name}] Found OpenAPI spec at {path}")
                        dashboard.log(f"[{self.name}] Found API spec at {path}", "SUCCESS")
                        break
            except Exception:
                continue

        if not spec_data:
            return set()

        # Extract URLs from OpenAPI spec (PURE)
        discovered = extract_openapi_urls(spec_data, base, self.target_domain)

        logger.info(f"[{self.name}] OpenAPI discovery: {len(discovered)} endpoints found")
        dashboard.log(f"[{self.name}] OpenAPI: {len(discovered)} API endpoints discovered", "INFO")
        return discovered

    async def _fallback_parse_page(self, client, url: str, discovered: Set[str]):  # I/O
        """
        Parse HTML page and extract:
        1. Links with parameters
        2. Form actions WITH input parameters
        3. URLs from inline JavaScript
        """
        from bs4 import BeautifulSoup

        try:
            resp = await client.get(url)
            if resp.status_code != 200:
                return

            html = resp.text
            soup = BeautifulSoup(html, 'html.parser')

            # 1. Extract links (including those with params)
            for a in soup.find_all('a', href=True):
                href = a['href']
                full_url = urljoin(url, href)
                if is_in_scope(full_url, self.target_domain):
                    discovered.add(full_url.split('#')[0])

            # 2. Extract forms WITH their input parameters
            for form in soup.find_all('form'):
                action = form.get('action', '')
                action_url = urljoin(url, action) if action else url

                if not is_in_scope(action_url, self.target_domain):
                    continue

                # Extract all input names
                inputs = form.find_all(['input', 'textarea', 'select'])
                for inp in inputs:
                    name = inp.get('name')
                    inp_type = inp.get('type', 'text').lower()

                    # Skip hidden/submit/csrf (PURE check)
                    if should_skip_input(name, inp_type, SKIP_INPUT_TYPES, SKIP_INPUT_NAMES):
                        continue

                    # Build parameterized URL (PURE)
                    param_url = build_param_url(action_url, name)
                    discovered.add(param_url)
                    logger.debug(f"[{self.name}] Found form param: {name}")

            # 3. Extract URLs from inline JavaScript (PURE)
            js_urls = extract_js_urls(html, url, self.target_domain)
            discovered.update(js_urls)

        except Exception as e:
            logger.debug(f"[{self.name}] Failed to parse {url}: {e}")

    # =====================================================================
    # PLAYWRIGHT CRAWLING (I/O)
    # =====================================================================

    async def _crawl_with_playwright(self, base_url: str) -> Set[str]:  # I/O
        """
        Playwright fallback for JS-heavy sites.
        Extracts links, forms with params, and JS-generated content.
        """
        from bugtrace.tools.visual.browser import browser_manager

        urls: Set[str] = set()
        try:
            async with browser_manager.get_page() as page:
                await page.goto(base_url, wait_until="networkidle", timeout=30000)

                # Get rendered HTML (after JS execution)
                html = await page.content()

                # Extract links
                links = await page.query_selector_all("a[href]")
                for link in links:
                    href = await link.get_attribute("href")
                    if href and not href.startswith("#"):
                        full_url = urljoin(base_url, href)
                        if is_in_scope(full_url, self.target_domain):
                            urls.add(full_url)

                # Extract form params (the key improvement)
                forms = await page.query_selector_all("form")
                for form in forms:
                    action = await form.get_attribute("action") or ""
                    action_url = urljoin(base_url, action) if action else base_url

                    if not is_in_scope(action_url, self.target_domain):
                        continue

                    # Get all inputs in this form
                    inputs = await form.query_selector_all("input[name], textarea[name], select[name]")
                    for inp in inputs:
                        name = await inp.get_attribute("name")
                        inp_type = await inp.get_attribute("type") or "text"

                        # Skip hidden/submit/csrf (PURE check)
                        if should_skip_input(name, inp_type, SKIP_INPUT_TYPES_PW, SKIP_INPUT_NAMES_PW):
                            continue

                        # Build parameterized URL (PURE)
                        urls.add(build_param_url(action_url, name))

                # Extract JS URLs from rendered HTML (PURE)
                js_urls = extract_js_urls(html, base_url, self.target_domain)
                urls.update(js_urls)

        except Exception as e:
            logger.warning(f"Playwright crawl failed: {e}")

        return urls
