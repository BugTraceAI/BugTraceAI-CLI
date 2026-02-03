from typing import List, Dict, Any, Set
from loguru import logger
from bugtrace.tools.external import external_tools
from bugtrace.core.ui import dashboard
from urllib.parse import urlparse, urljoin, parse_qs
from bugtrace.utils.prioritizer import URLPrioritizer
from bugtrace.core.config import settings
from pathlib import Path
from bugtrace.agents.base import BaseAgent
import re


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

    def __init__(self, target: str, report_dir: Path, max_depth: int = 2, max_urls: int = 10, event_bus: Any = None):
        super().__init__("GoSpiderAgent", "URL Discovery", event_bus=event_bus, agent_id="gospider_agent")
        self.target = target
        self.report_dir = report_dir
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.target_domain = urlparse(target).hostname.lower() if urlparse(target).hostname else ""

        # Load extension filters from config
        self.exclude_extensions = [ext.strip().lower() for ext in settings.CRAWLER_EXCLUDE_EXTENSIONS.split(",") if ext.strip()]
        self.include_extensions = [ext.strip().lower() for ext in settings.CRAWLER_INCLUDE_EXTENSIONS.split(",") if ext.strip()]
        
    def _should_analyze_url(self, url: str) -> bool:
        """
        Determines if a URL should be analyzed based on extension filtering.
        Excludes static files like .js, .css, .jpg, etc.
        """
        try:
            parsed = urlparse(url)
            path = parsed.path.lower()
            
            # Extract extension from path
            if '.' in path.split('/')[-1]:
                ext = '.' + path.rsplit('.', 1)[-1]
            else:
                ext = ''  # No extension (likely dynamic endpoint)
            
            # If include_extensions is set, only allow those
            if self.include_extensions:
                if ext and ext not in self.include_extensions:
                    return False
                return True
            
            # Otherwise, exclude the excluded extensions
            if ext and ext in self.exclude_extensions:
                return False
            
            return True
            
        except Exception:
            return True  # If parsing fails, include the URL
        
    async def _discover_urls(self) -> List[str]:
        """Run GoSpider and fallback discovery if needed."""
        # Pass max_urls to support early exit (optimization)
        gospider_urls = await external_tools.run_gospider(
            self.target, 
            depth=self.max_depth,
            max_urls=self.max_urls
        )

        # If GoSpider only returns 1 URL (the target itself), trigger fallback
        if len(gospider_urls) <= 1:
            dashboard.log(f"[{self.name}] GoSpider returned only {len(gospider_urls)} URL(s). Activating fallback link discovery...", "WARN")
            fallback_urls = await self._fallback_discovery()
            gospider_urls = list(set(gospider_urls + fallback_urls))

        return gospider_urls

    def _filter_and_prioritize_urls(self, gospider_urls: List[str]) -> List[str]:
        """Apply scoping, filtering, prioritization and limits to URLs."""
        if not gospider_urls:
            return []

        # Scope enforcement (same domain only)
        target_domain = urlparse(self.target).hostname.lower()
        scoped_urls = [u for u in gospider_urls if urlparse(u).hostname and urlparse(u).hostname.lower().endswith(target_domain)]

        # Extension filtering (exclude static files)
        filtered_urls = [u for u in scoped_urls if self._should_analyze_url(u)]
        excluded_count = len(scoped_urls) - len(filtered_urls)
        if excluded_count > 0:
            dashboard.log(f"[{self.name}] Filtered out {excluded_count} static files (.js, .css, .jpg, etc.)", "INFO")

        # Prioritize and limit
        prioritized = URLPrioritizer.prioritize(filtered_urls)
        final_urls = prioritized[:self.max_urls]

        # Ensure target is always included and at the top
        if self.target in final_urls:
            final_urls.remove(self.target)
            final_urls.insert(0, self.target)
        else:
            # Target was not in top N, force insert it at top
            final_urls.insert(0, self.target)
            # Resizing to respect max_urls if we exceeded it
            if len(final_urls) > self.max_urls:
                final_urls.pop()  # Remove lowest priority URL

        return final_urls

    async def run(self) -> List[str]:
        """Runs GoSpider and returns a prioritized, filtered list of URLs."""
        dashboard.current_agent = self.name
        dashboard.log(f"[{self.name}] Starting URL discovery (max_depth={self.max_depth}, max_urls={self.max_urls})...", "INFO")

        try:
            # Discover URLs
            gospider_urls = await self._discover_urls()
            if not gospider_urls:
                dashboard.log(f"[{self.name}] No URLs discovered. Using target URL.", "WARN")
                return [self.target]

            # Filter, prioritize and limit
            final_urls = self._filter_and_prioritize_urls(gospider_urls)

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

    async def _fallback_discovery(self) -> List[str]:
        """
        Comprehensive fallback discovery if GoSpider fails.
        Extracts URLs AND parameters from forms and JavaScript.
        """
        import httpx

        discovered: Set[str] = set()
        discovered.add(self.target)

        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=15.0, verify=False) as client:
                # Parse main page
                await self._fallback_parse_page(client, self.target, discovered)

            # Try Playwright for JS-heavy sites
            js_urls = await self._crawl_with_playwright(self.target)
            discovered.update(js_urls)

            logger.info(f"[{self.name}] Fallback discovered {len(discovered)} URLs with params")
            return list(discovered)
        except Exception as e:
            logger.error(f"Fallback discovery failed: {e}", exc_info=True)
            return [self.target]

    async def _fallback_parse_page(self, client, url: str, discovered: Set[str]):
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
                if self._is_in_scope(full_url):
                    discovered.add(full_url.split('#')[0])

            # 2. Extract forms WITH their input parameters
            for form in soup.find_all('form'):
                action = form.get('action', '')
                action_url = urljoin(url, action) if action else url

                if not self._is_in_scope(action_url):
                    continue

                # Extract all input names
                inputs = form.find_all(['input', 'textarea', 'select'])
                for inp in inputs:
                    name = inp.get('name')
                    inp_type = inp.get('type', 'text').lower()

                    # Skip hidden/submit/csrf
                    if not name:
                        continue
                    if inp_type in ('hidden', 'submit', 'button', 'image', 'reset'):
                        continue
                    if name.lower() in ('csrf', 'token', '_token', 'csrfmiddlewaretoken'):
                        continue

                    # Build parameterized URL
                    separator = "&" if "?" in action_url else "?"
                    param_url = f"{action_url}{separator}{name}=FUZZ"
                    discovered.add(param_url)
                    logger.debug(f"[{self.name}] Found form param: {name}")

            # 3. Extract URLs from inline JavaScript
            js_urls = self._extract_js_urls(html, url)
            discovered.update(js_urls)

        except Exception as e:
            logger.debug(f"[{self.name}] Failed to parse {url}: {e}")

    def _extract_js_urls(self, html: str, base_url: str) -> Set[str]:
        """Extract parameterized URLs from inline JavaScript."""
        urls = set()

        # Pattern: "/path?param=value" or '/path?param=value'
        js_url_pattern = re.compile(r'["\'](/[^"\']*\?[^"\']+)["\']')

        for match in js_url_pattern.finditer(html):
            relative_url = match.group(1)
            try:
                full_url = urljoin(base_url, relative_url)
                if self._is_in_scope(full_url):
                    urls.add(full_url)
            except Exception:
                pass

        return urls

    def _is_in_scope(self, url: str) -> bool:
        """Check if URL is in scope (same domain)."""
        try:
            url_domain = urlparse(url).hostname
            if not url_domain:
                return False
            return url_domain.lower() == self.target_domain or url_domain.lower().endswith('.' + self.target_domain)
        except Exception:
            return False

    async def _crawl_with_playwright(self, base_url: str) -> Set[str]:
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
                        if self._is_in_scope(full_url):
                            urls.add(full_url)

                # Extract form params (the key improvement)
                forms = await page.query_selector_all("form")
                for form in forms:
                    action = await form.get_attribute("action") or ""
                    action_url = urljoin(base_url, action) if action else base_url

                    if not self._is_in_scope(action_url):
                        continue

                    # Get all inputs in this form
                    inputs = await form.query_selector_all("input[name], textarea[name], select[name]")
                    for inp in inputs:
                        name = await inp.get_attribute("name")
                        inp_type = await inp.get_attribute("type") or "text"

                        if not name:
                            continue
                        if inp_type.lower() in ('hidden', 'submit', 'button'):
                            continue
                        if name.lower() in ('csrf', 'token', '_token'):
                            continue

                        separator = "&" if "?" in action_url else "?"
                        urls.add(f"{action_url}{separator}{name}=FUZZ")

                # Extract JS URLs from rendered HTML
                js_urls = self._extract_js_urls(html, base_url)
                urls.update(js_urls)

        except Exception as e:
            logger.warning(f"Playwright crawl failed: {e}")

        return urls

    async def run_loop(self):
        await self.run()
