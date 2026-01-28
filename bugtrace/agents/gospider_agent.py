from typing import List, Dict, Any
from loguru import logger
from bugtrace.tools.external import external_tools
from bugtrace.core.ui import dashboard
from urllib.parse import urlparse
from bugtrace.utils.prioritizer import URLPrioritizer
from bugtrace.core.config import settings
from pathlib import Path
from bugtrace.agents.base import BaseAgent

class GoSpiderAgent(BaseAgent):
    """
    Specialized Agent for URL Discovery using GoSpider.
    Phase 1 of the Sequential Pipeline.
    
    Features:
    - URL discovery via GoSpider
    - Extension filtering (excludes .js, .css, .jpg, etc.)
    - Scope enforcement (same domain only)
    - Priority-based URL ordering
    """
    
    def __init__(self, target: str, report_dir: Path, max_depth: int = 2, max_urls: int = 10, event_bus: Any = None):
        super().__init__("GoSpiderAgent", "URL Discovery", event_bus=event_bus, agent_id="gospider_agent")
        self.target = target
        self.report_dir = report_dir
        self.max_depth = max_depth
        self.max_urls = max_urls
        
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
        gospider_urls = await external_tools.run_gospider(self.target, depth=self.max_depth)

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
        A simple BeautifulSoup discovery method if GoSpider fails.
        """
        import httpx

        discovered = set()
        discovered.add(self.target)

        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=10.0, verify=False) as client:
                await self._fallback_parse_html(client, discovered)

            # Try Playwright for JS-heavy sites
            js_urls = await self._crawl_with_playwright(self.target)
            for u in js_urls:
                discovered.add(u.split('#')[0])

            logger.info(f"[{self.name}] Fallback crawler discovered {len(discovered)} URLs (including JS discovery)")
            return list(discovered)
        except Exception as e:
            logger.error(f"Fallback discovery failed: {e}", exc_info=True)
            return [self.target]

    async def _fallback_parse_html(self, client, discovered: set):
        """Parse HTML and extract URLs from links and forms."""
        from bs4 import BeautifulSoup
        from urllib.parse import urljoin

        resp = await client.get(self.target)
        if resp.status_code != 200:
            return

        soup = BeautifulSoup(resp.text, 'html.parser')

        # Extract links
        for a in soup.find_all('a', href=True):
            self._fallback_add_url(urljoin(self.target, a['href']), discovered)

        # Extract forms
        for form in soup.find_all('form', action=True):
            self._fallback_add_url(urljoin(self.target, form['action']), discovered)

    def _fallback_add_url(self, full_url: str, discovered: set):
        """Add URL to discovered set if in scope."""
        # Basic scope check: only same origin or relative
        if urlparse(full_url).netloc == urlparse(self.target).netloc:
            discovered.add(full_url.split('#')[0])  # Remove fragments

    async def _crawl_with_playwright(self, base_url: str) -> List[str]:
        """Fallback para sitios JS-heavy que GoSpider no puede crawlear."""
        from bugtrace.tools.visual.browser import browser_manager

        urls = []
        try:
            async with browser_manager.get_page() as page:
                await page.goto(base_url, wait_until="networkidle", timeout=30000)
                await self._playwright_extract_links(page, base_url, urls)
                await self._playwright_extract_forms(page, base_url, urls)
        except Exception as e:
            logger.warning(f"Playwright crawl failed: {e}")

        return list(set(urls))

    async def _playwright_extract_links(self, page, base_url: str, urls: list):
        """Extract all href links from page."""
        from urllib.parse import urljoin

        links = await page.query_selector_all("a[href]")
        for link in links:
            href = await link.get_attribute("href")
            if not href or href.startswith("#"):
                continue

            full_url = urljoin(base_url, href)
            # Scope check
            if urlparse(full_url).netloc == urlparse(base_url).netloc:
                urls.append(full_url)

    async def _playwright_extract_forms(self, page, base_url: str, urls: list):
        """Extract all form action URLs from page."""
        from urllib.parse import urljoin

        forms = await page.query_selector_all("form[action]")
        for form in forms:
            action = await form.get_attribute("action")
            if not action:
                continue

            full_url = urljoin(base_url, action)
            # Scope check
            if urlparse(full_url).netloc == urlparse(base_url).netloc:
                urls.append(full_url)

    async def run_loop(self):
        await self.run()
