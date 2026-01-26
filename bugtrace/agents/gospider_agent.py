import asyncio
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
        
    async def run(self) -> List[str]:
        """Runs GoSpider and returns a prioritized, filtered list of URLs."""
        dashboard.current_agent = self.name
        dashboard.log(f"[{self.name}] Starting URL discovery (max_depth={self.max_depth}, max_urls={self.max_urls})...", "INFO")
        
        try:
            # 1. Run GoSpider
            gospider_urls = await external_tools.run_gospider(
                self.target, 
                depth=self.max_depth
            )
            
            # If GoSpider only returns 1 URL (the target itself), it means it didn't follow links
            # Trigger fallback discovery to find links
            if len(gospider_urls) <= 1:
                dashboard.log(f"[{self.name}] GoSpider returned only {len(gospider_urls)} URL(s). Activating fallback link discovery...", "WARN")
                fallback_urls = await self._fallback_discovery()
                # Merge with GoSpider results
                gospider_urls = list(set(gospider_urls + fallback_urls))
            
            if not gospider_urls:
                dashboard.log(f"[{self.name}] No URLs discovered. Using target URL.", "WARN")
                return [self.target]

                
            # 2. Scope enforcement (same domain only)
            target_domain = urlparse(self.target).hostname.lower()
            scoped_urls = [u for u in gospider_urls if urlparse(u).hostname and urlparse(u).hostname.lower().endswith(target_domain)]
            
            # 3. Extension filtering (exclude static files)
            filtered_urls = [u for u in scoped_urls if self._should_analyze_url(u)]
            excluded_count = len(scoped_urls) - len(filtered_urls)
            if excluded_count > 0:
                dashboard.log(f"[{self.name}] Filtered out {excluded_count} static files (.js, .css, .jpg, etc.)", "INFO")
            
            # 4. Prioritize
            prioritized = URLPrioritizer.prioritize(filtered_urls)
            
            # 5. Limit based on config
            final_urls = prioritized[:self.max_urls]
            
            # Ensure target is always included and at the top
            if self.target in final_urls:
                final_urls.remove(self.target)
            final_urls.insert(0, self.target)
            
            # 6. Save Artifact
            urls_path = self.report_dir / "urls.txt"
            with open(urls_path, "w") as f:
                f.write("\n".join(final_urls))
                
            dashboard.log(f"[{self.name}] Discovered {len(final_urls)} prioritized URLs (filtered from {len(gospider_urls)} raw).", "SUCCESS")
            
            return final_urls
            
        except Exception as e:
            logger.error(f"GoSpiderAgent failed: {e}")
            dashboard.log(f"[{self.name}] Error: {e}", "ERROR")
            return [self.target]

    async def _fallback_discovery(self) -> List[str]:
        """
        A simple BeautifulSoup discovery method if GoSpider fails.
        """
        import httpx
        from bs4 import BeautifulSoup
        from urllib.parse import urljoin
        
        discovered = set()
        discovered.add(self.target)
        
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=10.0, verify=False) as client:
                resp = await client.get(self.target)
                if resp.status_code == 200:
                    soup = BeautifulSoup(resp.text, 'html.parser')
                    for a in soup.find_all('a', href=True):
                        full_url = urljoin(self.target, a['href'])
                        # Basic scope check: only same origin or relative
                        if urlparse(full_url).netloc == urlparse(self.target).netloc:
                            discovered.add(full_url.split('#')[0]) # Remove fragments
                    
                    for form in soup.find_all('form', action=True):
                        full_url = urljoin(self.target, form['action'])
                        if urlparse(full_url).netloc == urlparse(self.target).netloc:
                            discovered.add(full_url.split('#')[0])

            # Try Playwright for JS-heavy sites
            js_urls = await self._crawl_with_playwright(self.target)
            for u in js_urls:
                discovered.add(u.split('#')[0])
                            
            logger.info(f"[{self.name}] Fallback crawler discovered {len(discovered)} URLs (including JS discovery)")
            return list(discovered)
        except Exception as e:
            logger.error(f"Fallback discovery failed: {e}")
            return [self.target]

    async def _crawl_with_playwright(self, base_url: str) -> List[str]:
        """Fallback para sitios JS-heavy que GoSpider no puede crawlear."""
        from bugtrace.tools.visual.browser import browser_manager
        from urllib.parse import urljoin

        urls = []
        try:
            async with browser_manager.get_page() as page:
                await page.goto(base_url, wait_until="networkidle", timeout=30000)

                # Extraer todos los hrefs
                links = await page.query_selector_all("a[href]")
                for link in links:
                    href = await link.get_attribute("href")
                    if href and not href.startswith("#"):
                        full_url = urljoin(base_url, href)
                        # Scope check
                        if urlparse(full_url).netloc == urlparse(base_url).netloc:
                            urls.append(full_url)

                # Extraer forms con action
                forms = await page.query_selector_all("form[action]")
                for form in forms:
                    action = await form.get_attribute("action")
                    if action:
                        full_url = urljoin(base_url, action)
                        # Scope check
                        if urlparse(full_url).netloc == urlparse(base_url).netloc:
                            urls.append(full_url)

        except Exception as e:
            logger.warning(f"Playwright crawl failed: {e}")

        return list(set(urls))

    async def run_loop(self):
        await self.run()
