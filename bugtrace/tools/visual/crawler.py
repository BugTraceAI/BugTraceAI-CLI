import asyncio
from typing import List, Dict, Any, Set
from urllib.parse import urlparse, urljoin, urlunparse
from bugtrace.utils.logger import get_logger
from bugtrace.tools.visual.browser import browser_manager
from bugtrace.core.ui import dashboard

logger = get_logger("tools.visual.crawler")

class VisualCrawler:
    """
    Advanced Visual Crawler.
    Uses Playwright to render pages (handling SPA/JS) and extracts attack surface.
    Implements robust URL normalization and scope enforcement.
    """
    def __init__(self):
        self.visited_urls: Set[str] = set()
        
    def _normalize_url(self, url: str) -> str:
        """
        Normalizes URL by removing fragments and query params for uniqueness check.
        Retains query params if they make the page distinct for attack surface? 
        For crawling, we usually want unique endpoints. Let's keep params but sort them?
        For simplicity: Protocol + Netloc + Path + Sorted Params.
        """
        try:
            parsed = urlparse(url)
            # Standardize scheme
            scheme = parsed.scheme.lower()
            if scheme not in ['http', 'https']:
                return ""
            
            # Standardize netloc (remove port if default)
            netloc = parsed.netloc.lower()
            if ":" in netloc:
                host, port = netloc.split(":")
                if (scheme == "http" and port == "80") or (scheme == "https" and port == "443"):
                    netloc = host
            
            # Remove fragment
            return urlunparse((scheme, netloc, parsed.path, parsed.params, parsed.query, ""))
        except Exception as e:
            logger.debug(f"URL normalization error: {e}")
            return ""

    def _is_in_scope(self, url: str, start_url: str) -> bool:
        """
        Checks if the URL is within the scope of the start URL.
        Relaxed check: Same Domain (ignoring subdomains? No, strict usually).
        """
        try:
            target = urlparse(url)
            start = urlparse(start_url)
            
            # Check domain match
            if target.netloc != start.netloc:
                return False
                
            # Check if path is under start path (optional, maybe too strict for typical crawling)
            # usually we just want same domain.
            return True
        except Exception as e:
            logger.debug(f"Scope check error: {e}")
            return False

    async def crawl(self, start_url: str, max_pages: int = 25, max_depth: int = 2) -> Dict[str, Any]:
        """
        Crawls the target visually, extracting links and identifying attack surface (inputs).
        """
        logger.info(f"Starting Visual Crawl on {start_url}...")
        
        results = {
            "urls": set(),
            "inputs": [],
            "forms": [],
            "tokens": []
        }
        
        # Initialize
        # Initialize queue locally inside context manager
        self.visited_urls.add(self._normalize_url(start_url))
        results["urls"].add(start_url)
        
        pages_crawled = 0
        
        # Use our managed page context
        async with browser_manager.get_page(use_auth=True) as page:
            # Queue stores (url, current_depth)
            queue = [(start_url, 0)]
            self.visited_urls.add(self._normalize_url(start_url))
            results["urls"].add(start_url)
            
            while queue and pages_crawled < max_pages:
                current_url, current_depth = queue.pop(0)
                
                if current_depth > max_depth:
                    continue

                dashboard.update_task("crawler", name="Visual Crawler", status=f"Scanning [D:{current_depth}]: {current_url}")
                logger.debug(f"Crawling {current_url} (Depth: {current_depth})...")
                
                from bugtrace.core.config import settings
                
                try:
                    # Navigate
                    await page.goto(current_url, timeout=settings.TIMEOUT_MS, wait_until="domcontentloaded")
                    # Wait a bit for SPA hydration
                    await page.wait_for_timeout(settings.SPA_WAIT_MS)
                    pages_crawled += 1
                    
                    # 1. Extract Links (Absolute)
                    hrefs = await page.evaluate("""() => {
                        return Array.from(document.querySelectorAll('a')).map(a => a.href)
                    }""")
                    
                    for href in hrefs:
                        # Normalize and Check Scope
                        normalized = self._normalize_url(href)
                        if not normalized: continue
                        
                        if self._is_in_scope(href, start_url) and normalized not in self.visited_urls:
                            self.visited_urls.add(normalized)
                            results["urls"].add(href) 
                            
                            if current_depth + 1 <= max_depth:
                                if len(queue) < settings.MAX_QUEUE_SIZE: # Prevent explosion
                                    queue.append((href, current_depth + 1))
                            
                    # 2. Extract Inputs (Attack Surface)
                    # We capture details + generic path to identify "Search Page" vs "Login Page"
                    inputs = await page.evaluate("""() => {
                        return Array.from(document.querySelectorAll('input, textarea, select')).map(el => ({
                            tag: el.tagName.toLowerCase(),
                            type: el.type,
                            name: el.name,
                            id: el.id,
                            placeholder: el.placeholder,
                            value: el.value 
                        }))
                    }""")
                    
                    if inputs:
                        logger.info(f"Found {len(inputs)} inputs on {current_url}")
                        # Store simple dict for MemoryManager ingestion
                        results["inputs"].extend([{"url": current_url, "details": i} for i in inputs])
                        
                    # 3. Extract JWT Tokens (Cookies & LocalStorage)
                    tokens = await page.evaluate("""() => {
                        const jwtRegex = /eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*/g;
                        let found = [];
                        
                        // Check Cookies
                        if (document.cookie) {
                            const cookies = document.cookie.split(';');
                            cookies.forEach(c => {
                                const match = c.match(jwtRegex);
                                if (match) {
                                    found.push({
                                        token: match[0],
                                        location: 'cookie',
                                        context: c.trim()
                                    });
                                }
                            });
                        }
                        
                        // Check LocalStorage
                        for (let i = 0; i < localStorage.length; i++) {
                            const key = localStorage.key(i);
                            const val = localStorage.getItem(key);
                            if (val && typeof val === 'string') {
                                const match = val.match(jwtRegex);
                                if (match) {
                                    found.push({
                                        token: match[0],
                                        location: 'local_storage',
                                        context: key
                                    });
                                }
                            }
                        }
                        
                        return found;
                    }""")
                    
                    if tokens:
                        for t in tokens:
                            t['url'] = current_url
                            results["tokens"].append(t)
                        logger.info(f"Found {len(tokens)} POTENTIAL TOKENS on {current_url}")

                        
                except Exception as e:
                    logger.warning(f"Failed to crawl {current_url}: {e}")
                    
        dashboard.log(f"Crawl finished. Visited {pages_crawled} pages.", "SUCCESS")
        return results

visual_crawler = VisualCrawler()
