"""GoSpiderAgent shell — package owner (dual collapse).

Historical path gospider_agent is a thin re-export.
"""

from typing import List, Dict, Any, Set
from loguru import logger
from bugtrace.tools.external import external_tools
from bugtrace.core.ui import dashboard
from urllib.parse import urlparse, urljoin, parse_qs
from bugtrace.utils.prioritizer import URLPrioritizer
from bugtrace.core.config import settings
from pathlib import Path
from bugtrace.agents.base import BaseAgent
import httpx
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

    def __init__(
        self,
        target: str,
        report_dir: Path,
        max_depth: int = 2,
        max_urls: int = 10,
        event_bus: Any = None,
        scope_path: str = None,
        cookies: List[Dict[str, Any]] = None,
        headers: Dict[str, str] = None,
    ):
        super().__init__("GoSpiderAgent", "URL Discovery", event_bus=event_bus, agent_id="gospider_agent")
        self.target = target
        self.report_dir = report_dir
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.target_domain = urlparse(target).hostname.lower() if urlparse(target).hostname else ""
        self.scope_path = scope_path  # Optional: restrict URLs to this path (e.g., "/WebPA/")
        self.cookies = list(cookies or [])
        self.headers = dict(headers or {})

        # Load extension filters from config
        self.exclude_extensions = [ext.strip().lower() for ext in settings.CRAWLER_EXCLUDE_EXTENSIONS.split(",") if ext.strip()]
        self.include_extensions = [ext.strip().lower() for ext in settings.CRAWLER_INCLUDE_EXTENSIONS.split(",") if ext.strip()]
        self.js_endpoint_mining = bool(settings.CRAWLER_JS_ENDPOINT_MINING)
        self.js_max_scripts = max(0, min(50, int(settings.CRAWLER_JS_MAX_SCRIPTS)))
        self.js_max_endpoints = max(1, min(500, int(settings.CRAWLER_JS_MAX_ENDPOINTS)))
        self.js_max_response_bytes = max(4096, min(5 * 1024 * 1024, int(settings.CRAWLER_JS_MAX_RESPONSE_BYTES)))
        self.js_fetch_timeout = max(1.0, min(30.0, float(settings.CRAWLER_JS_FETCH_TIMEOUT)))

        if scope_path:
            logger.info(f"[GoSpiderAgent] URL scope restricted to: {scope_path}")

    def _should_analyze_url(self, url: str) -> bool:
        """
        Determines if a URL should be analyzed based on extension filtering and scope_path.
        Excludes static files like .js, .css, .jpg, etc.
        """
        try:
            parsed = urlparse(url)
            path = parsed.path.lower()

            # Check scope_path restriction first
            if self.scope_path:
                normalized_scope = "/" + self.scope_path.strip("/").lower()
                url_path = (parsed.path or "/").lower()
                if not url_path.startswith(normalized_scope):
                    logger.debug(f"[GoSpiderAgent] URL excluded (out of scope): {url}")
                    return False

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
        # Static assets share GoSpider's raw stream, so allow a few extra raw
        # discoveries without expanding the final DAST budget.
        discovery_limit = self.max_urls + (self.js_max_scripts if self.js_endpoint_mining else 0)
        gospider_kwargs: Dict[str, Any] = {
            "depth": self.max_depth,
            "max_urls": discovery_limit,
        }
        if self.cookies:
            gospider_kwargs["cookies"] = self.cookies
        if self.headers:
            gospider_kwargs["headers"] = self.headers
        gospider_urls = await external_tools.run_gospider(
            self.target,
            **gospider_kwargs,
        )

        # OpenAPI is an authoritative, target-provided source of routes and
        # parameters. Merge it even when GoSpider succeeds; previously schema
        # discovery only ran in the fallback path, so healthy crawls missed
        # unlinked POST endpoints and templated API routes.
        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=15.0,
                verify=False,
                headers=self.headers or None,
            ) as client:
                api_urls = await self._discover_from_openapi(client)
            gospider_urls = list(set(gospider_urls) | api_urls)
        except Exception as e:
            logger.warning(f"[{self.name}] OpenAPI route merge skipped: {e}")

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
        _hostname = urlparse(self.target).hostname
        if not _hostname:
            return []
        target_domain = _hostname.lower()
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

    async def _apply_reachability_gate(self, urls: List[str], allow_empty: bool = False) -> List[str]:
        """Drop phantom endpoints mined out of JS bundles (react-dom/client, /M/d/yy,
        /MyComponent, react-devtools/...) that were never real routes, by probing HTTP
        status and removing ONLY definitively-not-found URLs (404/410).

        Recall-safe by design (see gospider.core.is_dead_endpoint): auth-gated (401/403),
        wrong-method (405), rate-limited (429), server-error (5xx) and unknown (timeout/
        connection error) URLs are all KEPT. Fail-safe: any error leaves the list untouched,
        and the target is never dropped. Structural + differential — no keyword list.
        """
        import asyncio
        if not urls or (len(urls) <= 1 and not allow_empty):
            return urls
        try:
            import httpx
            from bugtrace.agents.gospider.core import partition_by_reachability

            sem = asyncio.Semaphore(10)

            async def _status(client, u):
                async with sem:
                    try:
                        r = await client.get(u, timeout=8.0)
                        return (u, r.status_code)
                    except Exception:
                        return (u, None)  # unknown -> KEEP (recall-safe)

            async with httpx.AsyncClient(
                follow_redirects=False,
                verify=False,
                headers=self.headers or None,
            ) as client:
                pairs = await asyncio.gather(*[_status(client, u) for u in urls])

            kept, dropped = partition_by_reachability(pairs)

            # The target is never a phantom — always keep it.
            if self.target in urls and self.target not in kept:
                kept.insert(0, self.target)
                dropped = [u for u in dropped if u != self.target]

            if dropped:
                names = ", ".join((d.rstrip("/").split("/")[-1] or d) for d in dropped[:5])
                dashboard.log(
                    f"[{self.name}] Reachability gate: dropped {len(dropped)} phantom endpoint(s) "
                    f"(404/410): {names}{'...' if len(dropped) > 5 else ''}", "INFO")
                logger.info(f"[{self.name}] Reachability gate dropped (404/410): {dropped}")

            return kept if allow_empty else kept or urls
        except Exception as e:
            logger.warning(f"[{self.name}] Reachability gate skipped (keeping all URLs): {e}")
            return urls

    @staticmethod
    def _is_low_value_script(url: str) -> bool:
        path = urlparse(url).path.lower()
        name = path.rsplit("/", 1)[-1]
        return (
            name.endswith(".min.js")
            or any(marker in name for marker in ("vendor", "polyfill", "runtime", "webpack"))
            or "/node_modules/" in path
        )

    async def _fetch_bounded_text(self, session, url: str, expect_javascript: bool) -> str | None:
        """Fetch one same-origin text asset with strict redirect and byte limits."""
        from bugtrace.agents.gospider.core import is_same_origin

        current = url
        for redirect_count in range(2):
            try:
                async with session.get(
                    current,
                    allow_redirects=False,
                    timeout=self.js_fetch_timeout,
                    ssl=False,
                    headers=self.headers or None,
                ) as response:
                    if response.status in {301, 302, 303, 307, 308}:
                        location = response.headers.get("location")
                        redirected = urljoin(current, location) if location else ""
                        if redirect_count or not redirected or not is_same_origin(redirected, self.target):
                            return None
                        current = redirected
                        continue
                    if response.status != 200:
                        return None

                    declared_length = response.headers.get("content-length")
                    if declared_length:
                        try:
                            if int(declared_length) > self.js_max_response_bytes:
                                return None
                        except ValueError:
                            pass

                    content_type = response.headers.get("content-type", "").lower()
                    if expect_javascript:
                        allowed_types = ("javascript", "ecmascript", "text/plain", "application/octet-stream")
                        if content_type and not any(value in content_type for value in allowed_types):
                            return None

                    chunks = bytearray()
                    async for chunk in response.content.iter_chunked(65536):
                        chunks.extend(chunk)
                        if len(chunks) > self.js_max_response_bytes:
                            return None

                    prefix = bytes(chunks[:256]).lstrip().lower()
                    if expect_javascript and prefix.startswith((b"<!doctype html", b"<html")):
                        return None
                    encoding = response.charset or "utf-8"
                    try:
                        return bytes(chunks).decode(encoding, errors="ignore")
                    except LookupError:
                        return bytes(chunks).decode("utf-8", errors="ignore")
            except Exception as exc:
                logger.debug(f"[{self.name}] Skipped JS asset {current}: {exc}")
                return None
        return None

    async def _mine_javascript_endpoints(self, discovered_urls: List[str]) -> List[str]:
        """Mine endpoints from a bounded set of same-origin scripts, never returning the assets."""
        if not self.js_endpoint_mining or self.js_max_scripts == 0:
            return []

        import asyncio
        from bugtrace.agents.gospider.core import (
            extract_endpoint_urls_from_js,
            extract_script_src_urls,
            is_javascript_asset_url,
            is_same_origin,
        )
        from bugtrace.core.http_orchestrator import DestinationType, orchestrator

        raw_candidates = [
            url for url in discovered_urls
            if is_javascript_asset_url(url)
            and is_same_origin(url, self.target)
        ]

        try:
            async with orchestrator.session(DestinationType.TARGET) as session:
                candidates: Dict[str, bool] = {}
                html = await self._fetch_bounded_text(session, self.target, expect_javascript=False)
                if html:
                    for script_url in extract_script_src_urls(html, self.target, self.target):
                        candidates[script_url] = True
                for script_url in raw_candidates:
                    candidates.setdefault(script_url, False)

                scripts = sorted(
                    candidates,
                    key=lambda url: (self._is_low_value_script(url), len(url)),
                )[:self.js_max_scripts]
                if not scripts:
                    return []

                semaphore = asyncio.Semaphore(min(4, len(scripts)))

                async def mine(script_url: str) -> Set[str]:
                    async with semaphore:
                        source = await self._fetch_bounded_text(session, script_url, expect_javascript=True)
                    return extract_endpoint_urls_from_js(
                        source,
                        self.target,
                        self.js_max_endpoints,
                        allow_relative=candidates[script_url],
                    ) if source else set()

                mined_sets = await asyncio.gather(*(mine(script) for script in scripts))
        except Exception as exc:
            logger.warning(f"[{self.name}] JavaScript endpoint mining skipped: {exc}")
            return []

        endpoints = URLPrioritizer.prioritize(list(set().union(*mined_sets)))[:self.js_max_endpoints] if mined_sets else []
        if endpoints:
            dashboard.log(
                f"[{self.name}] JavaScript mining: {len(endpoints)} endpoint candidate(s) from {len(scripts)} bounded script(s)",
                "INFO",
            )
        return endpoints

    async def run(self) -> List[str]:
        """Runs GoSpider and returns a prioritized, filtered list of URLs."""
        dashboard.current_agent = self.name
        dashboard.log(f"[{self.name}] Starting URL discovery (max_depth={self.max_depth}, max_urls={self.max_urls})...", "INFO")

        try:
            # Discover URLs
            gospider_urls = await self._discover_urls()
            mined_urls = await self._mine_javascript_endpoints(gospider_urls)
            reachable_mined: Set[str] = set()
            if mined_urls:
                reachable_mined = set(await self._apply_reachability_gate(mined_urls, allow_empty=True))
                gospider_urls = list(dict.fromkeys([*gospider_urls, *reachable_mined]))
            if not gospider_urls:
                dashboard.log(f"[{self.name}] No URLs discovered. Using target URL.", "WARN")
                return [self.target]

            # Filter, prioritize and limit
            final_urls = self._filter_and_prioritize_urls(gospider_urls)

            # Reachability gate: drop JS-mined phantom endpoints (404/410), recall-safe
            unchecked_urls = [url for url in final_urls if url not in reachable_mined]
            checked_urls = set(await self._apply_reachability_gate(unchecked_urls, allow_empty=True))
            final_urls = [url for url in final_urls if url in reachable_mined or url in checked_urls]

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
        Extracts URLs AND parameters from forms, JavaScript, and API specs.
        """
        import httpx

        discovered: Set[str] = set()
        discovered.add(self.target)

        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=15.0,
                verify=False,
                headers=self.headers or None,
            ) as client:
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

    async def _discover_from_openapi(self, client) -> Set[str]:
        """
        Probe well-known OpenAPI/Swagger endpoints and extract API URLs.
        Works generically for any REST API with standard documentation.
        """
        import json

        discovered: Set[str] = set()
        parsed_target = urlparse(self.target)
        base = f"{parsed_target.scheme}://{parsed_target.netloc}"

        # Well-known OpenAPI/Swagger spec paths
        spec_paths = [
            "/openapi.json", "/swagger.json", "/api-docs",
            "/v1/openapi.json", "/v2/openapi.json", "/v3/openapi.json",
            "/api/openapi.json", "/api/swagger.json",
            "/swagger/v1/swagger.json", "/docs/openapi.json",
        ]

        spec_data = None
        for path in spec_paths:
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

        if not spec_data or "paths" not in spec_data:
            return discovered

        # Extract URLs from OpenAPI paths
        for path_template, methods in spec_data["paths"].items():
            if not isinstance(methods, dict):
                continue

            # Build concrete URL from path template
            # Replace {param} with sample values for testing
            concrete_path = self._resolve_openapi_path(path_template, methods)
            url = f"{base}{concrete_path}"

            if not self._is_in_scope(url):
                continue

            discovered.add(url)

            # Extract query parameters defined in the spec
            for method, details in methods.items():
                if not isinstance(details, dict):
                    continue
                params = details.get("parameters", [])
                for param in params:
                    if not isinstance(param, dict):
                        continue
                    if param.get("in") == "query" and param.get("name"):
                        separator = "&" if "?" in url else "?"
                        param_url = f"{url}{separator}{param['name']}=test"
                        discovered.add(param_url)

        logger.info(f"[{self.name}] OpenAPI discovery: {len(discovered)} endpoints found")
        dashboard.log(f"[{self.name}] OpenAPI: {len(discovered)} API endpoints discovered", "INFO")
        return discovered

    def _resolve_openapi_path(self, path_template: str, methods: dict) -> str:
        """Replace OpenAPI path template variables with sample values."""
        import re as _re

        resolved = path_template
        # Find all {param_name} in path
        template_vars = _re.findall(r'\{(\w+)\}', path_template)

        for var in template_vars:
            # Try to find example/default values in spec parameters
            sample = "1"  # Default: numeric ID
            for method_details in methods.values():
                if not isinstance(method_details, dict):
                    continue
                for param in method_details.get("parameters", []):
                    if isinstance(param, dict) and param.get("name") == var and param.get("in") == "path":
                        example = param.get("example") or param.get("default")
                        if example:
                            sample = str(example)
                        elif param.get("schema", {}).get("type") == "string":
                            sample = "test"
                        break

            resolved = resolved.replace(f"{{{var}}}", sample)

        return resolved

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
