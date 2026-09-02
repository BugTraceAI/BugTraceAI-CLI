"""ExternalTools mixin."""

from __future__ import annotations

import shutil
import asyncio
import json
import re
import os
from typing import List, Dict, Optional, Any, Tuple
from urllib.parse import urlparse, urljoin

from bugtrace.utils.logger import get_logger
from bugtrace.utils.parsers import extract_sqlmap_verdict
from bugtrace.core.config import settings
from bugtrace.core.ui import dashboard
from bugtrace.core.http_orchestrator import orchestrator, DestinationType
from bugtrace.core.exceptions import (
    ToolError, DockerError, DockerTimeoutError, DockerNotFoundError,
    SubprocessError, FuzzerError, FuzzerTimeoutError, NucleiError, JSONParseError,
)
import bugtrace.tools.external_util as _eu
from bugtrace.tools.external_util import *  # noqa: F401,F403

logger = get_logger("tools.external")


class ExternalGospiderMixin:
    """GoSpider crawl helpers."""

    def _parse_gospider_urls(self, output: str, target_domain: str) -> Tuple[List[str], List[str]]:
        """
        Parse URLs from GoSpider output, filtering to target domain.

        Returns:
            Tuple of (all_urls, form_urls) - form_urls need parameter extraction
        """
        urls = []
        form_urls = []

        for line in output.splitlines():
            line = line.strip()

            # Detect line type BEFORE stripping brackets
            is_form = line.startswith("[form]")

            # Extract URL from line
            parts = line.replace("[", "").replace("]", "").split(" - ")
            extracted = self._extract_urls_from_parts(parts, target_domain)

            urls.extend(extracted)

            # Track form URLs separately for parameter extraction
            if is_form:
                form_urls.extend(extracted)

        return list(set(urls)), list(set(form_urls))

    # Path segments that indicate a content-type or metadata, not a real endpoint
    _INVALID_PATH_SEGMENTS = frozenset({
        "application/json", "application/xml", "application/javascript",
        "text/html", "text/plain", "text/css", "text/javascript",
        "image/png", "image/jpeg", "image/gif", "image/svg+xml",
        "multipart/form-data", "application/x-www-form-urlencoded",
        "charset=utf-8", "charset=iso-8859-1",
    })

    def _extract_urls_from_parts(self, parts: list, target_domain: str) -> list:
        """Extract in-scope URLs from line parts."""
        urls = []
        for p in parts:
            p = p.strip()
            if not p.startswith("http"):
                continue

            url = self._parse_url_if_in_scope(p, target_domain)
            if url:
                # Reject URLs where path contains MIME types (e.g. /application/json)
                path = urlparse(url).path.lower()
                if any(seg in path for seg in self._INVALID_PATH_SEGMENTS):
                    continue
                urls.append(url)
        return urls

    def _parse_url_if_in_scope(self, url: str, target_domain: str) -> str:
        """Parse URL and return it if in scope, otherwise None."""
        try:
            parsed = urlparse(url)
            url_host = (parsed.hostname or "").lower()
            if url_host == target_domain or url_host.endswith("." + target_domain):
                return url
        except Exception as e:
            logger.debug(f"URL parsing error in GoSpider output: {e}")
        return None

    async def run_gospider(
        self,
        url: str,
        cookies: List[Dict] = None,
        headers: Dict[str, str] = None,
        depth: int = 3,
        max_urls: int = None,
    ) -> List[str]:
        """
        Runs GoSpider crawler (native preferred, Docker fallback).
        Respects max_urls by counting unique in-scope URLs in real-time.

        FIX 2026-03-02: Replaced line-based kill limit with URL-counted streaming.
        Previously, GoSpider was killed after N raw output lines, which produced
        wildly inconsistent URL counts (14, 20, 50 for the same site) because
        the raw line count includes duplicates, out-of-scope URLs, and status lines.
        Now we parse each line in real-time and kill only when we have enough
        unique in-scope URLs.

        Args:
            url: Target URL to crawl
            cookies: Optional session cookies
            headers: Optional authenticated request headers
            depth: Crawl depth
            max_urls: Stop after finding this many unique in-scope URLs
        """
        native = self._native_tools.get("gospider")
        if not native and not self.docker_cmd:
            return []

        self._record_tool_run("gospider")
        mode = "native" if native else "Docker"
        logger.info(f"Starting GoSpider ({mode}) on {url} (depth={depth}, limit={max_urls})...")
        dashboard.log(f"[External] Launching GoSpider ({mode}, depth={depth}) against {url}", "INFO")
        dashboard.update_task("gospider", name="GoSpider", status=f"Crawling: {url}")

        from bugtrace.core.config import settings
        concurrency = str(settings.GOSPIDER_CONCURRENCY)
        cmd = ["-s", url, "-d", str(depth), "-c", concurrency, "--sitemap"]

        # External archive queries (-a) are a major source of variability;
        # Wayback/CommonCrawl/VirusTotal return different results per run.
        if settings.GOSPIDER_USE_ARCHIVES:
            cmd.append("-a")

        if cookies:
            cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
            cmd.extend(["--cookie", cookie_str])

        for name, value in (headers or {}).items():
            if name.lower() != "cookie":
                cmd.extend(["-H", f"{name}: {value}"])

        if settings.GOSPIDER_NO_REDIRECT:
            cmd.append("--no-redirect")

        _hostname = urlparse(url).hostname
        if not _hostname:
            logger.warning(f"GoSpider: could not extract hostname from URL: {url}")
            return []
        target_domain = _hostname.lower()

        # Use URL-counted streaming when limit is set (consistent results)
        if max_urls and max_urls > 0:
            if native:
                output = await self._run_gospider_streaming(
                    [native] + cmd, target_domain, max_urls
                )
            else:
                full_cmd = self._build_docker_command(
                    "trickest/gospider", cmd, "512m", "1.0", "bridge"
                )
                output = await self._run_gospider_streaming(
                    full_cmd, target_domain, max_urls
                )
        else:
            if native:
                output = await self._run_native("gospider", [native] + cmd)
            else:
                output = await self._run_container("trickest/gospider", cmd)

        if output:
            lines = output.splitlines()
            logger.info(f"GoSpider raw output examples:\n{chr(10).join(lines[:5])}")

        unique_urls, form_urls = self._parse_gospider_urls(output, target_domain)
        logger.info(f"GoSpider found {len(unique_urls)} in-scope URLs, {len(form_urls)} forms.")

        # Extract parameters from forms - ALWAYS do this, params are critical for vuln discovery
        # FIX 2026-02-04: Previously skipped when max_urls reached, missing vulns like searchTerm XSS
        if form_urls:
            logger.info(f"[GoSpider] Extracting parameters from {len(form_urls)} forms...")
            param_urls = await self._extract_form_params(form_urls, cookies)
            if param_urls:
                # Add form param URLs with HIGH priority (insert at front)
                unique_urls = list(set(param_urls + unique_urls))

        dashboard.log(f"[External] GoSpider discovered {len(unique_urls)} endpoints.", "INFO")
        return unique_urls

    async def _run_gospider_streaming(
        self,
        full_cmd: List[str],
        target_domain: str,
        max_urls: int,
        timeout: int = 600,
    ) -> str:
        """
        Run GoSpider with URL-counted streaming: parse output in real-time,
        count unique in-scope URLs, and kill when we have enough.

        This replaces the old line-based kill limit which produced inconsistent
        results because raw line count != unique URL count.

        Args:
            full_cmd: Complete command to execute (native binary or docker)
            target_domain: Target domain for scope filtering
            max_urls: Kill process after finding this many unique in-scope URLs
            timeout: Maximum execution time in seconds

        Returns:
            Raw GoSpider output (all lines read before kill)
        """
        logger.debug(f"GoSpider URL-counted streaming: target={max_urls} unique URLs")

        process = await asyncio.create_subprocess_exec(
            *full_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        output_lines = []
        seen_urls: set = set()
        # Safety: absolute max lines to prevent infinite reads on pathological output
        absolute_line_cap = max(max_urls * 20, 2000)

        try:
            while len(output_lines) < absolute_line_cap:
                try:
                    line_bytes = await asyncio.wait_for(
                        process.stdout.readline(), timeout=30
                    )
                    if not line_bytes:
                        break  # EOF — GoSpider finished naturally
                    line = line_bytes.decode("utf-8", errors="replace")
                    output_lines.append(line)

                    # Parse this line for in-scope URLs (same logic as _parse_gospider_urls)
                    stripped = line.strip()
                    is_form = stripped.startswith("[form]")
                    parts = stripped.replace("[", "").replace("]", "").split(" - ")
                    for p in parts:
                        p = p.strip()
                        if not p.startswith("http"):
                            continue
                        parsed_url = self._parse_url_if_in_scope(p, target_domain)
                        if parsed_url:
                            # Reject MIME-type paths
                            path = urlparse(parsed_url).path.lower()
                            if any(seg in path for seg in self._INVALID_PATH_SEGMENTS):
                                continue
                            seen_urls.add(parsed_url)

                    # Check if we've found enough unique in-scope URLs
                    if len(seen_urls) >= max_urls:
                        logger.info(
                            f"GoSpider URL limit reached: {len(seen_urls)} unique "
                            f"in-scope URLs found (from {len(output_lines)} output lines). "
                            f"Terminating crawler."
                        )
                        break

                except asyncio.TimeoutError:
                    if output_lines:
                        logger.info(
                            f"GoSpider read timeout after 30s with {len(seen_urls)} "
                            f"unique URLs from {len(output_lines)} lines. Stopping."
                        )
                        break
                    raise  # Real timeout — no data at all

            if len(output_lines) >= absolute_line_cap:
                logger.warning(
                    f"GoSpider hit absolute line cap ({absolute_line_cap}) with "
                    f"{len(seen_urls)} unique URLs. Force stopping."
                )

        except Exception as e:
            logger.error(f"GoSpider streaming error: {e}")
        finally:
            # Kill the process if still running
            try:
                if process.returncode is None:
                    process.kill()
                    await process.wait()
            except (ProcessLookupError, OSError):
                pass

        logger.info(
            f"GoSpider streaming complete: {len(seen_urls)} unique in-scope URLs "
            f"from {len(output_lines)} raw output lines"
        )
        return "".join(output_lines)

    async def _extract_form_params(self, form_urls: List[str], cookies: List[Dict] = None) -> List[str]:
        """
        Fetch form URLs and extract input names to build parameterized URLs.

        This is CRITICAL for discovering vulnerabilities like:
        - /blog?search=X (CSTI)
        - /catalog?category=X (SQLi, CSTI)
        - /login?username=X (SQLi)

        Extracts from:
        1. HTML forms (<input name="...">)
        2. Inline JavaScript (URLs with query params in JS objects/strings)

        Args:
            form_urls: List of URLs where GoSpider detected forms
            cookies: Optional session cookies

        Returns:
            List of URLs with discovered parameters (e.g., /blog?search=FUZZ)
        """
        from bs4 import BeautifulSoup

        param_urls = []
        headers = {"User-Agent": settings.USER_AGENT}

        # Build cookie header if provided
        cookie_header = None
        if cookies:
            cookie_header = "; ".join([f"{c['name']}={c['value']}" for c in cookies])

        async with orchestrator.session(DestinationType.TARGET) as session:
            for form_url in form_urls:
                try:
                    req_headers = headers.copy()
                    if cookie_header:
                        req_headers["Cookie"] = cookie_header

                    async with session.get(form_url, headers=req_headers, ssl=False) as resp:
                        if resp.status != 200:
                            continue

                        html = await resp.text()
                        soup = BeautifulSoup(html, 'html.parser')
                        base_domain = urlparse(form_url).hostname

                        # 1. Extract from HTML forms
                        for form in soup.find_all('form'):
                            action = form.get('action', '')
                            method = form.get('method', 'GET').upper()

                            # Build form action URL
                            if action:
                                action_url = urljoin(form_url, action)
                            else:
                                action_url = form_url

                            # Ensure action URL is in scope
                            action_domain = urlparse(action_url).hostname
                            if action_domain and action_domain != base_domain:
                                continue

                            # Extract all input elements
                            inputs = form.find_all(['input', 'textarea', 'select'])
                            for inp in inputs:
                                name = inp.get('name')
                                inp_type = inp.get('type', 'text').lower()

                                # Skip hidden tokens, CSRF, submit buttons
                                if not name:
                                    continue
                                if inp_type in ('hidden', 'submit', 'button', 'image', 'reset'):
                                    continue
                                if name.lower() in ('csrf', 'token', '_token', 'csrfmiddlewaretoken'):
                                    continue

                                # Build URL with parameter
                                separator = "&" if "?" in action_url else "?"
                                param_url = f"{action_url}{separator}{name}=FUZZ"
                                param_urls.append(param_url)
                                logger.debug(f"[GoSpider] Found form param: {name} at {action_url}")

                        # 2. Extract URLs with params from inline JavaScript
                        # This catches dynamic navigation like: {"/catalog?category=Gin"}
                        js_param_urls = self._extract_js_urls(html, form_url, base_domain)
                        param_urls.extend(js_param_urls)

                except Exception as e:
                    logger.debug(f"[GoSpider] Failed to extract form params from {form_url}: {e}")

        return list(set(param_urls))

    def _extract_js_urls(self, html: str, base_url: str, base_domain: str) -> List[str]:
        """
        Extract URLs with query parameters from inline JavaScript.

        Catches patterns like:
        - "/catalog?category=Accessories"
        - '/blog?search=' + query
        - href="/page?param=value"

        Args:
            html: Page HTML content
            base_url: Base URL for resolving relative paths
            base_domain: Domain for scope checking

        Returns:
            List of discovered parameterized URLs
        """
        urls = []

        # Pattern to find URLs with query params in JS strings
        # Matches: "/path?param=value" or '/path?param=value'
        js_url_pattern = re.compile(r'["\'](/[^"\']*\?[^"\']+)["\']')

        for match in js_url_pattern.finditer(html):
            relative_url = match.group(1)
            try:
                full_url = urljoin(base_url, relative_url)
                url_domain = urlparse(full_url).hostname

                # Check scope
                if url_domain == base_domain:
                    urls.append(full_url)
                    logger.debug(f"[GoSpider] Found JS URL with params: {full_url}")
            except Exception:
                pass

        return urls
