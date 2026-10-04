"""OpenRedirect agent mixin."""

from __future__ import annotations

import asyncio
import re
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import aiohttp
from bs4 import BeautifulSoup

from bugtrace.core.job_manager import JobStatus
from bugtrace.core.ui import dashboard
from bugtrace.core.queue import queue_manager
from bugtrace.core.event_bus import EventType
from bugtrace.core.config import settings
from bugtrace.core.validation_status import ValidationStatus
from bugtrace.utils.logger import get_logger
from bugtrace.core.http_orchestrator import orchestrator, DestinationType
from bugtrace.core.verbose_events import create_emitter
from bugtrace.reporting.standards import (
    get_cwe_for_vuln,
    get_remediation_for_vuln,
    normalize_severity,
)
from bugtrace.agents.openredirect_payloads import (
    REDIRECT_PARAMS, PATH_PATTERNS, JS_REDIRECT_PATTERNS,
    META_REFRESH_PATTERN, REDIRECT_STATUS_CODES,
    RANKED_PAYLOADS, get_payloads_for_tier, DEFAULT_ATTACKER_DOMAIN,
)
from bugtrace.agents.openredirect.detection import (
    discover_param_vectors,
    discover_path_vectors,
    analyze_javascript_redirects,
    analyze_meta_refresh,
    is_external_redirect,
    get_technique_name,
    analyze_http_redirect,
    generate_openredirect_fingerprint,
    fallback_fingerprint_dedup,
    get_validation_status,
    validate_before_emit,
)
from bugtrace.agents.worker_pool import WorkerPool, WorkerConfig

logger = get_logger("agents.openredirect")


class OpenRedirectTestingMixin:
    """Payload / vector testing I/O for OpenRedirectAgent."""

    async def _test_param_vector(self, vector: Dict) -> Optional[Dict]:
        """Test a query parameter vector with ranked payloads."""  # I/O
        param = vector["param"]
        parsed = urlparse(self.url)
        trusted_domain = parsed.netloc

        for tier in ["basic", "encoding", "whitelist", "advanced"]:
            payloads = get_payloads_for_tier(tier, DEFAULT_ATTACKER_DOMAIN, trusted_domain)
            for payload in payloads:
                result = await self._test_single_payload(param, payload, tier)
                if result and result.get("exploitable"):
                    return result
        return None

    async def _test_single_payload(
        self, param: str, payload: str, tier: str,
    ) -> Optional[Dict]:
        """Test a single payload against a parameter."""  # I/O
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

        try:
            async with orchestrator.session(DestinationType.TARGET) as session:
                async with session.get(
                    test_url, allow_redirects=False,
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as response:
                    if response.status not in REDIRECT_STATUS_CODES:
                        return None
                    location = response.headers.get("Location", "")
                    if not location:
                        return None
                    if is_external_redirect(location, payload, self.url):
                        return {
                            "exploitable": True,
                            "type": "OPEN_REDIRECT",
                            "param": param,
                            "payload": payload,
                            "tier": tier,
                            "technique": get_technique_name(payload),
                            "status_code": response.status,
                            "location": location,
                            "test_url": test_url,
                            "method": "HTTP_HEADER",
                            "severity": "MEDIUM",
                            "http_request": f"GET {test_url}",
                            "http_response": (
                                f"HTTP/{response.version.major}.{response.version.minor} "
                                f"{response.status}\nLocation: {location}"
                            ),
                        }
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.debug(f"Request failed for {test_url}: {e}")
        return None

    async def _test_path_vector(self, vector: Dict) -> Optional[Dict]:
        """Test a path-based redirect vector."""  # I/O
        parsed = urlparse(self.url)
        path = parsed.path

        for tier in ["basic"]:
            payloads = get_payloads_for_tier(tier, DEFAULT_ATTACKER_DOMAIN)
            for payload in payloads:
                test_paths = [
                    f"{path.rstrip('/')}/{payload}",
                    f"{path}?url={payload}",
                ]
                for test_path in test_paths:
                    test_url = urlunparse(parsed._replace(path=test_path, query=""))
                    try:
                        async with orchestrator.session(DestinationType.TARGET) as session:
                            async with session.get(
                                test_url, allow_redirects=False,
                                timeout=aiohttp.ClientTimeout(total=5),
                            ) as response:
                                if response.status not in REDIRECT_STATUS_CODES:
                                    continue
                                location = response.headers.get("Location", "")
                                if is_external_redirect(location, payload, self.url):
                                    return {
                                        "exploitable": True,
                                        "type": "OPEN_REDIRECT",
                                        "param": None,
                                        "path": test_path,
                                        "payload": payload,
                                        "tier": tier,
                                        "technique": "path_based",
                                        "status_code": response.status,
                                        "location": location,
                                        "test_url": test_url,
                                        "method": "PATH_REDIRECT",
                                        "severity": "MEDIUM",
                                        "http_request": f"GET {test_url}",
                                        "http_response": (
                                            f"HTTP/{response.version.major}.{response.version.minor} "
                                            f"{response.status}\nLocation: {location}"
                                        ),
                                    }
                    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                        logger.debug(f"Path test failed for {test_url}: {e}")
        return None

    async def _test_content_vector(self, vector: Dict) -> Optional[Dict]:
        """Analyse JS/meta refresh vectors for exploitability."""  # I/O
        redirect_url = vector.get("redirect_url", "")
        if not redirect_url:
            return None

        parsed = urlparse(redirect_url)
        original_host = urlparse(self.url).netloc.lower()
        redirect_host = parsed.netloc.lower()

        if redirect_host and redirect_host != original_host:
            return {
                "exploitable": True,
                "type": "OPEN_REDIRECT",
                "param": None,
                "payload": redirect_url,
                "tier": "content",
                "technique": vector.get("pattern_name", "javascript_redirect"),
                "status_code": None,
                "location": redirect_url,
                "test_url": self.url,
                "method": vector["type"],
                "severity": "MEDIUM",
                "http_request": f"GET {self.url}",
                "http_response": f"JavaScript/Meta redirect to: {redirect_url}",
            }

        dynamic_markers = ["getParam", "URLSearchParams", "location.search", "document.URL"]
        for marker in dynamic_markers:
            if marker in str(vector.get("source", "")):
                return {
                    "exploitable": True,
                    "type": "OPEN_REDIRECT",
                    "param": None,
                    "payload": "User-controlled JavaScript redirect",
                    "tier": "content",
                    "technique": "dynamic_javascript",
                    "status_code": None,
                    "location": redirect_url,
                    "test_url": self.url,
                    "method": "JAVASCRIPT_DYNAMIC",
                    "severity": "MEDIUM",
                    "http_request": f"GET {self.url}",
                    "http_response": "Dynamic JS redirect pattern detected",
                }
        return None

    async def _test_dom_redirects(self) -> List[Dict]:
        """Test for DOM-based open redirects using Playwright."""  # I/O
        from bugtrace.tools.visual.browser import browser_manager

        findings: List[Dict] = []
        evil_domain = "evil.bugtraceai.test"
        evil_url = f"https://{evil_domain}/redirect-probe"

        urls_to_test = [self.url]
        if hasattr(self, "_discovered_internal_urls") and self._discovered_internal_urls:
            urls_to_test.extend(self._discovered_internal_urls)

        logger.info(f"[{self.name}] DOM redirect testing on {len(urls_to_test)} URLs")

        for test_url in urls_to_test:
            parsed = urlparse(test_url)
            url_params = list(parse_qs(parsed.query).keys())
            redirect_keywords = [
                "redirect", "next", "return", "returnUrl", "goto", "dest",
                "continue", "callback", "url", "redir", "returnTo", "forward",
                "back", "backUrl", "ref", "target", "to", "out",
            ]
            params_to_test = list(set(url_params + redirect_keywords))

            for param in params_to_test:
                try:
                    if "?" in test_url:
                        injected_url = f"{test_url}&{param}={evil_url}"
                    else:
                        injected_url = f"{test_url}?{param}={evil_url}"

                    redirected_to = None

                    async with browser_manager.get_page() as page:
                        async def handle_request(route):
                            nonlocal redirected_to
                            try:
                                req_host = urlparse(route.request.url).netloc
                            except Exception:
                                req_host = ""
                            if req_host == evil_domain:
                                redirected_to = route.request.url
                                await route.abort()
                            else:
                                await route.continue_()

                        await page.route("**/*", handle_request)

                        try:
                            await page.goto(
                                injected_url,
                                wait_until="networkidle",
                                timeout=settings.TIMEOUT_MS,
                            )
                            await asyncio.sleep(settings.DOM_CLICK_INITIAL_WAIT_SEC)
                        except Exception:
                            pass

                        max_links = settings.DOM_CLICK_MAX_LINKS
                        max_text_links = settings.DOM_CLICK_MAX_TEXT_LINKS
                        click_wait = settings.DOM_CLICK_WAIT_SEC
                        try:
                            onclick_links = await page.query_selector_all("a[onclick]")
                            for link in onclick_links[:max_links]:
                                try:
                                    await link.click()
                                    await asyncio.sleep(click_wait)
                                    if redirected_to:
                                        break
                                except Exception:
                                    pass

                            if not redirected_to:
                                hash_links = await page.query_selector_all('a[href="#"]')
                                for link in hash_links[:max_links]:
                                    try:
                                        await link.click()
                                        await asyncio.sleep(click_wait)
                                        if redirected_to:
                                            break
                                    except Exception:
                                        pass

                            if not redirected_to:
                                all_links = await page.query_selector_all("a")
                                for link in all_links[:max_text_links]:
                                    try:
                                        text = await link.text_content()
                                        if text and any(
                                            kw in text.lower()
                                            for kw in ["back", "return", "go back", "redirect", "continue"]
                                        ):
                                            await link.click()
                                            await asyncio.sleep(click_wait)
                                            if redirected_to:
                                                break
                                    except Exception:
                                        pass
                        except Exception as click_err:
                            logger.debug(f"[{self.name}] Click trigger error: {click_err}")

                    if redirected_to:
                        logger.info(f"[{self.name}] DOM Open Redirect: {param} on {test_url} -> {redirected_to}")
                        findings.append({
                            "exploitable": True,
                            "validated": True,
                            "type": "OPEN_REDIRECT",
                            "param": param,
                            "payload": evil_url,
                            "url": test_url,
                            "tier": "dom",
                            "technique": "dom_redirect",
                            "status_code": None,
                            "location": redirected_to,
                            "test_url": injected_url,
                            "method": "DOM_REDIRECT",
                            "severity": "LOW",
                            "evidence": {
                                "dom_redirect": True,
                                "redirected_to": redirected_to,
                                "injected_param": param,
                            },
                            "status": ValidationStatus.VALIDATED_CONFIRMED.value,
                            "http_request": f"GET {injected_url}",
                            "http_response": f"DOM redirect to: {redirected_to}",
                        })
                        break

                except Exception as e:
                    logger.debug(f"[{self.name}] DOM redirect test failed for {param} on {test_url}: {e}")

        if findings:
            dashboard.log(
                f"[{self.name}] Found {len(findings)} DOM-based open redirects!", "SUCCESS",
            )
        return findings

    # ------------------------------------------------------------------
    # Autonomous parameter discovery
    # ------------------------------------------------------------------

    async def _discover_openredirect_params(self, url: str) -> Dict[str, str]:
        """Open Redirect-focused parameter discovery."""  # I/O
        from bugtrace.tools.visual.browser import browser_manager
        from urllib.parse import urljoin

        all_params: Dict[str, str] = {}

        try:
            parsed = urlparse(url)
            url_params = parse_qs(parsed.query)
            for param_name, values in url_params.items():
                all_params[param_name] = values[0] if values else ""
        except Exception as e:
            logger.warning(f"[{self.name}] Failed to parse URL params: {e}")

        try:
            state = await browser_manager.capture_state(url)
            html = state.get("html", "")
            if html:
                self._last_discovery_html = html
                soup = BeautifulSoup(html, "html.parser")

                for tag in soup.find_all(["input", "textarea", "select"]):
                    param_name = tag.get("name")
                    if param_name and param_name not in all_params:
                        input_type = tag.get("type", "text").lower()
                        if input_type not in ["submit", "button", "reset"]:
                            if "token" not in param_name.lower() or "redirect" in param_name.lower():
                                all_params[param_name] = tag.get("value", "")

                base_domain = urlparse(url).netloc
                internal_urls: set = set()
                for a_tag in soup.find_all("a", href=True):
                    link = urljoin(url, a_tag["href"])
                    parsed_link = urlparse(link)
                    if parsed_link.netloc == base_domain and parsed_link.scheme in ("http", "https"):
                        clean_link = f"{parsed_link.scheme}://{parsed_link.netloc}{parsed_link.path}"
                        if clean_link != url.split("?")[0]:
                            internal_urls.add(clean_link)
                self._discovered_internal_urls = list(internal_urls)[:15]
                if self._discovered_internal_urls:
                    logger.info(
                        f"[{self.name}] Discovered {len(self._discovered_internal_urls)} "
                        f"internal URLs for DOM redirect testing"
                    )
        except Exception as e:
            logger.error(f"[{self.name}] HTML parsing failed for {url}: {e}")

        redirect_keywords = [
            "redirect", "next", "return", "goto", "dest",
            "continue", "callback", "url", "redir",
        ]
        priority_params = {
            k: v for k, v in all_params.items()
            if any(kw in k.lower() for kw in redirect_keywords)
        }
        other_params = {k: v for k, v in all_params.items() if k not in priority_params}
        sorted_params = {**priority_params, **other_params}

        logger.info(
            f"[{self.name}] Discovered {len(sorted_params)} params on {url}: "
            f"{list(sorted_params.keys())[:10]}"
            f"{' (+ more)' if len(sorted_params) > 10 else ''}"
        )
        return sorted_params

    # ------------------------------------------------------------------
    # Smart probe
    # ------------------------------------------------------------------

    async def _smart_probe_redirect(self, url: str, param: str) -> bool:
        """Smart probe: 1 request to check if param influences redirects."""  # I/O
        evil_url = "https://btprobe.example.com"
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [evil_url]
        test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

        try:
            async with orchestrator.session(DestinationType.TARGET) as session:
                async with session.get(
                    test_url, allow_redirects=False,
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as response:
                    if response.status in REDIRECT_STATUS_CODES:
                        location = response.headers.get("Location", "")
                        if "btprobe.example.com" in location:
                            dashboard.log(
                                f"[{self.name}] Smart probe: {param} redirects to external URL",
                                "INFO",
                            )
                            return True

                    body = await response.text()
                    if "btprobe.example.com" in body:
                        dashboard.log(
                            f"[{self.name}] Smart probe: {param} reflects URL in body",
                            "INFO",
                        )
                        return True

                    dashboard.log(
                        f"[{self.name}] Smart probe: {param} doesn't influence redirects, skipping",
                        "INFO",
                    )
                    return False
        except Exception as e:
            logger.debug(f"[{self.name}] Smart probe error for {param}: {e}")
            return True

    # ------------------------------------------------------------------
    # Queue consumer mode (WET -> DRY)
    # ------------------------------------------------------------------

