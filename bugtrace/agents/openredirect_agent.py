import asyncio
from typing import Dict, List, Optional, Any
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import aiohttp
import re
from bs4 import BeautifulSoup
from bugtrace.agents.base import BaseAgent
from bugtrace.agents.worker_pool import WorkerPool, WorkerConfig
from bugtrace.core.job_manager import JobStatus
from bugtrace.core.ui import dashboard
from bugtrace.core.queue import queue_manager
from bugtrace.core.event_bus import EventType
from bugtrace.core.config import settings
from bugtrace.utils.logger import get_logger
from bugtrace.reporting.standards import (
    get_cwe_for_vuln,
    get_remediation_for_vuln,
    normalize_severity,
)
from bugtrace.agents.openredirect_payloads import (
    REDIRECT_PARAMS, PATH_PATTERNS, JS_REDIRECT_PATTERNS,
    META_REFRESH_PATTERN, REDIRECT_STATUS_CODES,
    RANKED_PAYLOADS, get_payloads_for_tier, DEFAULT_ATTACKER_DOMAIN
)

logger = get_logger("agents.openredirect")


class OpenRedirectAgent(BaseAgent):
    """
    Specialist Agent for Open Redirect vulnerabilities (CWE-601).
    Target: Parameters, paths, and JavaScript patterns that control redirects.

    Exploitation approach:
    - Hunter phase: Discover redirect vectors (query params, paths, JS patterns)
    - Auditor phase: Validate with ranked payloads (protocol-relative, encoding, whitelist bypasses)
    """

    def __init__(self, url: str = "", params: List[str] = None, report_dir: Path = None, event_bus=None):
        super().__init__(
            name="OpenRedirectAgent",
            role="Open Redirect Specialist",
            event_bus=event_bus,
            agent_id="openredirect_specialist"
        )
        self.url = url
        self.params = params or []
        self.report_dir = report_dir or Path("./reports")
        self._tested_params = set()  # Deduplication

        # Queue consumption mode (Phase 20)
        self._queue_mode = False
        self._worker_pool: Optional[WorkerPool] = None
        self._scan_context: str = ""

    async def run_loop(self) -> Dict:
        """Main execution loop for Open Redirect testing."""
        dashboard.current_agent = self.name
        dashboard.log(f"[{self.name}] Starting Open Redirect analysis on {self.url}", "INFO")

        # Phase 1: Hunter - Discover redirect vectors
        vectors = await self._hunter_phase()

        if not vectors:
            dashboard.log(f"[{self.name}] No redirect vectors found", "INFO")
            return {
                "status": JobStatus.COMPLETED,
                "vulnerable": False,
                "findings": [],
                "findings_count": 0
            }

        # Phase 2: Auditor - Validate with exploitation payloads
        findings = await self._auditor_phase(vectors)

        # Report findings
        for finding in findings:
            await self._create_finding(finding)

        return {
            "status": JobStatus.COMPLETED,
            "vulnerable": len(findings) > 0,
            "findings": findings,
            "findings_count": len(findings)
        }

    async def _hunter_phase(self) -> List[Dict]:
        """
        Hunter Phase: Discover all potential redirect vectors.

        Scans for:
        - Query parameters matching known redirect names
        - URL paths that suggest redirect functionality
        - JavaScript redirect patterns in response
        - Meta refresh tags
        - HTTP header-based redirects

        Returns:
            List of vectors with type, parameter/path, and source
        """
        dashboard.log(f"[{self.name}] Hunter: Scanning for redirect vectors", "INFO")
        vectors = []

        # 1. Check existing query parameters
        param_vectors = self._discover_param_vectors()
        vectors.extend(param_vectors)

        # 2. Check URL path patterns
        path_vectors = self._discover_path_vectors()
        vectors.extend(path_vectors)

        # 3. Fetch page and analyze content
        try:
            content_vectors = await self._discover_content_vectors()
            vectors.extend(content_vectors)
        except Exception as e:
            logger.warning(f"[{self.name}] Content analysis failed: {e}")

        dashboard.log(f"[{self.name}] Hunter found {len(vectors)} potential vectors", "INFO")
        return vectors

    def _discover_param_vectors(self) -> List[Dict]:
        """Discover redirect vectors in query parameters."""
        vectors = []
        parsed = urlparse(self.url)
        existing_params = parse_qs(parsed.query)

        # Check if any existing params match redirect parameter names
        for param in existing_params.keys():
            param_lower = param.lower()

            # Check against known redirect parameter list
            for redirect_param in REDIRECT_PARAMS:
                if param_lower == redirect_param.lower():
                    vectors.append({
                        "type": "QUERY_PARAM",
                        "param": param,
                        "value": existing_params[param][0] if existing_params[param] else "",
                        "source": "URL_EXISTING",
                        "confidence": "HIGH"
                    })
                    break

            # Heuristic: check if param name contains redirect-related keywords
            if not any(v["param"] == param for v in vectors):
                keywords = ["redirect", "url", "next", "return", "goto", "dest", "redir", "callback", "continue"]
                for keyword in keywords:
                    if keyword in param_lower:
                        vectors.append({
                            "type": "QUERY_PARAM",
                            "param": param,
                            "value": existing_params[param][0] if existing_params[param] else "",
                            "source": "URL_HEURISTIC",
                            "confidence": "MEDIUM"
                        })
                        break

        # Also check params provided to agent
        if self.params:
            for param in self.params:
                if not any(v["param"] == param for v in vectors):
                    vectors.append({
                        "type": "QUERY_PARAM",
                        "param": param,
                        "value": "",
                        "source": "AGENT_INPUT",
                        "confidence": "HIGH"
                    })

        return vectors

    def _discover_path_vectors(self) -> List[Dict]:
        """Discover redirect vectors in URL paths."""
        vectors = []
        parsed = urlparse(self.url)
        path = parsed.path.lower()

        for pattern in PATH_PATTERNS:
            if pattern.rstrip("?/") in path:
                vectors.append({
                    "type": "PATH",
                    "param": None,
                    "path": parsed.path,
                    "pattern_matched": pattern,
                    "source": "URL_PATH",
                    "confidence": "MEDIUM"
                })
                break  # One match is enough

        return vectors

    async def _discover_content_vectors(self) -> List[Dict]:
        """
        Discover redirect vectors in page content.

        Fetches the page and analyzes:
        - JavaScript redirect patterns (window.location, location.href, etc.)
        - Meta refresh tags
        - Server redirect response (Location header)
        """
        vectors = []

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.url,
                    allow_redirects=False,  # Don't follow - inspect redirect headers
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    # Check for HTTP redirect
                    if response.status in REDIRECT_STATUS_CODES:
                        location = response.headers.get('Location', '')
                        if location:
                            vectors.append({
                                "type": "HTTP_REDIRECT",
                                "param": None,
                                "location": location,
                                "status_code": response.status,
                                "source": "HTTP_RESPONSE",
                                "confidence": "HIGH"
                            })

                    # Read content for JS analysis
                    content = await response.text()

                    # Check JavaScript patterns
                    js_vectors = self._analyze_javascript_redirects(content)
                    vectors.extend(js_vectors)

                    # Check meta refresh
                    meta_vectors = self._analyze_meta_refresh(content)
                    vectors.extend(meta_vectors)

        except aiohttp.ClientError as e:
            logger.warning(f"[{self.name}] HTTP request failed: {e}")
        except asyncio.TimeoutError:
            logger.warning(f"[{self.name}] Request timeout for {self.url}")

        return vectors

    def _analyze_javascript_redirects(self, html_content: str) -> List[Dict]:
        """Analyze HTML for JavaScript-based redirect patterns."""
        vectors = []

        for pattern_info in JS_REDIRECT_PATTERNS:
            pattern = pattern_info["pattern"]
            name = pattern_info["name"]

            matches = re.findall(pattern, html_content, re.IGNORECASE)
            for match in matches:
                # match could be the captured group or full match
                redirect_url = match if isinstance(match, str) else match[0] if match else None

                if redirect_url:
                    vectors.append({
                        "type": "JAVASCRIPT",
                        "param": None,
                        "redirect_url": redirect_url,
                        "pattern_name": name,
                        "source": "JS_ANALYSIS",
                        "confidence": "MEDIUM"
                    })

        return vectors

    def _analyze_meta_refresh(self, html_content: str) -> List[Dict]:
        """Analyze HTML for meta refresh redirect tags."""
        vectors = []

        # Method 1: Regex for meta refresh
        matches = re.findall(META_REFRESH_PATTERN, html_content, re.IGNORECASE)
        for url in matches:
            vectors.append({
                "type": "META_REFRESH",
                "param": None,
                "redirect_url": url,
                "source": "META_TAG",
                "confidence": "HIGH"
            })

        # Method 2: BeautifulSoup for more robust parsing
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            meta_tags = soup.find_all('meta', attrs={'http-equiv': re.compile(r'refresh', re.I)})

            for meta in meta_tags:
                content = meta.get('content', '')
                # Parse content: "0;url=https://..." or "5; URL=https://..."
                url_match = re.search(r'url\s*=\s*([^\s"\']+)', content, re.IGNORECASE)
                if url_match and not any(v.get("redirect_url") == url_match.group(1) for v in vectors):
                    vectors.append({
                        "type": "META_REFRESH",
                        "param": None,
                        "redirect_url": url_match.group(1),
                        "source": "META_TAG_BS4",
                        "confidence": "HIGH"
                    })
        except Exception as e:
            logger.debug(f"BeautifulSoup meta parsing failed: {e}")

        return vectors

    async def _auditor_phase(self, vectors: List[Dict]) -> List[Dict]:
        """
        Auditor Phase: Validate redirect vectors with exploitation payloads.

        Tests each vector with ranked payloads (stop on first success):
        - Tier 1: Protocol-relative (//evil.com)
        - Tier 2: Encoding bypasses
        - Tier 3: Whitelist bypasses
        - Tier 4: Advanced techniques

        Returns:
            List of confirmed findings with exploitation details
        """
        dashboard.log(f"[{self.name}] Auditor: Validating {len(vectors)} vectors", "INFO")
        findings = []

        for vector in vectors:
            # Skip already tested params (deduplication)
            key = f"{self.url}#{vector.get('param', vector.get('path', 'content'))}"
            if key in self._tested_params:
                continue
            self._tested_params.add(key)

            # Test based on vector type
            if vector["type"] == "QUERY_PARAM":
                result = await self._test_param_vector(vector)
            elif vector["type"] == "PATH":
                result = await self._test_path_vector(vector)
            elif vector["type"] in ("JAVASCRIPT", "META_REFRESH"):
                result = await self._test_content_vector(vector)
            elif vector["type"] == "HTTP_REDIRECT":
                result = self._analyze_http_redirect(vector)
            else:
                continue

            if result and result.get("exploitable"):
                findings.append(result)
                dashboard.log(
                    f"[{self.name}] CONFIRMED: {vector['type']} redirect via {result.get('technique', 'unknown')}",
                    "CRITICAL"
                )

        return findings

    async def _test_param_vector(self, vector: Dict) -> Optional[Dict]:
        """Test a query parameter vector with ranked payloads."""
        param = vector["param"]
        parsed = urlparse(self.url)

        # Get trusted domain from original URL for whitelist bypasses
        trusted_domain = parsed.netloc

        # Test payloads in tier order (stop on first success)
        for tier in ["basic", "encoding", "whitelist", "advanced"]:
            payloads = get_payloads_for_tier(tier, DEFAULT_ATTACKER_DOMAIN, trusted_domain)

            for payload in payloads:
                result = await self._test_single_payload(param, payload, tier)
                if result and result.get("exploitable"):
                    return result

        return None

    async def _test_single_payload(self, param: str, payload: str, tier: str) -> Optional[Dict]:
        """
        Test a single payload against a parameter.

        CRITICAL: Uses allow_redirects=False to inspect the redirect response.
        """
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)
        params[param] = [payload]

        test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    test_url,
                    allow_redirects=False,  # CRITICAL: Don't follow - inspect redirect
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as response:
                    # Check for redirect status
                    if response.status not in REDIRECT_STATUS_CODES:
                        return None

                    location = response.headers.get('Location', '')
                    if not location:
                        return None

                    # Validate if redirect is to external domain
                    if self._is_external_redirect(location, payload):
                        return {
                            "exploitable": True,
                            "type": "OPEN_REDIRECT",
                            "param": param,
                            "payload": payload,
                            "tier": tier,
                            "technique": self._get_technique_name(payload),
                            "status_code": response.status,
                            "location": location,
                            "test_url": test_url,
                            "method": "HTTP_HEADER",
                            "severity": "MEDIUM",
                            "http_request": f"GET {test_url}",
                            "http_response": f"HTTP/{response.version.major}.{response.version.minor} {response.status}\nLocation: {location}",
                        }

        except aiohttp.ClientError as e:
            logger.debug(f"Request failed for {test_url}: {e}")
        except asyncio.TimeoutError:
            logger.debug(f"Timeout testing {test_url}")

        return None

    def _is_external_redirect(self, location: str, payload: str) -> bool:
        """
        Validate if a redirect location is to an external (attacker-controlled) domain.

        This distinguishes safe internal redirects from exploitable external redirects.
        """
        if not location:
            return False

        # Parse original URL to get trusted domain
        original_host = urlparse(self.url).netloc.lower()

        # Handle protocol-relative URLs
        if location.startswith('//'):
            location = 'https:' + location

        # Parse redirect location
        try:
            redirect_parsed = urlparse(location)
            redirect_host = redirect_parsed.netloc.lower()

            # No host = relative redirect (safe)
            if not redirect_host:
                return False

            # Same host = internal redirect (safe)
            if redirect_host == original_host:
                return False

            # Check if redirect contains attacker domain marker
            if DEFAULT_ATTACKER_DOMAIN in redirect_host:
                return True

            # Different external host = exploitable
            if redirect_host and redirect_host != original_host:
                # Additional check: is it truly external?
                # (not a subdomain of original)
                if not redirect_host.endswith('.' + original_host):
                    return True

        except Exception as e:
            logger.debug(f"URL parsing failed for {location}: {e}")

        return False

    def _get_technique_name(self, payload: str) -> str:
        """Get human-readable technique name for payload."""
        if payload.startswith('//'):
            return "protocol_relative"
        if '@' in payload:
            return "whitelist_bypass_userinfo"
        if '%' in payload:
            return "encoding_bypass"
        if 'javascript:' in payload.lower():
            return "javascript_protocol"
        if 'data:' in payload.lower():
            return "data_uri"
        return "direct_url"

    async def _test_path_vector(self, vector: Dict) -> Optional[Dict]:
        """
        Test a path-based redirect vector.

        Path redirects like /redirect/{url} need different handling:
        - Append payload to path
        - Or inject in path segment
        """
        parsed = urlparse(self.url)
        path = parsed.path

        # Try appending payload to path
        for tier in ["basic"]:  # Path redirects usually work with basic payloads
            payloads = get_payloads_for_tier(tier, DEFAULT_ATTACKER_DOMAIN)

            for payload in payloads:
                # Try payload as path segment
                test_paths = [
                    f"{path.rstrip('/')}/{payload}",
                    f"{path}?url={payload}",  # Some path handlers accept query
                ]

                for test_path in test_paths:
                    test_url = urlunparse(parsed._replace(path=test_path, query=''))

                    try:
                        async with aiohttp.ClientSession() as session:
                            async with session.get(
                                test_url,
                                allow_redirects=False,
                                timeout=aiohttp.ClientTimeout(total=5)
                            ) as response:
                                if response.status not in REDIRECT_STATUS_CODES:
                                    continue

                                location = response.headers.get('Location', '')
                                if self._is_external_redirect(location, payload):
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
                                        "http_response": f"HTTP/{response.version.major}.{response.version.minor} {response.status}\nLocation: {location}",
                                    }

                    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                        logger.debug(f"Path test failed for {test_url}: {e}")

        return None

    async def _test_content_vector(self, vector: Dict) -> Optional[Dict]:
        """
        Analyze JavaScript/meta refresh vectors for exploitability.

        These are more informational - we check if user input flows to redirect.
        """
        redirect_url = vector.get("redirect_url", "")

        # Check if the redirect URL appears to be user-controllable
        # (contains param markers or dynamic content)
        if not redirect_url:
            return None

        # If redirect URL is already external, it's a finding
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

        # Check if redirect URL contains variable markers (suggests user control)
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
                    "http_response": f"Dynamic JS redirect pattern detected",
                }

        return None

    def _analyze_http_redirect(self, vector: Dict) -> Optional[Dict]:
        """
        Analyze an existing HTTP redirect for exploitability.

        If the page already redirects externally, check if it's controllable.
        """
        location = vector.get("location", "")
        status_code = vector.get("status_code")

        # Check if redirect is to external domain
        original_host = urlparse(self.url).netloc.lower()
        redirect_parsed = urlparse(location)
        redirect_host = redirect_parsed.netloc.lower()

        if redirect_host and redirect_host != original_host:
            # Check if any query param value appears in the redirect
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query)

            for param, values in params.items():
                for value in values:
                    if value and value in location:
                        return {
                            "exploitable": True,
                            "type": "OPEN_REDIRECT",
                            "param": param,
                            "payload": value,
                            "tier": "existing",
                            "technique": "reflected_redirect",
                            "status_code": status_code,
                            "location": location,
                            "test_url": self.url,
                            "method": "HTTP_HEADER_REFLECTED",
                            "severity": "MEDIUM",
                            "http_request": f"GET {self.url}",
                            "http_response": f"HTTP/1.1 {status_code}\nLocation: {location}",
                        }

        return None

    async def _create_finding(self, result: Dict):
        """Reports a confirmed finding."""
        finding = {
            "type": "OPEN_REDIRECT",
            "severity": result.get("severity", "MEDIUM"),
            "url": self.url,
            "parameter": result.get("param"),
            "payload": result.get("payload"),
            "description": f"Open Redirect via {result.get('method', 'unknown')} in '{result.get('param')}'",
            "validated": True,
            "status": "VALIDATED_CONFIRMED",
            "reproduction": f"curl -I '{result.get('test_url')}'",
            "cwe_id": get_cwe_for_vuln("OPEN_REDIRECT"),
            "remediation": get_remediation_for_vuln("OPEN_REDIRECT"),
            "cve_id": "N/A",
            "http_request": result.get("http_request", f"GET {result.get('test_url')}"),
            "http_response": result.get("http_response", f"Location: {result.get('location')}"),
        }
        logger.info(f"[{self.name}] OPEN REDIRECT CONFIRMED: {result.get('payload')} on {result.get('param')}")

    # ========================================
    # Queue Consumer Mode (Phase 20)
    # ========================================

    async def start_queue_consumer(self, scan_context: str) -> None:
        """Start OpenRedirectAgent in queue consumer mode."""
        self._queue_mode = True
        self._scan_context = scan_context

        config = WorkerConfig(
            specialist="openredirect",
            pool_size=settings.WORKER_POOL_DEFAULT_SIZE,
            process_func=self._process_queue_item,
            on_result=self._handle_queue_result,
            shutdown_timeout=settings.WORKER_POOL_SHUTDOWN_TIMEOUT
        )

        self._worker_pool = WorkerPool(config)

        if self.event_bus:
            self.event_bus.subscribe(
                EventType.WORK_QUEUED_OPENREDIRECT.value,
                self._on_work_queued
            )

        logger.info(f"[{self.name}] Starting queue consumer with {config.pool_size} workers")
        await self._worker_pool.start()

    async def _process_queue_item(self, item: dict) -> Optional[Dict]:
        """Process a single item from the openredirect queue."""
        finding = item.get("finding", {})
        url = finding.get("url")
        param = finding.get("parameter")

        if not url:
            logger.warning(f"[{self.name}] Invalid queue item: missing url")
            return None

        self.url = url
        if param:
            self.params = [param]
        return await self._test_single_item_from_queue(url, param, finding)

    async def _test_single_item_from_queue(self, url: str, param: str, finding: dict) -> Optional[Dict]:
        """Test a single item from queue for Open Redirect."""
        try:
            # Run hunter phase to discover vectors
            vectors = await self._hunter_phase()

            if not vectors:
                return None

            # Run auditor phase to validate
            findings = await self._auditor_phase(vectors)

            if findings:
                return findings[0]

            return None
        except Exception as e:
            logger.error(f"[{self.name}] Queue item test failed: {e}")
            return None

    async def _handle_queue_result(self, item: dict, result: Optional[Dict]) -> None:
        """Handle completed queue item processing."""
        if result is None:
            return

        if self.event_bus and settings.WORKER_POOL_EMIT_EVENTS:
            await self.event_bus.emit(EventType.VULNERABILITY_DETECTED, {
                "specialist": "openredirect",
                "finding": {
                    "type": "Open Redirect",
                    "url": result.get("url", result.get("test_url")),
                    "parameter": result.get("param") or result.get("parameter"),
                    "payload": result.get("payload"),
                },
                "status": result.get("status", "VALIDATED_CONFIRMED"),
                "scan_context": self._scan_context,
            })

        logger.info(f"[{self.name}] Confirmed Open Redirect: {result.get('url', result.get('test_url'))}")

    async def _on_work_queued(self, data: dict) -> None:
        """Handle work_queued_openredirect notification (logging only)."""
        logger.debug(f"[{self.name}] Work queued: {data.get('finding', {}).get('url', 'unknown')}")

    async def stop_queue_consumer(self) -> None:
        """Stop queue consumer mode gracefully."""
        if self._worker_pool:
            await self._worker_pool.stop()
            self._worker_pool = None

        if self.event_bus:
            self.event_bus.unsubscribe(
                EventType.WORK_QUEUED_OPENREDIRECT.value,
                self._on_work_queued
            )

        self._queue_mode = False
        logger.info(f"[{self.name}] Queue consumer stopped")

    def get_queue_stats(self) -> dict:
        """Get queue consumer statistics."""
        if not self._worker_pool:
            return {"mode": "direct", "queue_mode": False}

        return {
            "mode": "queue",
            "queue_mode": True,
            "worker_stats": self._worker_pool.get_stats(),
        }
