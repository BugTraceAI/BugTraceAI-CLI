import asyncio
from typing import Dict, List, Optional
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import aiohttp
import re
from bs4 import BeautifulSoup
from bugtrace.agents.base import BaseAgent
from bugtrace.core.job_manager import JobStatus
from bugtrace.core.ui import dashboard
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

    def __init__(self, url: str, params: List[str] = None, report_dir: Path = None):
        super().__init__(
            name="OpenRedirectAgent",
            role="Open Redirect Specialist",
            agent_id="openredirect_specialist"
        )
        self.url = url
        self.params = params or []
        self.report_dir = report_dir or Path("./reports")
        self._tested_params = set()  # Deduplication

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
        Hunter Phase: Discover redirect vectors.

        Returns:
            List of potential redirect vectors with their parameters and contexts.
        """
        # TODO: Implement in subsequent plan
        # Will detect:
        # 1. URL parameters (url, redirect, next, return, etc.)
        # 2. Path-based redirects (/redirect/*, /goto/*)
        # 3. JavaScript redirect patterns (window.location, location.href)
        # 4. Meta refresh tags
        logger.info(f"[{self.name}] Hunter phase placeholder - to be implemented")
        return []

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
