"""
WAF Fingerprinter - Identifies specific WAF products.

Techniques:
1. Response header analysis
2. Error page signatures
3. Cookie patterns
4. Behavioral analysis (timing, response codes)
"""

import httpx
import ssl
import asyncio
import hashlib
import time
from typing import Dict, Optional, List, Tuple
from dataclasses import dataclass
from bugtrace.utils.logger import get_logger
from bugtrace.core.config import settings

logger = get_logger("waf.fingerprinter")

# Cache TTL in seconds (15 minutes)
CACHE_TTL_SECONDS = 900


def get_ssl_context():
    """
    Get SSL context based on configuration settings.
    Returns True for default verification, or custom context for self-signed certs.
    """
    if settings.VERIFY_SSL_CERTIFICATES:
        if settings.ALLOW_SELF_SIGNED_CERTS:
            # Allow self-signed but still use SSL
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            logger.warning("SSL verification disabled - self-signed certs allowed (testing mode)")
            return ssl_context
        return True  # Default verification
    else:
        logger.warning("SSL verification disabled by configuration - NOT RECOMMENDED for production")
        return False


@dataclass
class WAFSignature:
    """Signature for identifying a specific WAF."""
    name: str
    headers: Dict[str, str]           # Header patterns to match
    cookies: List[str]                 # Cookie names to look for
    body_patterns: List[str]           # Patterns in error responses
    status_codes: List[int]            # Typical block status codes


# =============================================================================
# WAF SIGNATURE DATABASE
# =============================================================================
WAF_SIGNATURES: List[WAFSignature] = [
    WAFSignature(
        name="cloudflare",
        headers={
            "cf-ray": "",                    # Any value
            "cf-cache-status": "",
            "server": "cloudflare"
        },
        cookies=["__cfduid", "__cf_bm", "cf_clearance"],
        body_patterns=[
            "cloudflare",
            "ray id:",
            "please enable cookies",
            "checking your browser",
            "ddos protection by cloudflare"
        ],
        status_codes=[403, 503, 429]
    ),
    WAFSignature(
        name="modsecurity",
        headers={
            "server": "mod_security",
            "x-mod-security": ""
        },
        cookies=[],
        body_patterns=[
            "mod_security",
            "modsecurity",
            "not acceptable",
            "rule id:",
            "access denied"
        ],
        status_codes=[403, 406]
    ),
    WAFSignature(
        name="aws_waf",
        headers={
            "x-amzn-requestid": "",
            "x-amz-cf-id": "",
            "x-amz-apigw-id": ""
        },
        cookies=["awsalb", "awsalbcors"],
        body_patterns=[
            "request blocked",
            "aws waf",
            "forbidden",
            "waf rule"
        ],
        status_codes=[403]
    ),
    WAFSignature(
        name="akamai",
        headers={
            "x-akamai-transformed": "",
            "akamai-grn": "",
            "x-akamai-session-info": ""
        },
        cookies=["ak_bmsc", "bm_sv", "bm_sz"],
        body_patterns=[
            "access denied",
            "akamai",
            "reference#"
        ],
        status_codes=[403]
    ),
    WAFSignature(
        name="imperva",
        headers={
            "x-iinfo": "",
            "x-cdn": "imperva"
        },
        cookies=["incap_ses_", "visid_incap_", "nlbi_"],
        body_patterns=[
            "incapsula",
            "imperva",
            "request unsuccessful",
            "incident id"
        ],
        status_codes=[403]
    ),
    WAFSignature(
        name="f5_bigip",
        headers={
            "x-wa-info": "",
            "server": "bigip"
        },
        cookies=["ts", "bigipserver", "f5_cspm"],
        body_patterns=[
            "request rejected",
            "the requested url was rejected"
        ],
        status_codes=[403]
    ),
    WAFSignature(
        name="sucuri",
        headers={
            "x-sucuri-id": "",
            "x-sucuri-cache": "",
            "server": "sucuri"
        },
        cookies=["sucuri_cloudproxy_uuid"],
        body_patterns=[
            "sucuri website firewall",
            "access denied - sucuri",
            "blocked by sucuri"
        ],
        status_codes=[403]
    ),
    WAFSignature(
        name="fortiweb",
        headers={
            "server": "fortiweb"
        },
        cookies=["fwaas", "fortiweb"],
        body_patterns=[
            "fortiweb",
            "fortigate",
            "attack detected"
        ],
        status_codes=[403]
    ),
    WAFSignature(
        name="nginx_naxsi",
        headers={
            "server": "nginx"
        },
        cookies=[],
        body_patterns=[
            "naxsi",
            "request denied"
        ],
        status_codes=[403]
    ),
    WAFSignature(
        name="barracuda",
        headers={
            "server": "barracuda"
        },
        cookies=["barra_counter_session"],
        body_patterns=[
            "barracuda",
            "barra_counter"
        ],
        status_codes=[403]
    ),
]


@dataclass
class CacheEntry:
    """Cache entry with TTL support (TASK-69)."""
    waf_name: str
    confidence: float
    indicators: List[str]
    timestamp: float

    def is_expired(self) -> bool:
        return time.time() - self.timestamp > CACHE_TTL_SECONDS


class WAFFingerprinter:
    """
    Identifies WAF products through multiple detection techniques.

    Usage:
        fingerprinter = WAFFingerprinter()
        waf_name, confidence = await fingerprinter.detect("https://example.com")
    """

    def __init__(self):
        self.signatures = WAF_SIGNATURES
        self.cache: Dict[str, CacheEntry] = {}  # domain_hash -> CacheEntry

    async def detect(self, url: str, timeout: float = 10.0) -> Tuple[str, float]:
        """
        Detect WAF protecting the target URL.

        Args:
            url: Target URL to probe
            timeout: Request timeout in seconds

        Returns:
            Tuple of (waf_name, confidence) where confidence is 0.0-1.0
            Returns ("unknown", 0.0) if no WAF detected
        """
        # TASK-69: Check cache with TTL
        cache_key = self._get_cache_key(url)
        if cache_key in self.cache:
            entry = self.cache[cache_key]
            if not entry.is_expired():
                logger.debug(f"WAF cache hit for {self._extract_base_url(url)}")
                return entry.waf_name, entry.confidence
            else:
                # Cache expired, remove it
                del self.cache[cache_key]
                logger.debug(f"WAF cache expired for {self._extract_base_url(url)}")

        try:
            # Phase 1: Normal request analysis
            normal_result = await self._analyze_normal_request(url, timeout)

            # Phase 2: Trigger WAF with malicious payload
            triggered_result = await self._analyze_triggered_response(url, timeout)

            # Combine results (TASK-70: includes indicators)
            waf_name, confidence, indicators = self._combine_results(normal_result, triggered_result)

            # TASK-69: Cache result with TTL
            self.cache[cache_key] = CacheEntry(
                waf_name=waf_name,
                confidence=confidence,
                indicators=indicators,
                timestamp=time.time()
            )

            if waf_name != "unknown":
                logger.info(f"WAF Detected: {waf_name} (confidence: {confidence:.0%}, indicators: {indicators})")

            return waf_name, confidence

        except Exception as e:
            logger.debug(f"WAF detection failed: {e}")
            return "unknown", 0.0

    def _get_cache_key(self, url: str) -> str:
        """Generate cache key from URL domain (TASK-69)."""
        domain = self._extract_base_url(url)
        return hashlib.md5(domain.encode()).hexdigest()

    def _score_all_signatures(self, response) -> Dict[str, float]:
        """Score all WAF signatures against response. Returns {waf_name: score} for matches."""
        scores = {}
        for sig in self.signatures:
            score = self._score_waf_signature(sig, response)
            if score > 0:
                scores[sig.name] = score
        return scores

    async def _analyze_normal_request(self, url: str, timeout: float) -> Dict[str, float]:
        """
        Analyze headers/cookies from a normal request.
        Returns dict of {waf_name: score}
        """
        ssl_verify = get_ssl_context()
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=ssl_verify) as client:
            response = await self._fetch_normal_response(client, url)
            if not response:
                return {}
            return self._score_all_signatures(response)

    async def _fetch_normal_response(self, client, url: str):
        """Fetch response for WAF fingerprinting."""
        try:
            return await client.get(url)
        except Exception as e:
            logger.debug(f"Normal request failed: {e}")
            return None

    def _score_waf_signature(self, sig, response) -> float:
        """Score a WAF signature against response headers and cookies."""
        score = 0.0

        # Check headers
        for header_key, header_pattern in sig.headers.items():
            header_value = response.headers.get(header_key, "").lower()
            if not header_value:
                continue
            if header_pattern == "" or header_pattern.lower() in header_value:
                score += 0.3

        # Check cookies
        cookies = response.cookies
        for cookie_name in sig.cookies:
            if self._has_matching_cookie(cookies, cookie_name):
                score += 0.2
                break

        return score

    def _has_matching_cookie(self, cookies, cookie_name: str) -> bool:
        """Check if cookies contain a match for cookie_name (exact or prefix)."""
        for actual_cookie in cookies.keys():
            if actual_cookie.lower().startswith(cookie_name.lower()):
                return True
        return False

    async def _analyze_triggered_response(self, url: str, timeout: float) -> Dict[str, float]:
        """
        Send malicious payloads to trigger WAF and analyze block response.
        """
        scores: Dict[str, float] = {}

        # Payloads designed to trigger WAF
        trigger_payloads = [
            "' OR 1=1--",
            "<script>alert(1)</script>",
            "../../../etc/passwd",
            "{{7*7}}"
        ]

        ssl_verify = get_ssl_context()
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=ssl_verify) as client:
            for payload in trigger_payloads:
                if await self._test_waf_trigger(client, url, payload, scores):
                    break  # One trigger is enough if we got blocked

        return scores

    async def _test_waf_trigger(self, client, url: str, payload: str, scores: Dict[str, float]) -> bool:
        """Test a single WAF trigger payload."""
        try:
            # Inject in query parameter
            test_url = f"{url}{'&' if '?' in url else '?'}test={payload}"
            response = await client.get(test_url)

            # If we got blocked (403, 406, etc), analyze the response
            if response.status_code in [403, 406, 429, 503]:
                self._analyze_blocked_response(response, scores)
                return True
        except Exception as e:
            logger.debug(f"Trigger request failed: {e}")

        return False

    def _analyze_blocked_response(self, response, scores: Dict[str, float]):
        """Analyze a blocked response and update WAF scores."""
        body = response.text.lower()

        for sig in self.signatures:
            score = scores.get(sig.name, 0.0)

            # Check body patterns
            for pattern in sig.body_patterns:
                if pattern.lower() in body:
                    score += 0.4

            # Check status code match
            if response.status_code in sig.status_codes:
                score += 0.1

            if score > scores.get(sig.name, 0.0):
                scores[sig.name] = score

    def _combine_results(
        self,
        normal_scores: Dict[str, float],
        triggered_scores: Dict[str, float]
    ) -> Tuple[str, float, List[str]]:
        """
        Combine detection scores and return best match with indicators (TASK-70).

        Returns:
            Tuple of (waf_name, confidence, indicators_list)
        """
        combined: Dict[str, float] = {}
        indicators: Dict[str, List[str]] = {}

        all_wafs = set(normal_scores.keys()) | set(triggered_scores.keys())

        for waf in all_wafs:
            waf_indicators = []

            # Track which detection methods contributed
            if waf in normal_scores and normal_scores[waf] > 0:
                waf_indicators.append("header_match")
            if waf in triggered_scores and triggered_scores[waf] > 0:
                waf_indicators.append("response_pattern")

            indicators[waf] = waf_indicators

            # TASK-70: Weighted confidence calculation
            # Weights based on reliability of each indicator type
            normal_weight = 0.3  # Headers/cookies are less reliable
            triggered_weight = 0.7  # Blocked responses are more reliable

            combined[waf] = (
                normal_scores.get(waf, 0.0) * normal_weight +
                triggered_scores.get(waf, 0.0) * triggered_weight
            )

        if not combined:
            return "unknown", 0.0, []

        # Get highest scoring WAF
        best_waf = max(combined, key=combined.get)
        confidence = min(combined[best_waf], 1.0)  # Cap at 1.0

        # Require minimum confidence
        if confidence < 0.3:
            return "unknown", confidence, []

        return best_waf, confidence, indicators.get(best_waf, [])

    def _extract_base_url(self, url: str) -> str:
        """Extract base URL for caching (scheme + netloc)."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def clear_cache(self):
        """Clear the detection cache."""
        self.cache.clear()

    async def detect_all(self, url: str, timeout: float = 10.0, min_confidence: float = 0.2) -> List[Tuple[str, float, List[str]]]:
        """
        Detect ALL WAFs protecting the target (TASK-73: Multi-WAF support).

        Some targets use stacked WAFs (e.g., Cloudflare CDN + ModSecurity backend).
        This method returns all detected WAFs above the confidence threshold.

        Args:
            url: Target URL to probe
            timeout: Request timeout in seconds
            min_confidence: Minimum confidence to include a WAF

        Returns:
            List of (waf_name, confidence, indicators) tuples, sorted by confidence
        """
        try:
            normal_result = await self._analyze_normal_request(url, timeout)
            triggered_result = await self._analyze_triggered_response(url, timeout)

            combined, indicators = self._combine_all_waf_scores(normal_result, triggered_result)
            detected = self._filter_and_sort_detections(combined, indicators, min_confidence)

            if detected:
                waf_list = [f"{w}({c:.0%})" for w, c, _ in detected]
                logger.info(f"Multi-WAF Detection: {', '.join(waf_list)}")

            return detected

        except Exception as e:
            logger.debug(f"Multi-WAF detection failed: {e}")
            return []

    def _combine_all_waf_scores(
        self,
        normal_result: Dict[str, float],
        triggered_result: Dict[str, float]
    ) -> Tuple[Dict[str, float], Dict[str, List[str]]]:
        """Combine scores and indicators for all detected WAFs."""
        combined: Dict[str, float] = {}
        indicators: Dict[str, List[str]] = {}
        all_wafs = set(normal_result.keys()) | set(triggered_result.keys())

        for waf in all_wafs:
            waf_indicators = []
            if waf in normal_result and normal_result[waf] > 0:
                waf_indicators.append("header_match")
            if waf in triggered_result and triggered_result[waf] > 0:
                waf_indicators.append("response_pattern")

            indicators[waf] = waf_indicators
            combined[waf] = (
                normal_result.get(waf, 0.0) * 0.3 +
                triggered_result.get(waf, 0.0) * 0.7
            )

        return combined, indicators

    def _filter_and_sort_detections(
        self,
        combined: Dict[str, float],
        indicators: Dict[str, List[str]],
        min_confidence: float
    ) -> List[Tuple[str, float, List[str]]]:
        """Filter by confidence threshold and sort by confidence."""
        detected = [
            (waf, min(conf, 1.0), indicators.get(waf, []))
            for waf, conf in combined.items()
            if conf >= min_confidence
        ]
        detected.sort(key=lambda x: x[1], reverse=True)
        return detected

    def get_cache_stats(self) -> Dict[str, int]:
        """Get cache statistics (TASK-69)."""
        total = len(self.cache)
        expired = sum(1 for entry in self.cache.values() if entry.is_expired())
        return {
            "total_entries": total,
            "valid_entries": total - expired,
            "expired_entries": expired
        }

    async def validate_detection(self, url: str, detected_waf: str, timeout: float = 10.0) -> Tuple[bool, str]:
        """
        Validate WAF detection to reduce false positives (TASK-77).

        Performs additional checks to confirm the WAF detection is accurate.

        Args:
            url: Target URL
            detected_waf: The WAF that was detected
            timeout: Request timeout

        Returns:
            Tuple of (is_valid, reason)
        """
        if detected_waf == "unknown":
            return True, "No WAF detected, no validation needed"

        ssl_verify = get_ssl_context()

        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=ssl_verify) as client:
                # Test 1: Validate safe request behavior
                safe_response = await client.get(url)
                is_valid, reason = self._validate_safe_request(safe_response)
                if not is_valid:
                    return is_valid, reason

                # Test 2 & 3: Validate malicious request behavior
                test_url = f"{url}{'&' if '?' in url else '?'}test=' OR 1=1--<script>alert(1)</script>"
                malicious_response = await client.get(test_url)
                return self._validate_malicious_request(malicious_response, detected_waf)

        except Exception as e:
            logger.debug(f"Validation failed: {e}")
            return True, f"Validation inconclusive: {e}"

    def _validate_safe_request(self, response: httpx.Response) -> Tuple[bool, str]:
        """Validate that safe requests are not blocked."""
        if response.status_code in [403, 429, 503]:
            return False, "Site blocks normal requests - possible IP block, not WAF"
        return True, "Safe request passed"

    def _validate_malicious_request(self, response: httpx.Response, detected_waf: str) -> Tuple[bool, str]:
        """Validate malicious request was handled correctly by detected WAF."""
        if response.status_code == 200:
            return self._validate_waf_indicators_in_success(response, detected_waf)

        if response.status_code in [403, 406, 429, 503]:
            return self._validate_block_page_patterns(response, detected_waf)

        return True, "Detection validated successfully"

    def _validate_waf_indicators_in_success(self, response: httpx.Response, detected_waf: str) -> Tuple[bool, str]:
        """Check if WAF indicators are present even when malicious request succeeds."""
        headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}

        if detected_waf == "cloudflare":
            if "cf-ray" not in headers_lower:
                return False, "Cloudflare indicators not present in follow-up request"
        elif detected_waf == "akamai":
            if not any(k.startswith("x-akamai") for k in headers_lower):
                return False, "Akamai indicators not present in follow-up request"

        return True, "WAF indicators confirmed"

    def _validate_block_page_patterns(self, response: httpx.Response, detected_waf: str) -> Tuple[bool, str]:
        """Validate block page contains expected WAF patterns."""
        body_lower = response.text.lower()

        waf_patterns = {
            "cloudflare": ["cloudflare", "ray id"],
            "modsecurity": ["modsecurity", "not acceptable"],
            "aws_waf": ["request blocked", "aws"],
            "akamai": ["access denied", "akamai"],
            "imperva": ["incapsula", "incident id"],
        }

        if detected_waf in waf_patterns:
            patterns = waf_patterns[detected_waf]
            if not any(p in body_lower for p in patterns):
                return False, f"Block page doesn't match {detected_waf} patterns"

        return True, "Detection validated successfully"

    def is_false_positive_likely(self, waf_name: str, confidence: float, indicators: List[str]) -> bool:
        """
        Quick check if detection is likely a false positive (TASK-77).

        Args:
            waf_name: Detected WAF name
            confidence: Detection confidence
            indicators: List of detection indicators

        Returns:
            True if false positive is likely
        """
        # Low confidence detections are suspicious
        if confidence < 0.4:
            return True

        # Only header match without response pattern is less reliable
        if indicators == ["header_match"] and confidence < 0.6:
            return True

        # Very common patterns that cause false positives
        false_positive_prone = {
            "nginx_naxsi": 0.5,  # nginx is common, naxsi detection needs high confidence
        }

        if waf_name in false_positive_prone:
            if confidence < false_positive_prone[waf_name]:
                return True

        return False


# Singleton instance
waf_fingerprinter = WAFFingerprinter()
