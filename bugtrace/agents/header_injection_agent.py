"""
HeaderInjectionAgent - HTTP Response Header Injection / CRLF Specialist

CREATED: 2026-01-30
PURPOSE: Detect HTTP Response Header Injection (CRLF injection) vulnerabilities.

Burp Scanner finds these as "HTTP Response Header Injection" which allows:
- Response splitting attacks
- Cache poisoning
- XSS via injected headers
- Session fixation
"""

import asyncio
import aiohttp
import json
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from bugtrace.utils.logger import get_logger
from bugtrace.core.config import settings
from bugtrace.core.ui import dashboard
from bugtrace.core.job_manager import JobStatus
from bugtrace.agents.base import BaseAgent
from bugtrace.core.validation_status import ValidationStatus
from bugtrace.agents.worker_pool import WorkerPool, WorkerConfig
from bugtrace.core.event_bus import EventType
from bugtrace.core.http_orchestrator import orchestrator, DestinationType

# v3.2.0: Import TechContextMixin for context-aware detection
from bugtrace.agents.mixins.tech_context import TechContextMixin

logger = get_logger("agents.header_injection")


class HeaderInjectionAgent(BaseAgent, TechContextMixin):
    """
    HTTP Response Header Injection (CRLF) Specialist Agent.

    Tests for:
    1. CRLF injection in URL parameters
    2. CRLF injection in cookies
    3. CRLF injection in custom headers
    4. Response splitting for cache poisoning
    """

    # CRLF payloads - various encodings to bypass filters
    CRLF_PAYLOADS = [
        # Standard CRLF
        "%0d%0aX-Injected: header",
        "%0d%0aSet-Cookie: injected=true",
        # Double encoding
        "%250d%250aX-Injected: header",
        # Unicode variants
        "%E5%98%8A%E5%98%8DX-Injected: header",
        # Mixed encoding
        "%0d%0a%0d%0a<html>injected</html>",
        # Null byte bypass
        "%00%0d%0aX-Injected: header",
        # Line feed only (some servers)
        "%0aX-Injected: header",
        # Carriage return only
        "%0dX-Injected: header",
        # URL encoded newline
        "\r\nX-Injected: header",
        # Tab + newline
        "%09%0d%0aX-Injected: header",
    ]

    # Headers to check for injection evidence
    INJECTION_MARKERS = [
        "X-Injected",
        "Set-Cookie: injected",
        "<html>injected",
    ]

    # Config path for header injection scope filtering
    SCOPE_CONFIG_PATH = Path(__file__).parent.parent / "data" / "header_injection_scope.json"

    def __init__(
        self,
        url: str,
        params: List[str] = None,
        report_dir: Path = None,
        event_bus: Any = None,
        cookies: List[Dict] = None,
        headers: Dict[str, str] = None,
    ):
        super().__init__("HeaderInjectionAgent", "CRLF Injection Specialist", event_bus=event_bus, agent_id="header_injection_agent")
        self.url = url
        self.params = params or []
        self.report_dir = report_dir or Path("reports")
        self.cookies = cookies or []
        self.headers = headers or {}
        self.findings: List[Dict] = []

        # Statistics
        self._stats = {
            "params_tested": 0,
            "vulns_found": 0,
            "payloads_tested": 0,
        }

        # Queue consumption mode
        self._queue_mode = False

        # Expert deduplication: Track emitted findings by fingerprint
        self._emitted_findings: set = set()  # Agent-specific fingerprint

        # WET → DRY transformation (Two-phase processing)
        self._dry_findings: List[Dict] = []  # Dedup'd findings after Phase A

        self._worker_pool: Optional[WorkerPool] = None
        self._scan_context: str = ""

        # v3.2.0: Context-aware tech stack (loaded in start_queue_consumer)
        self._tech_stack_context: Dict = {}
        self._header_injection_prime_directive: str = ""

    # =========================================================================
    # FINDING VALIDATION: Header Injection-specific validation (Phase 1 Refactor)
    # =========================================================================

    def _validate_before_emit(self, finding: Dict) -> Tuple[bool, str]:
        """
        Header Injection-specific validation before emitting finding.

        Validates:
        1. Basic requirements (type, url) via parent
        2. Has header injection evidence (header reflected)
        3. Payload contains CRLF patterns
        """
        # Call parent validation first
        is_valid, error = super()._validate_before_emit(finding)
        if not is_valid:
            return False, error

        # Extract from nested structure if needed
        nested = finding.get("finding", {})
        evidence = finding.get("evidence", {})

        # Header injection-specific: Must have header name or evidence
        header_name = finding.get("header_name", nested.get("header_name", ""))
        has_evidence = header_name or evidence.get("header_reflected")
        if not has_evidence:
            return False, "Header Injection requires proof: injected header name or evidence"

        # Header injection-specific: Payload should contain CRLF patterns
        payload = finding.get("payload", nested.get("payload", ""))
        crlf_markers = ['%0d', '%0a', '\r', '\n', '%250d', '%250a', '%E5%98%8']
        if payload and not any(m in str(payload) for m in crlf_markers):
            return False, f"Header Injection payload missing CRLF patterns: {payload[:50]}"

        return True, ""

    def _emit_header_injection_finding(self, finding_dict: Dict, scan_context: str = None) -> Optional[Dict]:
        """
        Helper to emit Header Injection finding using BaseAgent.emit_finding() with validation.
        """
        if "type" not in finding_dict:
            finding_dict["type"] = "HEADER_INJECTION"

        if scan_context:
            finding_dict["scan_context"] = scan_context

        finding_dict["agent"] = self.name
        return self.emit_finding(finding_dict)

    async def run_loop(self):
        """Standard run loop."""
        return await self.run()

    async def run(self) -> Dict:
        """
        Test for Header Injection vulnerabilities.

        Flow:
        1. Discover parameters from URL
        2. Test each parameter with CRLF payloads
        3. Check response headers for injection evidence
        4. Report confirmed findings
        """
        dashboard.current_agent = self.name
        logger.info(f"[{self.name}] 🔍 Starting Header Injection scan on {self.url}")
        dashboard.log(f"[{self.name}] 🔍 Starting Header Injection scan on {self.url}", "INFO")

        try:
            # Smart Scope Filter - skip if URL not in scope
            if not self._should_test():
                dashboard.log(f"[{self.name}] Skipping - URL not in scope", "INFO")
                return {"findings": [], "status": JobStatus.COMPLETED, "stats": self._stats}

            # Get parameters to test
            params_to_test = self._get_parameters_to_test()

            if not params_to_test:
                dashboard.log(f"[{self.name}] No parameters found to test", "WARN")
                return {"findings": [], "status": JobStatus.COMPLETED, "stats": self._stats}

            # Test each parameter
            async with orchestrator.session(DestinationType.TARGET) as session:
                for param in params_to_test:
                    await self._test_parameter(session, param)

            self._log_completion_stats()

            return {"findings": self.findings, "status": JobStatus.COMPLETED, "stats": self._stats}

        except Exception as e:
            logger.error(f"HeaderInjectionAgent failed: {e}", exc_info=True)
            return {"error": str(e), "findings": [], "status": JobStatus.FAILED}

    def _get_parameters_to_test(self) -> List[str]:
        """Get list of parameters to test."""
        params_to_test = list(self.params) if self.params else []

        # Extract from URL query string
        if not params_to_test:
            parsed = urlparse(self.url)
            query_params = parse_qs(parsed.query)
            params_to_test = list(query_params.keys())

        # Also test cookie names
        if self.cookies:
            for cookie in self.cookies:
                cookie_name = cookie.get('name', '')
                if cookie_name and cookie_name not in params_to_test:
                    params_to_test.append(cookie_name)

        params_to_test = list(set(params_to_test))

        if not params_to_test:
            # Add common parameters that might be vulnerable
            params_to_test = ["url", "redirect", "next", "return", "callback", "ref", "page"]

        logger.info(f"[{self.name}] Parameters to test: {params_to_test}")
        return params_to_test

    def _should_test(self) -> bool:
        """
        Determines if Header Injection should be tested on this URL
        based on configurable scope rules from header_injection_scope.json.

        Logic:
        1. If url.path is / or empty -> TRUE
        2. If url.path contains any string from patterns.paths -> TRUE
        3. If any GET parameter matches patterns.params -> TRUE
        4. Default: FALSE (log as "Skipped")
        """
        try:
            with open(self.SCOPE_CONFIG_PATH, 'r') as f:
                scope = json.load(f)
        except Exception as e:
            logger.warning(f"[{self.name}] Failed to load scope config: {e}, defaulting to test")
            return True  # Fail-safe: test if config unavailable

        config = scope.get("config", {})
        patterns = scope.get("patterns", {})
        path_patterns = patterns.get("paths", [])
        param_patterns = patterns.get("params", [])

        parsed = urlparse(self.url)
        path = parsed.path.lower()
        query_params = parse_qs(parsed.query)

        # Check 1: Root or empty path
        if config.get("always_test_root", True) and (path == "/" or path == ""):
            logger.info(f"[{self.name}] URL in scope: root path")
            return True

        # Check 2: Path contains sensitive patterns
        for pattern in path_patterns:
            if pattern.lower() in path:
                logger.info(f"[{self.name}] URL in scope: path contains '{pattern}'")
                return True

        # Check 3: Query parameters match sensitive patterns
        for param in query_params.keys():
            if param.lower() in [p.lower() for p in param_patterns]:
                logger.info(f"[{self.name}] URL in scope: param '{param}' is redirect-related")
                return True

        # Default: Not in scope
        logger.debug(f"[{self.name}] Skipping Header Injection on {self.url} (Not in scope)")
        return False

    async def _test_parameter(self, session: aiohttp.ClientSession, param: str):
        """Test a single parameter for CRLF injection."""
        self._stats["params_tested"] += 1
        dashboard.log(f"[{self.name}] Testing parameter: {param}", "INFO")

        for payload in self.CRLF_PAYLOADS:
            self._stats["payloads_tested"] += 1

            test_url = self._build_test_url(param, payload)
            finding = await self._check_injection(session, test_url, param, payload)

            if finding:
                self.findings.append(finding)
                self._stats["vulns_found"] += 1
                dashboard.add_finding("Header Injection", f"{self.url} [{param}]", "HIGH")

                # Found vulnerability, no need to test more payloads for this param
                break

    def _build_test_url(self, param: str, payload: str) -> str:
        """Build URL with CRLF payload in specified parameter."""
        parsed = urlparse(self.url)
        query_params = parse_qs(parsed.query)

        # Set or replace parameter with payload
        query_params[param] = [payload]

        new_query = urlencode(query_params, doseq=True)
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))

    async def _check_injection(
        self,
        session: aiohttp.ClientSession,
        test_url: str,
        param: str,
        payload: str
    ) -> Optional[Dict]:
        """Check if CRLF injection was successful by examining response."""
        try:
            req_headers = {"User-Agent": getattr(settings, 'USER_AGENT', 'BugTraceAI/2.4')}
            req_headers.update(self.headers)

            if self.cookies:
                cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in self.cookies])
                req_headers["Cookie"] = cookie_str

            async with session.get(
                test_url,
                headers=req_headers,
                allow_redirects=False,  # Important: Don't follow redirects
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False
            ) as response:
                # Check response headers for injection evidence
                resp_headers = dict(response.headers)
                body = await response.text()

                for marker in self.INJECTION_MARKERS:
                    # Check in response headers
                    for header_name, header_value in resp_headers.items():
                        if marker.lower() in header_name.lower() or marker.lower() in header_value.lower():
                            return self._create_finding(param, payload, marker, "header", header_name, header_value)

                    # Check in body (response splitting)
                    if marker.lower() in body.lower():
                        # Could be response splitting - check if HTML was injected
                        if "<html>injected" in body.lower():
                            return self._create_finding(param, payload, marker, "body", None, body[:500])

        except asyncio.TimeoutError:
            logger.debug(f"Timeout testing {param} with payload")
        except Exception as e:
            logger.debug(f"Error testing {param}: {e}")

        return None

    def _create_finding(
        self,
        param: str,
        payload: str,
        marker: str,
        location: str,
        header_name: Optional[str],
        evidence: str
    ) -> Dict:
        """Create a finding dictionary."""
        logger.info(f"[{self.name}] ✅ Header Injection confirmed in {param}!")
        dashboard.log(f"[{self.name}] ✅ Header Injection CONFIRMED in {param}!", "SUCCESS")

        return {
            "type": "Header Injection",
            "vulnerability_type": "HTTP_RESPONSE_HEADER_INJECTION",
            "url": self.url,
            "parameter": param,
            "payload": payload,
            "evidence": f"Injection marker '{marker}' found in {location}: {evidence[:200]}",
            "validated": True,
            "validation_method": "Response Header Analysis",
            "severity": "HIGH",
            "status": ValidationStatus.VALIDATED_CONFIRMED.value,
            "cwe": "CWE-113",
            "remediation": "Sanitize user input before including in HTTP headers. Remove or encode CR (\\r) and LF (\\n) characters.",
            "reproduction": f"curl -v '{self._build_test_url(param, payload)}'",
            "impact": "Response splitting, cache poisoning, XSS via headers, session fixation",
            "header_name": header_name,
        }

    def _log_completion_stats(self):
        """Log completion statistics."""
        stats_msg = (
            f"[{self.name}] Complete: {self._stats['params_tested']} params, "
            f"{self._stats['payloads_tested']} payloads, "
            f"{self._stats['vulns_found']} vulns found"
        )
        logger.info(stats_msg)
        dashboard.log(stats_msg, "SUCCESS" if self.findings else "INFO")

    def get_stats(self) -> Dict:
        """Get agent statistics."""
        return self._stats

    # =========================================================================
    # AUTONOMOUS PARAMETER DISCOVERY (Specialist Autonomy Pattern)
    # =========================================================================

    async def _discover_header_params(self, url: str) -> Dict[str, str]:
        """
        Header Injection-focused parameter discovery.

        Extracts ALL testable parameters from:
        1. URL query string
        2. HTML forms (input, textarea, select)

        Prioritizes parameters that might influence HTTP headers:
        - redirect, language, locale, encoding, charset
        - url, callback, next, return, ref

        Returns:
            Dict mapping param names to default values
            Example: {"redirect": "/home", "locale": "en", "searchTerm": ""}

        Architecture Note:
            Specialists must be AUTONOMOUS - they discover their own attack surface.
            The finding from DASTySAST is just a "signal" that the URL is interesting.
            We IGNORE the specific parameter and test ALL discoverable params.
        """
        from bugtrace.tools.visual.browser import browser_manager
        from urllib.parse import urlparse, parse_qs
        from bs4 import BeautifulSoup

        all_params = {}

        # 1. Extract URL query parameters
        try:
            parsed = urlparse(url)
            url_params = parse_qs(parsed.query)
            for param_name, values in url_params.items():
                all_params[param_name] = values[0] if values else ""
        except Exception as e:
            logger.warning(f"[{self.name}] Failed to parse URL params: {e}")

        # 2. Fetch HTML and extract form parameters + link parameters
        try:
            state = await browser_manager.capture_state(url)
            html = state.get("html", "")

            if html:
                self._last_discovery_html = html  # Cache for URL resolution
                soup = BeautifulSoup(html, "html.parser")

                # Extract from <input>, <textarea>, <select>
                for tag in soup.find_all(["input", "textarea", "select"]):
                    param_name = tag.get("name")
                    if param_name and param_name not in all_params:
                        input_type = tag.get("type", "text").lower()

                        # Skip non-testable input types
                        if input_type not in ["submit", "button", "reset"]:
                            # Include CSRF tokens for header injection (they can trigger headers)
                            default_value = tag.get("value", "")
                            all_params[param_name] = default_value

                # Extract params from <a> href links (same-origin only)
                # Many sites put params in navigation links, not forms
                # e.g. <a href="/catalog?category=Juice">
                parsed_base = urlparse(url)
                for a_tag in soup.find_all("a", href=True):
                    href = a_tag["href"]
                    try:
                        parsed_href = urlparse(href)
                        # Same-origin or relative links only
                        if parsed_href.netloc and parsed_href.netloc != parsed_base.netloc:
                            continue
                        href_params = parse_qs(parsed_href.query)
                        for p_name, p_vals in href_params.items():
                            if p_name not in all_params:
                                all_params[p_name] = p_vals[0] if p_vals else ""
                    except Exception:
                        continue

        except Exception as e:
            logger.error(f"[{self.name}] HTML parsing failed: {e}")

        logger.info(f"[{self.name}] 🔍 Discovered {len(all_params)} params on {url}: {list(all_params.keys())}")
        return all_params

    # =========================================================================
    # WET → DRY Two-Phase Processing (Phase A: Deduplication, Phase B: Exploitation)
    # =========================================================================

    async def analyze_and_dedup_queue(self) -> List[Dict]:
        """
        PHASE A: Drain WET findings from queue, expand with autonomous discovery, and deduplicate.

        Flow:
        1. Drain WET queue (signals from DASTySAST)
        2. Expand each signal by discovering ALL params on that URL
        3. Deduplicate with LLM (respects _discovered flag)
        4. Return DRY list ready for exploitation

        Returns:
            List of DRY (deduplicated) findings
        """
        import asyncio
        import time
        import json
        from bugtrace.core.queue import queue_manager

        logger.info(f"[{self.name}] ===== PHASE A: Analyzing WET list =====")

        queue = queue_manager.get_queue("header_injection")
        wet_findings = []

        # Wait for queue to have items (timeout 300s)
        wait_start = time.monotonic()
        while (time.monotonic() - wait_start) < 300.0:
            if queue.depth() if hasattr(queue, 'depth') else 0 > 0:
                break
            await asyncio.sleep(0.5)

        # Drain all WET findings from queue
        logger.info(f"[{self.name}] Phase A: Queue has {queue.depth() if hasattr(queue, 'depth') else 0} items, starting drain...")

        stable_empty_count = 0
        drain_start = time.monotonic()

        while stable_empty_count < 10 and (time.monotonic() - drain_start) < 300.0:
            item = await queue.dequeue(timeout=0.5)  # Use dequeue(), not get_nowait()

            if item is None:
                stable_empty_count += 1
                continue

            stable_empty_count = 0

            finding = item.get("finding", {}) if isinstance(item, dict) else {}
            if finding:
                wet_findings.append({
                    "url": finding.get("url", ""),
                    "parameter": finding.get("parameter", ""),
                    "finding": finding,
                    "scan_context": item.get("scan_context", self._scan_context),
                })

        logger.info(f"[{self.name}] Phase A: Drained {len(wet_findings)} WET findings from queue")

        if not wet_findings:
            logger.info(f"[{self.name}] Phase A: No findings to process")
            return []

        # ========== AUTONOMOUS PARAMETER DISCOVERY ==========
        # Strategy: ALWAYS keep original WET params + ADD discovered params
        logger.info(f"[{self.name}] Phase A: Expanding WET findings with autonomous discovery...")
        expanded_wet_findings = []
        seen_urls = set()
        seen_params = set()

        # 1. Always include ALL original WET params first (DASTySAST signals)
        for wet_item in wet_findings:
            url = wet_item.get("url", "")
            param = wet_item.get("parameter", "") or (wet_item.get("finding", {}) or {}).get("parameter", "")
            if param and (url, param) not in seen_params:
                seen_params.add((url, param))
                expanded_wet_findings.append(wet_item)

        # 2. Discover additional params per unique URL
        for wet_item in wet_findings:
            url = wet_item.get("url", "")
            if url in seen_urls:
                continue
            seen_urls.add(url)

            try:
                all_params = await self._discover_header_params(url)
                if not all_params:
                    continue

                new_count = 0
                for param_name, param_value in all_params.items():
                    if (url, param_name) not in seen_params:
                        seen_params.add((url, param_name))
                        expanded_wet_findings.append({
                            "url": url,
                            "parameter": param_name,
                            "context": wet_item.get("context", "unknown"),
                            "finding": wet_item.get("finding", {}),
                            "scan_context": wet_item.get("scan_context", self._scan_context),
                            "_discovered": True
                        })
                        new_count += 1

                if new_count:
                    logger.info(f"[{self.name}] 🔍 Discovered {new_count} additional params on {url}")

            except Exception as e:
                logger.error(f"[{self.name}] Discovery failed for {url}: {e}")

        # 2.5 Resolve endpoint URLs from HTML links/forms + reasoning fallback
        from bugtrace.agents.specialist_utils import resolve_param_endpoints, resolve_param_from_reasoning
        if hasattr(self, '_last_discovery_html') and self._last_discovery_html:
            for base_url in seen_urls:
                endpoint_map = resolve_param_endpoints(self._last_discovery_html, base_url)
                # Fallback: extract endpoints from DASTySAST reasoning text
                reasoning_map = resolve_param_from_reasoning(expanded_wet_findings, base_url)
                for k, v in reasoning_map.items():
                    if k not in endpoint_map:
                        endpoint_map[k] = v
                if endpoint_map:
                    resolved_count = 0
                    for item in expanded_wet_findings:
                        if item.get("url") == base_url:
                            param = item.get("parameter", "")
                            if param in endpoint_map and endpoint_map[param] != base_url:
                                item["url"] = endpoint_map[param]
                                resolved_count += 1
                    if resolved_count:
                        logger.info(f"[{self.name}] 🔗 Resolved {resolved_count} params to actual endpoint URLs")

        logger.info(f"[{self.name}] Phase A: Expanded {len(wet_findings)} hints → {len(expanded_wet_findings)} testable params")

        # ========== DEDUPLICATION ==========
        try:
            dry_list = await self._llm_analyze_and_dedup(expanded_wet_findings, self._scan_context)
        except Exception as e:
            logger.warning(f"[{self.name}] LLM dedup failed: {e}, using fallback")
            dry_list = self._fallback_fingerprint_dedup(expanded_wet_findings)

        # Store for later phases
        self._dry_findings = dry_list

        logger.info(f"[{self.name}] Phase A: {len(expanded_wet_findings)} WET → {len(dry_list)} DRY ({len(expanded_wet_findings) - len(dry_list)} duplicates removed)")

        return dry_list

    async def _llm_analyze_and_dedup(self, wet_findings: List[Dict], context: str) -> List[Dict]:
        """
        Use LLM to intelligently deduplicate Header Injection findings.
        Falls back to fingerprint-based dedup if LLM fails.

        CRITICAL: Respects autonomous discovery - same URL + DIFFERENT param = DIFFERENT finding.
        """
        import json
        from bugtrace.core.llm_client import llm_client

        # v3.2: Extract tech stack info for prompt
        tech_stack = getattr(self, '_tech_stack_context', {}) or {}
        server = tech_stack.get('server', 'generic')
        cdn = tech_stack.get('cdn')
        waf = tech_stack.get('waf')

        # Get Header Injection-specific context prompts
        header_injection_prime_directive = getattr(self, '_header_injection_prime_directive', '')
        header_injection_dedup_context = self.generate_header_injection_dedup_context(tech_stack) if tech_stack else ''

        prompt = f"""You are analyzing {len(wet_findings)} potential HTTP Header Injection (CRLF) findings.

{header_injection_prime_directive}

{header_injection_dedup_context}

## TARGET CONTEXT
- Server: {server}
- CDN: {cdn or 'None'}
- WAF: {waf or 'None'}

## DEDUPLICATION RULES

1. **CRITICAL - Autonomous Discovery:**
   - If items have "_discovered": true, they are DIFFERENT PARAMETERS discovered autonomously
   - Even if they share the same "finding" object, treat them as SEPARATE based on "parameter" field
   - Same URL + DIFFERENT param → DIFFERENT (keep all)
   - Same URL + param + DIFFERENT context → DIFFERENT (keep both)

2. **Standard Deduplication:**
   - Same URL + Same param + Same context → DUPLICATE (keep best)
   - Different endpoints → DIFFERENT (keep both)

3. **Prioritization:**
   - Rank by exploitability given the tech stack
   - Remove findings unlikely to succeed

EXAMPLES:
- /page?redirect=X + /page?locale=Y (both _discovered=true) = DIFFERENT ✓ (keep both)
- /page?param=X (X-Injected) + /other?param=Y (X-Injected) = DUPLICATE ✓ (same param name across URLs)
- /page?param=X (X-Injected) + /page?param=Y (Set-Cookie) = DIFFERENT ✗ (different headers)

WET FINDINGS (may contain duplicates):
{json.dumps(wet_findings, indent=2)}

Return ONLY unique findings in JSON format:
{{
  "findings": [
    {{"url": "...", "parameter": "...", "header_name": "...", ...}},
    ...
  ],
  "duplicates_removed": <count>,
  "reasoning": "Brief explanation"
}}"""

        system_prompt = f"""You are an expert CRLF/Header Injection deduplication analyst.

{header_injection_prime_directive}

Your job is to identify and remove duplicate findings while preserving:
1. Unique parameter names (autonomous discovery)
2. Different injection contexts
3. Different injected headers

Focus on header name-only deduplication UNLESS parameters are different."""

        try:
            response = await llm_client.generate(
                prompt=prompt,
                system_prompt=system_prompt,
                module_name="HEADER_INJECTION_DEDUP",
                temperature=0.2
            )

            # Parse LLM response
            result = json.loads(response)
            dry_list = result.get("findings", [])

            if dry_list:
                logger.info(f"[{self.name}] LLM deduplication successful: {len(wet_findings)} → {len(dry_list)}")
                return dry_list
            else:
                logger.warning(f"[{self.name}] LLM returned empty list, using fallback")
                return self._fallback_fingerprint_dedup(wet_findings)

        except Exception as e:
            logger.warning(f"[{self.name}] LLM deduplication failed: {e}, using fallback")
            return self._fallback_fingerprint_dedup(wet_findings)

    def _fallback_fingerprint_dedup(self, wet_findings: List[Dict]) -> List[Dict]:
        """
        Fallback fingerprint-based deduplication if LLM fails.

        For autonomous discovery: Uses (url, parameter) as fingerprint.
        This ensures same URL with DIFFERENT params = DIFFERENT findings.
        """
        seen = set()
        dry_list = []

        for finding in wet_findings:
            # If autonomously discovered, fingerprint by URL+param
            if finding.get("_discovered"):
                url = finding.get("url", "")
                param = finding.get("parameter", "")
                fingerprint = (url, param)
            else:
                # Standard header injection: fingerprint by header name only
                header_name = finding.get("header_name", finding.get("injected_header", "X-Injected"))
                fingerprint = self._generate_headerinjection_fingerprint(header_name)

            if fingerprint not in seen:
                seen.add(fingerprint)
                dry_list.append(finding)

        logger.info(f"[{self.name}] Fingerprint dedup: {len(wet_findings)} → {len(dry_list)}")
        return dry_list

    async def exploit_dry_list(self) -> List[Dict]:
        """
        PHASE B: Exploit all DRY findings and emit validated vulnerabilities.

        Returns:
            List of validated findings
        """
        logger.info(f"[{self.name}] ===== PHASE B: Exploiting DRY list =====")
        logger.info(f"[{self.name}] Phase B: Exploiting {len(self._dry_findings)} DRY findings...")

        validated_findings = []

        for idx, finding in enumerate(self._dry_findings, 1):
            url = finding.get("url", "")
            parameter = finding.get("parameter", "")
            header_name = finding.get("header_name", finding.get("injected_header", "X-Injected"))

            logger.info(f"[{self.name}] Phase B: [{idx}/{len(self._dry_findings)}] Testing {url} header={header_name}")

            # Check fingerprint to avoid re-emitting
            fingerprint = self._generate_headerinjection_fingerprint(header_name)
            if fingerprint in self._emitted_findings:
                logger.debug(f"[{self.name}] Phase B: Skipping already emitted finding")
                continue

            # Execute Header Injection attack
            try:
                result = await self._test_parameter_from_queue(parameter)

                if result:
                    # Mark as emitted
                    self._emitted_findings.add(fingerprint)

                    # Ensure dict format
                    if not isinstance(result, dict):
                        result = {
                            "url": url,
                            "parameter": parameter,
                            "type": "HEADER_INJECTION",
                            "header_name": header_name,
                            "severity": "MEDIUM",
                            "validated": True
                        }

                    validated_findings.append(result)

                    # Emit event with validation
                    self._emit_header_injection_finding({
                        "type": "HEADER_INJECTION",
                        "url": result.get("url", url),
                        "parameter": result.get("parameter", parameter),
                        "header_name": result.get("header_name", header_name),
                        "payload": result.get("payload", ""),
                        "severity": result.get("severity", "MEDIUM"),
                        "evidence": {"header_reflected": True},
                    }, scan_context=self._scan_context)

                    logger.info(f"[{self.name}] ✓ Header Injection confirmed: header={header_name}")
                else:
                    logger.debug(f"[{self.name}] ✗ Header Injection not confirmed")

            except Exception as e:
                logger.error(f"[{self.name}] Phase B: Exploitation failed: {e}")

        logger.info(f"[{self.name}] Phase B: Exploitation complete. {len(validated_findings)} validated findings")
        return validated_findings

    async def _generate_specialist_report(self, validated_findings: List[Dict]) -> None:
        """
        Generate specialist report for Header Injection findings.

        Report structure:
        - phase_a: WET → DRY deduplication stats
        - phase_b: Exploitation results
        - findings: All validated Header Injection findings
        """
        import json
        import aiofiles

        # v3.1: Use unified report_dir if injected, else fallback to scan_context
        scan_dir = getattr(self, 'report_dir', None)
        if not scan_dir:
            scan_id = self._scan_context.split("/")[-1] if "/" in self._scan_context else self._scan_context
            scan_dir = settings.BASE_DIR / "reports" / scan_id
        # v3.2: Write to specialists/results/ for unified wet→dry→results flow
        results_dir = scan_dir / "specialists" / "results"
        results_dir.mkdir(parents=True, exist_ok=True)

        report = {
            "agent": f"{self.name}",
            "vulnerability_type": "HEADER_INJECTION",
            "scan_context": self._scan_context,
            "phase_a": {
                "wet_count": len(self._dry_findings) + (len(validated_findings) - len(self._dry_findings)),  # Approximate
                "dry_count": len(self._dry_findings),
                "deduplication_method": "LLM + fingerprint fallback (header name-only)"
            },
            "phase_b": {
                "exploited_count": len(self._dry_findings),
                "validated_count": len(validated_findings)
            },
            "findings": validated_findings,
            "summary": {
                "total_validated": len(validated_findings),
                "headers_found": list(set(f.get("header_name", "X-Injected") for f in validated_findings))
            }
        }

        report_path = results_dir / "header_injection_results.json"

        async with aiofiles.open(report_path, "w") as f:
            await f.write(json.dumps(report, indent=2))

        logger.info(f"[{self.name}] Specialist report saved: {report_path}")

    # =========================================================================
    # QUEUE CONSUMPTION MODE (Phase 29)
    # =========================================================================

    async def start_queue_consumer(self, scan_context: str) -> None:
        """
        TWO-PHASE queue consumer (WET → DRY). NO infinite loop.

        Phase A: Drain ALL findings from queue and deduplicate
        Phase B: Exploit DRY list only

        Args:
            scan_context: Scan identifier for event correlation
        """
        from bugtrace.agents.specialist_utils import (
            report_specialist_start,
            report_specialist_done,
            report_specialist_wet_dry,
            write_dry_file,
        )
        from bugtrace.core.queue import queue_manager

        self._queue_mode = True
        self._scan_context = scan_context

        # v3.2: Load context-aware tech stack for intelligent deduplication
        await self._load_header_injection_tech_context()

        logger.info(f"[{self.name}] Starting TWO-PHASE queue consumer (WET → DRY)")

        # Get initial queue depth for telemetry
        queue = queue_manager.get_queue("header_injection")
        initial_depth = queue.depth()
        report_specialist_start(self.name, queue_depth=initial_depth)

        # PHASE A: Analyze and deduplicate
        logger.info(f"[{self.name}] ===== PHASE A: Analyzing WET list =====")
        dry_list = await self.analyze_and_dedup_queue()

        # Report WET→DRY metrics for integrity verification
        report_specialist_wet_dry(self.name, initial_depth, len(dry_list) if dry_list else 0)
        write_dry_file(self, dry_list, initial_depth, "header_injection")

        if not dry_list:
            logger.info(f"[{self.name}] No findings to exploit after deduplication")
            report_specialist_done(self.name, processed=0, vulns=0)
            return  # Terminate agent

        # PHASE B: Exploit DRY findings
        logger.info(f"[{self.name}] ===== PHASE B: Exploiting DRY list =====")
        results = await self.exploit_dry_list()

        # Count confirmed vulnerabilities
        vulns_count = len([r for r in results if r]) if results else 0
        vulns_count += len(self._dry_findings) if hasattr(self, '_dry_findings') else 0

        # REPORTING: Generate specialist report
        if results or self._dry_findings:
            await self._generate_specialist_report(results)

        # Report completion with final stats
        report_specialist_done(
            self.name,
            processed=len(dry_list),
            vulns=vulns_count
        )

        logger.info(f"[{self.name}] Queue consumer complete: {len(results)} validated findings")

        # Method ends - agent terminates ✅

    async def stop_queue_consumer(self) -> None:
        """Stop queue consumer mode gracefully."""
        if self._worker_pool:
            await self._worker_pool.stop()
            self._worker_pool = None

        if self.event_bus:
            self.event_bus.unsubscribe(
                EventType.WORK_QUEUED_HEADER_INJECTION.value,
                self._on_work_queued
            )

        self._queue_mode = False
        logger.info(f"[{self.name}] Queue consumer stopped")

    async def _on_work_queued(self, data: dict) -> None:
        """Handle work_queued_header_injection notification (logging only)."""
        logger.debug(f"[{self.name}] Work queued: {data.get('finding', {}).get('url', 'unknown')}")

    async def _process_queue_item(self, item: dict) -> Optional[Dict]:
        """
        Process a single item from the header_injection queue.

        Item structure (from ThinkingConsolidationAgent):
        {
            "finding": {
                "type": "Header Injection",
                "url": "...",
                "parameter": "...",
            },
            "priority": 85.5,
            "scan_context": "scan_123",
        }
        """
        finding = item.get("finding", {})
        url = finding.get("url")
        param = finding.get("parameter")

        if not url or not param:
            logger.warning(f"[{self.name}] Invalid queue item: missing url or parameter")
            return None

        # Configure self for this specific test
        self.url = url

        # Test parameter for CRLF injection
        return await self._test_parameter_from_queue(param)

    async def _test_parameter_from_queue(self, param: str) -> Optional[Dict]:
        """Test a single parameter from queue for CRLF injection."""
        try:
            async with orchestrator.session(DestinationType.TARGET) as session:
                for payload in self.CRLF_PAYLOADS:
                    test_url = self._build_test_url(param, payload)
                    finding = await self._check_injection(session, test_url, param, payload)

                    if finding:
                        return finding

                return None

        except Exception as e:
            logger.error(f"[{self.name}] Queue item test failed: {e}")
            return None

    def _generate_headerinjection_fingerprint(self, header_name: str) -> tuple:
        """
        Generate Header Injection finding fingerprint for expert deduplication.

        Returns:
            Tuple fingerprint for deduplication
        """
        # Header injection is global (same header = same vulnerability)
        fingerprint = ("HEADER_INJECTION", header_name.lower())

        return fingerprint

    async def _handle_queue_result(self, item: dict, result: Optional[Dict]) -> None:
        """
        Handle completed queue item processing.

        Emits vulnerability_detected event on confirmed findings.
        """
        if result is None:
            return

        # EXPERT DEDUPLICATION: Check if we already emitted this finding
        header_name = result["parameter"]
        fingerprint = self._generate_headerinjection_fingerprint(header_name)

        if fingerprint in self._emitted_findings:
            logger.info(f"[{self.name}] Skipping duplicate HEADER_INJECTION finding (already reported)")
            return

        # Mark as emitted
        self._emitted_findings.add(fingerprint)

        # Emit vulnerability_detected event with validation
        if getattr(settings, 'WORKER_POOL_EMIT_EVENTS', True):
            self._emit_header_injection_finding({
                "specialist": "header_injection",
                "type": "HEADER_INJECTION",
                "url": result["url"],
                "parameter": result["parameter"],
                "header_name": result["parameter"],
                "payload": result["payload"],
                "severity": result["severity"],
                "status": result["status"],
                "evidence": {"header_reflected": True},
                "validation_requires_cdp": False,
            }, scan_context=self._scan_context)

        logger.info(f"[{self.name}] Confirmed Header Injection: {result['url']}?{result['parameter']}")

    def get_queue_stats(self) -> dict:
        """Get queue consumer statistics."""
        if not self._worker_pool:
            return {"mode": "direct", "queue_mode": False}

        return {
            "mode": "queue",
            "queue_mode": True,
            "worker_stats": self._worker_pool.get_stats(),
        }

    # =========================================================================
    # TECH CONTEXT LOADING (v3.2)
    # =========================================================================

    async def _load_header_injection_tech_context(self) -> None:
        """
        Load technology stack context from recon data (v3.2).

        Uses TechContextMixin methods to load and generate context-aware
        prompts for Header Injection-specific deduplication.
        """
        # Determine report directory
        scan_dir = getattr(self, 'report_dir', None)
        if not scan_dir:
            scan_id = self._scan_context.split("/")[-1] if self._scan_context else ""
            scan_dir = settings.BASE_DIR / "reports" / scan_id if scan_id else None

        if not scan_dir or not Path(scan_dir).exists():
            logger.debug(f"[{self.name}] No report directory found, using generic tech context")
            self._tech_stack_context = {"db": "generic", "server": "generic", "lang": "generic"}
            self._header_injection_prime_directive = ""
            return

        # Use TechContextMixin methods
        self._tech_stack_context = self.load_tech_stack(Path(scan_dir))
        self._header_injection_prime_directive = self.generate_header_injection_context_prompt(self._tech_stack_context)

        server = self._tech_stack_context.get("server", "generic")
        cdn = self._tech_stack_context.get("cdn")
        waf = self._tech_stack_context.get("waf")

        logger.info(f"[{self.name}] Header Injection tech context loaded: server={server}, cdn={cdn or 'none'}, waf={waf or 'none'}")
