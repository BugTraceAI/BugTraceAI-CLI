"""
Discovery, recon load, queue consumer, coverage/report shell.

Shell mixin extracted from xss_agent.py (hard max 1500 LOC per module for agent work).
"""
from __future__ import annotations

# --- shell runtime deps (mixin methods used these from xss_agent module scope) ---
import asyncio
import aiohttp
import json
import re
import urllib.parse
import html as html_module
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union, Iterable

from bugtrace.utils.logger import get_logger
from bugtrace.core.ui import dashboard
from bugtrace.core.config import settings
from bugtrace.core.llm_client import llm_client
from bugtrace.core.http_manager import http_manager, ConnectionProfile
from bugtrace.core.queue import queue_manager
from bugtrace.core.event_bus import EventType
from bugtrace.core.verbose_events import create_emitter
from bugtrace.core.validation_status import ValidationStatus, requires_cdp_validation, get_validation_status
from bugtrace.schemas.validation_feedback import ValidationFeedback, FailureReason
from bugtrace.tools.interactsh import InteractshClient
from bugtrace.tools.visual.verifier import XSSVerifier
from bugtrace.tools.headless import detect_dom_xss, detect_dom_xss_batch
from bugtrace.tools.external import external_tools
from bugtrace.tools.go_bridge import GoFuzzerBridge, FuzzResult, Reflection
from bugtrace.utils.payload_amplifier import PayloadAmplifier
from bugtrace.memory.payload_learner import PayloadLearner
from bugtrace.tools.manipulator.orchestrator import ManipulatorOrchestrator
from bugtrace.tools.manipulator.models import MutableRequest, MutationStrategy
from bugtrace.tools.manipulator.context_analyzer import ContextAnalyzer, ReflectionContext
from bugtrace.tools.waf import waf_fingerprinter, strategy_router, encoding_techniques
from bugtrace.agents.worker_pool import WorkerPool, WorkerConfig
from bugtrace.agents.specialist_utils import load_full_payload_from_json, load_full_finding_data
from bugtrace.reporting.standards import (
    get_cwe_for_vuln,
    get_remediation_for_vuln,
    normalize_severity,
    get_default_severity,
)
from bugtrace.agents.xss import coverage as xss_coverage
from bugtrace.agents.xss.types import XSSFinding, InjectionContext, ValidationMethod
from bugtrace.agents.xss.constants import (
    PROBE_STRING,
    PROBE_STRING_SAFE,
    OMNIPROBE_PAYLOAD,
    GOLDEN_PAYLOADS,
    FRAGMENT_PAYLOADS,
)
from bugtrace.agents.xss.finding_builder import (
    mask_auth_headers as _mask_auth_headers,
    auth_meta as _auth_meta,
    excerpt_around as _excerpt_around,
    build_raw_http as _build_raw_http,
    promote_repro as _promote_repro,
)
from bugtrace.agents.xss.waf import (
    detect_payload_encoding as _pure_detect_payload_encoding,
    record_bypass_result as _pure_record_bypass_result,
    get_waf_optimized_payloads as _pure_get_waf_optimized_payloads,
)
logger = get_logger(__name__)
from bugtrace.agents.xss.shell_constants import (
    _BROWSER_ONLY_CONTEXTS,
    _CDP_PROOF_LOCK,
    _L05_CHAR_PROBE,
    _LEGACY_PROBE_MARKER,
    _PROBE_NO_REFLECTION,
    _PROBE_NO_RESPONSE,
    _PROBE_REFLECTED,
    _REDIRECT_PARAM_SET,
    _REFLECTION_SNIPPET_RADIUS,
)
from bugtrace.agents.xss.context_reflection import as_context_set as _as_context_set
from bugtrace.agents.xss.position import release_document_caches
# --- end shell runtime deps ---

class XSSDiscoveryRunMixin:
    async def _loop_discover_params(self) -> bool:
        """Phase 2: Discover parameters. Returns True if params available.

        FIXED (2026-02-01): ALWAYS extract URL query params as first-class citizens.
        Previously, if params were provided to constructor, URL query params were ignored.
        This caused us to miss obvious XSS in ?category= and ?search= that Burp found.
        """
        # ALWAYS extract URL query params first (first-class citizens)
        from urllib.parse import urlparse, parse_qs
        url_query_params = list(parse_qs(urlparse(self.url).query).keys())

        if url_query_params:
            logger.info(f"[{self.name}] 🎯 URL Query Params (first-class): {url_query_params}")
            dashboard.log(f"[{self.name}] 🎯 URL Query Params: {url_query_params}", "INFO")

        # If no params provided, do full discovery
        if not self.params:
            dashboard.log(f"[{self.name}] 🔎 Discovering parameters...", "INFO")
            logger.info(f"[{self.name}] Phase 2: Discovering parameters")
            self.params = await self._discover_params()
            logger.info(f"[{self.name}] Discovered {len(self.params)} params")
        else:
            # MERGE: URL query params FIRST, then provided params (avoid duplicates)
            merged_params = list(url_query_params)  # URL params are first-class
            for p in self.params:
                if p not in merged_params:
                    merged_params.append(p)

            if len(merged_params) > len(self.params):
                logger.info(f"[{self.name}] MERGED: {len(self.params)} provided + {len(url_query_params)} URL = {len(merged_params)} total")

            self.params = self._prioritize_params(merged_params)

        if not self.params:
            dashboard.log(f"[{self.name}] ⚠️ No parameters found to test", "WARN")
            return False

        dashboard.log(f"[{self.name}] Testing {len(self.params)} params: {', '.join(self.params[:5])}", "INFO")
        logger.info(f"[{self.name}] Params List (Raw): {self.params}")
        return True

    def _load_recon_urls_with_params(self, max_urls: int = 15) -> List[str]:
        """
        Load recon URLs that have query parameters from GoSpider output.

        SPRINT-2 (2026-02-12): XSS Agent only tested the assigned URL.
        This expands testing to recon URLs discovered during reconnaissance.

        Only includes URLs with ?param=value (they have injectable surfaces).
        Capped to avoid excessive testing.
        """
        if not hasattr(self, 'report_dir') or not self.report_dir:
            return []

        urls_file = Path(self.report_dir) / "recon" / "urls.txt"
        if not urls_file.exists():
            return []

        try:
            from urllib.parse import urlparse, parse_qs
            base_domain = urlparse(self.url).netloc
            recon_urls = []
            seen_surfaces = set()

            for line in urls_file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parsed = urlparse(line)
                # Only same-domain URLs with query params
                if parsed.netloc == base_domain and parsed.query:
                    # Dedup by endpoint SURFACE (path + param names) before the cap. Otherwise a
                    # few near-duplicate URLs (catalog?category=Books, =Juice, =Gin, ...) fill the
                    # cap and crowd out distinct sink surfaces like /blog/post?postId= (where
                    # ?back=javascript:... is a DOM location sink). One URL per surface suffices —
                    # the specialists fuzz param VALUES themselves.
                    surface = (parsed.path, tuple(sorted(parse_qs(parsed.query).keys())))
                    if surface in seen_surfaces:
                        continue
                    seen_surfaces.add(surface)
                    recon_urls.append(line)
                    if len(recon_urls) >= max_urls:
                        break

            if recon_urls:
                logger.info(f"[{self.name}] Loaded {len(recon_urls)} recon URLs with params")
            return recon_urls

        except Exception as e:
            logger.warning(f"[{self.name}] Failed to load recon URLs: {e}")
            return []

    async def _discover_xss_params(self, url: str) -> Dict[str, str]:
        """
        XSS-focused parameter discovery for a given URL.

        Extracts ALL testable parameters from:
        1. URL query string
        2. HTML forms (input, textarea, select)
        3. JavaScript variables (var x = "USER_INPUT")

        Returns:
            Dict mapping param names to default values
            Example: {"category": "Juice", "searchTerm": "", "filter": ""}

        Architecture Note:
            Specialists must be AUTONOMOUS - they discover their own attack surface.
            The finding from DASTySAST is just a "signal" that the URL is interesting.
            We IGNORE the specific parameter and test ALL discoverable params.
        """
        from bugtrace.tools.visual.browser import browser_manager
        from bugtrace.agents.specialist_utils import extract_param_metadata
        from urllib.parse import urlparse, parse_qs, urljoin
        from bs4 import BeautifulSoup
        import re

        all_params = {}
        self._param_methods = {}  # Track HTTP method per param (GET/POST)
        self._param_metadata = {}  # Full metadata from centralized extraction

        # 1-3. Centralized extraction: URL query + HTML forms + anchor hrefs
        try:
            state = await browser_manager.capture_state(url)
            html = state.get("html", "")
        except Exception as e:
            logger.warning(f"[{self.name}] Failed to fetch HTML: {e}")
            html = ""

        # Extract URL params even without HTML
        try:
            parsed = urlparse(url)
            url_params = parse_qs(parsed.query)
            for param_name, values in url_params.items():
                all_params[param_name] = values[0] if values else ""
                self._param_methods[param_name] = "GET"
        except Exception as e:
            logger.warning(f"[{self.name}] Failed to parse URL params: {e}")

        if html:
            self._last_discovery_html = html  # Cache for URL resolution

            # Centralized metadata extraction (deterministic ground truth)
            self._param_metadata = extract_param_metadata(html, url)
            for param_name, meta in self._param_metadata.items():
                if param_name not in all_params:
                    all_params[param_name] = meta.get("default_value", "")
                self._param_methods[param_name] = meta["method"]

            # 4. XSS-specific: Extract JavaScript variables (not in shared util)
            try:
                js_var_pattern = r'var\s+(\w+)\s*=\s*["\']([^"\']*)["\']'
                for match in re.finditer(js_var_pattern, html):
                    var_name, var_value = match.groups()
                    if var_name not in all_params and len(var_name) > 2:
                        all_params[var_name] = var_value
            except Exception:
                pass

            # 5. XSS-specific: Extract internal links for DOM XSS coverage
            try:
                soup = BeautifulSoup(html, "html.parser")
                base_domain = urlparse(url).netloc
                internal_urls = set()
                for a_tag in soup.find_all("a", href=True):
                    href = a_tag["href"]
                    if href.startswith(("javascript:", "mailto:", "#", "tel:")):
                        continue
                    link = urljoin(url, href)
                    parsed_link = urlparse(link)
                    if parsed_link.netloc == base_domain and parsed_link.scheme in ("http", "https"):
                        clean_link = f"{parsed_link.scheme}://{parsed_link.netloc}{parsed_link.path}"
                        if clean_link != url.split("?")[0]:
                            internal_urls.add(clean_link)
                self._discovered_internal_urls = list(internal_urls)[:3]
                if self._discovered_internal_urls:
                    logger.info(f"[{self.name}] Discovered {len(self._discovered_internal_urls)} internal URLs for DOM XSS")
            except Exception:
                pass

        # Log detected methods
        post_params = [p for p, m in self._param_methods.items() if m == "POST"]
        if post_params:
            logger.info(f"[{self.name}] 📮 POST params detected: {post_params}")

        logger.info(f"[{self.name}] 🔍 Discovered {len(all_params)} params on {url}: {list(all_params.keys())}")
        return all_params

    async def _discover_params(self) -> List[str]:
        """Discover injectable parameters from the page."""
        from bs4 import BeautifulSoup
        from urllib.parse import urlparse, parse_qs

        discovered = []

        # 1. Extract from URL
        parsed = urlparse(self.url)
        for param in parse_qs(parsed.query).keys():
            discovered.append(param)

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }

        # 2. Extract from HTML forms
        try:
            # Use HTTPClientManager for proper connection management (v2.4)
            async with http_manager.session(ConnectionProfile.STANDARD) as session:
                async with session.get(self.url, headers=headers, ssl=False) as resp:
                    html = await resp.text()

            soup = BeautifulSoup(html, 'html.parser')

            for inp in soup.find_all(['input', 'textarea', 'select']):
                name = inp.get('name')
                if name and name not in discovered:
                    discovered.append(name)

        except Exception as e:
            logger.warning(f"Param discovery error: {e}")

        # 3. Aggressively add common vulnerable parameters (Burp-equivalent)
        # Added (2026-02-01): Even if not found, we test these as they are common hidden vectors
        common_vuln_params = [
            "category", "search", "q", "query", "filter", "sort", 
            "template", "view", "page", "lang", "theme", "type", "action", "mode", "tab"
        ]
        for param in common_vuln_params:
            if param not in discovered:
                discovered.append(param)
                logger.debug(f"[{self.name}] Added common vuln parameter for fuzzed testing: {param}")

        # PRIORITIZE parameters (high-value first)
        return self._prioritize_params(discovered)

    async def _discover_and_test_post_forms(
        self,
        interactsh_url: str,
        screenshots_dir: Path
    ) -> List[XSSFinding]:
        """Discover POST forms and test them for XSS."""
        from bs4 import BeautifulSoup

        findings = []
        html = await self._fetch_page_forms(self.url)
        if not html:
            return findings

        soup = BeautifulSoup(html, 'html.parser')

        for form in soup.find_all('form'):
            form_action, post_params = self._extract_form_data(form, self.url)
            if not post_params:
                continue

            finding = await self._test_post_params(
                form_action, post_params, interactsh_url, screenshots_dir
            )
            if finding:
                findings.append(finding)
                if self._max_impact_achieved:
                    break

        return findings

    async def start_queue_consumer(self, scan_context: str) -> None:
        """TWO-PHASE queue consumer (WET → DRY). Context-aware dedup. NO infinite loop."""
        from bugtrace.agents.specialist_utils import (
            report_specialist_start,
            report_specialist_progress,
            report_specialist_done,
            report_specialist_wet_dry,
            write_dry_file,
        )

        self._queue_mode = True
        self._scan_context = scan_context
        self._v = create_emitter("XSSAgent", self._scan_context)
        logger.info(f"[{self.name}] Starting TWO-PHASE queue consumer (WET → DRY)")

        # v3.2: Load context-aware tech stack for intelligent deduplication
        await self._load_xss_tech_context()

        # Get initial queue depth for telemetry
        queue = queue_manager.get_queue("xss")
        initial_depth = queue.depth()
        report_specialist_start(self.name, queue_depth=initial_depth)
        self._v.emit("exploit.xss.started", {"queue_depth": initial_depth})

        dry_list = await self.analyze_and_dedup_queue()

        # Report WET→DRY metrics for integrity verification
        report_specialist_wet_dry(self.name, initial_depth, len(dry_list) if dry_list else 0)
        write_dry_file(self, dry_list, initial_depth, "xss")

        if not dry_list:
            logger.info(f"[{self.name}] No findings to exploit after deduplication")
            report_specialist_done(self.name, processed=0, vulns=0)
            self._v.emit("exploit.xss.completed", {"processed": 0, "vulns": 0, "reason": "empty_dry_list"})
            return

        results = await self.exploit_dry_list()

        # Confirmed vulns only (not dry candidates). stable 4074425.
        vulns_count = len([r for r in results if r]) if results else 0
        candidates_count = len(self._dry_findings) if hasattr(self, "_dry_findings") else 0

        if results or self._dry_findings:
            # v3.2: Convert XSSFinding dataclasses to dicts for JSON serialization
            # Phase B.3 (Stored XSS) returns dicts, other phases return XSSFinding dataclasses
            findings_as_dicts = [_promote_repro(asdict(r) if is_dataclass(r) else r) for r in results if r] if results else []
            await self._generate_specialist_report(findings_as_dicts)

        # Report completion with final stats
        report_specialist_done(
            self.name,
            processed=len(dry_list),
            vulns=vulns_count
        )
        self._v.emit(
            "exploit.xss.completed",
            {
                "processed": len(dry_list),
                "vulns": vulns_count,
                "candidates": candidates_count,
            },
        )
        logger.info(
            f"[{self.name}] Queue consumer complete: {vulns_count} confirmed findings "
            f"from {candidates_count} candidates"
        )

    async def stop_queue_consumer(self) -> None:
        """Stop queue consumer mode gracefully."""
        try:
            if self._worker_pool:
                await self._worker_pool.stop()
                self._worker_pool = None

            self.event_bus.unsubscribe(
                EventType.WORK_QUEUED_XSS.value,
                self._on_work_queued
            )

            self._queue_mode = False
        finally:
            # Pipeline exit for the queue-driven path (the one the API actually runs).
            # In a finally because the caller gathers this with return_exceptions=True:
            # a failure in worker-pool shutdown would otherwise leak the whole scan's
            # documents for the lifetime of the process.
            freed = release_document_caches()
            logger.info(
                f"[{self.name}] Queue consumer stopped; released document caches: {freed}")

    async def _process_queue_item(self, item: dict) -> Optional[XSSFinding]:
        """
        Process a single item from the xss queue.

        Item structure (from ThinkingConsolidationAgent):
        {
            "finding": {
                "type": "XSS",
                "url": "...",
                "parameter": "...",
                "payload": "...",  # Optional suggested payload
                "context": "...",  # Reflection context
            },
            "priority": 85.5,
            "scan_context": "scan_123",
            "classified_at": 1234567890.0
        }
        """
        finding = item.get("finding", {})
        url = finding.get("url")
        param = finding.get("parameter")

        if not url or not param:
            logger.warning(f"[{self.name}] Invalid queue item: missing url or parameter")
            return None

        # Use existing XSS testing logic
        # Configure self for this specific test
        self.url = url
        self.params = [param]

        # Run validation (reuse existing _test_parameter or similar)
        result = await self._test_single_param_from_queue(url, param, finding)

        return result

    async def _handle_queue_result(self, item: dict, result: Optional[XSSFinding]) -> None:
        """
        Handle completed queue item processing.

        Emits vulnerability_detected event on confirmed findings.
        v3.2: Respects the status already set by _test_payload_from_queue
        (VALIDATED_CONFIRMED, CANDIDATE) instead of re-calculating.
        """
        if result is None:
            return

        # Add to findings list
        self.findings.append(result)

        # v3.2.1: XSSAgent validates everything, no CDP escalation
        validation_status = result.status
        # CDP disabled - all findings go direct to reporting
        needs_cdp = False

        # EXPERT DEDUPLICATION: Check if we already emitted this finding
        # Pass sink/source from evidence for global root cause detection
        _sink = result.evidence.get("sink") if result.evidence else None
        _source = result.evidence.get("source") if result.evidence else None
        fingerprint = self._generate_xss_fingerprint(
            result.url, result.parameter, result.context,
            sink=_sink, source=_source
        )

        # For global XSS (e.g., postMessage->eval from shared JS), group by root cause
        # and track affected URLs — only emit ONE finding per root cause
        if fingerprint[0] == "XSS_GLOBAL":
            if fingerprint in self._global_xss_findings:
                # Already emitted this root cause — just add URL to affected list
                if result.url not in self._global_xss_findings[fingerprint]:
                    self._global_xss_findings[fingerprint].append(result.url)
                logger.info(f"[{self.name}] Global XSS dedup: added {result.url} to root cause {fingerprint[2]} "
                           f"(now {len(self._global_xss_findings[fingerprint])} affected URLs)")
                return  # Don't emit duplicate
            else:
                # First occurrence — track and continue to emit
                logger.info(f"[{self.name}] Global XSS detected: root cause {fingerprint[2]} on {result.url}")

        if fingerprint in self._emitted_findings:
            logger.info(f"[{self.name}] Skipping duplicate XSS finding: {result.url}?{result.parameter} in {result.context} (already reported)")
            return

        # Use validated emit helper (Phase 1 Refactor)
        finding_dict = {
            "type": "XSS",
            "url": result.url,
            "parameter": result.parameter,
            "payload": result.payload,
            "context": result.context,
            "confidence": result.confidence,
            "validation_method": result.validation_method,
            "evidence": dict(result.evidence or {}),
        }
        finding_dict["evidence"].setdefault("validated", True)

        # For global XSS, include affected_urls in evidence
        if fingerprint[0] == "XSS_GLOBAL":
            finding_dict["evidence"]["root_cause"] = fingerprint[2]
            finding_dict["evidence"]["affected_urls"] = [result.url]

        emitted = self._emit_xss_finding(
            finding_dict,
            status=validation_status if isinstance(validation_status, str) else validation_status.value,
            needs_cdp=needs_cdp
        )

        if emitted:
            self._emitted_findings.add(fingerprint)
            if fingerprint[0] == "XSS_GLOBAL":
                self._global_xss_findings[fingerprint] = [result.url]

        logger.info(f"[{self.name}] Confirmed XSS: {result.url}?{result.parameter}")

    async def run_loop(self) -> Dict:
        """Main entry point for XSS scanning."""
        dashboard.current_agent = self.name
        dashboard.log(f"[{self.name}] 🚀 Starting LLM-driven XSS analysis on {self.url}", "INFO")

        # Use captures/ directly - no need for intermediate screenshots/ folder
        screenshots_dir = self.report_dir / "captures"
        screenshots_dir.mkdir(parents=True, exist_ok=True)

        try:
            # Phase 0-1: WAF detection and Interactsh setup
            interactsh_domain = await self._loop_setup_waf_and_interactsh()

            # Phase 2: Discover parameters
            if not await self._loop_discover_params():
                return {"findings": [], "message": "No parameters found"}

            # Phase 3: Test parameters
            await self._loop_test_params(interactsh_domain, screenshots_dir)

            # Phase 3.5: DOM XSS with visual validation
            await self._loop_test_dom_xss(screenshots_dir)

            # Phase 4: Additional vectors
            await self._loop_test_additional_vectors(interactsh_domain, screenshots_dir)

            # Phase 5: Cleanup
            if self.interactsh:
                await self.interactsh.deregister()

            # Return results
            validated_count = len(self.findings)
            logger.info(f"[{self.name}] Returning {validated_count} findings.")
            dashboard.log(f"[{self.name}] ✅ Scan complete. {validated_count} XSS found.", "SUCCESS")

            # v3.2: Base64 encode payloads to prevent JSON escaping issues
            from bugtrace.core.payload_format import encode_finding_payloads
            findings_dicts = [self._finding_to_dict(f) for f in self.findings]
            encoded_findings = [encode_finding_payloads(fd) for fd in findings_dicts]

            return {
                "findings": encoded_findings,
                "validated_count": validated_count,
                "params_tested": len(self.params)
            }

        except Exception as e:
            logger.exception(f"XSSAgent error: {e}")
            dashboard.log(f"[{self.name}] ❌ Error: {e}", "ERROR")
            return {"findings": [], "error": str(e)}

        finally:
            # Pipeline exit: the response bodies memoized by the confirmation predicates
            # are dead weight from here on, and this process outlives the scan.
            freed = release_document_caches()
            logger.debug(
                f"[{self.name}] Released document caches at run_loop exit: {freed}")

    def _create_finding_from_interactsh(
        self,
        param: str,
        payload: str,
        evidence: Dict,
        screenshots_dir: Path
    ) -> XSSFinding:
        """Create XSSFinding from Interactsh confirmation."""
        return self._create_xss_finding(
            param=param,
            payload=payload,
            context="Interactsh OOB Confirmation",
            validation_method="interactsh_oob",
            evidence=evidence,
            confidence=1.0,
            reflection_type="oob",
            surviving_chars="",
            successful_payloads=[payload],
            injection_ctx=None,
            bypass_technique="oob_callback",
            bypass_explanation="Target made HTTP request to Interactsh domain, confirming JS execution"
        )

    def _write_xss_coverage(self) -> Optional[Path]:
        """Persist the per-parameter coverage artifact. Diagnostics — never a finding.

        Deliberately NOT written into specialists/{results,dry,wet} (four generic loaders
        ingest every dict there as a FINDING) nor as specialists/*_report.json
        (reporting.py globs that), and never at the reports ROOT, which is what
        self.report_dir defaults to before the team injects the real scan directory.
        """
        if not settings.XSS_COVERAGE_ENABLED or not getattr(self, "_xss_coverage", None):
            return None
        path = xss_coverage.resolve_coverage_path(
            getattr(self, "report_dir", None),
            settings.REPORT_DIR,
            settings.XSS_COVERAGE_SUBDIR,
            settings.XSS_COVERAGE_FILENAME,
        )
        if path is None:
            logger.warning(
                f"[{self.name}] XSS coverage NOT written: report_dir "
                f"{getattr(self, 'report_dir', None)!r} + subdir "
                f"{settings.XSS_COVERAGE_SUBDIR!r} is not a safe location "
                f"({len(self._xss_coverage)} parameter records dropped)"
            )
            return None
        document = xss_coverage.build_document(
            self._xss_coverage,
            scan_url=getattr(self, "url", "") or "",
            max_params=settings.XSS_COVERAGE_MAX_PARAMS,
        )
        if document["truncated"]:
            logger.warning(
                f"[{self.name}] XSS coverage truncated: kept "
                f"{document['params_recorded']} of {document['params_total']} parameter "
                f"records (XSS_COVERAGE_MAX_PARAMS={settings.XSS_COVERAGE_MAX_PARAMS})"
            )
        written = xss_coverage.write_coverage_document(path, document)
        if written is None:
            logger.warning(f"[{self.name}] XSS coverage write failed: {path}")
            return None
        s = document["summary"]
        logger.info(
            f"[{self.name}] XSS coverage: {s['params_tested']} params — "
            f"{s['confirmed']} confirmed, {s['reflected_but_unconfirmed']} reflected but "
            f"unconfirmed, {s['no_reflection']} no reflection, {s['no_response']} no "
            f"response → {written}"
        )
        return written

    async def _generate_specialist_report(self, findings: List[Dict]) -> str:
        import json, aiofiles
        from datetime import datetime
        from bugtrace.core.config import settings
        from bugtrace.core.payload_format import encode_finding_payloads

        # v3.2: Write to specialists/results/ for unified wet→dry→results flow
        scan_dir = getattr(self, 'report_dir', None) or (settings.BASE_DIR / "reports" / self._scan_context.split("/")[-1])
        results_dir = scan_dir / "specialists" / "results"
        results_dir.mkdir(parents=True, exist_ok=True)
        report_path = results_dir / "xss_results.json"

        # Attach a real PoC screenshot to every validated XSS that lacks one.
        # This is the SINGLE chokepoint that feeds the report (xss_results.json ->
        # validated_findings.json), so the screenshot reliably reaches the report
        # — capturing at emit time did not, because the report is rebuilt from
        # these rich finding dicts, not the emitted event. The findings already
        # carry exploit_url, so the capture hits the exact PoC URL.
        for _f in findings:
            try:
                if "xss" in str(_f.get("type", "")).lower() and _f.get("validated"):
                    await self._capture_proof_screenshot(_f)
            except Exception:
                pass

        # v3.2: Base64 encode payloads to prevent JSON escaping issues
        # Complex payloads with <, >, ", ' break JSON without encoding
        encoded_findings = [encode_finding_payloads(f) for f in findings]

        async with aiofiles.open(report_path, 'w') as f:
            await f.write(json.dumps({
                "agent": self.name,
                "timestamp": datetime.now().isoformat(),
                "scan_context": self._scan_context,
                "phase_a": {"wet_count": len(self._dry_findings), "dry_count": len(self._dry_findings), "dedup_method": "llm_context_aware"},
                "phase_b": {"validated_count": len([x for x in findings if x.get("validated")]), "total_findings": len(findings)},
                "findings": encoded_findings,
                "_encoding_note": "payload fields with special chars are base64 encoded as payload_b64"
            }, indent=2))
        logger.info(f"[{self.name}] Report saved: {report_path}")
        return str(report_path)

    def _smart_build_finding_from_payload(
        self,
        param: str,
        sp: Dict,
        payload: str,
        evidence: Dict,
        reflection_type: str,
        surviving_chars: str,
        injection_ctx: Any
    ) -> XSSFinding:
        """Build XSS finding from validated smart payload."""
        return self._create_xss_finding(
            param, payload, sp.get("reasoning", "LLM Smart Analysis"),
            "llm_smart_analysis", evidence, sp.get("confidence", 0.9),
            reflection_type, surviving_chars, [payload],
            injection_ctx, "context_aware_payload",
            sp.get("reasoning", "LLM generated specific payload for this context.")
        )

    async def _smart_validate_and_build_finding(
        self,
        param: str,
        sp: Dict,
        payload: str,
        screenshots_dir: Path,
        reflection_type: str,
        surviving_chars: str,
        injection_ctx: Any
    ) -> Optional[XSSFinding]:
        """Validate smart payload and build finding if successful."""
        response_html = await self._send_payload(param, payload)
        if not response_html:
            return None

        validated, evidence = await self._validate(
            param, payload, response_html, screenshots_dir
        )
        if not validated:
            return None

        finding_data = {
            "evidence": evidence,
            "screenshot_path": evidence.get("screenshot_path"),
            "context": sp.get("reasoning", "LLM Smart Analysis"),
            "reflection_context": reflection_type
        }

        if not self._should_create_finding(finding_data):
            return None

        return self._smart_build_finding_from_payload(
            param, sp, payload, evidence, reflection_type,
            surviving_chars, injection_ctx
        )

    def _create_xss_finding(
        self, param: str, payload: str, context: str, validation_method: str,
        evidence: Dict, confidence: float, reflection_type: str, surviving_chars: str,
        successful_payloads: List[str], injection_ctx: Any, bypass_technique: str,
        bypass_explanation: str
    ) -> XSSFinding:
        """Pure assembly: xss.finding_builder.create_reflected_xss_finding."""
        from bugtrace.agents.xss.finding_builder import create_reflected_xss_finding

        status, validated = self._determine_validation_status(
            {"evidence": evidence, "reflection_context": reflection_type}
        )
        return create_reflected_xss_finding(
            url=self.url,
            parameter=param,
            payload=payload,
            context=context,
            validation_method=validation_method,
            evidence=evidence,
            confidence=confidence,
            status=status,
            validated=validated,
            screenshot_path=evidence.get("screenshot_path"),
            reflection_context=reflection_type,
            surviving_chars=surviving_chars,
            successful_payloads=successful_payloads,
            injection_context_type=injection_ctx.type,
            vulnerable_code_snippet=injection_ctx.code_snippet,
            server_escaping=getattr(self, "_last_server_escaping", {}),
            escape_bypass_technique=bypass_technique,
            bypass_explanation=bypass_explanation,
            exploit_url=self.build_exploit_url(self.url, param, payload, encoded=False),
            exploit_url_encoded=self.build_exploit_url(
                self.url, param, payload, encoded=True
            ),
            verification_methods=self.generate_verification_methods(
                self.url, param, injection_ctx, payload
            ),
            verification_warnings=self.get_verification_warnings(injection_ctx),
            reproduction_steps=self.generate_repro_steps(
                self.url, param, injection_ctx, payload
            ),
            finding_cls=XSSFinding,
        )

    def _create_authority_finding(
        self, param: str, payload: str, ref_context: str, injection_ctx: Any
    ) -> XSSFinding:
        """Pure assembly: xss.finding_builder.create_authority_xss_finding."""
        from bugtrace.agents.xss.finding_builder import create_authority_xss_finding

        return create_authority_xss_finding(
            url=self.url,
            parameter=param,
            payload=payload,
            ref_context=ref_context,
            injection_context_type=injection_ctx.type,
            vulnerable_code_snippet=injection_ctx.code_snippet,
            server_escaping=getattr(self, "_last_server_escaping", {}),
            exploit_url=self.build_exploit_url(self.url, param, payload, encoded=False),
            exploit_url_encoded=self.build_exploit_url(
                self.url, param, payload, encoded=True
            ),
            verification_methods=self.generate_verification_methods(
                self.url, param, injection_ctx, payload
            ),
            verification_warnings=self.get_verification_warnings(injection_ctx),
            reproduction_steps=self.generate_repro_steps(
                self.url, param, injection_ctx, payload
            ),
            finding_cls=XSSFinding,
        )
