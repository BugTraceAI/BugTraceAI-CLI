from typing import Dict, List, Optional, Any
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import aiohttp
from bugtrace.agents.base import BaseAgent
from bugtrace.agents.worker_pool import WorkerPool, WorkerConfig
from bugtrace.core.ui import dashboard
from bugtrace.core.job_manager import JobStatus
from bugtrace.core.event_bus import EventType
from bugtrace.core.config import settings
from bugtrace.utils.logger import get_logger
from bugtrace.tools.external import external_tools
from bugtrace.core.http_orchestrator import orchestrator, DestinationType
from bugtrace.reporting.standards import (
    get_cwe_for_vuln,
    get_remediation_for_vuln,
    normalize_severity,
)
from bugtrace.core.validation_status import ValidationStatus, requires_cdp_validation

logger = get_logger("agents.idor")

class IDORAgent(BaseAgent):
    """
    Specialist Agent for Insecure Direct Object Reference (IDOR).
    Target: Numeric ID parameters.
    Strategy: Test ID-1, ID+1 and compare with baseline.
    """

    def __init__(self, url: str, params: List[Dict] = None, report_dir: Path = None, event_bus=None):
        super().__init__(
            name="IDORAgent",
            role="IDOR Specialist",
            event_bus=event_bus,
            agent_id="idor_agent"
        )
        self.url = url
        self.params = params or []
        self.report_dir = report_dir or Path("./reports")

        # Deduplication
        self._tested_params = set()

        # Queue consumption mode (Phase 20)
        self._queue_mode = False

        # Expert deduplication: Track emitted findings by fingerprint
        self._emitted_findings: set = set()  # Agent-specific fingerprint
        self._worker_pool: Optional[WorkerPool] = None
        self._scan_context: str = ""

        # WET → DRY transformation (Two-phase processing)
        self._dry_findings: List[Dict] = []  # Dedup'd findings after Phase A
        
    def _determine_validation_status(self, evidence_type: str, confidence: str) -> str:
        """
        TIER 1 (VALIDATED_CONFIRMED):
            - Cookie tampering success (horizontal privilege escalation)
            - HIGH confidence differential with sensitive data markers

        TIER 2 (PENDING_VALIDATION):
            - MEDIUM/LOW confidence differential analysis
            - Needs human/CDP verification
        """
        if evidence_type == "cookie_tampering":
            return "VALIDATED_CONFIRMED"

        if evidence_type == "differential" and confidence == "HIGH":
            return "VALIDATED_CONFIRMED"

        return "PENDING_VALIDATION"
        
    def _create_idor_finding(self, hit: Dict, param: str, original_value: str) -> Dict:
        """Create IDOR finding from fuzzer hit."""
        confidence_level = "HIGH" if hit["severity"] == "CRITICAL" else "MEDIUM"
        return {
            "type": "IDOR",
            "url": self.url,
            "parameter": param,
            "payload": hit["id"],
            "description": f"IDOR vulnerability detected on ID {hit['id']}. Differed from baseline ID {original_value}. Status: {hit['status_code']}. Contains sensitive data: {hit.get('contains_sensitive')}",
            "severity": hit["severity"].upper() if isinstance(hit["severity"], str) else hit["severity"],
            "validated": hit["severity"] == "CRITICAL",
            "evidence": f"Status {hit['status_code']}. Diff Type: {hit['diff_type']}. Sensitive: {hit.get('contains_sensitive')}",
            "status": self._determine_validation_status("differential", confidence_level),
            "reproduction": f"# Compare responses:\ncurl '{self.url}?{param}={original_value}'\ncurl '{self.url}?{param}={hit['id']}'",
            "cwe_id": get_cwe_for_vuln("IDOR"),
            "remediation": get_remediation_for_vuln("IDOR"),
            "cve_id": "N/A",
            "http_request": f"GET {self.url}?{param}={hit['id']}",
            "http_response": f"Status: {hit['status_code']}, Diff: {hit['diff_type']}, Sensitive data: {hit.get('contains_sensitive', False)}",
        }

    async def run_loop(self) -> Dict:
        dashboard.current_agent = self.name
        dashboard.log(f"[{self.name}] 🚀 Starting IDOR analysis on {self.url}", "INFO")

        all_findings = []
        async with orchestrator.session(DestinationType.TARGET) as session:
            for item in self.params:
                finding = await self._test_idor_param(item)
                if finding:
                    all_findings.append(finding)

        return {"vulnerable": len(all_findings) > 0, "findings": all_findings}

    async def _test_idor_param(self, item: dict):
        """Test a single parameter for IDOR vulnerability."""
        param = item.get("parameter")
        original_value = str(item.get("original_value", ""))

        # Guard: Skip if no parameter
        if not param:
            return None

        logger.info(f"[{self.name}] Testing IDOR on {param}={original_value}")

        # Guard: Skip if already tested
        key = f"{self.url}#{param}"
        if key in self._tested_params:
            logger.info(f"[{self.name}] Skipping {param} - already tested")
            return None

        # High-Performance Go IDOR Fuzzer
        dashboard.log(f"[{self.name}] 🚀 Launching Go IDOR Fuzzer on '{param}' (Range 1-1000)...", "INFO")
        go_result = await external_tools.run_go_idor_fuzzer(self.url, param, id_range="1-1000", baseline_id=original_value)

        self._tested_params.add(key)

        # Guard: Skip if no hits
        if not go_result or not go_result.get("hits"):
            logger.info(f"[{self.name}] ✅ No IDOR found on '{param}' - semantic analysis passed")
            return None

        # Process first hit
        hit = go_result["hits"][0]
        dashboard.log(f"[{self.name}] 🚨 IDOR HIT: ID {hit['id']} ({hit['severity']})", "CRITICAL")
        return self._create_idor_finding(hit, param, original_value)

    async def _fetch(self, session, val, param_name, original_val) -> Optional[str]:
        text, _ = await self._fetch_full(session, val, param_name, original_val)
        return text

    async def _fetch_full(self, session, val, param_name, original_val):
        target = self._inject(val, param_name, original_val)
        try:
            dashboard.update_task(f"IDOR:{param_name}", status=f"Probing ID {val}")
            async with session.get(target, timeout=5) as resp:
                return await resp.text(), resp.status
        except Exception as e:
            logger.debug(f"_fetch failed: {e}")
            return None, 0

    def _inject(self, val, param_name, original_val):
        parsed = urlparse(self.url)
        path = parsed.path
        
        # 1. Path-based IDOR
        if original_val and str(original_val) in path:
            import re
            new_path = re.sub(rf'(^|/){re.escape(str(original_val))}(/|$)', rf'\g<1>{val}\g<2>', path)
            if new_path != path:
                return urlunparse((parsed.scheme, parsed.netloc, new_path, parsed.params, parsed.query, parsed.fragment))

        # 2. Query-based IDOR
        q = parse_qs(parsed.query)
        q[param_name] = [val]
        new_query = urlencode(q, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, path, parsed.params, new_query, parsed.fragment))

    async def _fetch_with_cookie(self, session, val, param_name, original_val, cookies):
        target = self._inject(val, param_name, original_val)
        try:
            dashboard.update_task(f"IDOR:{param_name}", status=f"Tampering Cookie for ID {val}")
            async with session.get(target, cookies=cookies, timeout=5) as resp:
                return await resp.text()
        except Exception as e:
            logger.debug(f"_fetch_with_cookie failed: {e}")
            return None

    # =========================================================================
    # Queue Consumption Mode (Phase 20) - WET→DRY Two-Phase Processing
    # =========================================================================

    async def analyze_and_dedup_queue(self) -> List[Dict]:
        """Phase A: Global analysis of WET list with LLM-powered deduplication."""
        import asyncio
        import time
        from bugtrace.core.queue import queue_manager

        logger.info(f"[{self.name}] ===== PHASE A: Analyzing WET list =====")

        queue = queue_manager.get_queue("idor")
        wet_findings = []

        # Wait for queue items (max 300s)
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

        # Drain ALL items
        empty_count = 0
        max_empty_checks = 10

        while empty_count < max_empty_checks:
            item = await queue.dequeue(timeout=0.5)
            if item is None:
                empty_count += 1
                await asyncio.sleep(0.5)
                continue

            empty_count = 0
            finding = item.get("finding", {})
            url = finding.get("url", "")
            parameter = finding.get("parameter", "")

            if url and parameter:
                wet_findings.append({
                    "url": url,
                    "parameter": parameter,
                    "original_value": finding.get("original_value", ""),
                    "finding": finding,
                    "scan_context": item.get("scan_context", self._scan_context)
                })

        logger.info(f"[{self.name}] Phase A: Drained {len(wet_findings)} WET findings from queue")

        if not wet_findings:
            return []

        # LLM dedup with fallback
        try:
            dry_list = await self._llm_analyze_and_dedup(wet_findings, self._scan_context)
        except Exception as e:
            logger.error(f"[{self.name}] LLM dedup failed: {e}. Falling back to fingerprint dedup")
            dry_list = self._fallback_fingerprint_dedup(wet_findings)

        self._dry_findings = dry_list
        dup_count = len(wet_findings) - len(dry_list)
        logger.info(f"[{self.name}] Phase A: Deduplication complete. {len(wet_findings)} WET → {len(dry_list)} DRY ({dup_count} duplicates removed)")

        return dry_list

    async def _llm_analyze_and_dedup(self, wet_findings: List[Dict], context: str) -> List[Dict]:
        """LLM-powered intelligent deduplication with agent-specific rules."""
        from bugtrace.core.llm_client import llm_client
        import json

        prompt = f"""You are analyzing {len(wet_findings)} potential IDOR findings.

DEDUPLICATION RULES FOR IDOR:
- Same endpoint + resource type = DUPLICATE
- Example: /api/users?id=123 and /api/users?id=456 = DUPLICATE (keep 1)
- Different endpoint = DIFFERENT (/api/users vs /api/orders)

WET LIST:
{json.dumps(wet_findings, indent=2)}

Return JSON array of UNIQUE findings only:
{{"findings": [...]}}
"""

        response = await llm_client.generate(
            prompt=prompt,
            system_prompt="You are an expert security analyst specializing in IDOR deduplication.",
            module_name="IDOR_DEDUP",
            temperature=0.2
        )

        try:
            result = json.loads(response)
            return result.get("findings", wet_findings)
        except json.JSONDecodeError:
            logger.warning(f"[{self.name}] LLM returned invalid JSON, using fallback")
            return self._fallback_fingerprint_dedup(wet_findings)

    def _fallback_fingerprint_dedup(self, wet_findings: List[Dict]) -> List[Dict]:
        """Fallback fingerprint-based deduplication (no LLM)."""
        seen_fingerprints = set()
        dry_list = []

        for finding_data in wet_findings:
            url = finding_data.get("url", "")
            parameter = finding_data.get("parameter", "")

            if not url or not parameter:
                continue

            fingerprint = self._generate_idor_fingerprint(url, parameter)

            if fingerprint not in seen_fingerprints:
                seen_fingerprints.add(fingerprint)
                dry_list.append(finding_data)

        return dry_list

    async def exploit_dry_list(self) -> List[Dict]:
        """Phase B: Exploit DRY list (deduplicated findings only)."""
        logger.info(f"[{self.name}] ===== PHASE B: Exploiting DRY list =====")
        logger.info(f"[{self.name}] Phase B: Exploiting {len(self._dry_findings)} DRY findings...")

        validated_findings = []

        for idx, finding_data in enumerate(self._dry_findings, 1):
            url = finding_data.get("url", "")
            parameter = finding_data.get("parameter", "")
            original_value = finding_data.get("original_value", "")

            logger.info(f"[{self.name}] Phase B [{idx}/{len(self._dry_findings)}]: Testing {url}?{parameter}")

            try:
                self.url = url
                result = await self._test_single_param_from_queue(url, parameter, original_value, finding_data.get("finding", {}))

                if result and result.get("validated"):
                    validated_findings.append(result)

                    # FINGERPRINT CHECK
                    fingerprint = self._generate_idor_fingerprint(url, parameter)

                    if fingerprint not in self._emitted_findings:
                        self._emitted_findings.add(fingerprint)

                        if self.event_bus and settings.WORKER_POOL_EMIT_EVENTS:
                            status = result.get("status", ValidationStatus.VALIDATED_CONFIRMED.value)

                            await self.event_bus.emit(EventType.VULNERABILITY_DETECTED, {
                                "specialist": "idor",
                                "finding": {
                                    "type": "IDOR",
                                    "url": result.get("url"),
                                    "parameter": result.get("parameter"),
                                    "payload": result.get("payload"),
                                    "severity": result.get("severity"),
                                },
                                "status": status,
                                "validation_requires_cdp": status == ValidationStatus.PENDING_VALIDATION.value,
                                "scan_context": self._scan_context,
                            })

                        logger.info(f"[{self.name}] ✅ Emitted unique IDOR finding: {url}?{parameter}")
                    else:
                        logger.debug(f"[{self.name}] ⏭️  Skipped duplicate: {fingerprint}")

            except Exception as e:
                logger.error(f"[{self.name}] Phase B [{idx}/{len(self._dry_findings)}]: Attack failed: {e}")
                continue

        logger.info(f"[{self.name}] Phase B: Exploitation complete. {len(validated_findings)} validated findings")

        return validated_findings

    async def _generate_specialist_report(self, findings: List[Dict]) -> str:
        """Generate specialist report after exploitation."""
        import json
        import aiofiles
        from datetime import datetime
        from bugtrace.core.config import settings

        scan_id = self._scan_context.split("/")[-1]
        scan_dir = settings.BASE_DIR / "reports" / scan_id
        specialists_dir = scan_dir / "specialists"
        specialists_dir.mkdir(parents=True, exist_ok=True)

        report = {
            "agent": f"{self.name}",
            "timestamp": datetime.now().isoformat(),
            "scan_context": self._scan_context,
            "phase_a": {
                "wet_count": len(self._dry_findings) + (len(findings) if findings else 0),
                "dry_count": len(self._dry_findings),
                "dedup_method": "llm_with_fingerprint_fallback"
            },
            "phase_b": {
                "validated_count": len([f for f in findings if f.get("validated")]),
                "pending_count": len([f for f in findings if not f.get("validated")]),
                "total_findings": len(findings)
            },
            "findings": findings
        }

        report_path = specialists_dir / "idor_report.json"
        async with aiofiles.open(report_path, 'w') as f:
            await f.write(json.dumps(report, indent=2))

        logger.info(f"[{self.name}] Specialist report saved: {report_path}")

        return str(report_path)

    async def start_queue_consumer(self, scan_context: str) -> None:
        """TWO-PHASE queue consumer (WET → DRY). NO infinite loop."""
        self._queue_mode = True
        self._scan_context = scan_context

        logger.info(f"[{self.name}] Starting TWO-PHASE queue consumer (WET → DRY)")

        # PHASE A: ANALYSIS & DEDUPLICATION
        logger.info(f"[{self.name}] ===== PHASE A: Analyzing WET list =====")
        dry_list = await self.analyze_and_dedup_queue()

        if not dry_list:
            logger.info(f"[{self.name}] No findings to exploit after deduplication")
            return

        # PHASE B: EXPLOITATION
        logger.info(f"[{self.name}] ===== PHASE B: Exploiting DRY list =====")
        results = await self.exploit_dry_list()

        # REPORTING
        if results or self._dry_findings:
            await self._generate_specialist_report(results)

        logger.info(f"[{self.name}] Queue consumer complete: {len(results)} validated findings")

    async def stop_queue_consumer(self) -> None:
        """Stop queue consumer mode gracefully."""
        if self._worker_pool:
            await self._worker_pool.stop()
            self._worker_pool = None

        if self.event_bus:
            self.event_bus.unsubscribe(
                EventType.WORK_QUEUED_IDOR.value,
                self._on_work_queued
            )

        self._queue_mode = False
        logger.info(f"[{self.name}] Queue consumer stopped")

    async def _on_work_queued(self, data: dict) -> None:
        """Handle work_queued_idor notification (logging only)."""
        logger.debug(f"[{self.name}] Work queued: {data.get('finding', {}).get('url', 'unknown')}")

    async def _process_queue_item(self, item: dict) -> Optional[Dict]:
        """
        Process a single item from the idor queue.

        Item structure (from ThinkingConsolidationAgent):
        {
            "finding": {
                "type": "IDOR",
                "url": "...",
                "parameter": "...",
                "original_value": "...",  # Current ID value
            },
            "priority": 85.5,
            "scan_context": "scan_123",
            "classified_at": 1234567890.0
        }
        """
        finding = item.get("finding", {})
        url = finding.get("url")
        param = finding.get("parameter")
        original_value = finding.get("original_value", "")

        if not url or not param:
            logger.warning(f"[{self.name}] Invalid queue item: missing url or parameter")
            return None

        # Configure self for this specific test
        self.url = url

        # Run validation using existing IDOR testing logic
        return await self._test_single_param_from_queue(url, param, original_value, finding)

    async def _test_single_param_from_queue(
        self, url: str, param: str, original_value: str, finding: dict
    ) -> Optional[Dict]:
        """
        Test a single parameter from queue for IDOR.

        Uses existing validation pipeline optimized for queue processing.
        """
        try:
            # Use existing IDOR testing logic via _test_idor_param
            item = {"parameter": param, "original_value": original_value}
            return await self._test_idor_param(item)
        except Exception as e:
            logger.error(f"[{self.name}] Queue item test failed: {e}")
            return None

    def _generate_idor_fingerprint(self, url: str, resource_type: str) -> tuple:
        """
        Generate IDOR finding fingerprint for expert deduplication.

        Returns:
            Tuple fingerprint for deduplication
        """
        from urllib.parse import urlparse

        parsed = urlparse(url)
        normalized_path = parsed.path.rstrip('/')

        # IDOR signature: Endpoint + resource type (parameter)
        fingerprint = ("IDOR", parsed.netloc, normalized_path, resource_type)

        return fingerprint

    async def _handle_queue_result(self, item: dict, result: Optional[Dict]) -> None:
        """
        Handle completed queue item processing.

        Emits vulnerability_detected event on confirmed findings.
        Uses centralized validation status to determine if CDP validation is needed.
        """
        if result is None:
            return

        # Use centralized validation status for proper tagging
        # IDOR with differential analysis may need human verification
        finding_data = {
            "context": "idor_differential",
            "payload": result.get("payload", ""),
            "validation_method": "idor_fuzzer",
            "evidence": {"diff_type": result.get("evidence", "")},
        }
        needs_cdp = requires_cdp_validation(finding_data)

        # IDOR-specific edge case: Response differs but no clear user data markers
        status = result.get("status", "PENDING_VALIDATION")
        if status == "PENDING_VALIDATION":
            # IDOR findings without clear PII/user data markers need validation
            needs_cdp = True

        # EXPERT DEDUPLICATION: Check if we already emitted this finding
        url = result.get("url")
        parameter = result.get("parameter")
        fingerprint = self._generate_idor_fingerprint(url, parameter)

        if fingerprint in self._emitted_findings:
            logger.info(f"[{self.name}] Skipping duplicate IDOR finding (already reported)")
            return

        # Mark as emitted
        self._emitted_findings.add(fingerprint)

        # Emit vulnerability_detected event
        if self.event_bus and settings.WORKER_POOL_EMIT_EVENTS:
            await self.event_bus.emit(EventType.VULNERABILITY_DETECTED, {
                "specialist": "idor",
                "finding": {
                    "type": "IDOR",
                    "url": result.get("url"),
                    "parameter": result.get("parameter"),
                    "payload": result.get("payload"),
                },
                "status": status,
                "validation_requires_cdp": needs_cdp,
                "scan_context": self._scan_context,
            })

        logger.info(f"[{self.name}] Confirmed IDOR: {result.get('url')}?{result.get('parameter')}")

    def get_queue_stats(self) -> dict:
        """Get queue consumer statistics."""
        if not self._worker_pool:
            return {"mode": "direct", "queue_mode": False}

        return {
            "mode": "queue",
            "queue_mode": True,
            "worker_stats": self._worker_pool.get_stats(),
        }
