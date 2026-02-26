"""
SSRF specialist agent -- thin orchestrator.

All PURE logic lives in ``detection.py``.
This module contains **only** the I/O layer: HTTP requests, queue
management, file I/O, LLM calls, and event emission.
"""
import asyncio
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import aiohttp

from bugtrace.agents.base import BaseAgent
from bugtrace.agents.worker_pool import WorkerPool, WorkerConfig
from bugtrace.core.queue import queue_manager
from bugtrace.core.event_bus import EventType
from bugtrace.core.config import settings
from bugtrace.core.job_manager import JobStatus
from bugtrace.core.ui import dashboard
from bugtrace.core.validation_status import ValidationStatus, requires_cdp_validation
from bugtrace.core.verbose_events import create_emitter
from bugtrace.utils.logger import get_logger
from bugtrace.tools.external import external_tools
from bugtrace.core.http_orchestrator import orchestrator, DestinationType
from bugtrace.reporting.standards import (
    get_cwe_for_vuln,
    get_remediation_for_vuln,
    normalize_severity,
)

# v3.2.0: Import TechContextMixin for context-aware detection
from bugtrace.agents.mixins.tech_context import TechContextMixin

# Import PURE functions from sibling module
from bugtrace.agents.ssrf.detection import (
    validate_before_emit,
    determine_validation_status,
    get_validation_status,
    generate_ssrf_fingerprint,
    fallback_fingerprint_dedup,
    build_queue_evidence,
)

logger = get_logger("agents.ssrf")


class SSRFAgent(BaseAgent, TechContextMixin):
    """
    Specialist Agent for Server-Side Request Forgery (SSRF).
    Target: Parameters containing URLs or likely to trigger outbound requests.
    """

    def __init__(self, url: str, params: List[str] = None, report_dir: Path = None, event_bus: Any = None):
        super().__init__(
            name="SSRFAgent",
            role="SSRF & Outbound Specialist",
            event_bus=event_bus,
            agent_id="ssrf_specialist"
        )
        self.url = url
        self.params = params or []
        self.report_dir = report_dir or Path("./reports")

        # Deduplication
        self._tested_params = set()

        # Queue consumption mode (Phase 20)
        self._queue_mode = False
        self._worker_pool: Optional[WorkerPool] = None
        self._scan_context: str = ""

        # Expert deduplication: Track emitted findings by fingerprint
        self._emitted_findings: set = set()

        # WET -> DRY transformation (Two-phase processing)
        self._dry_findings: List[Dict] = []

        # v3.2.0: Context-aware tech stack (loaded in start_queue_consumer)
        self._tech_stack_context: Dict = {}
        self._ssrf_prime_directive: str = ""

    # =========================================================================
    # FINDING VALIDATION (delegates to PURE function)
    # =========================================================================

    def _validate_before_emit(self, finding: Dict) -> Tuple[bool, str]:
        """SSRF-specific validation before emitting finding."""
        return validate_before_emit(finding, super()._validate_before_emit)

    def _emit_ssrf_finding(self, finding_dict: Dict, scan_context: str = None) -> Optional[Dict]:
        """Helper to emit SSRF finding using BaseAgent.emit_finding() with validation."""
        if "type" not in finding_dict:
            finding_dict["type"] = "SSRF"
        if scan_context:
            finding_dict["scan_context"] = scan_context
        finding_dict["agent"] = self.name
        return self.emit_finding(finding_dict)

    # =========================================================================
    # PAYLOAD TESTING (I/O)
    # =========================================================================

    async def _test_with_go_fuzzer(self, param: str) -> list:  # I/O
        """Test parameter with Go SSRF fuzzer."""
        findings = []
        dashboard.log(f"[{self.name}] Launching Go SSRF Fuzzer on '{param}'...", "INFO")
        if hasattr(self, '_v'):
            self._v.emit("exploit.specialist.go_fuzzer", {"agent": "SSRF", "param": param, "url": self.url})
        go_result = await external_tools.run_go_ssrf_fuzzer(self.url, param)

        if go_result and go_result.get("hits"):
            for hit in go_result["hits"]:
                if hasattr(self, '_v'):
                    self._v.emit("exploit.specialist.signature_match", {
                        "agent": "SSRF", "param": param,
                        "payload": hit["payload"][:100], "method": "go_fuzzer",
                    })
                dashboard.log(f"[{self.name}] SSRF HIT: {hit['payload']} ({hit['severity']})", "CRITICAL")
                findings.append({
                    "type": "SSRF",
                    "param": param,
                    "payload": hit["payload"],
                    "severity": hit["severity"].upper(),
                    "reason": hit["reason"],
                    "status": "VALIDATED_CONFIRMED",
                    "validated": True,
                    "cwe_id": get_cwe_for_vuln("SSRF"),
                    "remediation": get_remediation_for_vuln("SSRF"),
                    "cve_id": "N/A",
                    "http_request": f"GET {self.url}?{param}={hit['payload']}",
                    "http_response": hit.get("response", "Callback or internal response detected"),
                })
        return findings

    async def _test_with_llm_strategy(self, param: str) -> list:  # I/O
        """Test parameter with LLM-generated payloads."""
        findings = []
        dashboard.log(f"[{self.name}] Requesting LLM bypass strategy for '{param}'...", "INFO")
        strategy = await self._llm_get_strategy(param)

        if not strategy or "payloads" not in strategy:
            return findings

        return await self._test_strategy_payloads(strategy, param, findings)

    async def _test_strategy_payloads(self, strategy: Dict, param: str, findings: List) -> List:  # I/O
        """Test each payload in the strategy."""
        for payload_item in strategy["payloads"]:
            payload = payload_item.get("payload")
            if not payload:
                continue

            if hasattr(self, '_v'):
                self._v.progress("exploit.specialist.progress", {
                    "agent": "SSRF", "param": param, "payload": payload[:80],
                }, every=50)

            res = await self._test_payload(param, payload)
            if res and determine_validation_status(res):
                if hasattr(self, '_v'):
                    self._v.emit("exploit.specialist.signature_match", {
                        "agent": "SSRF", "param": param,
                        "payload": payload[:100], "method": "llm_strategy",
                    })
                findings.append({
                    "type": "SSRF",
                    "param": param,
                    "payload": payload,
                    "severity": "HIGH",
                    "reason": "Confirmed via LLM-designed payload",
                    "status": "VALIDATED_CONFIRMED",
                    "validated": True,
                    "cwe_id": get_cwe_for_vuln("SSRF"),
                    "remediation": get_remediation_for_vuln("SSRF"),
                    "cve_id": "N/A",
                    "http_request": f"GET {self.url}?{param}={payload}",
                    "http_response": res.get("text", "")[:200],
                })
                break
        return findings

    async def _test_payload(self, param: str, payload: str) -> Optional[Dict]:  # I/O
        """Injects payload and returns results if interesting."""
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)
        params[param] = [payload]

        test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

        try:
            async with orchestrator.session(DestinationType.TARGET) as session:
                start_time = asyncio.get_event_loop().time()
                async with session.get(test_url, timeout=5) as response:
                    text = await response.text()
                    elapsed = asyncio.get_event_loop().time() - start_time

                    return {
                        "param": param,
                        "payload": payload,
                        "status": response.status,
                        "elapsed": elapsed,
                        "text": text,
                        "headers": dict(response.headers),
                    }
        except Exception as e:
            logger.error(f"Error testing payload {payload}: {e}", exc_info=True)
            return None

    async def _llm_get_strategy(self, param: str) -> Dict:  # I/O
        """Asks LLM for best SSRF payloads based on context."""
        from bugtrace.core.llm_client import llm_client

        prompt = f"""
        Act as a SSRF Specialist.
        Target URL: {self.url}
        Vulnerable Parameter: {param}

        Provide 5 specialized SSRF payloads (Cloud metadata, bypasses, internal ports).
        Return in JSON:
        {{
          "thought": "reasons for these payloads",
          "payloads": [
             {{"payload": "http://...", "desc": "why this"}}
          ]
        }}
        """

        try:
            res = await llm_client.generate(prompt, module_name="SSRF_AGENT")
            from bugtrace.utils.parsers import XmlParser
            json_str = XmlParser.extract_tag(res, "json") or res
            import json
            json_str = json_str.replace("```json", "").replace("```", "").strip()
            return json.loads(json_str)
        except Exception as e:
            logger.debug(f"operation failed: {e}")
            return {}

    # =========================================================================
    # MAIN EXECUTION LOOP (I/O)
    # =========================================================================

    async def run_loop(self) -> Dict:  # I/O
        """Main execution loop for SSRF testing."""
        dashboard.current_agent = self.name
        dashboard.log(f"[{self.name}] Starting SSRF analysis on {self.url}", "INFO")

        all_findings = []
        for param in self.params:
            logger.info(f"[{self.name}] Testing {param} on {self.url}")

            key = f"{self.url}#{param}"
            if key in self._tested_params:
                logger.info(f"[{self.name}] Skipping {param} - already tested")
                continue

            # High-Performance Go Fuzzer
            findings = await self._test_with_go_fuzzer(param)

            # LLM-Driven deep strategy (fallback)
            if not findings:
                findings = await self._test_with_llm_strategy(param)

            if findings:
                all_findings.extend(findings)
                await self._create_finding(findings[0])

            self._tested_params.add(key)

        return {
            "status": JobStatus.COMPLETED,
            "vulnerable": len(all_findings) > 0,
            "findings": all_findings,
            "findings_count": len(all_findings),
        }

    async def _create_finding(self, res: Dict):  # I/O
        """Reports a confirmed finding to the conductor."""
        finding = {
            "type": "SSRF",
            "severity": "CRITICAL",
            "url": self.url,
            "parameter": res["param"],
            "payload": res["payload"],
            "description": f"Confirmed SSRF in '{res['param']}'. Response contains internal data or indicators.",
            "validated": True,
            "status": "VALIDATED_CONFIRMED",
            "reproduction": f"curl '{self.url}' --data-urlencode '{res['param']}={res['payload']}'",
            "cwe_id": get_cwe_for_vuln("SSRF"),
            "remediation": get_remediation_for_vuln("SSRF"),
            "cve_id": "N/A",
            "http_request": f"GET {self.url}?{res['param']}={res['payload']}",
            "http_response": res.get("text", res.get("reason", "Internal data or callback detected")),
        }
        logger.info(f"SSRF CONFIRMED: {res['payload']} on {res['param']}")
        self._emit_ssrf_finding(finding)

    # =========================================================================
    # QUEUE CONSUMPTION MODE (Phase 20) - WET->DRY
    # =========================================================================

    async def analyze_and_dedup_queue(self) -> List[Dict]:  # I/O
        """Phase A: Analyze WET list with deduplication."""
        import time
        logger.info(f"[{self.name}] ===== PHASE A: Analyzing WET list =====")
        queue = queue_manager.get_queue("ssrf")
        wet_findings = []
        wait_start = time.monotonic()
        while (time.monotonic() - wait_start) < 300.0:
            if queue.depth() if hasattr(queue, 'depth') else 0 > 0:
                break
            await asyncio.sleep(0.5)
        else:
            return []
        empty_count = 0
        while empty_count < 10:
            item = await queue.dequeue(timeout=0.5)
            if item is None:
                empty_count += 1
                await asyncio.sleep(0.5)
                continue
            empty_count = 0
            finding = item.get("finding", {})
            if finding.get("url") and finding.get("parameter"):
                wet_findings.append({
                    "url": finding["url"],
                    "parameter": finding["parameter"],
                    "finding": finding,
                    "scan_context": item.get("scan_context", self._scan_context),
                })
        logger.info(f"[{self.name}] Phase A: Drained {len(wet_findings)} WET findings")
        if not wet_findings:
            return []

        # ========== AUTONOMOUS PARAMETER DISCOVERY ==========
        logger.info(f"[{self.name}] Phase A: Expanding WET findings with SSRF-focused discovery...")
        expanded_wet_findings = []
        seen_urls = set()
        seen_params = set()

        # 1. Always include ALL original WET params first
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
                all_params = await self._discover_ssrf_params(url)
                if not all_params:
                    continue

                new_count = 0
                for param_name, param_value in all_params.items():
                    if (url, param_name) not in seen_params:
                        seen_params.add((url, param_name))
                        expanded_wet_findings.append({
                            "url": url,
                            "parameter": param_name,
                            "finding": wet_item.get("finding", {}),
                            "scan_context": wet_item.get("scan_context", self._scan_context),
                            "_discovered": True,
                        })
                        new_count += 1

                if new_count:
                    logger.info(f"[{self.name}] Discovered {new_count} additional params on {url}")

            except Exception as e:
                logger.error(f"[{self.name}] Discovery failed for {url}: {e}")

        # 2.5 Resolve endpoint URLs from HTML links/forms + reasoning fallback
        from bugtrace.agents.specialist_utils import resolve_param_endpoints, resolve_param_from_reasoning
        if hasattr(self, '_last_discovery_html') and self._last_discovery_html:
            for base_url in seen_urls:
                endpoint_map = resolve_param_endpoints(self._last_discovery_html, base_url)
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
                        logger.info(f"[{self.name}] Resolved {resolved_count} params to actual endpoint URLs")

        logger.info(f"[{self.name}] Phase A: Expanded {len(wet_findings)} hints -> {len(expanded_wet_findings)} testable params")

        # ========== DEDUPLICATION ==========
        try:
            dry_list = await self._llm_analyze_and_dedup(expanded_wet_findings, self._scan_context)
        except Exception:
            dry_list = fallback_fingerprint_dedup(expanded_wet_findings)
        self._dry_findings = dry_list
        logger.info(f"[{self.name}] Phase A: {len(expanded_wet_findings)} WET -> {len(dry_list)} DRY ({len(expanded_wet_findings)-len(dry_list)} duplicates removed)")
        return dry_list

    async def _llm_analyze_and_dedup(self, wet_findings: List[Dict], context: str) -> List[Dict]:  # I/O
        """LLM-powered intelligent deduplication."""
        from bugtrace.core.llm_client import llm_client
        import json

        tech_stack = getattr(self, '_tech_stack_context', {}) or {}
        lang = tech_stack.get('lang', 'generic')
        server = tech_stack.get('server', 'generic')

        ssrf_prime_directive = getattr(self, '_ssrf_prime_directive', '')
        ssrf_dedup_context = self.generate_ssrf_dedup_context(tech_stack) if tech_stack else ''

        infrastructure = tech_stack.get("raw_profile", {}).get("infrastructure", [])
        cloud_providers = self._detect_cloud_provider(infrastructure)

        prompt = f"""You are analyzing {len(wet_findings)} potential SSRF findings.

{ssrf_prime_directive}

{ssrf_dedup_context}

## TARGET CONTEXT
- Language: {lang}
- Server: {server}
- Cloud Providers: {', '.join(cloud_providers) if cloud_providers else 'None detected'}

WET FINDINGS (may contain duplicates):
{json.dumps(wet_findings, indent=2)}

## DEDUPLICATION RULES

1. **CRITICAL - Autonomous Discovery:**
   - If items have "_discovered": true, they are DIFFERENT PARAMETERS discovered autonomously
   - Even if they share the same "finding" object, treat them as SEPARATE based on "parameter" field
   - Same URL + DIFFERENT param -> DIFFERENT (keep all)
   - Same URL + param + DIFFERENT target -> DIFFERENT (keep both)

2. **Standard Deduplication:**
   - Same URL + Same param + Same internal target -> DUPLICATE (keep best)
   - Different endpoints -> DIFFERENT (keep both)

3. **Prioritization:**
   - Rank by exploitability: callback= > url= > redirect= > other
   - Remove findings unlikely to succeed given cloud provider detection

## OUTPUT FORMAT (JSON only):
{{
  "findings": [
    {{
      "url": "...",
      "parameter": "...",
      "rationale": "why this is unique and exploitable",
      "attack_priority": 1-5
    }}
  ],
  "duplicates_removed": <count>,
  "reasoning": "Brief explanation of deduplication strategy"
}}

Return ONLY unique findings in this JSON format."""

        system_prompt = f"""You are an expert SSRF deduplication analyst.

{ssrf_prime_directive}

## AUTONOMOUS DISCOVERY RULES:
- Items with "_discovered": true are DIFFERENT PARAMETERS discovered autonomously
- Same URL + DIFFERENT param -> KEEP ALL
- Only merge if: Same URL + Same param + Same internal target

Focus on parameter+target deduplication. Same internal target via different bypasses = DUPLICATE."""

        response = await llm_client.generate(
            prompt=prompt,
            system_prompt=system_prompt,
            module_name="SSRF_DEDUP",
            temperature=0.2,
        )
        try:
            return json.loads(response).get("findings", wet_findings)
        except Exception:
            return fallback_fingerprint_dedup(wet_findings)

    async def exploit_dry_list(self) -> List[Dict]:  # I/O
        """Phase B: Exploit DRY list."""
        logger.info(f"[{self.name}] ===== PHASE B: Exploiting {len(self._dry_findings)} DRY findings =====")
        validated = []
        for idx, f in enumerate(self._dry_findings, 1):
            if hasattr(self, '_v'):
                self._v.emit("exploit.specialist.param.started", {
                    "agent": "SSRF", "param": f["parameter"], "url": f["url"],
                    "idx": idx, "total": len(self._dry_findings),
                })
                self._v.reset("exploit.specialist.progress")
            try:
                self.url = f["url"]
                result = await self._test_single_param_from_queue(f["url"], f["parameter"], f.get("finding", {}))
                if result and result.get("validated"):
                    validated.append(result)
                    fp = generate_ssrf_fingerprint(f["url"], f["parameter"], result.get("payload", ""))
                    if fp not in self._emitted_findings:
                        self._emitted_findings.add(fp)

                        if hasattr(self, '_v'):
                            self._v.emit("exploit.specialist.confirmed", {
                                "agent": "SSRF", "param": f["parameter"], "url": f["url"],
                                "payload": result.get("payload", "")[:100],
                                "status": result.get("status", ""),
                            })

                        if settings.WORKER_POOL_EMIT_EVENTS:
                            status = result.get("status", ValidationStatus.VALIDATED_CONFIRMED.value)
                            self._emit_ssrf_finding({
                                "specialist": "ssrf",
                                "type": "SSRF",
                                "url": f["url"],
                                "parameter": f["parameter"],
                                "payload": result.get("payload", ""),
                                "status": status,
                                "evidence": result.get("evidence", {}),
                                "validation_requires_cdp": status == ValidationStatus.PENDING_VALIDATION.value,
                            }, scan_context=self._scan_context)
                        logger.info(f"[{self.name}] Emitted unique: {f['url']}?{f['parameter']}")
            except Exception as e:
                logger.error(f"[{self.name}] Phase B [{idx}/{len(self._dry_findings)}]: {e}")
            finally:
                if hasattr(self, '_v'):
                    self._v.emit("exploit.specialist.param.completed", {
                        "agent": "SSRF", "param": f["parameter"], "url": f["url"], "idx": idx,
                    })
        logger.info(f"[{self.name}] Phase B complete: {len(validated)} validated")
        return validated

    async def _generate_specialist_report(self, findings: List[Dict]) -> str:  # I/O
        """Generate specialist report."""
        import json
        import aiofiles
        from datetime import datetime

        scan_dir = getattr(self, 'report_dir', None) or (
            settings.BASE_DIR / "reports" / self._scan_context.split("/")[-1]
        )
        results_dir = scan_dir / "specialists" / "results"
        results_dir.mkdir(parents=True, exist_ok=True)
        report_path = results_dir / "ssrf_results.json"
        async with aiofiles.open(report_path, 'w') as f:
            await f.write(json.dumps({
                "agent": self.name,
                "timestamp": datetime.now().isoformat(),
                "scan_context": self._scan_context,
                "phase_a": {
                    "wet_count": len(self._dry_findings),
                    "dry_count": len(self._dry_findings),
                    "dedup_method": "llm_fallback",
                },
                "phase_b": {
                    "validated_count": len([x for x in findings if x.get("validated")]),
                    "total_findings": len(findings),
                },
                "findings": findings,
            }, indent=2))
        logger.info(f"[{self.name}] Report saved: {report_path}")
        return str(report_path)

    async def start_queue_consumer(self, scan_context: str) -> None:  # I/O
        """TWO-PHASE queue consumer (WET -> DRY). NO infinite loop."""
        from bugtrace.agents.specialist_utils import (
            report_specialist_start,
            report_specialist_progress,
            report_specialist_done,
            report_specialist_wet_dry,
            write_dry_file,
        )

        self._queue_mode = True
        self._scan_context = scan_context
        self._v = create_emitter("SSRF", self._scan_context)

        # v3.2: Load context-aware tech stack for intelligent deduplication
        await self._load_ssrf_tech_context()

        logger.info(f"[{self.name}] Starting TWO-PHASE queue consumer (WET -> DRY)")

        # Get initial queue depth for telemetry
        queue = queue_manager.get_queue("ssrf")
        initial_depth = queue.depth()
        report_specialist_start(self.name, queue_depth=initial_depth)

        self._v.emit("exploit.specialist.started", {"agent": "SSRF", "queue_depth": initial_depth})

        dry_list = await self.analyze_and_dedup_queue()

        # Report WET->DRY metrics
        report_specialist_wet_dry(self.name, initial_depth, len(dry_list) if dry_list else 0)
        write_dry_file(self, dry_list, initial_depth, "ssrf")

        if not dry_list:
            logger.info(f"[{self.name}] No findings to exploit after deduplication")
            report_specialist_done(self.name, processed=0, vulns=0)
            self._v.emit("exploit.specialist.completed", {"agent": "SSRF", "processed": 0, "vulns": 0})
            return

        results = await self.exploit_dry_list()

        vulns_count = len([r for r in results if r]) if results else 0
        vulns_count += len(self._dry_findings) if hasattr(self, '_dry_findings') else 0

        if results or self._dry_findings:
            await self._generate_specialist_report(results)

        report_specialist_done(
            self.name,
            processed=len(dry_list),
            vulns=vulns_count,
        )

        self._v.emit("exploit.specialist.completed", {"agent": "SSRF", "processed": len(dry_list), "vulns": vulns_count})

        logger.info(f"[{self.name}] Queue consumer complete: {len(results)} validated findings")

    async def _process_queue_item(self, item: dict) -> Optional[Dict]:  # I/O
        """Process a single item from the ssrf queue."""
        finding = item.get("finding", {})
        url = finding.get("url")
        param = finding.get("parameter")

        if not url or not param:
            logger.warning(f"[{self.name}] Invalid queue item: missing url or parameter")
            return None

        self.url = url
        return await self._test_single_param_from_queue(url, param, finding)

    async def _test_single_param_from_queue(
        self, url: str, param: str, finding: dict,
    ) -> Optional[Dict]:  # I/O
        """Test a single parameter from queue for SSRF."""
        try:
            # Test with Go fuzzer first
            findings = await self._test_with_go_fuzzer(param)
            if findings:
                return findings[0]

            # Fallback to LLM strategy
            findings = await self._test_with_llm_strategy(param)
            if findings:
                return findings[0]

            return None
        except Exception as e:
            logger.error(f"[{self.name}] Queue item test failed: {e}")
            return None

    async def _handle_queue_result(self, item: dict, result: Optional[Dict]) -> None:  # I/O
        """Handle completed queue item processing."""
        if result is None:
            return

        # Build evidence from result for validation status determination
        evidence = build_queue_evidence(result)

        # Determine validation status
        status = get_validation_status(evidence)

        # EXPERT DEDUPLICATION
        fingerprint = generate_ssrf_fingerprint(self.url, result.get("param", ""), result.get("payload", ""))

        if fingerprint in self._emitted_findings:
            logger.info(f"[{self.name}] Skipping duplicate SSRF finding: {self.url}?{result.get('param')} (already reported)")
            return

        self._emitted_findings.add(fingerprint)

        if settings.WORKER_POOL_EMIT_EVENTS:
            self._emit_ssrf_finding({
                "specialist": "ssrf",
                "type": "SSRF",
                "url": self.url,
                "parameter": result.get("param"),
                "payload": result.get("payload"),
                "status": status,
                "evidence": result.get("evidence", {}),
                "validation_requires_cdp": status == ValidationStatus.PENDING_VALIDATION.value,
            }, scan_context=self._scan_context)

        logger.info(f"[{self.name}] Confirmed SSRF: {self.url}?{result.get('param')} [status={status}]")

    async def _on_work_queued(self, data: dict) -> None:  # I/O
        """Handle work_queued_ssrf notification (logging only)."""
        logger.debug(f"[{self.name}] Work queued: {data.get('finding', {}).get('url', 'unknown')}")

    async def stop_queue_consumer(self) -> None:  # I/O
        """Stop queue consumer mode gracefully."""
        if self._worker_pool:
            await self._worker_pool.stop()
            self._worker_pool = None

        if self.event_bus:
            self.event_bus.unsubscribe(
                EventType.WORK_QUEUED_SSRF.value,
                self._on_work_queued,
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
    # PARAMETER DISCOVERY (I/O)
    # =========================================================================

    async def _discover_ssrf_params(self, url: str) -> Dict[str, str]:  # I/O
        """
        SSRF-focused parameter discovery for a given URL.

        Extracts ALL testable parameters from:
        1. URL query string
        2. HTML forms (input, textarea, select)
        3. Prioritizes params with URL-like names
        """
        from bugtrace.tools.visual.browser import browser_manager
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

        # 2. Fetch HTML and extract form parameters
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
                            if "csrf" not in param_name.lower():
                                default_value = tag.get("value", "")
                                all_params[param_name] = default_value

                                ssrf_keywords = [
                                    "url", "callback", "target", "redirect", "proxy",
                                    "fetch", "webhook", "api", "endpoint",
                                ]
                                if any(keyword in param_name.lower() for keyword in ssrf_keywords):
                                    logger.info(f"[{self.name}] Found SSRF-likely param: {param_name}")

        except Exception as e:
            logger.error(f"[{self.name}] HTML parsing failed: {e}")

        logger.info(f"[{self.name}] Discovered {len(all_params)} params on {url}: {list(all_params.keys())}")
        return all_params

    # =========================================================================
    # TECH CONTEXT LOADING (v3.2)
    # =========================================================================

    async def _load_ssrf_tech_context(self) -> None:  # I/O
        """Load technology stack context from recon data (v3.2)."""
        scan_dir = getattr(self, 'report_dir', None)
        if not scan_dir:
            scan_id = self._scan_context.split("/")[-1] if self._scan_context else ""
            scan_dir = settings.BASE_DIR / "reports" / scan_id if scan_id else None

        if not scan_dir or not Path(scan_dir).exists():
            logger.debug(f"[{self.name}] No report directory found, using generic tech context")
            self._tech_stack_context = {"db": "generic", "server": "generic", "lang": "generic"}
            self._ssrf_prime_directive = ""
            return

        self._tech_stack_context = self.load_tech_stack(Path(scan_dir))
        self._ssrf_prime_directive = self.generate_ssrf_context_prompt(self._tech_stack_context)

        lang = self._tech_stack_context.get("lang", "generic")
        infrastructure = self._tech_stack_context.get("raw_profile", {}).get("infrastructure", [])
        cloud_providers = self._detect_cloud_provider(infrastructure)

        logger.info(f"[{self.name}] SSRF tech context loaded: lang={lang}, cloud={', '.join(cloud_providers) if cloud_providers else 'none'}")
