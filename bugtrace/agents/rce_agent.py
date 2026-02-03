import logging
import aiohttp
import time
from typing import Dict, List, Optional, Any
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bugtrace.agents.base import BaseAgent
from bugtrace.agents.worker_pool import WorkerPool, WorkerConfig
from bugtrace.core.queue import queue_manager
from bugtrace.core.event_bus import EventType
from bugtrace.core.config import settings
from bugtrace.core.ui import dashboard
from bugtrace.core.http_orchestrator import orchestrator, DestinationType
from bugtrace.reporting.standards import (
    get_cwe_for_vuln,
    get_remediation_for_vuln,
    normalize_severity,
)
from bugtrace.core.validation_status import ValidationStatus, requires_cdp_validation

# v3.2.0: Import TechContextMixin for context-aware detection
from bugtrace.agents.mixins.tech_context import TechContextMixin

logger = logging.getLogger(__name__)

class RCEAgent(BaseAgent, TechContextMixin):
    """
    Specialist Agent for Remote Code Execution (RCE) and Command Injection.
    """

    def __init__(self, url: str, params: List[str] = None, report_dir: Path = None, event_bus: Any = None):
        super().__init__(
            name="RCEAgent",
            role="RCE Specialist",
            event_bus=event_bus,
            agent_id="rce_agent"
        )
        self.url = url
        self.params = params or []
        self.report_dir = report_dir or Path("./reports")

        # Queue consumption mode (Phase 20)
        self._queue_mode = False
        self._worker_pool: Optional[WorkerPool] = None
        self._scan_context: str = ""

        # Expert deduplication: Track emitted findings by fingerprint
        self._emitted_findings: set = set()  # (url, param)

        # WET → DRY transformation (Two-phase processing)
        self._dry_findings: List[Dict] = []  # Dedup'd findings after Phase A

        # v3.2.0: Context-aware tech stack (loaded in start_queue_consumer)
        self._tech_stack_context: Dict = {}
        self._rce_prime_directive: str = ""
        
    def _get_time_payloads(self) -> list:
        """Get time-based RCE payloads."""
        return [
            ";sleep 5", "|sleep 5", "&sleep 5", "`sleep 5`", "$(sleep 5)", "\nsleep 5\n",
            "__import__('time').sleep(5)", "eval('sleep(5)')", "1+1"
        ]

    def _create_time_based_finding(self, param: str, payload: str, elapsed: float) -> Dict:
        """Create finding for time-based RCE."""
        return {
            "type": "RCE",
            "url": self.url,
            "parameter": param,
            "payload": payload,
            "severity": "CRITICAL",
            "validated": True,
            "status": "VALIDATED_CONFIRMED",
            "evidence": f"Delay of {elapsed:.2f}s detected with payload: {payload}",
            "description": f"Time-based Command Injection confirmed. Parameter '{param}' executes OS commands. Payload caused {elapsed:.2f}s delay (expected 5s+).",
            "reproduction": f"# Time-based RCE test:\ntime curl '{self._inject_payload(self.url, param, payload)}'",
            "cwe_id": get_cwe_for_vuln("RCE"),
            "remediation": get_remediation_for_vuln("RCE"),
            "cve_id": "N/A",
            "http_request": f"GET {self._inject_payload(self.url, param, payload)}",
            "http_response": f"Time delay: {elapsed:.2f}s (indicates command execution)",
        }

    def _create_eval_finding(self, param: str, payload: str, target: str) -> Dict:
        """Create finding for eval-based RCE."""
        return {
            "type": "RCE",
            "url": self.url,
            "parameter": param,
            "payload": payload,
            "severity": "CRITICAL",
            "validated": True,
            "status": "VALIDATED_CONFIRMED",
            "evidence": f"Mathematical expression '1+1' evaluated to '2' in response.",
            "description": f"Remote Code Execution via eval() confirmed. Parameter '{param}' evaluates arbitrary code. Expression '1+1' returned '2'.",
            "reproduction": f"curl '{target}' | grep -i 'result'",
            "cwe_id": get_cwe_for_vuln("RCE"),
            "remediation": get_remediation_for_vuln("RCE"),
            "cve_id": "N/A",
            "http_request": f"GET {target}",
            "http_response": "Result: 2 (indicates code evaluation)",
        }

    async def run_loop(self) -> Dict:
        """Main RCE testing loop."""
        dashboard.current_agent = self.name
        dashboard.log(f"[{self.name}] 🚀 Starting RCE analysis on {self.url}", "INFO")

        all_findings = []
        time_payloads = self._get_time_payloads()

        async with orchestrator.session(DestinationType.TARGET) as session:
            for param in self.params:
                logger.info(f"[{self.name}] Testing RCE on {self.url} (Param: {param})")
                finding = await self._test_parameter(session, param, time_payloads)
                if finding:
                    all_findings.append(finding)

        return {"vulnerable": len(all_findings) > 0, "findings": all_findings}

    async def _test_parameter(self, session, param: str, payloads: List[str]) -> Optional[Dict]:
        """Test a single parameter with all payloads."""
        for p in payloads:
            finding = await self._test_single_payload(session, param, p)
            if finding:
                return finding
        return None

    async def _test_single_payload(self, session, param: str, payload: str) -> Optional[Dict]:
        """Test a single payload against a parameter."""
        if "sleep" in payload:
            return await self._test_time_based(session, param, payload)
        elif "1+1" in payload:
            return await self._test_eval_based(session, param, payload)
        return None

    async def _test_time_based(self, session, param: str, payload: str) -> Optional[Dict]:
        """Test time-based RCE payload."""
        dashboard.update_task(f"RCE:{param}", status=f"Testing Time: {payload}")
        start = time.time()

        if not await self._test_payload(session, payload, param):
            return None

        elapsed = time.time() - start
        if elapsed >= 5:
            return self._create_time_based_finding(param, payload, elapsed)
        return None

    async def _test_eval_based(self, session, param: str, payload: str) -> Optional[Dict]:
        """Test eval-based RCE payload."""
        dashboard.update_task(f"RCE:{param}", status=f"Testing Eval: {payload}")
        target = self._inject_payload(self.url, param, payload)

        try:
            async with session.get(target) as resp:
                text = await resp.text()
                if "Result: 2" in text:
                    return self._create_eval_finding(param, payload, target)
        except Exception as e:
            logger.debug(f"Eval test failed: {e}")

        return None

    async def _test_payload(self, session, payload, param) -> bool:
        """Injects payload and analyzes response."""
        target_url = self._inject_payload(self.url, param, payload)
        try:
            async with session.get(target_url, timeout=10) as resp:
                await resp.text()
                return True
        except Exception as e:
            logger.debug(f"Connectivity check failed: {e}")
        return False

    def _inject_payload(self, url, param, payload):
        parsed = urlparse(url)
        q = parse_qs(parsed.query)
        q[param] = [payload]
        new_query = urlencode(q, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

    # =========================================================================
    # QUEUE CONSUMPTION MODE (Phase 20) - WET→DRY
    # =========================================================================

    async def analyze_and_dedup_queue(self) -> List[Dict]:
        import asyncio, time
        from bugtrace.core.queue import queue_manager
        logger.info(f"[{self.name}] ===== PHASE A: Analyzing WET list =====")
        queue = queue_manager.get_queue("rce")
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
                wet_findings.append({"url": finding["url"], "parameter": finding["parameter"], "finding": finding, "scan_context": item.get("scan_context", self._scan_context)})
        logger.info(f"[{self.name}] Phase A: Drained {len(wet_findings)} WET findings")
        if not wet_findings:
            return []
        try:
            dry_list = await self._llm_analyze_and_dedup(wet_findings, self._scan_context)
        except:
            dry_list = self._fallback_fingerprint_dedup(wet_findings)
        self._dry_findings = dry_list
        logger.info(f"[{self.name}] Phase A: {len(wet_findings)} WET → {len(dry_list)} DRY ({len(wet_findings)-len(dry_list)} duplicates removed)")
        return dry_list

    async def _llm_analyze_and_dedup(self, wet_findings: List[Dict], context: str) -> List[Dict]:
        from bugtrace.core.llm_client import llm_client
        import json

        # v3.2: Extract tech stack info for prompt
        tech_stack = getattr(self, '_tech_stack_context', {}) or {}
        lang = tech_stack.get('lang', 'generic')
        server = tech_stack.get('server', 'generic')
        waf = tech_stack.get('waf')

        # Get RCE-specific context prompts
        rce_prime_directive = getattr(self, '_rce_prime_directive', '')
        rce_dedup_context = self.generate_rce_dedup_context(tech_stack) if tech_stack else ''

        # Infer OS for context
        os_type = self._infer_os_from_stack(tech_stack)

        prompt = f"""You are analyzing {len(wet_findings)} potential RCE findings.

{rce_prime_directive}

{rce_dedup_context}

## TARGET CONTEXT
- Language: {lang}
- Server: {server}
- Likely OS: {os_type}
- WAF: {waf or 'None'}

WET FINDINGS:
{json.dumps(wet_findings, indent=2)}

Return ONLY unique findings in JSON format:
{{"findings": [...]}}"""

        system_prompt = f"""You are an expert RCE deduplication analyst.

{rce_prime_directive}

Focus on parameter+injection point deduplication. Different command separators on same param = technique variants."""

        response = await llm_client.generate(
            prompt=prompt,
            system_prompt=system_prompt,
            module_name="RCE_DEDUP",
            temperature=0.2
        )
        try:
            return json.loads(response).get("findings", wet_findings)
        except:
            return self._fallback_fingerprint_dedup(wet_findings)

    def _fallback_fingerprint_dedup(self, wet_findings: List[Dict]) -> List[Dict]:
        seen, dry_list = set(), []
        for f in wet_findings:
            fp = self._generate_rce_fingerprint(f.get("url",""), f.get("parameter",""))
            if fp not in seen:
                seen.add(fp)
                dry_list.append(f)
        return dry_list

    async def exploit_dry_list(self) -> List[Dict]:
        logger.info(f"[{self.name}] ===== PHASE B: Exploiting {len(self._dry_findings)} DRY findings =====")
        validated = []
        for idx, f in enumerate(self._dry_findings, 1):
            try:
                self.url = f["url"]
                result = await self._test_single_param_from_queue(f["url"], f["parameter"], f.get("finding",{}))
                if result and result.get("validated"):
                    validated.append(result)
                    fp = self._generate_rce_fingerprint(f["url"], f["parameter"])
                    if fp not in self._emitted_findings:
                        self._emitted_findings.add(fp)
                        if self.event_bus and settings.WORKER_POOL_EMIT_EVENTS:
                            await self.event_bus.emit(EventType.VULNERABILITY_DETECTED, {
                                "specialist": "rce",
                                "finding": {"type": "RCE", "url": result.get("url"), "parameter": result.get("parameter"), "payload": result.get("payload")},
                                "status": result.get("status", ValidationStatus.VALIDATED_CONFIRMED.value),
                                "validation_requires_cdp": result.get("status") == ValidationStatus.PENDING_VALIDATION.value,
                                "scan_context": self._scan_context,
                            })
                        logger.info(f"[{self.name}] ✅ Emitted unique: {f['url']}?{f['parameter']}")
            except Exception as e:
                logger.error(f"[{self.name}] Phase B [{idx}/{len(self._dry_findings)}]: {e}")
        logger.info(f"[{self.name}] Phase B complete: {len(validated)} validated")
        return validated

    async def _generate_specialist_report(self, findings: List[Dict]) -> str:
        import json, aiofiles
        from datetime import datetime
        from bugtrace.core.config import settings
        # v3.2: Write to specialists/results/ for unified wet→dry→results flow
        scan_dir = getattr(self, 'report_dir', None) or (settings.BASE_DIR / "reports" / self._scan_context.split("/")[-1])
        results_dir = scan_dir / "specialists" / "results"
        results_dir.mkdir(parents=True, exist_ok=True)
        report_path = results_dir / "rce_results.json"
        async with aiofiles.open(report_path, 'w') as f:
            await f.write(json.dumps({
                "agent": self.name,
                "timestamp": datetime.now().isoformat(),
                "scan_context": self._scan_context,
                "phase_a": {"wet_count": len(self._dry_findings), "dry_count": len(self._dry_findings), "dedup_method": "llm_fallback"},
                "phase_b": {"validated_count": len([x for x in findings if x.get("validated")]), "total_findings": len(findings)},
                "findings": findings
            }, indent=2))
        logger.info(f"[{self.name}] Report saved: {report_path}")
        return str(report_path)

    async def start_queue_consumer(self, scan_context: str) -> None:
        """TWO-PHASE queue consumer (WET → DRY). NO infinite loop."""
        from bugtrace.agents.specialist_utils import (
            report_specialist_start,
            report_specialist_done,
            report_specialist_wet_dry,
        )

        self._queue_mode = True
        self._scan_context = scan_context

        # v3.2: Load context-aware tech stack for intelligent deduplication
        await self._load_rce_tech_context()

        logger.info(f"[{self.name}] Starting TWO-PHASE queue consumer (WET → DRY)")

        # Get initial queue depth for telemetry
        queue = queue_manager.get_queue("rce")
        initial_depth = queue.depth()
        report_specialist_start(self.name, queue_depth=initial_depth)

        dry_list = await self.analyze_and_dedup_queue()

        # Report WET→DRY metrics for integrity verification
        report_specialist_wet_dry(self.name, initial_depth, len(dry_list) if dry_list else 0)

        if not dry_list:
            logger.info(f"[{self.name}] No findings to exploit after deduplication")
            report_specialist_done(self.name, processed=0, vulns=0)
            return

        results = await self.exploit_dry_list()

        # Count confirmed vulnerabilities
        vulns_count = len([r for r in results if r]) if results else 0
        vulns_count += len(self._dry_findings) if hasattr(self, '_dry_findings') else 0

        if results or self._dry_findings:
            await self._generate_specialist_report(results)

        # Report completion with final stats
        report_specialist_done(
            self.name,
            processed=len(dry_list),
            vulns=vulns_count
        )
        logger.info(f"[{self.name}] Queue consumer complete: {len(results)} validated findings")

    async def _process_queue_item(self, item: dict) -> Optional[Dict]:
        """Process a single item from the rce queue."""
        finding = item.get("finding", {})
        url = finding.get("url")
        param = finding.get("parameter")

        if not url or not param:
            logger.warning(f"[{self.name}] Invalid queue item: missing url or parameter")
            return None

        self.url = url
        return await self._test_single_param_from_queue(url, param, finding)

    async def _test_single_param_from_queue(self, url: str, param: str, finding: dict) -> Optional[Dict]:
        """Test a single parameter from queue for RCE."""
        try:
            async with orchestrator.session(DestinationType.TARGET) as session:
                time_payloads = self._get_time_payloads()
                return await self._test_parameter(session, param, time_payloads)
        except Exception as e:
            logger.error(f"[{self.name}] Queue item test failed: {e}")
            return None

    def _generate_rce_fingerprint(self, url: str, parameter: str) -> tuple:
        """
        Generate RCE finding fingerprint for expert deduplication.

        RCE is URL-specific and parameter-specific.

        Args:
            url: Target URL
            parameter: Parameter name

        Returns:
            Tuple fingerprint for deduplication
        """
        from urllib.parse import urlparse

        parsed = urlparse(url)
        normalized_path = parsed.path.rstrip('/')

        # RCE signature: (host, path, parameter)
        fingerprint = ("RCE", parsed.netloc, normalized_path, parameter.lower())

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
        finding_data = {
            "context": "rce_command",
            "payload": result.get("payload", ""),
            "validation_method": "rce_fuzzer",
            "evidence": {"technique": result.get("evidence", "")},
        }
        needs_cdp = requires_cdp_validation(finding_data)

        # RCE-specific edge case: Time-based blind RCE without command output
        status = result.get("status", "VALIDATED_CONFIRMED")
        evidence_str = result.get("evidence", "")
        if "time" in str(evidence_str).lower() and "delay" in str(evidence_str).lower():
            # Time-based detection without output confirmation may need validation
            if "command_output" not in str(evidence_str):
                needs_cdp = True
                if status == "VALIDATED_CONFIRMED":
                    status = ValidationStatus.PENDING_VALIDATION.value

        # EXPERT DEDUPLICATION: Check if we already emitted this finding
        fingerprint = self._generate_rce_fingerprint(result.get("url", ""), result.get("parameter", ""))

        if fingerprint in self._emitted_findings:
            logger.info(f"[{self.name}] Skipping duplicate RCE finding: {result.get('url')}?{result.get('parameter')} (already reported)")
            return

        # Mark as emitted
        self._emitted_findings.add(fingerprint)

        if self.event_bus and settings.WORKER_POOL_EMIT_EVENTS:
            await self.event_bus.emit(EventType.VULNERABILITY_DETECTED, {
                "specialist": "rce",
                "finding": {
                    "type": "RCE",
                    "url": result.get("url"),
                    "parameter": result.get("parameter"),
                    "payload": result.get("payload"),
                },
                "status": status,
                "validation_requires_cdp": needs_cdp,
                "scan_context": self._scan_context,
            })

        logger.info(f"[{self.name}] Confirmed RCE: {result.get('url')}?{result.get('parameter')}")

    async def _on_work_queued(self, data: dict) -> None:
        """Handle work_queued_rce notification (logging only)."""
        logger.debug(f"[{self.name}] Work queued: {data.get('finding', {}).get('url', 'unknown')}")

    async def stop_queue_consumer(self) -> None:
        """Stop queue consumer mode gracefully."""
        if self._worker_pool:
            await self._worker_pool.stop()
            self._worker_pool = None

        if self.event_bus:
            self.event_bus.unsubscribe(
                EventType.WORK_QUEUED_RCE.value,
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

    async def _load_rce_tech_context(self) -> None:
        """
        Load technology stack context from recon data (v3.2).

        Uses TechContextMixin methods to load and generate context-aware
        prompts for RCE-specific deduplication (OS and language detection).
        """
        # Determine report directory
        scan_dir = getattr(self, 'report_dir', None)
        if not scan_dir:
            scan_id = self._scan_context.split("/")[-1] if self._scan_context else ""
            scan_dir = settings.BASE_DIR / "reports" / scan_id if scan_id else None

        if not scan_dir or not Path(scan_dir).exists():
            logger.debug(f"[{self.name}] No report directory found, using generic tech context")
            self._tech_stack_context = {"db": "generic", "server": "generic", "lang": "generic"}
            self._rce_prime_directive = ""
            return

        # Use TechContextMixin methods
        self._tech_stack_context = self.load_tech_stack(Path(scan_dir))
        self._rce_prime_directive = self.generate_rce_context_prompt(self._tech_stack_context)

        lang = self._tech_stack_context.get("lang", "generic")
        os_type = self._infer_os_from_stack(self._tech_stack_context)
        waf = self._tech_stack_context.get("waf")

        logger.info(f"[{self.name}] RCE tech context loaded: lang={lang}, os={os_type}, waf={waf or 'none'}")
