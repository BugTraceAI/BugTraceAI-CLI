"""
IDOR Agent - Thin Orchestrator

Orchestrates IDOR (Insecure Direct Object Reference) detection and exploitation.
Delegates pure logic to idor.patterns/payloads/validation/dedup modules
and I/O operations to idor.discovery/exploitation modules.
"""

import asyncio
import json
import time
import aiohttp
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

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
from bugtrace.core.verbose_events import create_emitter

# v3.2.0: Import TechContextMixin for context-aware detection
from bugtrace.agents.mixins.tech_context import TechContextMixin

# Extracted modules
from bugtrace.agents.idor.patterns import (
    detect_id_format,
    infer_app_context,
    generate_horizontal_test_ids,
    is_special_account,
    detect_privilege_indicators,
)
from bugtrace.agents.idor.payloads import inject_id, extract_path_id
from bugtrace.agents.idor.validation import (
    validate_idor_finding,
    determine_validation_status,
    analyze_differential,
    analyze_response_diff,
    phase3_impact_analysis,
)
from bugtrace.agents.idor.discovery import discover_idor_params
from bugtrace.agents.idor.exploitation import (
    test_custom_ids_python,
    phase1_retest,
    phase2_http_methods,
    phase4_horizontal_escalation,
    phase5_vertical_escalation,
    wait_for_auth_token,
    fetch_auth_headers,
)
from bugtrace.agents.idor.dedup import (
    generate_idor_fingerprint,
    fallback_fingerprint_dedup,
)

logger = get_logger("agents.idor")


class IDORAgent(BaseAgent, TechContextMixin):
    """
    Specialist Agent for Insecure Direct Object Reference (IDOR).

    Thin orchestrator: delegates pure logic to idor.patterns/payloads/validation/dedup
    and I/O to idor.discovery/exploitation.
    """

    def __init__(self, url: str, params: List[Dict] = None, report_dir: Path = None, event_bus=None):
        super().__init__(
            name="IDORAgent",
            role="IDOR Specialist",
            event_bus=event_bus,
            agent_id="idor_agent",
        )
        self.url = url
        self.params = params or []
        self.report_dir = report_dir or Path("./reports")

        self._tested_params = set()
        self._queue_mode = False
        self._emitted_findings: set = set()
        self._worker_pool: Optional[WorkerPool] = None
        self._scan_context: str = ""
        self._dry_findings: List[Dict] = []

        # v3.2.0: Context-aware tech stack
        self._tech_stack_context: Dict = {}
        self._idor_prime_directive: str = ""

    # =========================================================================
    # FINDING VALIDATION
    # =========================================================================

    def _validate_before_emit(self, finding: Dict) -> Tuple[bool, str]:
        """IDOR-specific validation before emitting finding."""
        is_valid, error = super()._validate_before_emit(finding)
        if not is_valid:
            return False, error
        return validate_idor_finding(finding)

    def _emit_idor_finding(self, finding_dict: Dict, scan_context: str = None) -> Optional[Dict]:
        """Helper to emit IDOR finding using BaseAgent.emit_finding() with validation."""
        if "type" not in finding_dict:
            finding_dict["type"] = "IDOR"
        if scan_context:
            finding_dict["scan_context"] = scan_context
        finding_dict["agent"] = self.name
        return self.emit_finding(finding_dict)

    # =========================================================================
    # VALIDATION STATUS
    # =========================================================================

    def _determine_validation_status(self, evidence_type: str, confidence: str) -> str:
        """Determine IDOR validation status."""  # PURE
        return determine_validation_status(evidence_type, confidence)

    # =========================================================================
    # FINDING CREATION
    # =========================================================================

    def _create_idor_finding(self, hit: Dict, param: str, original_value: str) -> Dict:
        """Create IDOR finding from fuzzer hit."""  # PURE
        confidence_level = "HIGH" if hit["severity"] in ["CRITICAL", "HIGH"] else "MEDIUM"
        return {
            "type": "IDOR",
            "url": self.url,
            "parameter": param,
            "payload": hit["id"],
            "description": f"IDOR vulnerability detected on ID {hit['id']}. Differed from baseline ID {original_value}. Status: {hit['status_code']}. Contains sensitive data: {hit.get('contains_sensitive')}",
            "severity": hit["severity"].upper() if isinstance(hit["severity"], str) else hit["severity"],
            "validated": hit["severity"] in ["CRITICAL", "HIGH"],
            "evidence": {
                "differential_analysis": True,
                "status_change": hit.get("diff_type") == "status_change",
                "length_change": hit.get("diff_type") == "length_change",
                "user_data_leakage": hit.get("diff_type") == "user_data_leakage",
                "contains_sensitive": hit.get("contains_sensitive", False),
                "status_code": hit["status_code"],
                "diff_type": hit["diff_type"],
            },
            "status": determine_validation_status("differential", confidence_level),
            "reproduction": f"# Compare responses:\ncurl '{self.url}?{param}={original_value}'\ncurl '{self.url}?{param}={hit['id']}'",
            "cwe_id": get_cwe_for_vuln("IDOR"),
            "remediation": get_remediation_for_vuln("IDOR"),
            "cve_id": "N/A",
            "http_request": f"GET {self.url}?{param}={hit['id']}",
            "http_response": f"Status: {hit['status_code']}, Diff: {hit['diff_type']}, Sensitive data: {hit.get('contains_sensitive', False)}",
        }

    # =========================================================================
    # PATTERN DETECTION (delegates to idor.patterns)
    # =========================================================================

    def _detect_id_format(self, original_value: str) -> tuple:
        """Detect ID format and generate test IDs."""  # PURE
        return detect_id_format(original_value)

    def _infer_app_context(self, domain: str, path: str) -> str:
        """Infer application type from domain/path."""  # PURE
        return infer_app_context(domain, path)

    def _generate_horizontal_test_ids(self, base_id, id_format, max_count):
        """Generate test IDs for enumeration."""  # PURE
        return generate_horizontal_test_ids(base_id, id_format, max_count)

    def _is_special_account(self, response_body: str) -> bool:
        """Check if response indicates special/privileged account."""  # PURE
        return is_special_account(response_body)

    def _detect_privilege_indicators(self, response_body: str) -> list:
        """Detect privilege indicators in response."""  # PURE
        return detect_privilege_indicators(response_body)

    # =========================================================================
    # PAYLOADS (delegates to idor.payloads)
    # =========================================================================

    def _inject(self, val, param_name, original_val):
        """Inject a test ID value into the URL."""  # PURE
        return inject_id(self.url, val, param_name, original_val)

    # =========================================================================
    # VALIDATION (delegates to idor.validation)
    # =========================================================================

    def _analyze_differential(self, baseline_status, baseline_body, baseline_length,
                              test_status, test_body, test_length, test_id):
        """Simplified semantic analysis."""  # PURE
        return analyze_differential(
            baseline_status, baseline_body, baseline_length,
            test_status, test_body, test_length, test_id,
        )

    def _analyze_response_diff(self, baseline, exploit):
        """Analyze response differences."""  # PURE
        return analyze_response_diff(baseline, exploit)

    def _phase3_impact_analysis(self, phase1, phase2):
        """Phase 3: Analyze impact."""  # PURE
        return phase3_impact_analysis(phase1, phase2)

    # =========================================================================
    # DEDUP (delegates to idor.dedup)
    # =========================================================================

    def _generate_idor_fingerprint(self, url: str, resource_type: str) -> tuple:
        """Generate IDOR finding fingerprint."""  # PURE
        return generate_idor_fingerprint(url, resource_type)

    def _fallback_fingerprint_dedup(self, wet_findings):
        """Fallback fingerprint-based deduplication."""  # PURE
        return fallback_fingerprint_dedup(wet_findings)

    # =========================================================================
    # MAIN LOOP
    # =========================================================================

    async def run_loop(self) -> Dict:
        """Main loop for the agent."""  # I/O
        dashboard.current_agent = self.name
        dashboard.log(f"[{self.name}] Starting IDOR analysis on {self.url}", "INFO")

        all_findings = []
        async with orchestrator.session(DestinationType.TARGET) as session:
            for item in self.params:
                finding = await self._test_idor_param(item)
                if finding:
                    all_findings.append(finding)

        return {"vulnerable": len(all_findings) > 0, "findings": all_findings}

    # =========================================================================
    # LLM PREDICTION
    # =========================================================================

    async def _llm_predict_ids(self, original_value: str, url: str, param: str) -> List[str]:
        """Use LLM to predict likely IDOR target IDs."""  # I/O
        from bugtrace.core.llm_client import llm_client

        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        app_context = infer_app_context(domain, path)

        prompt = f"""You are analyzing an IDOR vulnerability target.

**Current Context:**
- Domain: {domain}
- Path: {path}
- Parameter: {param}
- Baseline ID: {original_value}
- Inferred Type: {app_context}

**Task:** Generate {settings.IDOR_LLM_PREDICTION_COUNT} likely ID values that could reveal unauthorized data through IDOR.

**Consider:**
1. Common test/admin accounts (admin, root, test, demo, guest)
2. Sequential patterns (+1, -1, x10, x100, /2)
3. Edge cases (0, 1, -1, 999, 1000, 9999, 99999)
4. Common typos and variations of the baseline
5. Well-known default IDs for this app type
6. Obvious enumeration targets (first user, last user, system accounts)

Return ONLY a JSON object with an "ids" array:
{{"ids": ["id1", "id2", "id3", ...]}}"""

        try:
            response = await llm_client.generate(
                prompt=prompt,
                module_name="IDOR_ID_PREDICTION",
                temperature=0.3,
                max_tokens=500,
            )
            if not response:
                return []
            result = json.loads(response)
            predicted_ids = result.get("ids", [])
            valid_ids = [str(id_val).strip() for id_val in predicted_ids if id_val]
            return valid_ids[:settings.IDOR_LLM_PREDICTION_COUNT]
        except json.JSONDecodeError:
            return []
        except Exception as e:
            logger.error(f"[{self.name}] LLM prediction failed: {e}")
            return []

    # =========================================================================
    # EXPLOITATION
    # =========================================================================

    async def _test_custom_ids_python(self, candidate_ids, param, original_value) -> Optional[Dict]:
        """Test custom IDs using Python analyzer."""  # I/O
        auth_headers = getattr(self, '_auth_headers', {})

        if not auth_headers:
            # Check auth gate
            baseline_url = inject_id(self.url, original_value, param, original_value)
            async with orchestrator.session(DestinationType.TARGET) as session:
                try:
                    async with session.get(baseline_url, timeout=5) as resp:
                        if resp.status in (401, 403):
                            logger.info(f"[{self.name}] Auth gate detected, waiting for JWT token...")
                            auth_headers = await wait_for_auth_token(self._scan_context)
                            self._auth_headers = auth_headers
                            if not auth_headers:
                                logger.warning(f"[{self.name}] No auth token available")
                                return None
                except Exception:
                    pass

        verbose_emitter = getattr(self, '_v', None)
        hit = await test_custom_ids_python(
            candidate_ids, param, original_value, self.url,
            auth_headers, self._scan_context, verbose_emitter,
        )

        if hit is None:
            return None

        # LLM validation for MEDIUM severity (if enabled)
        if hit["severity"] == "MEDIUM" and settings.IDOR_ENABLE_LLM_VALIDATION:
            # Re-fetch bodies for LLM validation
            baseline_url = inject_id(self.url, original_value, param, original_value)
            test_url = inject_id(self.url, str(hit["id"]), param, original_value)
            try:
                if auth_headers:
                    async with aiohttp.ClientSession(headers=auth_headers) as s:
                        async with s.get(baseline_url, timeout=5, ssl=False) as r:
                            baseline_body = await r.text()
                            baseline_status = r.status
                            baseline_length = len(baseline_body)
                        async with s.get(test_url, timeout=5, ssl=False) as r:
                            test_body = await r.text()
                            test_status = r.status
                            test_length = len(test_body)
                else:
                    async with orchestrator.session(DestinationType.TARGET) as s:
                        async with s.get(baseline_url, timeout=5) as r:
                            baseline_body = await r.text()
                            baseline_status = r.status
                            baseline_length = len(baseline_body)
                        async with s.get(test_url, timeout=5) as r:
                            test_body = await r.text()
                            test_status = r.status
                            test_length = len(test_body)

                is_valid_idor, validated_severity = await self._llm_validate_medium_severity(
                    baseline_body, test_body,
                    baseline_status, test_status,
                    baseline_length, test_length,
                    hit["diff_type"], hit["id"],
                )
                if not is_valid_idor:
                    return None
                if validated_severity != hit["severity"]:
                    hit["severity"] = validated_severity
            except Exception:
                pass

        dashboard.log(f"[{self.name}] LLM Prediction Success! ID {hit['id']}", "SUCCESS")
        return self._create_idor_finding(hit, param, original_value)

    async def _llm_validate_medium_severity(
        self, baseline_body, test_body,
        baseline_status, test_status,
        baseline_length, test_length,
        indicators, test_id,
    ) -> tuple:
        """Use LLM to validate MEDIUM severity findings."""  # I/O
        from bugtrace.core.llm_client import llm_client
        import re

        baseline_snippet = baseline_body[:2000]
        test_snippet = test_body[:2000]

        baseline_keys = re.findall(r'"(\w+)":', baseline_snippet)
        test_keys = re.findall(r'"(\w+)":', test_snippet)

        baseline_key_set = set(baseline_keys)
        test_key_set = set(test_keys)
        common_keys = baseline_key_set & test_key_set
        key_similarity = len(common_keys) / max(len(baseline_key_set), len(test_key_set), 1)

        prompt = f"""You are analyzing a potential IDOR vulnerability with MEDIUM confidence.

**Context:**
- Test ID: {test_id}
- Indicators: {indicators}
- Baseline Status: {baseline_status}, Test Status: {test_status}
- Baseline Length: {baseline_length}, Test Length: {test_length}
- Key Similarity: {key_similarity:.2%}

**Response Structure Analysis:**
- Baseline keys (first 20): {baseline_keys[:20]}
- Test keys (first 20): {test_keys[:20]}

**Task:** Determine if this is a REAL IDOR or just dynamic content.

Return ONLY a JSON object:
{{"is_idor": true/false, "severity": "HIGH"|"MEDIUM"|"LOW", "reasoning": "brief 1-sentence explanation"}}"""

        try:
            response = await llm_client.generate(
                prompt=prompt,
                module_name="IDOR_MEDIUM_VALIDATION",
                temperature=0.2,
                max_tokens=300,
            )
            if not response:
                return (True, "MEDIUM")
            result = json.loads(response)
            return (result.get("is_idor", False), result.get("severity", "MEDIUM"))
        except Exception:
            return (True, "MEDIUM")

    # =========================================================================
    # DEEP EXPLOITATION
    # =========================================================================

    async def _exploit_deep(self, finding: Dict) -> Dict:
        """Deep exploitation analysis (6 phases)."""  # I/O
        logger.info(f"[{self.name}] ===== Phase 4b: Deep Exploitation Analysis =====")

        url = finding["url"]
        param = finding["parameter"]
        payload = finding["payload"]
        original_value = finding.get("original_value")
        auth = getattr(self, '_auth_headers', {})

        exploitation_log = []

        # Phase 1: Re-test
        phase1 = await phase1_retest(url, param, payload, original_value, auth)
        exploitation_log.append({"phase": "retest", **phase1})
        if not phase1.get("confirmed"):
            finding["exploitation_failed"] = "retest_failed"
            return finding

        # Phase 2: HTTP Methods
        phase2 = await phase2_http_methods(url, param, payload, auth)
        exploitation_log.append({"phase": "http_methods", **phase2})

        # Phase 3: Impact Analysis
        phase3 = phase3_impact_analysis(phase1, phase2)
        exploitation_log.append({"phase": "impact", **phase3})

        # Phase 4-5: Escalation (only if mode=full)
        phase4 = None
        phase5 = None
        if settings.IDOR_EXPLOITER_MODE == "full":
            phase4 = await phase4_horizontal_escalation(url, param, payload, original_value, auth)
            exploitation_log.append({"phase": "horizontal", **phase4})

            phase5 = await phase5_vertical_escalation(url, param, auth)
            exploitation_log.append({"phase": "vertical", **phase5})

        # Phase 6: LLM Report
        phase6_report = await self._phase6_llm_report(finding, {
            "retest": phase1, "http_methods": phase2, "impact": phase3,
            "horizontal": phase4, "vertical": phase5,
        })

        finding["exploitation"] = {
            "retest": phase1, "http_methods": phase2, "impact": phase3,
            "horizontal": phase4, "vertical": phase5,
            "llm_report": phase6_report, "timeline": exploitation_log,
        }

        if phase3.get("delete_capability"):
            original_severity = finding["severity"]
            finding["severity"] = "CRITICAL"
            logger.warning(f"[{self.name}] Severity: {original_severity} -> CRITICAL")

        finding["deep_exploitation_completed"] = True
        return finding

    async def _phase1_retest(self, url, param, payload, original_value):
        """Phase 1: Re-test."""  # I/O
        auth = getattr(self, '_auth_headers', {})
        return await phase1_retest(url, param, payload, original_value, auth)

    async def _phase2_http_methods(self, url, param, payload):
        """Phase 2: HTTP methods."""  # I/O
        auth = getattr(self, '_auth_headers', {})
        return await phase2_http_methods(url, param, payload, auth)

    async def _phase4_horizontal_escalation(self, url, param, payload, original_value):
        """Phase 4: Horizontal escalation."""  # I/O
        auth = getattr(self, '_auth_headers', {})
        return await phase4_horizontal_escalation(url, param, payload, original_value, auth)

    async def _phase5_vertical_escalation(self, url, param):
        """Phase 5: Vertical escalation."""  # I/O
        auth = getattr(self, '_auth_headers', {})
        return await phase5_vertical_escalation(url, param, auth)

    async def _phase6_llm_report(self, finding: Dict, phases: Dict) -> str:
        """Phase 6: Generate LLM report."""  # I/O
        from bugtrace.core.llm_client import llm_client
        from datetime import datetime

        report_context = {
            "url": finding["url"], "parameter": finding["parameter"],
            "payload": finding["payload"], "original_value": finding.get("original_value"),
            "severity": finding["severity"],
            "retest": phases.get("retest", {}), "http_methods": phases.get("http_methods", {}),
            "impact": phases.get("impact", {}),
            "horizontal": phases.get("horizontal"), "vertical": phases.get("vertical"),
        }

        prompt = f"""You are a professional security researcher writing an IDOR exploitation report.

**Exploitation Context:**
```json
{json.dumps(report_context, indent=2)}
```

Generate a comprehensive IDOR exploitation report in Markdown format covering:
- Executive Summary, Vulnerability Details, Technical Analysis, PoC, Business Impact, Remediation

**Report Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Tool:** BugTraceAI IDORAgent Deep Exploitation"""

        try:
            report = await llm_client.generate(
                prompt=prompt, module_name="IDOR_EXPLOITATION_REPORT",
                temperature=0.3, max_tokens=2000,
            )
            return report if report else self._generate_fallback_report(finding, phases)
        except Exception:
            return self._generate_fallback_report(finding, phases)

    def _generate_fallback_report(self, finding: Dict, phases: Dict) -> str:
        """Generate basic report if LLM fails."""  # PURE
        from datetime import datetime
        return f"""# IDOR Exploitation Report (Automated)

## Vulnerability Details
- **URL:** {finding['url']}
- **Parameter:** {finding['parameter']}
- **Exploit ID:** {finding['payload']}
- **Severity:** {finding['severity']}

## Impact Summary
{phases.get('impact', {}).get('impact_description', 'Unknown impact')}

**Report Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
"""

    # =========================================================================
    # PARAM TESTING
    # =========================================================================

    async def _test_idor_param(self, item: dict):
        """Test a single parameter for IDOR vulnerability."""  # I/O
        param = item.get("parameter")
        original_value = str(item.get("original_value", ""))

        if not param:
            return None

        if not original_value:
            segments = [s for s in urlparse(self.url).path.split("/") if s]
            for seg in reversed(segments):
                if seg.isdigit():
                    original_value = seg
                    break

        logger.info(f"[{self.name}] Testing IDOR on {param}={original_value}")

        key = f"{self.url}#{param}"
        if key in self._tested_params:
            return None

        # Phase 1: LLM Prediction
        if settings.IDOR_ENABLE_LLM_PREDICTION and original_value:
            llm_predicted_ids = await self._llm_predict_ids(original_value, self.url, param)
            if llm_predicted_ids:
                llm_finding = await self._test_custom_ids_python(llm_predicted_ids, param, original_value)
                if llm_finding:
                    self._tested_params.add(key)
                    return llm_finding

        # Phase 2: Smart ID Detection
        custom_ids = []
        if settings.IDOR_SMART_ID_DETECTION and original_value:
            id_format, detected_ids = detect_id_format(original_value)
            if detected_ids:
                custom_ids = detected_ids

        # Phase 3: Custom IDs from config
        if settings.IDOR_CUSTOM_IDS:
            config_ids = [id_val.strip() for id_val in settings.IDOR_CUSTOM_IDS.split(",") if id_val.strip()]
            if config_ids:
                custom_ids = config_ids

        if custom_ids:
            custom_finding = await self._test_custom_ids_python(custom_ids, param, original_value)
            if custom_finding:
                self._tested_params.add(key)
                return custom_finding

        # Phase 4: Go IDOR Fuzzer
        id_range = settings.IDOR_ID_RANGE
        dashboard.log(f"[{self.name}] Launching Go IDOR Fuzzer on '{param}' (Range {id_range})...", "INFO")
        if hasattr(self, '_v'):
            self._v.emit("exploit.specialist.go_fuzzer", {"agent": "IDOR", "param": param, "id_range": id_range})
        go_result = await external_tools.run_go_idor_fuzzer(self.url, param, id_range=id_range, baseline_id=original_value)

        self._tested_params.add(key)

        if not go_result or not go_result.get("hits"):
            return None

        hit = go_result["hits"][0]
        dashboard.log(f"[{self.name}] IDOR HIT: ID {hit['id']} ({hit['severity']})", "CRITICAL")
        return self._create_idor_finding(hit, param, original_value)

    # =========================================================================
    # DISCOVERY
    # =========================================================================

    async def _discover_idor_params(self, url: str) -> Dict[str, str]:
        """IDOR-focused parameter discovery."""  # I/O
        result = await discover_idor_params(url)
        return result

    # =========================================================================
    # QUEUE CONSUMER
    # =========================================================================

    async def analyze_and_dedup_queue(self) -> List[Dict]:
        """Phase A: WET -> DRY with autonomous parameter discovery."""  # I/O
        from bugtrace.core.queue import queue_manager
        from bugtrace.agents.specialist_utils import resolve_param_endpoints, resolve_param_from_reasoning

        logger.info(f"[{self.name}] ===== PHASE A: Analyzing WET list (autonomous discovery) =====")

        queue = queue_manager.get_queue("idor")
        wet_findings = []

        batch_size = settings.IDOR_QUEUE_BATCH_SIZE
        max_wait = settings.IDOR_QUEUE_MAX_WAIT

        wait_start = time.monotonic()
        while (time.monotonic() - wait_start) < max_wait:
            depth = queue.depth() if hasattr(queue, 'depth') else 0
            if depth > 0:
                break
            await asyncio.sleep(0.5)
        else:
            return []

        # Drain WET queue
        empty_count = 0
        while empty_count < 10:
            item = await queue.dequeue(timeout=0.5)
            if item is None:
                empty_count += 1
                await asyncio.sleep(0.5)
                continue
            empty_count = 0
            finding = item.get("finding", {})
            url = finding.get("url", "")
            if url:
                wet_findings.append({
                    "url": url,
                    "parameter": finding.get("parameter", ""),
                    "original_value": finding.get("original_value", ""),
                    "finding": finding,
                    "scan_context": item.get("scan_context", self._scan_context),
                })

        logger.info(f"[{self.name}] Phase A: Drained {len(wet_findings)} WET findings")
        if not wet_findings:
            return []

        # Autonomous parameter discovery
        expanded_wet_findings = []
        seen_urls = set()
        seen_params = set()

        for wet_item in wet_findings:
            url = wet_item.get("url", "")
            param = wet_item.get("parameter", "") or (wet_item.get("finding", {}) or {}).get("parameter", "")
            if param and (url, param) not in seen_params:
                seen_params.add((url, param))
                expanded_wet_findings.append(wet_item)

        for wet_item in wet_findings:
            url = wet_item.get("url", "")
            if url in seen_urls:
                continue
            seen_urls.add(url)
            try:
                all_params = await discover_idor_params(url)
                if not all_params:
                    continue
                for param_name, param_value in all_params.items():
                    if (url, param_name) not in seen_params:
                        seen_params.add((url, param_name))
                        expanded_wet_findings.append({
                            "url": url, "parameter": param_name,
                            "original_value": param_value,
                            "finding": wet_item.get("finding", {}),
                            "scan_context": wet_item.get("scan_context", self._scan_context),
                            "_discovered": True,
                        })
            except Exception as e:
                logger.error(f"[{self.name}] Discovery failed for {url}: {e}")

        # Resolve endpoint URLs
        if hasattr(self, '_last_discovery_html') and self._last_discovery_html:
            for base_url in seen_urls:
                endpoint_map = resolve_param_endpoints(self._last_discovery_html, base_url)
                reasoning_map = resolve_param_from_reasoning(expanded_wet_findings, base_url)
                for k, v in reasoning_map.items():
                    if k not in endpoint_map:
                        endpoint_map[k] = v
                if endpoint_map:
                    for item in expanded_wet_findings:
                        if item.get("url") == base_url:
                            param = item.get("parameter", "")
                            if param in endpoint_map and endpoint_map[param] != base_url:
                                item["url"] = endpoint_map[param]

        # Deduplication
        try:
            dry_list = await self._llm_analyze_and_dedup(expanded_wet_findings, self._scan_context)
        except Exception:
            dry_list = fallback_fingerprint_dedup(expanded_wet_findings)

        self._dry_findings = dry_list
        logger.info(f"[{self.name}] Phase A: {len(expanded_wet_findings)} WET -> {len(dry_list)} DRY")
        return dry_list

    async def _llm_analyze_and_dedup(self, wet_findings: List[Dict], context: str) -> List[Dict]:
        """LLM-powered intelligent deduplication."""  # I/O
        from bugtrace.core.llm_client import llm_client

        tech_stack = getattr(self, '_tech_stack_context', {}) or {}
        lang = tech_stack.get('lang', 'generic')
        frameworks = tech_stack.get('frameworks', [])

        idor_prime_directive = getattr(self, '_idor_prime_directive', '')
        idor_dedup_context = self.generate_idor_dedup_context(tech_stack) if tech_stack else ''

        system_prompt = f"""You are an expert security analyst specializing in IDOR deduplication.

## DEDUPLICATION RULES
1. Same URL + DIFFERENT param -> DIFFERENT (keep all)
2. Same URL + Same parameter + Same original_value -> DUPLICATE (keep best)
3. Different endpoints -> DIFFERENT (keep both)

{idor_prime_directive}"""

        prompt = f"""Analyzing {len(wet_findings)} potential IDOR findings.

{idor_dedup_context}

## TARGET CONTEXT
- Language: {lang}
- Frameworks: {', '.join(frameworks[:3]) if frameworks else 'None detected'}

## WET LIST:
{json.dumps(wet_findings, indent=2)}

## OUTPUT FORMAT (JSON only):
{{
  "findings": [
    {{"url": "...", "parameter": "...", "original_value": "...", "rationale": "...", "attack_priority": 1-5}}
  ],
  "duplicates_removed": <count>,
  "reasoning": "Brief explanation"
}}"""

        response = await llm_client.generate(
            prompt=prompt, system_prompt=system_prompt,
            module_name="IDOR_DEDUP", temperature=0.2,
        )

        try:
            result = json.loads(response)
            return result.get("findings", wet_findings)
        except json.JSONDecodeError:
            return fallback_fingerprint_dedup(wet_findings)

    async def exploit_dry_list(self) -> List[Dict]:
        """Phase B: Exploit DRY list."""  # I/O
        logger.info(f"[{self.name}] ===== PHASE B: Exploiting DRY list =====")

        self._auth_headers = await fetch_auth_headers(self._scan_context)
        validated_findings = []

        for idx, finding_data in enumerate(self._dry_findings, 1):
            url = finding_data.get("url", "")
            parameter = finding_data.get("parameter", "")
            original_value = finding_data.get("original_value", "")

            logger.info(f"[{self.name}] Phase B [{idx}/{len(self._dry_findings)}]: Testing {url}?{parameter}")

            if hasattr(self, '_v'):
                self._v.emit("exploit.specialist.param.started", {
                    "agent": "IDOR", "param": parameter, "url": url,
                    "idx": idx, "total": len(self._dry_findings),
                })
                self._v.reset("exploit.specialist.progress")

            try:
                self.url = url
                result = await self._test_single_param_from_queue(url, parameter, original_value, finding_data.get("finding", {}))

                if result and result.get("status") in [
                    ValidationStatus.VALIDATED_CONFIRMED.value,
                    ValidationStatus.PENDING_VALIDATION.value,
                ]:
                    if settings.IDOR_ENABLE_DEEP_EXPLOITATION:
                        severity = result.get("severity")
                        threshold = settings.IDOR_EXPLOITER_SEVERITY_THRESHOLD
                        severity_order = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
                        if severity_order.get(severity, 0) >= severity_order.get(threshold, 2):
                            result = await self._exploit_deep(result)

                    validated_findings.append(result)
                    fingerprint = generate_idor_fingerprint(url, parameter)

                    if fingerprint not in self._emitted_findings:
                        self._emitted_findings.add(fingerprint)
                        if settings.WORKER_POOL_EMIT_EVENTS:
                            status = result.get("status", ValidationStatus.VALIDATED_CONFIRMED.value)
                            self._emit_idor_finding({
                                "specialist": "idor", "type": "IDOR",
                                "url": result.get("url"), "parameter": result.get("parameter"),
                                "payload": result.get("payload"),
                                "tested_value": result.get("tested_value", result.get("payload")),
                                "severity": result.get("severity"), "status": status,
                                "evidence": result.get("evidence", {"differential_analysis": True}),
                                "validation_requires_cdp": status == ValidationStatus.PENDING_VALIDATION.value,
                            }, scan_context=self._scan_context)

                        if hasattr(self, '_v'):
                            self._v.emit("exploit.specialist.confirmed", {
                                "agent": "IDOR", "param": parameter, "url": url,
                                "severity": result.get("severity"),
                            })

            except Exception as e:
                logger.error(f"[{self.name}] Phase B [{idx}]: Attack failed: {e}")
            finally:
                if hasattr(self, '_v'):
                    self._v.emit("exploit.specialist.param.completed", {
                        "agent": "IDOR", "param": parameter, "url": url, "idx": idx,
                    })

        logger.info(f"[{self.name}] Phase B: {len(validated_findings)} validated findings")
        return validated_findings

    async def _generate_specialist_report(self, findings: List[Dict]) -> str:
        """Generate specialist report."""  # I/O
        import aiofiles
        from datetime import datetime

        scan_dir = getattr(self, 'report_dir', None)
        if not scan_dir:
            scan_id = self._scan_context.split("/")[-1]
            scan_dir = settings.BASE_DIR / "reports" / scan_id
        results_dir = scan_dir / "specialists" / "results"
        results_dir.mkdir(parents=True, exist_ok=True)

        report = {
            "agent": self.name,
            "timestamp": datetime.now().isoformat(),
            "scan_context": self._scan_context,
            "phase_a": {
                "wet_count": len(self._dry_findings) + (len(findings) if findings else 0),
                "dry_count": len(self._dry_findings),
                "dedup_method": "llm_with_fingerprint_fallback",
            },
            "phase_b": {
                "validated_count": len([f for f in findings if f.get("validated")]),
                "pending_count": len([f for f in findings if not f.get("validated")]),
                "total_findings": len(findings),
            },
            "findings": findings,
        }

        report_path = results_dir / "idor_results.json"
        async with aiofiles.open(report_path, 'w') as f:
            await f.write(json.dumps(report, indent=2))

        logger.info(f"[{self.name}] Specialist report saved: {report_path}")
        return str(report_path)

    async def start_queue_consumer(self, scan_context: str) -> None:
        """TWO-PHASE queue consumer (WET -> DRY)."""  # I/O
        from bugtrace.agents.specialist_utils import (
            report_specialist_start, report_specialist_done,
            report_specialist_wet_dry, write_dry_file,
        )
        from bugtrace.core.queue import queue_manager

        self._queue_mode = True
        self._scan_context = scan_context
        self._v = create_emitter("IDORAgent", self._scan_context)

        await self._load_idor_tech_context()

        queue = queue_manager.get_queue("idor")
        initial_depth = queue.depth()
        report_specialist_start(self.name, queue_depth=initial_depth)
        self._v.emit("exploit.specialist.started", {"agent": "IDOR", "queue_depth": initial_depth})

        # PHASE A
        dry_list = await self.analyze_and_dedup_queue()
        report_specialist_wet_dry(self.name, initial_depth, len(dry_list) if dry_list else 0)
        write_dry_file(self, dry_list, initial_depth, "idor")

        if not dry_list:
            report_specialist_done(self.name, processed=0, vulns=0)
            self._v.emit("exploit.specialist.completed", {"agent": "IDOR", "dry_count": 0, "vulns": 0})
            return

        # PHASE B
        results = await self.exploit_dry_list()
        vulns_count = len([r for r in results if r]) if results else 0
        vulns_count += len(self._dry_findings) if hasattr(self, '_dry_findings') else 0

        if results or self._dry_findings:
            await self._generate_specialist_report(results)

        report_specialist_done(self.name, processed=len(dry_list), vulns=vulns_count)
        self._v.emit("exploit.specialist.completed", {"agent": "IDOR", "dry_count": len(dry_list), "vulns": vulns_count})

    async def stop_queue_consumer(self) -> None:
        """Stop queue consumer."""
        if self._worker_pool:
            await self._worker_pool.stop()
            self._worker_pool = None
        self._queue_mode = False
        logger.info(f"[{self.name}] Queue consumer stopped")

    async def _test_single_param_from_queue(self, url, param, original_value, finding) -> Optional[Dict]:
        """Test a single parameter from queue for IDOR."""  # I/O
        try:
            item = {"parameter": param, "original_value": original_value}
            return await self._test_idor_param(item)
        except Exception as e:
            logger.error(f"[{self.name}] Queue item test failed: {e}")
            return None

    async def _handle_queue_result(self, item: dict, result: Optional[Dict]) -> None:
        """Handle completed queue item processing."""
        if result is None:
            return

        finding_data = {
            "context": "idor_differential", "payload": result.get("payload", ""),
            "validation_method": "idor_fuzzer",
            "evidence": {"diff_type": result.get("evidence", "")},
        }
        needs_cdp = requires_cdp_validation(finding_data)

        status = result.get("status", "PENDING_VALIDATION")
        if status == "PENDING_VALIDATION":
            needs_cdp = True

        url = result.get("url")
        parameter = result.get("parameter")
        fingerprint = generate_idor_fingerprint(url, parameter)

        if fingerprint in self._emitted_findings:
            return

        self._emitted_findings.add(fingerprint)

        if settings.WORKER_POOL_EMIT_EVENTS:
            self._emit_idor_finding({
                "specialist": "idor", "type": "IDOR",
                "url": result.get("url"), "parameter": result.get("parameter"),
                "payload": result.get("payload"),
                "tested_value": result.get("tested_value", result.get("payload")),
                "status": status,
                "evidence": result.get("evidence", {"differential_analysis": True}),
                "validation_requires_cdp": needs_cdp,
            }, scan_context=self._scan_context)

    def get_queue_stats(self) -> dict:
        """Get queue consumer statistics."""
        if not self._worker_pool:
            return {"mode": "direct", "queue_mode": False}
        return {"mode": "queue", "queue_mode": True, "worker_stats": self._worker_pool.get_stats()}

    # =========================================================================
    # TECH CONTEXT LOADING (v3.2)
    # =========================================================================

    async def _load_idor_tech_context(self) -> None:
        """Load technology stack context from recon data (v3.2)."""  # I/O
        scan_dir = getattr(self, 'report_dir', None)
        if not scan_dir:
            scan_id = self._scan_context.split("/")[-1] if self._scan_context else ""
            scan_dir = settings.BASE_DIR / "reports" / scan_id if scan_id else None

        if not scan_dir or not Path(scan_dir).exists():
            self._tech_stack_context = {"db": "generic", "server": "generic", "lang": "generic"}
            self._idor_prime_directive = ""
            return

        self._tech_stack_context = self.load_tech_stack(Path(scan_dir))
        self._idor_prime_directive = self.generate_idor_context_prompt(self._tech_stack_context)

        lang = self._tech_stack_context.get("lang", "generic")
        frameworks = self._tech_stack_context.get("frameworks", [])
        logger.info(f"[{self.name}] IDOR tech context loaded: lang={lang}, frameworks={frameworks[:3] if frameworks else 'none'}")
