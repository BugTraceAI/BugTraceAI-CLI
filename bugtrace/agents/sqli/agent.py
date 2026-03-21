"""
SQLi Agent - Thin Orchestration Class

SQLiAgent inherits from BaseAgent and TechContextMixin.
All business logic is delegated to the extracted modules:
- types: SQLiFinding dataclass, enums, constants
- context: PURE confidence, prioritization, technique mapping
- payloads: PURE payload generation, URL building, filter mutations
- validation: PURE response analysis, SQLi confirmation checks
- discovery: I/O parameter discovery, SPA detection
- exploitation: I/O payload sending, technique testing
- dedup: PURE SQLi fingerprint dedup
- reporting: I/O save SQLi reports
- pipeline: ORCHESTRATION escalation levels, WET->DRY flow
"""

import asyncio
import json
import time
import aiohttp
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
from urllib.parse import urlparse, parse_qs

from loguru import logger

from bugtrace.agents.base import BaseAgent
from bugtrace.agents.worker_pool import WorkerPool, WorkerConfig
from bugtrace.core.http_manager import http_manager, ConnectionProfile
from bugtrace.core.queue import queue_manager
from bugtrace.core.event_bus import EventType
from bugtrace.tools.external import external_tools
from bugtrace.core.ui import dashboard
from bugtrace.core.config import settings
from bugtrace.core.validation_status import ValidationStatus, requires_cdp_validation
from bugtrace.core.verbose_events import create_emitter
from bugtrace.agents.mixins.tech_context import TechContextMixin

# Import from extracted modules
from bugtrace.agents.sqli.types import SQLiFinding, SQLiConfidenceTier
from bugtrace.agents.sqli.context import (
    get_confidence_tier,
    determine_validation_status,
    should_stop_testing,
    prioritize_params,
    validate_sqli_finding,
    should_test_cookie,
    detect_dbms_from_output,
    get_sqlmap_technique_hint,
    get_technique_name,
    sqlmap_type_to_technique,
)
from bugtrace.agents.sqli.payloads import (
    get_base_url,
    build_url_with_param,
    build_exploit_url,
    mutate_payload_for_filters,
    generate_repro_steps,
    extract_post_params,
    flatten_json,
    set_nested_value,
    build_full_sqlmap_command,
    build_progressive_sqlmap_commands,
)
from bugtrace.agents.sqli.validation import (
    detect_database_type,
    extract_info_from_error,
    finding_to_dict,
    parse_sqlmap_output,
    extract_finding_data,
    build_llm_prompt,
)
from bugtrace.agents.sqli.discovery import (
    discover_sqli_params,
    detect_and_resolve_spa_url,
)
from bugtrace.agents.sqli.exploitation import (
    detect_filtered_chars,
    detect_prepared_statements,
    test_error_based,
    test_boolean_based,
    test_union_based,
    test_time_based,
    test_oob_sqli,
    test_json_body_injection,
    test_second_order_sqli,
    test_cookie_sqli,
    test_header_sqli,
    run_sqlmap_on_param,
    generate_llm_exploitation_explanation,
)
from bugtrace.agents.sqli.dedup import (
    generate_sqli_fingerprint,
    fallback_fingerprint_dedup,
)
from bugtrace.agents.sqli.reporting import generate_specialist_report
from bugtrace.agents.sqli.pipeline import (
    sqli_escalation_pipeline,
    analyze_and_dedup_queue,
)


class SQLiAgent(BaseAgent, TechContextMixin):
    """
    Intelligent SQL Injection Specialist v3.

    Thin orchestration class. All business logic delegates to extracted modules.

    Features:
    - Confidence-based validation hierarchy
    - Parameter prioritization
    - OOB detection with Interactsh
    - Filter detection and adaptive mutation
    - Error info extraction
    - Triple time-based verification
    - JSON/API body injection
    - Second-order SQLi detection
    - Prepared statement early exit
    - Complete SQLMap reproduction commands
    - LLM exploitation explanation
    - Context-aware technology stack integration (v3.2)
    """

    def __init__(self, url: str = None, param: str = None, event_bus: Any = None,
                 cookies: List[Dict] = None, headers: Dict[str, str] = None,
                 post_data: str = None, observation_points: List[str] = None,
                 report_dir: Path = None):
        super().__init__("SQLiAgent", "SQL Injection Specialist v3", event_bus=event_bus, agent_id="sqli_agent")
        self.url = url
        self.param = param
        self.cookies = cookies or []
        self.headers = headers or {}
        self.post_data = post_data
        self.observation_points = observation_points or []
        self.report_dir = report_dir

        self._tested_params: Set[str] = set()
        self._detected_db_type: Optional[str] = None
        self._detected_filters: Set[str] = set()
        self._baseline_response_time: float = 0
        self._baseline_content_length: int = 0
        self._baseline_status_code: int = 0
        self._max_impact_achieved = False
        self._interactsh = None

        # Statistics
        self._stats = {
            "params_tested": 0,
            "vulns_found": 0,
            "oob_callbacks": 0,
            "filters_detected": 0,
            "prepared_statement_exits": 0,
        }

        # Queue consumption mode (Phase 19)
        self._queue_mode = False
        self._worker_pool: Optional[WorkerPool] = None
        self._scan_context: str = ""
        self._stop_requested = False

        # Expert deduplication
        self._emitted_findings: set = set()

        # WET -> DRY transformation
        self._dry_findings: List[Dict] = []

        # v3.2: Context-aware tech stack
        self._tech_stack_context: Dict = {}
        self._prime_directive: str = ""

        # Cached HTML from discovery
        self._last_discovery_html: Optional[str] = None

    # =========================================================================
    # AUTO-VALIDATION
    # =========================================================================

    def _validate_before_emit(self, finding: Dict) -> tuple[bool, str]:
        """SQLi-specific validation before emitting finding."""
        is_valid, error = super()._validate_before_emit(finding)
        if not is_valid:
            return False, error
        return validate_sqli_finding(finding)

    def _emit_sqli_finding(self, finding_dict: Dict, status: str = None, needs_cdp: bool = False):
        """Helper to emit SQLi finding using BaseAgent.emit_finding() with validation."""
        full_event = {
            "specialist": "sqli",
            "finding": finding_dict,
            "status": status or ValidationStatus.VALIDATED_CONFIRMED.value,
            "validation_requires_cdp": needs_cdp,
            "scan_context": getattr(self, '_scan_context', 'unknown'),
        }

        result = self.emit_finding(finding_dict)

        if result:
            if settings.WORKER_POOL_EMIT_EVENTS:
                asyncio.create_task(self.event_bus.emit(EventType.VULNERABILITY_DETECTED, full_event))

    # =========================================================================
    # DELEGATE TO PURE FUNCTIONS
    # =========================================================================

    def _finding_to_dict(self, finding: SQLiFinding) -> Dict:
        """Convert SQLiFinding to dict. Delegates to validation module."""
        return finding_to_dict(finding)

    def _get_base_url(self) -> str:
        """Get base URL. Delegates to payloads module."""
        return get_base_url(self.url)

    def _build_url_with_param(self, base_url: str, param: str, value: str) -> str:
        """Build URL with param. Delegates to payloads module."""
        return build_url_with_param(self.url, param, value)

    def _build_exploit_url(self, url: str, param: str, payload: str):
        """Build exploit URL. Delegates to payloads module."""
        return build_exploit_url(url, param, payload)

    def _prioritize_params(self, params: List[str]) -> List[str]:
        """Prioritize params. Delegates to context module."""
        result = prioritize_params(params)
        high = [p for p in result if p in params[:len(result)]]
        if high:
            logger.info(f"[{self.name}] High-priority params: {high[:5]}")
        return result

    def _detect_database_type(self, response_text: str) -> Optional[str]:
        """Detect DB type. Delegates to validation module."""
        return detect_database_type(response_text)

    def _extract_info_from_error(self, error_response: str) -> Dict:
        """Extract error info. Delegates to validation module."""
        return extract_info_from_error(error_response)

    def _generate_repro_steps(self, url: str, param: str, payload: str, curl_cmd: str) -> List[str]:
        """Generate repro steps. Delegates to payloads module."""
        return generate_repro_steps(url, param, payload, curl_cmd)

    def _get_confidence_tier(self, technique: str, evidence: Dict) -> int:
        """Get confidence tier. Delegates to context module."""
        return get_confidence_tier(technique, evidence)

    def _determine_validation_status(self, technique: str, evidence: Dict) -> str:
        """Determine validation status. Delegates to context module."""
        return determine_validation_status(technique, evidence)

    def _should_stop_testing(self, technique: str, evidence: Dict, findings_count: int):
        """Check if should stop. Delegates to context module."""
        return should_stop_testing(technique, evidence, findings_count)

    def _generate_sqli_fingerprint(self, parameter: str, url: str) -> tuple:
        """Generate fingerprint. Delegates to dedup module."""
        return generate_sqli_fingerprint(parameter, url)

    def _should_test_cookie(self, cookie_name: str) -> bool:
        """Check cookie. Delegates to context module."""
        return should_test_cookie(cookie_name)

    def _detect_dbms_from_output(self, output: str) -> str:
        """Detect DBMS. Delegates to context module."""
        return detect_dbms_from_output(output)

    def _mutate_payload_for_filters(self, payload: str) -> List[str]:
        """Mutate payload. Delegates to payloads module."""
        return mutate_payload_for_filters(payload, self._detected_filters)

    def _has_block_indicators(self, content: str) -> bool:
        """Check block indicators. Delegates to payloads module."""
        from bugtrace.agents.sqli.payloads import has_block_indicators
        return has_block_indicators(content)

    def _parse_sqlmap_output(self, output: str) -> Dict:
        """Parse SQLMap output. Delegates to validation module."""
        return parse_sqlmap_output(output)

    def _sqlmap_type_to_technique(self, sqlmap_type: str) -> str:
        """Convert SQLMap type. Delegates to context module."""
        return sqlmap_type_to_technique(sqlmap_type)

    def _get_sqlmap_technique_hint(self, ai_suggestion: str) -> str:
        """Get technique hint. Delegates to context module."""
        return get_sqlmap_technique_hint(ai_suggestion)

    def _get_technique_name(self, technique: str) -> str:
        """Get technique name. Delegates to context module."""
        return get_technique_name(technique)

    def _extract_post_params(self, post_data: str) -> List[str]:
        """Extract POST params. Delegates to payloads module."""
        return extract_post_params(post_data)

    def _build_full_sqlmap_command(self, param: str, technique: str, db_type=None, tamper=None, extra_options=None) -> str:
        """Build SQLMap command. Delegates to payloads module."""
        return build_full_sqlmap_command(
            self.url, param, technique, self.cookies, self.headers,
            self._detected_filters, db_type, tamper, extra_options
        )

    def _build_progressive_sqlmap_commands(self, param: str, technique: str, db_type=None):
        """Build progressive SQLMap commands. Delegates to payloads module."""
        return build_progressive_sqlmap_commands(
            self.url, param, technique, self.cookies, self.headers,
            self._detected_filters, db_type
        )

    # =========================================================================
    # DELEGATE TO I/O FUNCTIONS
    # =========================================================================

    async def _detect_filtered_chars(self, session, param):
        """Detect filtered chars. Delegates to exploitation module."""
        filtered = await detect_filtered_chars(
            session, self.url, param, self.name,
            getattr(self, '_v', None)
        )
        self._detected_filters = filtered
        self._stats["filters_detected"] = len(filtered)
        return filtered

    async def _detect_prepared_statements(self, session, param):
        """Detect prepared statements. Delegates to exploitation module."""
        result = await detect_prepared_statements(session, self.url, param, self.name)
        if result:
            self._stats["prepared_statement_exits"] += 1
        return result

    async def _test_error_based(self, session, param):
        """Test error-based. Delegates to exploitation module."""
        finding, db_type = await test_error_based(
            session, self.url, param, self._detected_filters,
            self._baseline_status_code, getattr(self, '_v', None), self.name
        )
        if db_type:
            self._detected_db_type = db_type
        return finding

    async def _test_boolean_based(self, session, param):
        """Test boolean-based. Delegates to exploitation module."""
        return await test_boolean_based(
            session, self.url, param, self._detected_db_type,
            getattr(self, '_v', None), self.name
        )

    async def _test_union_based(self, session, param):
        """Test union-based. Delegates to exploitation module."""
        return await test_union_based(
            session, self.url, param, self._detected_filters,
            getattr(self, '_v', None), self.name
        )

    async def _test_time_based(self, session, param):
        """Test time-based. Delegates to exploitation module."""
        return await test_time_based(
            session, self.url, param, self._detected_db_type,
            getattr(self, '_v', None), self.name
        )

    async def _test_oob_sqli(self, session, param):
        """Test OOB. Delegates to exploitation module."""
        return await test_oob_sqli(
            session, self.url, param, self._interactsh,
            self._detected_db_type, self._detected_filters,
            getattr(self, '_v', None), self.name
        )

    async def _test_json_body_injection(self, session, url, json_body):
        """Test JSON injection. Delegates to exploitation module."""
        return await test_json_body_injection(
            session, url, json_body, self.headers, self.name
        )

    async def _test_second_order_sqli(self, session, injection_url, injection_param):
        """Test second-order. Delegates to exploitation module."""
        return await test_second_order_sqli(
            session, injection_url, injection_param,
            self.observation_points, self.name
        )

    async def _discover_sqli_params(self, url: str) -> Dict[str, str]:
        """Discover params. Delegates to discovery module."""
        result = await discover_sqli_params(url, self.name)
        # Cache HTML for endpoint resolution
        return result

    async def _detect_and_resolve_spa_url(self, url: str, param: str):
        """Detect SPA. Delegates to discovery module."""
        return await detect_and_resolve_spa_url(url, param, self.name)

    async def _run_sqlmap_on_param(self, param, technique_hint=None, exploit_mode=False):
        """Run SQLMap. Delegates to exploitation module."""
        return await run_sqlmap_on_param(
            self.url, param, technique_hint, exploit_mode,
            getattr(self, '_v', None), self.name
        )

    async def _test_cookie_sqli_from_queue(self, url, cookie_name, finding):
        """Test cookie SQLi. Delegates to exploitation module."""
        return await test_cookie_sqli(url, cookie_name, finding, self.name)

    async def _test_header_sqli(self, url, header_name, finding):
        """Test header SQLi. Delegates to exploitation module."""
        return await test_header_sqli(url, header_name, finding, self.name)

    async def _generate_llm_exploitation_explanation(self, finding):
        """Generate LLM explanation. Delegates to exploitation module."""
        return await generate_llm_exploitation_explanation(finding)

    async def _generate_specialist_report(self, findings: List[Dict]) -> str:
        """Generate report. Delegates to reporting module."""
        return generate_specialist_report(
            findings, self._dry_findings, self._scan_context,
            self.report_dir, getattr(self, '_wet_count', None)
        )

    # =========================================================================
    # PIPELINE DELEGATION
    # =========================================================================

    async def _sqli_escalation_pipeline(self, url, param, dry_item):
        """Run escalation pipeline. Delegates to pipeline module."""
        return await sqli_escalation_pipeline(
            url, param, dry_item,
            self._baseline_response_time,
            self._baseline_content_length,
            self._baseline_status_code,
            self._detected_db_type,
            self._interactsh,
            getattr(self, '_scan_depth', '') or settings.SCAN_DEPTH,
            getattr(self, '_v', None),
            self.name,
        )

    # =========================================================================
    # INTERACTSH
    # =========================================================================

    async def _init_interactsh(self):
        """Initialize Interactsh client for OOB detection."""
        try:
            from bugtrace.tools.interactsh_client import InteractshClient
            self._interactsh = InteractshClient()
            await self._interactsh.register()
            logger.info(f"[{self.name}] Interactsh initialized for OOB SQLi")
        except Exception as e:
            logger.warning(f"[{self.name}] Interactsh init failed: {e}")
            self._interactsh = None

    # =========================================================================
    # RUN LOOP HELPERS
    # =========================================================================

    def _configure_session(self, session: aiohttp.ClientSession):
        """Configure session with cookies and headers."""
        if self.cookies:
            cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in self.cookies])
            session.cookie_jar.update_cookies({"Cookie": cookie_str})

    async def _initialize_baseline(self, session: aiohttp.ClientSession):
        """Initialize baseline response and Interactsh."""
        dashboard.log(f"[{self.name}] Phase 1: Initializing...", "INFO")

        try:
            start = time.time()
            async with session.get(self.url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                baseline_content = await resp.text()
                self._baseline_response_time = time.time() - start
                self._baseline_content_length = len(baseline_content)
                self._baseline_status_code = resp.status
                self._detected_db_type = detect_database_type(baseline_content)
                logger.info(f"[{self.name}] Baseline: status={resp.status}, length={self._baseline_content_length}, time={self._baseline_response_time:.2f}s")
        except Exception as e:
            logger.warning(f"Baseline failed: {e}")

        await self._init_interactsh()

    async def _extract_and_prioritize_params(self) -> List[str]:
        """Extract and prioritize parameters from URL and POST data."""
        parsed = urlparse(self.url)
        params = list(parse_qs(parsed.query).keys())

        if self.param and self.param not in params:
            params.insert(0, self.param)

        if self.post_data:
            post_params = extract_post_params(self.post_data)
            params.extend(post_params)

        params = prioritize_params(list(set(params)))

        if not params:
            params = ["id"]

        return params

    async def _test_all_parameters(self, session, params, findings):
        """Test all parameters for SQL injection."""
        for param in params:
            if self._max_impact_achieved:
                dashboard.log(f"[{self.name}] Max impact achieved, stopping", "SUCCESS")
                break

            if param in self._tested_params:
                continue

            self._tested_params.add(param)
            self._stats["params_tested"] += 1
            dashboard.log(f"[{self.name}] Testing: {param}", "INFO")

            if await self._detect_prepared_statements(session, param):
                continue

            await self._detect_filtered_chars(session, param)

            finding = await self._test_single_parameter(session, param)
            if finding:
                findings.append(self._finding_to_dict(finding))
                if self._should_stop_after_finding(finding, findings):
                    break

        return findings

    async def _test_single_parameter(self, session, param):
        """Test single parameter with all techniques."""
        # OOB SQLi
        if self._interactsh:
            finding = await self._test_oob_sqli(session, param)
            if finding:
                return await self._finalize_finding(finding, "oob")

        # Error-based
        error_finding = await self._test_error_based(session, param)

        # Union-based (Prioritized)
        union_finding = await self._test_union_based(session, param)
        if union_finding:
            dashboard.log(f"[{self.name}] UNION SQLi confirmed. Escalate to SQLMap...", "INFO")
            dump_finding = await self._run_sqlmap_on_param(param, technique_hint="U", exploit_mode=True)
            if dump_finding:
                return await self._finalize_finding(dump_finding, "union_based")
            else:
                return await self._finalize_finding(union_finding, "union_based")

        # Error-based
        if error_finding:
            dashboard.log(f"[{self.name}] Error-based SQLi confirmed. Escalate to SQLMap...", "INFO")
            dump_finding = await self._run_sqlmap_on_param(param, technique_hint="E", exploit_mode=True)
            if dump_finding:
                return await self._finalize_finding(dump_finding, "error_based")
            return await self._finalize_finding(error_finding, "error_based")

        # Boolean-based
        finding = await self._test_boolean_based(session, param)
        if finding:
            return await self._finalize_finding(finding, "boolean_based")

        # Time-based
        time_finding = await self._test_time_based(session, param)
        if time_finding:
            dashboard.log(f"[{self.name}] Time-based candidate found. Verifying with SQLMap...", "INFO")
            sqlmap_confirmation = await self._run_sqlmap_on_param(param, technique_hint="T")
            if sqlmap_confirmation:
                return await self._finalize_finding(sqlmap_confirmation, "time_based")
            else:
                dashboard.log(f"[{self.name}] Discarding unverified Time-based finding (SQLMap failed)", "WARNING")

        return None

    async def _finalize_finding(self, finding: SQLiFinding, technique: str) -> SQLiFinding:
        """Finalize finding with stats."""
        self._stats["vulns_found"] += 1
        return finding

    def _should_stop_after_finding(self, finding: SQLiFinding, findings: List) -> bool:
        """Check if we should stop testing after this finding."""
        stop, reason = should_stop_testing(
            finding.technique, finding.evidence, len(findings)
        )
        if stop:
            self._max_impact_achieved = True
            dashboard.log(f"[{self.name}] {reason}", "SUCCESS")
        return stop

    async def _test_json_injection(self, session, findings):
        """Test JSON body injection if applicable."""
        if not self.post_data or self._max_impact_achieved:
            return findings

        try:
            json_body = json.loads(self.post_data)
            if hasattr(self, '_v'):
                self._v.emit("exploit.sqli.json_testing", {
                    "url": self.url,
                    "keys": list(json_body.keys()) if isinstance(json_body, dict) else [],
                })
            dashboard.log(f"[{self.name}] Phase 4: Testing JSON body...", "INFO")
            json_findings = await self._test_json_body_injection(session, self.url, json_body)
            for jf in json_findings:
                findings.append(self._finding_to_dict(jf))
            self._stats["vulns_found"] += len(json_findings)
        except json.JSONDecodeError:
            pass

        return findings

    async def _test_second_order_injection(self, session, params, findings):
        """Test second-order SQL injection if applicable."""
        if not self.observation_points or self._max_impact_achieved:
            return findings

        dashboard.log(f"[{self.name}] Phase 5: Testing second-order SQLi...", "INFO")
        for param in params[:5]:
            so_finding = await self._test_second_order_sqli(session, self.url, param)
            if so_finding:
                findings.append(so_finding)
                self._stats["vulns_found"] += 1
                break

        return findings

    async def _run_sqlmap_fallback(self, session, params, findings):
        """Run SQLMap as fallback if no findings."""
        if findings or not external_tools.docker_cmd:
            return findings

        dashboard.log(f"[{self.name}] Phase 6: SQLMap fallback...", "INFO")

        for param in params[:3]:
            finding = await self._run_sqlmap_on_param(param)
            if finding:
                findings.append(self._finding_to_dict(finding))
                self._stats["vulns_found"] += 1
                if settings.EARLY_EXIT_ON_FINDING:
                    break

        return findings

    def _log_final_stats(self, findings: List):
        """Log final statistics."""
        dashboard.log(
            f"[{self.name}] Complete: {self._stats['params_tested']} params, "
            f"{self._stats['vulns_found']} vulns, {self._stats['oob_callbacks']} OOB callbacks",
            "SUCCESS" if findings else "INFO"
        )

    # =========================================================================
    # MAIN RUN LOOP
    # =========================================================================

    async def run_loop(self) -> Dict:
        """Multi-phase SQLi detection and validation."""
        dashboard.current_agent = self.name
        dashboard.log(f"[{self.name}] Starting SQLi v3 scan on {self.url}", "INFO")

        findings = []

        async with http_manager.isolated_session(ConnectionProfile.EXTENDED) as session:
            self._configure_session(session)

            try:
                await self._initialize_baseline(session)
                params = await self._extract_and_prioritize_params()

                dashboard.log(f"[{self.name}] Testing {len(params)} parameters (prioritized)", "INFO")

                findings = await self._test_all_parameters(session, params, findings)
                findings = await self._test_json_injection(session, findings)
                findings = await self._test_second_order_injection(session, params, findings)
                findings = await self._run_sqlmap_fallback(session, params, findings)

                self._log_final_stats(findings)

                return {
                    "vulnerable": len(findings) > 0,
                    "findings": findings,
                    "stats": self._stats
                }

            except Exception as e:
                logger.error(f"[{self.name}] SQLi scan failed: {e}", exc_info=True)
                return {"vulnerable": False, "findings": [], "error": str(e)}

    # =========================================================================
    # WET -> DRY TWO-PHASE PROCESSING
    # =========================================================================

    async def analyze_and_dedup_queue(self) -> List[Dict]:
        """Phase A: Global analysis of WET list with LLM-powered deduplication."""
        dry_list = await analyze_and_dedup_queue(
            self.url,
            self._tech_stack_context,
            self._prime_directive,
            discover_fn=self._discover_sqli_params,
            last_discovery_html=self._last_discovery_html,
            agent_name=self.name,
        )

        self._dry_findings = dry_list
        return dry_list

    async def exploit_dry_list(self) -> List[Dict]:
        """Phase B: Attack each DRY finding with escalation pipeline."""
        results = []

        logger.info(f"[{self.name}] Phase B: Exploiting {len(self._dry_findings)} DRY findings (v3.4 escalation)...")

        for dry_item in self._dry_findings:
            url = dry_item.get("url")
            param = dry_item.get("parameter")

            if not url or not param:
                continue

            # SPA detection
            if not param.startswith(("Cookie:", "Header:")):
                api_url = await self._detect_and_resolve_spa_url(url, param)
                if api_url:
                    url = api_url
                    dry_item = {**dry_item, "url": api_url}
                    logger.info(f"[{self.name}] Redirected SPA route to API: {api_url}")

            # Configure agent for this specific test
            self.url = url
            self.param = param

            # Route by param type
            if param.startswith("Cookie:"):
                cookie_name = param.replace("Cookie:", "").strip()
                result = await self._test_cookie_sqli_from_queue(url, cookie_name, dry_item)
            elif param.startswith("Header:"):
                header_name = param.replace("Header:", "").strip()
                result = await self._test_header_sqli(url, header_name, dry_item)
            else:
                result = await self._sqli_escalation_pipeline(url, param, dry_item)

            if result:
                finding_dict = self._finding_to_dict(result)

                is_valid, error_msg = self._validate_before_emit(finding_dict)
                if not is_valid:
                    logger.warning(f"[{self.name}] Finding rejected for {result.parameter}: {error_msg}")
                    continue

                self._emit_sqli_finding(
                    finding_dict,
                    status=finding_dict.get("status", "VALIDATED_CONFIRMED"),
                    needs_cdp=False
                )

                if hasattr(self, '_v'):
                    self._v.emit("exploit.sqli.confirmed", {
                        "param": result.parameter,
                        "url": result.url,
                        "technique": result.injection_type,
                        "dbms": result.dbms_detected,
                        "payload_preview": result.working_payload[:80] if result.working_payload else "",
                    })

                logger.info(f"[{self.name}] Confirmed SQLi: {result.url}?{result.parameter} ({result.injection_type})")

                dashboard.add_finding(
                    "SQL Injection",
                    f"{result.url} [{result.parameter}] ({result.injection_type})",
                    result.severity
                )
                dashboard.log(f"[{self.name}] SQLI CONFIRMED: {result.parameter} vulnerable via {result.injection_type}", "SUCCESS")

                results.append(finding_dict)

        logger.info(f"[{self.name}] Phase B: Exploitation complete. {len(results)} validated findings")

        await self._generate_specialist_report(results)

        return results

    # =========================================================================
    # QUEUE CONSUMPTION MODE
    # =========================================================================

    async def start_queue_consumer(self, scan_context: str) -> None:
        """Start SQLiAgent in TWO-PHASE queue consumer mode."""
        from bugtrace.agents.specialist_utils import (
            report_specialist_start,
            report_specialist_progress,
            report_specialist_done,
            report_specialist_wet_dry,
            write_dry_file,
        )

        self._queue_mode = True
        self._scan_context = scan_context
        self._v = create_emitter("SQLiAgent", self._scan_context)

        logger.info(f"[{self.name}] Starting TWO-PHASE queue consumer (WET -> DRY)")
        self._v.emit("exploit.sqli.started", {"url": self.url})

        await self._load_tech_context()

        queue = queue_manager.get_queue("sqli")
        initial_depth = queue.depth()
        report_specialist_start(self.name, queue_depth=initial_depth)

        # PHASE A
        logger.info(f"[{self.name}] ===== PHASE A: Analyzing WET list =====")
        dry_list = await self.analyze_and_dedup_queue()

        report_specialist_wet_dry(self.name, initial_depth, len(dry_list) if dry_list else 0)
        write_dry_file(self, dry_list, initial_depth, "sqli")

        if not dry_list:
            logger.info(f"[{self.name}] No findings to exploit after deduplication")
            if hasattr(self, '_v'):
                self._v.emit("exploit.sqli.completed", {"dry_count": 0, "vulns": 0})
            report_specialist_done(self.name, processed=0, vulns=0)
            return

        logger.info(f"[{self.name}] DRY list: {len(dry_list)} unique findings to attack")

        # PHASE B
        logger.info(f"[{self.name}] ===== PHASE B: Exploiting DRY list =====")
        results = await self.exploit_dry_list()

        vulns_count = len([r for r in results if r]) if results else 0

        report_specialist_done(
            self.name,
            processed=len(dry_list),
            vulns=vulns_count
        )

        if hasattr(self, '_v'):
            self._v.emit("exploit.sqli.completed", {
                "dry_count": len(dry_list),
                "vulns": vulns_count,
            })

        logger.info(f"[{self.name}] Queue consumer complete: {len(results)} validated findings")

    async def _load_tech_context(self) -> None:
        """Load technology stack context from recon data (v3.2)."""
        scan_dir = getattr(self, 'report_dir', None)
        if not scan_dir:
            scan_id = self._scan_context.split("/")[-1] if self._scan_context else ""
            scan_dir = settings.BASE_DIR / "reports" / scan_id if scan_id else None

        if not scan_dir or not Path(scan_dir).exists():
            logger.debug(f"[{self.name}] No report directory found, using generic tech context")
            self._tech_stack_context = {"db": "generic", "server": "generic", "lang": "generic"}
            self._prime_directive = ""
            return

        self._tech_stack_context = self.load_tech_stack(Path(scan_dir))
        self._prime_directive = self.generate_context_prompt(self._tech_stack_context)

        db_type = self._tech_stack_context.get("db", "generic")
        logger.info(f"[{self.name}] Tech context loaded: db={db_type}, "
                   f"server={self._tech_stack_context.get('server', 'generic')}, "
                   f"lang={self._tech_stack_context.get('lang', 'generic')}")

        if db_type != "generic":
            self._detected_db_type = db_type

    async def _process_queue_item(self, item: dict) -> Optional[SQLiFinding]:
        """Process a single item from the sqli queue."""
        finding = item.get("finding", {})
        url = finding.get("url")
        param = finding.get("parameter")

        if not url or not param:
            logger.warning(f"[{self.name}] Invalid queue item: missing url or parameter")
            return None

        self.url = url
        self.param = param

        if param.startswith("Cookie:"):
            cookie_name = param.replace("Cookie:", "").strip()
            return await self._test_cookie_sqli_from_queue(url, cookie_name, finding)
        elif param.startswith("Header:"):
            header_name = param.replace("Header:", "").strip()
            return await self._test_header_sqli(url, header_name, finding)
        else:
            return await self._test_single_param_from_queue(url, param, finding)

    async def _test_single_param_from_queue(self, url, param, finding):
        """Test a single parameter from queue for SQL injection."""
        try:
            async with http_manager.isolated_session(ConnectionProfile.EXTENDED) as session:
                if self._baseline_response_time == 0:
                    await self._initialize_baseline(session)

                if await self._detect_prepared_statements(session, param):
                    return None

                await self._detect_filtered_chars(session, param)

                suggested_technique = finding.get("technique", "").lower()

                result = await self._test_error_based(session, param)
                if result:
                    return await self._finalize_finding(result, "error_based")

                result = await self._test_boolean_based(session, param)
                if result:
                    return await self._finalize_finding(result, "boolean_based")

                result = await self._test_union_based(session, param)
                if result:
                    return await self._finalize_finding(result, "union_based")

                if "time" in suggested_technique:
                    result = await self._test_time_based(session, param)
                    if result:
                        return await self._finalize_finding(result, "time_based")

                if self._interactsh:
                    result = await self._test_oob_sqli(session, param)
                    if result:
                        return result

                technique_hint = get_sqlmap_technique_hint(suggested_technique)
                dashboard.log(f"[{self.name}] Internal checks inconclusive. Escalating to SQLMap for {param} (hint: {technique_hint})...", "INFO")
                return await self._run_sqlmap_on_param(param, technique_hint=technique_hint)

        except Exception as e:
            logger.error(f"[{self.name}] Queue item test failed: {e}")
            return None

    async def _handle_queue_result(self, item: dict, result: Optional[SQLiFinding]) -> None:
        """Handle completed queue item processing."""
        if result is None:
            return

        finding_data = {
            "context": result.injection_type,
            "payload": result.working_payload,
            "validation_method": result.technique,
            "evidence": result.evidence,
        }
        needs_cdp = False

        fingerprint = generate_sqli_fingerprint(result.parameter, result.url)

        if fingerprint in self._emitted_findings:
            logger.info(f"[{self.name}] Skipping duplicate SQLi finding: {result.url}?{result.parameter}")
            return

        self._emitted_findings.add(fingerprint)

        finding_dict = self._finding_to_dict(result)

        self._emit_sqli_finding(
            finding_dict,
            status=finding_dict.get("status", "VALIDATED_CONFIRMED"),
            needs_cdp=False
        )

        logger.info(f"[{self.name}] Confirmed SQLi: {result.url}?{result.parameter} ({result.injection_type})")

        dashboard.add_finding(
            "SQL Injection",
            f"{result.url} [{result.parameter}] ({result.injection_type})",
            result.severity
        )
        dashboard.log(f"[{self.name}] SQLI CONFIRMED: {result.parameter} vulnerable via {result.injection_type}", "SUCCESS")

    async def _on_work_queued(self, data: dict) -> None:
        """Handle work_queued_sqli notification (logging only)."""
        logger.debug(f"[{self.name}] Work queued: {data.get('finding', {}).get('url', 'unknown')}")

    async def stop_queue_consumer(self) -> None:
        """Stop queue consumer mode gracefully."""
        self._stop_requested = True

        if self._worker_pool:
            await self._worker_pool.stop()
            self._worker_pool = None

        self._queue_mode = False
        logger.info(f"[{self.name}] Queue consumer stop requested")

    def get_queue_stats(self) -> dict:
        """Get queue consumer statistics."""
        if not self._worker_pool:
            return {"mode": "direct", "queue_mode": False, "stats": self._stats}

        return {
            "mode": "queue",
            "queue_mode": True,
            "worker_stats": self._worker_pool.get_stats(),
            "agent_stats": self._stats,
        }
