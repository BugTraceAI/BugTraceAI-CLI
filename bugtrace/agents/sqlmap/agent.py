"""
SQLMap Agent

Thin orchestrator for SQLMapAgent v2 (Intelligent SQL Injection Specialist).
Delegates pure logic to core.py and I/O to runner.py.

Extracted from sqlmap_agent.py for modularity.
"""

import asyncio
import re
import json
from typing import Dict, List, Optional, Any
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode

from bugtrace.agents.base import BaseAgent
from bugtrace.core.config import settings
from bugtrace.core.ui import dashboard

from bugtrace.agents.sqlmap.core import (
    DBType,
    SQLMapConfig,
    SQLiEvidence,
    DBFingerprinter,
    WAFBypassStrategy,
    docker_url,
    extract_post_params,
    inject_probe_payload,
    default_error_patterns,
    default_test_payloads,
    evidence_to_finding,
    build_report_header,
    build_report_findings,
    build_extraction_command,
    parse_extracted_data,
)
from bugtrace.agents.sqlmap.runner import (
    EnhancedSQLMapRunner,
    detect_waf_async,
    get_smart_bypass_strategies,
)


class SQLMapAgent(BaseAgent):
    """
    Intelligent SQL Injection Specialist Agent v2.

    Features:
    - Multi-phase scanning (probe -> deep -> extract)
    - Session/cookie support for authenticated testing
    - Intelligent DB fingerprinting
    - WAF detection and bypass
    - POST/JSON body support
    - HTTP headers injection testing
    - Data extraction verification
    - Parallel parameter testing

    Validation Methods (in order):
    1. Quick probe with basic payloads
    2. SQLMap with intelligent configuration
    3. WAF bypass retry with tamper scripts
    4. Data extraction for proof of exploitation
    """

    def __init__(
        self,
        url: str,
        params: List[str] = None,
        report_dir: Path = None,
        event_bus: Any = None,
        cookies: List[Dict] = None,
        headers: Dict[str, str] = None,
        post_data: str = None,
    ):
        super().__init__("SQLMapAgent", "SQLi Specialist v2", event_bus=event_bus, agent_id="sqlmap_agent")
        self.url = url
        self.params = params or []
        self.report_dir = report_dir or Path("reports")
        self.cookies = cookies or []
        self.headers = headers or {}
        self.post_data = post_data

        # Load technology profile for database-specific attacks
        from bugtrace.utils.tech_loader import load_tech_profile
        self.tech_profile = load_tech_profile(self.report_dir)

        # Load from config or fallback
        self.error_patterns = self.agent_config.get("error_patterns", [])
        self.test_payloads = self.agent_config.get("test_payloads", [])

        # Initialize enhanced runner
        self.sqlmap_runner = EnhancedSQLMapRunner(cookies=self.cookies, headers=self.headers)

        # State tracking
        self._tested_params = set()
        self._detected_db_type = DBType.UNKNOWN
        self._detected_waf = None

        # Statistics
        self._stats = {
            "params_tested": 0,
            "vulns_found": 0,
            "waf_bypassed": 0,
            "data_extracted": 0,
        }

        # Logger
        from bugtrace.utils.logger import get_logger
        self._logger = get_logger("agents.sqlmap_v2")

    # =====================================================================
    # RUN LOOP
    # =====================================================================

    async def run_loop(self):
        """Standard run loop (typically called manually via run())."""
        return await self.run()

    async def run(self) -> Dict:
        """
        Multi-phase SQLi validation:
        1. Quick probe to detect basic SQLi
        2. Intelligent SQLMap scan
        3. WAF bypass if blocked
        4. Data extraction for proof
        """
        from bugtrace.core.job_manager import JobStatus

        dashboard.current_agent = self.name
        self._logger.info(f"[{self.name}] Starting intelligent SQLi scan on {self.url}")
        dashboard.log(f"[{self.name}] Starting intelligent SQLi scan on {self.url}", "INFO")

        findings = []

        try:
            # PHASE 1: Initial probe and fingerprinting
            await self._run_phase1_probe()

            # PHASE 2: Parameter-by-parameter testing
            params_to_test = self._get_parameters_to_test()
            findings = await self._run_phase2_parameter_testing(params_to_test)

            # PHASE 4: Data extraction verification
            if findings and getattr(settings, "SQLMAP_EXTRACT_PROOF", True):
                await self._run_phase4_extraction(findings)

            # Save report
            if findings:
                self._save_detailed_report(findings)

            self._log_completion_stats(findings)

            return {"findings": findings, "status": JobStatus.COMPLETED, "stats": self._stats}

        except Exception as e:
            self._logger.error(f"SQLMapAgent failed: {e}", exc_info=True)
            return {"error": str(e), "findings": [], "status": JobStatus.FAILED}

    # =====================================================================
    # PHASE 1: PROBE AND FINGERPRINTING
    # =====================================================================

    async def _run_phase1_probe(self):
        """Run PHASE 1: Initial probe and fingerprinting."""
        self._logger.info(f"[{self.name}] Phase 1: Probing and fingerprinting...")
        dashboard.log(f"[{self.name}] Phase 1: Probing and fingerprinting...", "INFO")

        probe_result = await self._initial_probe()
        if probe_result:
            self._detected_db_type = probe_result.get("db_type", DBType.UNKNOWN)
            self._detected_waf = probe_result.get("waf")

            if probe_result.get("quick_vuln"):
                dashboard.log(f"[{self.name}] Quick probe found SQLi!", "SUCCESS")

    async def _initial_probe(self) -> Dict:
        """
        Quick probe to fingerprint DB and detect WAF.
        Uses framework's intelligent WAF fingerprinter.
        """
        result = {
            "db_type": DBType.UNKNOWN,
            "waf": None,
            "waf_confidence": 0.0,
            "quick_vuln": False,
        }

        try:
            # PHASE 1: Use framework's WAF fingerprinter (Q-Learning)
            waf_name, waf_confidence = await detect_waf_async(self.url, logger=self._logger)
            result["waf"] = waf_name if waf_name != "unknown" else None
            result["waf_confidence"] = waf_confidence

            if waf_name != "unknown":
                dashboard.log(f"[{self.name}] WAF Detected: {waf_name} ({waf_confidence:.0%} confidence)", "INFO")

            # PHASE 2: Probe for DB fingerprinting and quick vuln check
            from bugtrace.core.http_orchestrator import orchestrator, DestinationType
            import aiohttp

            async with orchestrator.session(DestinationType.TARGET) as session:
                req_headers = self._build_probe_headers()
                probe_url = inject_probe_payload(self.url)

                async with session.get(probe_url, headers=req_headers, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
                    body = await resp.text()

                    # Fingerprint DB
                    result["db_type"] = DBFingerprinter.fingerprint(body, logger=self._logger)

                    if result["db_type"] != DBType.UNKNOWN:
                        dashboard.log(f"[{self.name}] DB Fingerprint: {result['db_type'].value}", "INFO")

                    # Quick vuln check
                    patterns = self.error_patterns or default_error_patterns()
                    for pattern in patterns:
                        if re.search(pattern, body, re.IGNORECASE):
                            result["quick_vuln"] = True
                            break

        except Exception as e:
            self._logger.debug(f"Initial probe failed: {e}")

        return result

    def _build_probe_headers(self) -> Dict[str, str]:
        """Build headers for probe request."""
        req_headers = {"User-Agent": settings.USER_AGENT}
        req_headers.update(self.headers)

        if self.cookies:
            cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in self.cookies])
            req_headers["Cookie"] = cookie_str

        return req_headers

    # =====================================================================
    # PHASE 2: PARAMETER TESTING
    # =====================================================================

    def _get_parameters_to_test(self) -> List[str]:
        """Get list of parameters to test.

        IMPROVED (2026-01-30): Also include cookie names as testable parameters.
        Cookies are often overlooked injection points.
        """
        params_to_test = list(self.params) if self.params else []

        # Add URL query parameters
        if not params_to_test:
            parsed = urlparse(self.url)
            query_params = parse_qs(parsed.query)
            params_to_test = list(query_params.keys())

        # Add POST parameters
        if self.post_data:
            post_params = extract_post_params(self.post_data)
            params_to_test.extend(post_params)

        # Add cookie names as testable parameters
        if self.cookies:
            for cookie in self.cookies:
                cookie_name = cookie.get('name', '')
                if cookie_name and cookie_name not in params_to_test:
                    params_to_test.append(cookie_name)
                    self._logger.info(f"Added cookie '{cookie_name}' to injection test list")

        params_to_test = list(set(params_to_test))

        if not params_to_test:
            params_to_test = ["id"]

        self._logger.info(f"Parameters to test: {params_to_test}")
        return params_to_test

    async def _run_phase2_parameter_testing(self, params_to_test: List[str]) -> List[Dict]:
        """Run PHASE 2: Parameter-by-parameter testing."""
        self._logger.info(f"[{self.name}] Phase 2: Testing {len(params_to_test)} parameters...")
        dashboard.log(f"[{self.name}] Phase 2: Testing {len(params_to_test)} parameters...", "INFO")

        findings = []
        docker_target = docker_url(self.url)

        for param in params_to_test:
            if param in self._tested_params:
                continue

            self._tested_params.add(param)
            self._stats["params_tested"] += 1
            dashboard.log(f"[{self.name}] Testing parameter: {param}", "INFO")

            finding = await self._test_single_parameter(docker_target, param)
            if finding:
                findings.append(finding)
                if self._should_early_exit(params_to_test):
                    break

        return findings

    def _should_early_exit(self, params_to_test: List[str]) -> bool:
        """Check if we should exit early after finding a vulnerability."""
        if not settings.EARLY_EXIT_ON_FINDING:
            return False

        remaining = len(params_to_test) - len(self._tested_params)
        if remaining > 0:
            dashboard.log(f"[{self.name}] Early exit: Skipping {remaining} params", "INFO")
        return True

    async def _test_single_parameter(self, docker_target: str, param: str) -> Optional[Dict]:
        """Test a single parameter for SQLi."""
        config = await self._build_intelligent_config_async()

        evidence = await self.sqlmap_runner.run_intelligent(
            url=docker_target,
            param=param,
            config=config,
            post_data=self.post_data,
            db_type=self._detected_db_type,
        )

        if evidence.vulnerable:
            self._stats["vulns_found"] += 1
            finding = evidence_to_finding(evidence, self.url)
            dashboard.add_finding("SQLi", f"{self.url} [{param}]", "CRITICAL")
            return finding

        # PHASE 3: WAF bypass retry if blocked
        if self._detected_waf:
            bypass_finding = await self._try_waf_bypass(docker_target, param)
            if bypass_finding:
                return bypass_finding

        # Fallback to error detection
        dashboard.log(f"[{self.name}] SQLMap inconclusive, trying error detection...", "DEBUG")
        error_finding = await self._detect_sql_error(param)
        if error_finding:
            dashboard.add_finding("SQLi", f"{self.url} [{param}]", "CRITICAL")
            return error_finding

        return None

    # =====================================================================
    # PHASE 3: WAF BYPASS
    # =====================================================================

    async def _try_waf_bypass(self, docker_target: str, param: str) -> Optional[Dict]:
        """Try WAF bypass techniques."""
        dashboard.log(f"[{self.name}] Phase 3: Attempting WAF bypass ({self._detected_waf})...", "INFO")

        bypass_evidence = await self._waf_bypass_retry(docker_target, param)
        if bypass_evidence and bypass_evidence.vulnerable:
            self._stats["waf_bypassed"] += 1
            self._stats["vulns_found"] += 1
            finding = evidence_to_finding(bypass_evidence, self.url)
            dashboard.add_finding("SQLi", f"{self.url} [{param}] (WAF Bypass)", "CRITICAL")
            return finding

        return None

    async def _waf_bypass_retry(self, url: str, param: str) -> Optional[SQLiEvidence]:
        """
        Retry with WAF bypass techniques using Q-Learning optimized strategies.
        Records results for continuous learning.
        """
        # Get Q-Learning optimized strategies
        _, smart_tampers = await get_smart_bypass_strategies(
            self.url, max_strategies=7, logger=self._logger,
        )

        config = SQLMapConfig(
            level=4,
            risk=2,
            tamper_scripts=smart_tampers,
            random_agent=True,
            timeout=60,
        )

        evidence = await self.sqlmap_runner.run_intelligent(
            url=url,
            param=param,
            config=config,
            post_data=self.post_data,
            db_type=self._detected_db_type,
        )

        # Record result for Q-Learning feedback
        if evidence and self._detected_waf:
            from bugtrace.tools.waf import strategy_router
            for tamper in smart_tampers[:3]:
                WAFBypassStrategy.record_bypass_result(
                    self._detected_waf,
                    tamper,
                    success=evidence.vulnerable,
                    strategy_router_ref=strategy_router,
                    logger=self._logger,
                )

        if evidence and evidence.vulnerable:
            evidence.tamper_used = ",".join(smart_tampers[:3])

        return evidence

    # =====================================================================
    # INTELLIGENT CONFIG
    # =====================================================================

    async def _build_intelligent_config_async(self) -> SQLMapConfig:
        """
        Build SQLMap config based on detected context.
        Uses Q-Learning router for optimal strategy selection.
        """
        config = SQLMapConfig()

        # WAF-specific configuration with Q-Learning strategies
        if self._detected_waf:
            config.level = 3
            config.risk = 2

            # Get Q-Learning optimized strategies
            _, smart_tampers = await get_smart_bypass_strategies(
                self.url, max_strategies=5, logger=self._logger,
            )
            config.tamper_scripts = smart_tampers

            dashboard.log(f"[{self.name}] Q-Learning selected tampers: {smart_tampers[:3]}...", "DEBUG")

        # DB-specific tampers
        if self._detected_db_type != DBType.UNKNOWN:
            db_tampers = DBFingerprinter.get_recommended_tampers(self._detected_db_type)
            for t in db_tampers:
                if t not in config.tamper_scripts:
                    config.tamper_scripts.append(t)

        return config

    def _build_intelligent_config(self) -> SQLMapConfig:
        """Sync wrapper for backwards compatibility."""
        config = SQLMapConfig()

        if self._detected_waf:
            config.level = 3
            config.risk = 2
            config.tamper_scripts = WAFBypassStrategy.get_bypass_tampers(self._detected_waf)

        if self._detected_db_type != DBType.UNKNOWN:
            config.tamper_scripts.extend(
                DBFingerprinter.get_recommended_tampers(self._detected_db_type)
            )

        return config

    # =====================================================================
    # PHASE 4: DATA EXTRACTION
    # =====================================================================

    async def _run_phase4_extraction(self, findings: List[Dict]):
        """Run PHASE 4: Data extraction verification."""
        dashboard.log(f"[{self.name}] Phase 4: Extracting proof data...", "INFO")

        for finding in findings:
            if finding.get("extraction_verified"):
                continue

            extraction = await self._extract_proof_data(finding)
            if extraction:
                finding["extracted_data"] = extraction
                finding["extraction_verified"] = True
                self._stats["data_extracted"] += 1

    async def _extract_proof_data(self, finding: Dict) -> Optional[Dict]:
        """
        Extract actual data to prove exploitation.
        Only runs on confirmed vulnerabilities.
        """
        from bugtrace.tools.external import external_tools

        if not external_tools.docker_cmd:
            return None

        url = docker_url(finding.get("url", self.url))
        param = finding.get("parameter")

        cmd = build_extraction_command(url, param, cookies=self.cookies)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            output = stdout.decode()
            return parse_extracted_data(output)
        except Exception as e:
            self._logger.debug(f"Data extraction failed: {e}")
            return None

    # =====================================================================
    # ERROR DETECTION FALLBACK
    # =====================================================================

    async def _detect_sql_error(self, param: str) -> Optional[Dict]:
        """Detect SQL injection by looking for SQL error messages in response."""
        try:
            import aiohttp
            from bugtrace.core.http_orchestrator import orchestrator, DestinationType

            parsed = urlparse(self.url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            existing_params = parse_qs(parsed.query)
            payloads_to_test = self.test_payloads[:10] if self.test_payloads else default_test_payloads()

            async with orchestrator.session(DestinationType.TARGET) as session:
                req_headers = {"User-Agent": settings.USER_AGENT}
                req_headers.update(self.headers)
                if self.cookies:
                    cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in self.cookies])
                    req_headers["Cookie"] = cookie_str

                for payload in payloads_to_test:
                    test_params = {k: v[0] if isinstance(v, list) else v for k, v in existing_params.items()}
                    test_params[param] = payload

                    test_url = f"{base_url}?{urlencode(test_params)}"

                    async with session.get(test_url, headers=req_headers, timeout=aiohttp.ClientTimeout(total=10)) as response:
                        body = await response.text()

                        patterns = self.error_patterns if self.error_patterns else default_error_patterns()
                        for pattern in patterns:
                            match = re.search(pattern, body, re.IGNORECASE)
                            if match:
                                dashboard.log(f"[{self.name}] SQL Error detected: {match.group()[:50]}...", "SUCCESS")
                                return {
                                    "type": "SQLi",
                                    "url": self.url,
                                    "parameter": param,
                                    "payload": payload,
                                    "evidence": f"SQL Error detected: {match.group()}",
                                    "validated": True,
                                    "validation_method": "SQL Error Detection",
                                    "severity": "CRITICAL",
                                    "status": "VALIDATED_CONFIRMED",
                                }

        except Exception as e:
            self._logger.debug(f"SQL error detection failed: {e}")
            return None

        return None

    # =====================================================================
    # REPORT GENERATION
    # =====================================================================

    def _save_detailed_report(self, findings: List[Dict]):
        """Save detailed markdown report."""
        safe_name = re.sub(r'[^\w\-_]', '_', self.url)[:50]
        report_path = self.report_dir / f"sqli_report_{safe_name}.md"

        content = build_report_header(
            self.url, self._stats, self._detected_waf,
            self._detected_db_type, self.name,
        )
        content += build_report_findings(findings)

        self.report_dir.mkdir(parents=True, exist_ok=True)
        with open(report_path, "w") as f:
            f.write(content)

        self._logger.info(f"Report saved to {report_path}")

    # =====================================================================
    # STATS & HELPERS
    # =====================================================================

    def _log_completion_stats(self, findings: List[Dict]):
        """Log completion statistics."""
        stats_msg = (
            f"[{self.name}] Complete: {self._stats['params_tested']} tested, "
            f"{self._stats['vulns_found']} vulns, {self._stats['waf_bypassed']} WAF bypasses"
        )
        self._logger.info(stats_msg)
        dashboard.log(stats_msg, "SUCCESS" if findings else "INFO")

    def get_stats(self) -> Dict:
        """Get agent statistics."""
        return self._stats
