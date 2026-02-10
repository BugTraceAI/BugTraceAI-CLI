from typing import Dict, List, Optional, Any, Tuple
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

# v3.2.0: Import TechContextMixin for context-aware detection
from bugtrace.agents.mixins.tech_context import TechContextMixin

logger = get_logger("agents.idor")

class IDORAgent(BaseAgent, TechContextMixin):
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

        # v3.2.0: Context-aware tech stack (loaded in start_queue_consumer)
        self._tech_stack_context: Dict = {}
        self._idor_prime_directive: str = ""

    # =========================================================================
    # FINDING VALIDATION: IDOR-specific validation (Phase 1 Refactor)
    # =========================================================================

    def _validate_before_emit(self, finding: Dict) -> Tuple[bool, str]:
        """
        IDOR-specific validation before emitting finding.

        Validates:
        1. Basic requirements (type, url) via parent
        2. Has differential evidence (status change, content change)
        3. Involves ID parameter manipulation
        """
        # Call parent validation first
        is_valid, error = super()._validate_before_emit(finding)
        if not is_valid:
            return False, error

        # Extract from nested structure if needed
        nested = finding.get("finding", {})
        evidence = finding.get("evidence", nested.get("evidence", {}))
        status = finding.get("status", nested.get("status", ""))

        # IDOR-specific: Must have differential evidence or confirmed status
        if status not in ["VALIDATED_CONFIRMED", "PENDING_VALIDATION"]:
            has_differential = evidence.get("differential_analysis") if isinstance(evidence, dict) else False
            has_status_change = evidence.get("status_change") if isinstance(evidence, dict) else False
            has_data_leak = evidence.get("user_data_leakage") if isinstance(evidence, dict) else False
            if not (has_differential or has_status_change or has_data_leak):
                return False, "IDOR requires proof: differential analysis, status change, or data leakage"

        # IDOR-specific: Should have tested_value or modified ID
        tested_value = finding.get("tested_value", nested.get("tested_value", ""))
        payload = finding.get("payload", nested.get("payload", ""))
        if not tested_value and not payload:
            return False, "IDOR requires tested_value or payload showing ID manipulation"

        return True, ""

    def _emit_idor_finding(self, finding_dict: Dict, scan_context: str = None) -> Optional[Dict]:
        """
        Helper to emit IDOR finding using BaseAgent.emit_finding() with validation.
        """
        if "type" not in finding_dict:
            finding_dict["type"] = "IDOR"

        if scan_context:
            finding_dict["scan_context"] = scan_context

        finding_dict["agent"] = self.name
        return self.emit_finding(finding_dict)

    def _determine_validation_status(self, evidence_type: str, confidence: str) -> str:
        """
        IDOR validation is purely HTTP-based (semantic differential analysis).
        No CDP/browser validation needed - specialist agent has full authority.

        TIER 1 (VALIDATED_CONFIRMED):
            - HIGH confidence differential analysis (CRITICAL or HIGH severity)
            - Robust semantic indicators: permission_bypass, user_data_leakage,
              or 2+ differential indicators (status_change + length_change + sensitive_data)

        TIER 2 (PENDING_VALIDATION):
            - MEDIUM confidence (single weak indicator like length_change only)
            - If IDOR_ENABLE_LLM_VALIDATION=True: LLM validates before reaching here
            - If LLM disabled or fails: Requires human review to rule out dynamic content

        Note: Cookie tampering (horizontal privilege escalation) can be enabled
        via settings.IDOR_ENABLE_COOKIE_TAMPERING for future implementation.
        """
        if evidence_type == "differential" and confidence == "HIGH":
            return "VALIDATED_CONFIRMED"

        return "PENDING_VALIDATION"

    def _create_idor_finding(self, hit: Dict, param: str, original_value: str) -> Dict:
        """Create IDOR finding from fuzzer hit."""
        # Auto-confirm CRITICAL and HIGH severity (robust semantic analysis)
        # CRITICAL: permission_bypass, user_data_leakage
        # HIGH: 2+ differential indicators (status_change + length_change + sensitive_data)
        # MEDIUM: single weak indicator → needs human review
        confidence_level = "HIGH" if hit["severity"] in ["CRITICAL", "HIGH"] else "MEDIUM"
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

    def _detect_id_format(self, original_value: str) -> tuple[str, list[str]]:
        """
        Detect ID format and generate test IDs.

        Returns:
            tuple: (format_type, list_of_test_ids)
            format_type: "numeric", "uuid", "hash", "timestamp", "unknown"
        """
        import re
        import uuid
        from datetime import datetime, timedelta

        if not original_value:
            return "numeric", []

        # UUID v4 format (8-4-4-4-12 hex chars)
        if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$', original_value, re.I):
            # Generate similar UUIDs
            test_ids = [str(uuid.uuid4()) for _ in range(10)]
            return "uuid", test_ids

        # MD5 hash (32 hex chars)
        if re.match(r'^[0-9a-f]{32}$', original_value, re.I):
            # Try incrementing last char
            test_ids = []
            for i in range(10):
                modified = original_value[:-1] + format(i, 'x')
                test_ids.append(modified)
            return "hash_md5", test_ids

        # SHA1 hash (40 hex chars)
        if re.match(r'^[0-9a-f]{40}$', original_value, re.I):
            test_ids = []
            for i in range(10):
                modified = original_value[:-1] + format(i, 'x')
                test_ids.append(modified)
            return "hash_sha1", test_ids

        # Unix timestamp (10 digits)
        if re.match(r'^\d{10}$', original_value):
            base_ts = int(original_value)
            test_ids = [str(base_ts + i) for i in range(-5, 5) if i != 0]
            return "timestamp", test_ids

        # Numeric (pure digits)
        if original_value.isdigit():
            return "numeric", []  # Use normal range

        # Alphanumeric (e.g., "ABC123")
        if re.match(r'^[A-Za-z0-9_-]+$', original_value):
            # Try incrementing trailing number if exists
            match = re.match(r'^(.*?)(\d+)$', original_value)
            if match:
                prefix, num = match.groups()
                test_ids = [f"{prefix}{int(num) + i}" for i in range(-5, 6) if i != 0]
                return "alphanumeric", test_ids

        return "unknown", []

    async def _llm_predict_ids(self, original_value: str, url: str, param: str) -> List[str]:
        """
        Use LLM to predict likely IDOR target IDs based on context.

        Returns:
            List of predicted ID strings to test
        """
        from bugtrace.core.llm_client import llm_client
        import json

        # Extract context from URL
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path

        # Determine likely app type from domain/path
        app_context = self._infer_app_context(domain, path)

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
2. Sequential patterns (+1, -1, ×10, ×100, /2)
3. Edge cases (0, 1, -1, 999, 1000, 9999, 99999)
4. Common typos and variations of the baseline
5. Well-known default IDs for this app type
6. Obvious enumeration targets (first user, last user, system accounts)

**Important:**
- Focus on IDs that are LIKELY to exist in a real application
- Prioritize special/privileged accounts over random IDs
- Include both smaller and larger IDs than baseline
- Match the format of the baseline (if numeric, stay numeric)

Return ONLY a JSON object with an "ids" array:
{{"ids": ["id1", "id2", "id3", ...]}}"""

        try:
            response = await llm_client.generate(
                prompt=prompt,
                module_name="IDOR_ID_PREDICTION",
                temperature=0.3,  # Low temperature for consistent, logical predictions
                max_tokens=500
            )

            if not response:
                logger.warning(f"[{self.name}] LLM prediction returned empty response")
                return []

            # Parse JSON response
            result = json.loads(response)
            predicted_ids = result.get("ids", [])

            # Validate and filter predictions
            valid_ids = [str(id).strip() for id in predicted_ids if id]

            logger.info(f"[{self.name}] LLM predicted {len(valid_ids)} candidate IDs for {param}={original_value}")
            return valid_ids[:settings.IDOR_LLM_PREDICTION_COUNT]

        except json.JSONDecodeError as e:
            logger.error(f"[{self.name}] LLM returned invalid JSON: {e}")
            logger.debug(f"Raw response: {response[:200]}")
            return []
        except Exception as e:
            logger.error(f"[{self.name}] LLM prediction failed: {e}")
            return []

    def _infer_app_context(self, domain: str, path: str) -> str:
        """Infer application type from domain/path for better LLM context."""
        domain_lower = domain.lower()
        path_lower = path.lower()

        # E-commerce
        if any(kw in domain_lower for kw in ['shop', 'store', 'commerce', 'cart']):
            return "e-commerce"
        if any(kw in path_lower for kw in ['product', 'order', 'cart', 'checkout']):
            return "e-commerce"

        # Social/Blog
        if any(kw in domain_lower for kw in ['social', 'blog', 'forum', 'community']):
            return "social platform"
        if any(kw in path_lower for kw in ['post', 'article', 'comment', 'user', 'profile']):
            return "social platform"

        # SaaS/API
        if 'api' in domain_lower or 'api' in path_lower:
            return "API/SaaS"

        # Admin/Dashboard
        if any(kw in path_lower for kw in ['admin', 'dashboard', 'panel']):
            return "admin panel"

        return "web application"

    async def _test_custom_ids_python(
        self,
        candidate_ids: List[str],
        param: str,
        original_value: str
    ) -> Optional[Dict]:
        """
        Test custom IDs using Python (without Go fuzzer).
        Performs semantic differential analysis similar to Go fuzzer.

        Returns:
            Finding dict if IDOR detected, None otherwise
        """
        from bugtrace.core.http_orchestrator import orchestrator, DestinationType

        logger.info(f"[{self.name}] Testing {len(candidate_ids)} predicted IDs with Python analyzer")

        # Fetch baseline first
        baseline_url = self._inject(original_value, param, original_value)
        async with orchestrator.session(DestinationType.TARGET) as session:
            try:
                async with session.get(baseline_url, timeout=5) as resp:
                    baseline_status = resp.status
                    baseline_body = await resp.text()
                    baseline_length = len(baseline_body)
            except Exception as e:
                logger.warning(f"[{self.name}] Failed to fetch baseline: {e}")
                return None

        # Test each candidate ID
        for test_id in candidate_ids:
            test_url = self._inject(str(test_id), param, original_value)

            try:
                async with orchestrator.session(DestinationType.TARGET) as session:
                    async with session.get(test_url, timeout=5) as resp:
                        test_status = resp.status
                        test_body = await resp.text()
                        test_length = len(test_body)

                # Semantic analysis (simplified from Go fuzzer)
                is_idor, severity, indicators = self._analyze_differential(
                    baseline_status, baseline_body, baseline_length,
                    test_status, test_body, test_length,
                    test_id
                )

                if is_idor:
                    # LLM validation for MEDIUM severity (if enabled)
                    if severity == "MEDIUM" and settings.IDOR_ENABLE_LLM_VALIDATION:
                        logger.info(f"[{self.name}] 🧠 MEDIUM severity detected, using LLM for validation...")
                        is_valid_idor, validated_severity = await self._llm_validate_medium_severity(
                            baseline_body, test_body,
                            baseline_status, test_status,
                            baseline_length, test_length,
                            indicators, test_id
                        )

                        if not is_valid_idor:
                            logger.info(f"[{self.name}] ❌ LLM marked as FALSE POSITIVE: {indicators}")
                            continue  # Skip this ID, not a real IDOR

                        # Upgrade severity if LLM upgraded it
                        if validated_severity != severity:
                            logger.info(f"[{self.name}] ⬆️ LLM upgraded severity: {severity} → {validated_severity}")
                            severity = validated_severity

                    logger.info(f"[{self.name}] 🚨 LLM-predicted IDOR HIT: ID {test_id} ({severity})")
                    dashboard.log(f"[{self.name}] 🎯 LLM Prediction Success! ID {test_id}", "SUCCESS")

                    return self._create_idor_finding({
                        "id": test_id,
                        "status_code": test_status,
                        "severity": severity,
                        "diff_type": indicators,
                        "contains_sensitive": "user_data" in indicators.lower()
                    }, param, original_value)

            except Exception as e:
                logger.debug(f"[{self.name}] Error testing ID {test_id}: {e}")
                continue

        logger.info(f"[{self.name}] No IDOR found in {len(candidate_ids)} LLM-predicted IDs")
        return None

    def _analyze_differential(
        self,
        baseline_status: int,
        baseline_body: str,
        baseline_length: int,
        test_status: int,
        test_body: str,
        test_length: int,
        test_id: str
    ) -> tuple[bool, str, str]:
        """
        Simplified semantic analysis (Python port of Go fuzzer logic).

        Returns:
            (is_idor: bool, severity: str, indicators: str)
        """
        import re

        indicators = []

        # 1. Permission bypass (CRITICAL)
        if baseline_status in [401, 403] and test_status == 200:
            return True, "CRITICAL", "permission_bypass"

        # 2. Status code change to success
        if baseline_status >= 400 and test_status == 200:
            indicators.append("status_change")

        # 3. Significant length difference (>30%)
        if baseline_length > 0:
            diff_ratio = abs(test_length - baseline_length) / baseline_length
            if diff_ratio > 0.3:
                indicators.append("length_change")

        # 4. User-specific data patterns (simplified)
        user_patterns = [
            r'"user_id":\s*"?(\d+)"?',
            r'"email":\s*"([^"]+@[^"]+)"',
            r'"username":\s*"([^"]+)"',
            r'/users/(\d+)',
        ]

        baseline_users = set()
        test_users = set()

        for pattern in user_patterns:
            baseline_users.update(re.findall(pattern, baseline_body))
            test_users.update(re.findall(pattern, test_body))

        if test_users and test_users != baseline_users:
            indicators.append("user_data_leakage")
            return True, "CRITICAL", ",".join(indicators)

        # 5. Sensitive data markers
        sensitive_markers = ['password', 'token', 'secret', 'api_key', 'ssn', 'credit_card']
        test_has_sensitive = any(marker in test_body.lower() for marker in sensitive_markers)
        baseline_has_sensitive = any(marker in baseline_body.lower() for marker in sensitive_markers)

        if test_has_sensitive and not baseline_has_sensitive:
            indicators.append("sensitive_data_exposure")

        # Decision logic
        if len(indicators) >= 2:
            return True, "HIGH", ",".join(indicators)
        elif len(indicators) == 1:
            return True, "MEDIUM", indicators[0]

        return False, "LOW", ""

    async def _llm_validate_medium_severity(
        self,
        baseline_body: str,
        test_body: str,
        baseline_status: int,
        test_status: int,
        baseline_length: int,
        test_length: int,
        indicators: str,
        test_id: str
    ) -> tuple[bool, str]:
        """
        Use LLM to analyze MEDIUM severity findings and determine if they're real IDORs.

        MEDIUM severity = single weak indicator (e.g., length_change only).
        Could be: 1) Real IDOR, or 2) Dynamic content (Product A vs Product B in catalog).

        Returns:
            (is_valid_idor: bool, upgraded_severity: str)
        """
        from bugtrace.core.llm_client import llm_client
        import json
        import re

        # Extract key patterns from responses (first 2K chars to avoid token limits)
        baseline_snippet = baseline_body[:2000]
        test_snippet = test_body[:2000]

        baseline_keys = re.findall(r'"(\w+)":', baseline_snippet)
        test_keys = re.findall(r'"(\w+)":', test_snippet)

        # Calculate key similarity
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

**Real IDOR indicators:**
1. Different user identifiers (email, username, user_id changed)
2. Access to different resource TYPE (e.g., admin panel vs user profile)
3. New sensitive fields appeared (password, token, api_key, ssn)
4. Structural change suggests privilege escalation
5. Different permission levels visible

**False Positive indicators:**
1. Same structure, different content (e.g., Product A vs Product B)
2. Keys/fields are >90% identical (key_similarity > 0.9)
3. Typical catalog/list pagination (items differ, structure same)
4. Timestamp or session-specific data only
5. Dynamic content like recommendations, ads, featured items

**Decision Rules:**
- If key_similarity >90% AND no user identifier changes → FALSE POSITIVE
- If new sensitive fields OR user identifier changes → REAL IDOR (upgrade to HIGH)
- If access to different resource type → REAL IDOR (upgrade to HIGH)
- If only length/content differs but structure identical → FALSE POSITIVE

Return ONLY a JSON object:
{{"is_idor": true/false, "severity": "HIGH"|"MEDIUM"|"LOW", "reasoning": "brief 1-sentence explanation"}}"""

        try:
            response = await llm_client.generate(
                prompt=prompt,
                module_name="IDOR_MEDIUM_VALIDATION",
                temperature=0.2,  # Low temp for consistent, logical decisions
                max_tokens=300
            )

            if not response:
                logger.warning(f"[{self.name}] LLM validation returned empty response")
                return (True, "MEDIUM")  # Fallback: keep as MEDIUM

            result = json.loads(response)
            is_idor = result.get("is_idor", False)
            severity = result.get("severity", "MEDIUM")
            reasoning = result.get("reasoning", "No reasoning provided")

            logger.info(f"[{self.name}] LLM MEDIUM validation for ID {test_id}: is_idor={is_idor}, severity={severity}")
            logger.debug(f"[{self.name}] LLM reasoning: {reasoning}")

            return (is_idor, severity)

        except json.JSONDecodeError as e:
            logger.error(f"[{self.name}] LLM returned invalid JSON: {e}")
            logger.debug(f"Raw response: {response[:200]}")
            return (True, "MEDIUM")  # Fallback: conservatively keep as MEDIUM
        except Exception as e:
            logger.error(f"[{self.name}] LLM validation failed: {e}")
            return (True, "MEDIUM")  # Fallback: conservatively keep as MEDIUM

    # =========================================================================
    # DEEP EXPLOITATION: Optional Phase 4b - Advanced IDOR Analysis
    # =========================================================================

    async def _exploit_deep(self, finding: Dict) -> Dict:
        """
        Deep exploitation analysis (6 phases).

        Enhances basic IDOR finding with comprehensive exploitation evidence.
        Called from exploit_dry_list() for CRITICAL/HIGH severity findings.

        Args:
            finding: Basic IDOR finding from _create_idor_finding()

        Returns:
            Enhanced finding with exploitation data in finding["exploitation"]
        """
        logger.info(f"[{self.name}] ===== Phase 4b: Deep Exploitation Analysis =====")

        # Extract context
        url = finding["url"]
        param = finding["parameter"]
        payload = finding["payload"]
        original_value = finding.get("original_value")

        exploitation_log = []

        # Phase 1: Re-test
        logger.info(f"[{self.name}] Phase 1/6: Re-testing...")
        phase1 = await self._phase1_retest(url, param, payload, original_value)
        exploitation_log.append({"phase": "retest", **phase1})

        if not phase1.get("confirmed"):
            logger.warning(f"[{self.name}] ⚠️ Re-test failed")
            finding["exploitation_failed"] = "retest_failed"
            return finding

        # Phase 2: HTTP Methods
        logger.info(f"[{self.name}] Phase 2/6: Testing HTTP methods...")
        phase2 = await self._phase2_http_methods(url, param, payload)
        exploitation_log.append({"phase": "http_methods", **phase2})

        # Phase 3: Impact Analysis
        logger.info(f"[{self.name}] Phase 3/6: Analyzing impact...")
        phase3 = self._phase3_impact_analysis(phase1, phase2)
        exploitation_log.append({"phase": "impact", **phase3})

        # Phase 4-5: Escalation (only if mode=full)
        phase4 = None
        phase5 = None
        if settings.IDOR_EXPLOITER_MODE == "full":
            logger.info(f"[{self.name}] Phase 4/6: Horizontal escalation...")
            phase4 = await self._phase4_horizontal_escalation(url, param, payload, original_value)
            exploitation_log.append({"phase": "horizontal", **phase4})

            logger.info(f"[{self.name}] Phase 5/6: Vertical escalation...")
            phase5 = await self._phase5_vertical_escalation(url, param)
            exploitation_log.append({"phase": "vertical", **phase5})

        # Phase 6: LLM Report
        logger.info(f"[{self.name}] Phase 6/6: Generating LLM report...")
        phase6_report = await self._phase6_llm_report(finding, {
            "retest": phase1,
            "http_methods": phase2,
            "impact": phase3,
            "horizontal": phase4,
            "vertical": phase5,
        })

        # Enhance finding
        finding["exploitation"] = {
            "retest": phase1,
            "http_methods": phase2,
            "impact": phase3,
            "horizontal": phase4,
            "vertical": phase5,
            "llm_report": phase6_report,
            "timeline": exploitation_log,
        }

        # Severity upgrade if delete capability
        if phase3.get("delete_capability"):
            original_severity = finding["severity"]
            finding["severity"] = "CRITICAL"
            logger.warning(f"[{self.name}] ⬆️ Severity: {original_severity} → CRITICAL")

        finding["deep_exploitation_completed"] = True
        logger.info(f"[{self.name}] ✅ Deep exploitation complete")

        return finding

    async def _phase1_retest(self, url: str, param: str, payload: str, original_value: str) -> Dict:
        """Phase 1: Re-test vulnerability confirmation."""
        from bugtrace.core.http_orchestrator import orchestrator, DestinationType
        from datetime import datetime

        try:
            # Fetch baseline
            baseline_url = self._inject(original_value, param, original_value)
            async with orchestrator.session(DestinationType.TARGET) as session:
                async with session.get(baseline_url, timeout=settings.IDOR_EXPLOITER_TIMEOUT) as resp:
                    baseline_status = resp.status
                    baseline_body = await resp.text()
                    baseline_length = len(baseline_body)

            # Fetch exploit
            exploit_url = self._inject(payload, param, original_value)
            async with orchestrator.session(DestinationType.TARGET) as session:
                async with session.get(exploit_url, timeout=settings.IDOR_EXPLOITER_TIMEOUT) as resp:
                    exploit_status = resp.status
                    exploit_body = await resp.text()
                    exploit_length = len(exploit_body)

            # Analyze
            confirmed = (
                exploit_status == 200 and
                baseline_status in [200, 401, 403] and
                exploit_body != baseline_body
            )

            diff_summary = self._analyze_response_diff(baseline_body, exploit_body)

            return {
                "confirmed": confirmed,
                "baseline_status": baseline_status,
                "exploit_status": exploit_status,
                "baseline_length": baseline_length,
                "exploit_length": exploit_length,
                "response_diff": diff_summary,
                "timestamp": datetime.now().isoformat(),
            }

        except Exception as e:
            logger.error(f"[{self.name}] Phase 1 failed: {e}")
            return {"confirmed": False, "error": str(e), "timestamp": datetime.now().isoformat()}

    def _analyze_response_diff(self, baseline: str, exploit: str) -> str:
        """Helper: Analyze response differences."""
        import re

        baseline_users = set(re.findall(r'"user_id":\s*"?(\d+)"?', baseline))
        exploit_users = set(re.findall(r'"user_id":\s*"?(\d+)"?', exploit))

        baseline_emails = set(re.findall(r'"email":\s*"([^"]+@[^"]+)"', baseline))
        exploit_emails = set(re.findall(r'"email":\s*"([^"]+@[^"]+)"', exploit))

        diffs = []
        if baseline_users != exploit_users:
            diffs.append(f"user_id: {baseline_users} → {exploit_users}")
        if baseline_emails != exploit_emails:
            diffs.append(f"email: {baseline_emails} → {exploit_emails}")

        return "; ".join(diffs) if diffs else "Different content"

    async def _phase2_http_methods(self, url: str, param: str, payload: str) -> Dict:
        """Phase 2: Test different HTTP methods."""
        from bugtrace.core.http_orchestrator import orchestrator, DestinationType
        import asyncio

        methods = ["GET", "POST", "PUT", "PATCH", "DELETE"]
        results = {}
        vulnerable_methods = []

        exploit_url = self._inject(payload, param, payload)

        for method in methods:
            # Skip destructive tests if disabled
            if method in ["PUT", "PATCH"] and not settings.IDOR_EXPLOITER_ENABLE_WRITE_TESTS:
                results[method] = {"skipped": True, "reason": "write_tests_disabled"}
                continue
            if method == "DELETE" and not settings.IDOR_EXPLOITER_ENABLE_DELETE_TESTS:
                results[method] = {"skipped": True, "reason": "delete_tests_disabled"}
                continue

            # Rate limiting
            await asyncio.sleep(settings.IDOR_EXPLOITER_RATE_LIMIT)

            try:
                async with orchestrator.session(DestinationType.TARGET) as session:
                    if method == "GET":
                        response = await session.get(exploit_url, timeout=settings.IDOR_EXPLOITER_TIMEOUT)
                    elif method == "POST":
                        response = await session.post(exploit_url, timeout=settings.IDOR_EXPLOITER_TIMEOUT)
                    elif method == "PUT":
                        response = await session.put(exploit_url, json={}, timeout=settings.IDOR_EXPLOITER_TIMEOUT)
                    elif method == "PATCH":
                        response = await session.patch(exploit_url, json={}, timeout=settings.IDOR_EXPLOITER_TIMEOUT)
                    elif method == "DELETE":
                        response = await session.delete(exploit_url, timeout=settings.IDOR_EXPLOITER_TIMEOUT)

                    status = response.status
                    accessible = status in [200, 201, 204]

                    results[method] = {
                        "status": status,
                        "accessible": accessible,
                    }

                    if accessible:
                        vulnerable_methods.append(method)
                        logger.warning(f"[{self.name}] ⚠️ Method {method} accessible!")

            except Exception as e:
                logger.debug(f"[{self.name}] Method {method} failed: {e}")
                results[method] = {"error": str(e), "accessible": False}

        # Severity upgrade
        severity_upgrade = None
        if "DELETE" in vulnerable_methods:
            severity_upgrade = "CRITICAL - DELETE accessible"
        elif any(m in vulnerable_methods for m in ["PUT", "PATCH"]):
            severity_upgrade = "HIGH - Write methods accessible"

        return {
            "methods_tested": methods,
            "vulnerable_methods": results,
            "accessible_methods": vulnerable_methods,
            "severity_upgrade": severity_upgrade,
        }

    def _phase3_impact_analysis(self, phase1: Dict, phase2: Dict) -> Dict:
        """Phase 3: Analyze impact."""

        # Read capability
        read_capability = phase1.get("confirmed", False)

        # Write capability
        write_capability = any(
            method in phase2.get("accessible_methods", [])
            for method in ["PUT", "PATCH", "POST"]
        )

        # Delete capability
        delete_capability = "DELETE" in phase2.get("accessible_methods", [])

        # Calculate impact score (0-10)
        impact_score = 0.0
        if read_capability:
            impact_score += 4.0
        if write_capability:
            impact_score += 3.0
        if delete_capability:
            impact_score += 3.0

        # Description
        capabilities = []
        if read_capability:
            capabilities.append("read unauthorized data")
        if write_capability:
            capabilities.append("modify data")
        if delete_capability:
            capabilities.append("delete data")

        impact_description = f"Attacker can: {', '.join(capabilities)}"

        return {
            "read_capability": read_capability,
            "write_capability": write_capability,
            "delete_capability": delete_capability,
            "impact_score": impact_score,
            "impact_description": impact_description,
        }

    async def _phase4_horizontal_escalation(
        self, url: str, param: str, payload: str, original_value: str
    ) -> Dict:
        """Phase 4: Enumerate other accessible IDs."""
        from bugtrace.core.http_orchestrator import orchestrator, DestinationType
        import asyncio

        max_enum = settings.IDOR_EXPLOITER_MAX_HORIZONTAL_ENUM

        # Detect ID format (reuse existing method)
        id_format, _ = self._detect_id_format(payload)

        # Generate test IDs
        test_ids = self._generate_horizontal_test_ids(payload, id_format, max_enum)

        # Test IDs concurrently
        accessible_ids = []
        special_accounts = []

        semaphore = asyncio.Semaphore(5)  # Max 5 concurrent

        async def test_id(test_id: str):
            async with semaphore:
                try:
                    test_url = self._inject(test_id, param, original_value)
                    async with orchestrator.session(DestinationType.TARGET) as session:
                        async with session.get(test_url, timeout=settings.IDOR_EXPLOITER_TIMEOUT) as resp:
                            if resp.status == 200:
                                body = await resp.text()
                                is_special = self._is_special_account(body)
                                return (test_id, True, is_special)
                    return (test_id, False, False)
                except:
                    return (test_id, False, False)

        tasks = [test_id(tid) for tid in test_ids]
        results = await asyncio.gather(*tasks)

        for test_id, accessible, is_special in results:
            if accessible:
                accessible_ids.append(test_id)
                if is_special:
                    special_accounts.append(test_id)

        total_accessible = len(accessible_ids)
        severity_multiplier = 1.0 + min(total_accessible / 100, 1.0)

        logger.info(f"[{self.name}] Found {total_accessible} accessible IDs")

        return {
            "enumerated_ids": accessible_ids[:20],  # First 20
            "total_accessible": total_accessible,
            "id_pattern": id_format,
            "special_accounts": special_accounts,
            "severity_multiplier": severity_multiplier,
        }

    def _generate_horizontal_test_ids(self, base_id: str, id_format: str, max_count: int) -> list:
        """Generate test IDs for enumeration."""
        test_ids = []

        if id_format == "numeric":
            base_int = int(base_id)
            for offset in range(-10, max_count):
                if offset != 0:
                    test_ids.append(str(base_int + offset))
        elif id_format == "uuid":
            import uuid
            test_ids = [str(uuid.uuid4()) for _ in range(min(max_count, 20))]
        else:
            test_ids = ["1", "2", "100", "admin", "root", "test"]

        return test_ids[:max_count]

    def _is_special_account(self, response_body: str) -> bool:
        """Check if response indicates special/privileged account."""
        special_markers = ["admin", "administrator", "root", "system", "superuser"]
        return any(marker in response_body.lower() for marker in special_markers)

    async def _phase5_vertical_escalation(self, url: str, param: str) -> Dict:
        """Phase 5: Check for admin/privileged access."""
        from bugtrace.core.http_orchestrator import orchestrator, DestinationType

        admin_candidates = ["0", "1", "-1", "admin", "root", "administrator", "superuser", "system"]

        admin_ids = []
        privilege_indicators = []

        for admin_id in admin_candidates:
            try:
                test_url = self._inject(admin_id, param, admin_id)
                async with orchestrator.session(DestinationType.TARGET) as session:
                    async with session.get(test_url, timeout=settings.IDOR_EXPLOITER_TIMEOUT) as resp:
                        if resp.status == 200:
                            body = await resp.text()
                            indicators = self._detect_privilege_indicators(body)

                            if indicators:
                                admin_ids.append(admin_id)
                                privilege_indicators.extend(indicators)
                                logger.warning(f"[{self.name}] 🚨 Admin access via ID: {admin_id}")

            except:
                continue

        return {
            "admin_accessible": len(admin_ids) > 0,
            "admin_ids": admin_ids,
            "privilege_indicators": list(set(privilege_indicators)),
            "vertical_confirmed": len(privilege_indicators) > 0,
        }

    def _detect_privilege_indicators(self, response_body: str) -> list:
        """Detect privilege indicators in response."""
        indicators = []
        body_lower = response_body.lower()

        privilege_keywords = {
            "admin_panel": ["admin panel", "dashboard", "control panel"],
            "user_management": ["delete user", "edit user", "manage users"],
            "system_config": ["system settings", "configuration", "server config"],
        }

        for indicator_type, keywords in privilege_keywords.items():
            if any(kw in body_lower for kw in keywords):
                indicators.append(indicator_type)

        return indicators

    async def _phase6_llm_report(self, finding: Dict, phases: Dict) -> str:
        """Phase 6: Generate professional exploitation report using LLM."""
        from bugtrace.core.llm_client import llm_client
        from datetime import datetime
        import json

        report_context = {
            "url": finding["url"],
            "parameter": finding["parameter"],
            "payload": finding["payload"],
            "original_value": finding.get("original_value"),
            "severity": finding["severity"],
            "retest": phases.get("retest", {}),
            "http_methods": phases.get("http_methods", {}),
            "impact": phases.get("impact", {}),
            "horizontal": phases.get("horizontal"),
            "vertical": phases.get("vertical"),
        }

        prompt = f"""You are a professional security researcher writing an IDOR exploitation report.

**Exploitation Context:**
```json
{json.dumps(report_context, indent=2)}
```

**Task:** Generate a comprehensive IDOR exploitation report in Markdown format.

**Report Structure:**

# IDOR Exploitation Report

## Executive Summary
[1-2 paragraphs explaining business impact]

## Vulnerability Details
- **Type:** Insecure Direct Object Reference (IDOR)
- **Severity:** {finding["severity"]}
- **CWE:** CWE-639
- **CVSS Score:** [Estimate based on impact]

## Technical Analysis

### 1. Re-test Confirmation
[Explain re-test results]

### 2. HTTP Methods Analysis
[Which methods are vulnerable?]

### 3. Impact Assessment
- **Read Access:** [Yes/No + details]
- **Write Access:** [Yes/No + details]
- **Delete Access:** [Yes/No + details]
- **Impact Score:** [0-10]

### 4. Horizontal Escalation
[How many users can be accessed?]

### 5. Vertical Escalation
[Can admin accounts be accessed?]

## Proof of Concept

```bash
# Baseline (authorized)
curl '{finding["url"]}' -H 'Cookie: session=...'

# IDOR exploit (unauthorized)
curl '{finding["url"].replace(finding.get("original_value", ""), finding["payload"])}' -H 'Cookie: session=...'
```

## Business Impact
[Real-world consequences]

## Remediation

### Immediate Actions
1. [First step]
2. [Second step]

### Long-term Fixes
1. Implement proper authorization checks
2. Use indirect references (tokens instead of sequential IDs)
3. Add access control logging

## References
- OWASP: https://owasp.org/www-community/attacks/Insecure_Direct_Object_References
- CWE-639: https://cwe.mitre.org/data/definitions/639.html

---
**Report Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Tool:** BugTraceAI IDORAgent Deep Exploitation
"""

        try:
            report = await llm_client.generate(
                prompt=prompt,
                module_name="IDOR_EXPLOITATION_REPORT",
                temperature=0.3,
                max_tokens=2000
            )

            if not report:
                logger.warning(f"[{self.name}] LLM returned empty report")
                return self._generate_fallback_report(finding, phases)

            return report

        except Exception as e:
            logger.error(f"[{self.name}] LLM report generation failed: {e}")
            return self._generate_fallback_report(finding, phases)

    def _generate_fallback_report(self, finding: Dict, phases: Dict) -> str:
        """Generate basic report if LLM fails."""
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

        # ===== PHASE 1: LLM-Powered Prediction (if enabled) =====
        if settings.IDOR_ENABLE_LLM_PREDICTION and original_value:
            dashboard.log(f"[{self.name}] 🧠 Using LLM to predict likely IDOR targets...", "INFO")

            # Get LLM predictions
            llm_predicted_ids = await self._llm_predict_ids(original_value, self.url, param)

            if llm_predicted_ids:
                logger.info(f"[{self.name}] Testing {len(llm_predicted_ids)} LLM-predicted IDs FIRST")

                # Test LLM predictions with Python analyzer
                llm_finding = await self._test_custom_ids_python(llm_predicted_ids, param, original_value)

                if llm_finding:
                    self._tested_params.add(key)
                    dashboard.log(f"[{self.name}] ✅ LLM prediction successful - IDOR found!", "SUCCESS")
                    return llm_finding

                logger.info(f"[{self.name}] LLM predictions didn't yield IDOR, falling back to fuzzing")

        # ===== PHASE 2: Smart ID Detection (format-based) =====
        custom_ids = []
        if settings.IDOR_SMART_ID_DETECTION and original_value:
            id_format, detected_ids = self._detect_id_format(original_value)
            if detected_ids:
                logger.info(f"[{self.name}] Detected ID format: {id_format}, testing {len(detected_ids)} similar IDs")
                custom_ids = detected_ids

        # ===== PHASE 3: Custom IDs from config (highest priority for manual testing) =====
        if settings.IDOR_CUSTOM_IDS:
            config_ids = [id.strip() for id in settings.IDOR_CUSTOM_IDS.split(",") if id.strip()]
            if config_ids:
                logger.info(f"[{self.name}] Using {len(config_ids)} custom IDs from config")
                custom_ids = config_ids

        # Test custom IDs if available
        if custom_ids:
            logger.info(f"[{self.name}] Testing {len(custom_ids)} custom/detected IDs with Python analyzer")
            custom_finding = await self._test_custom_ids_python(custom_ids, param, original_value)

            if custom_finding:
                self._tested_params.add(key)
                return custom_finding

        # ===== PHASE 4: High-Performance Go IDOR Fuzzer (numeric range fallback) =====
        id_range = settings.IDOR_ID_RANGE
        dashboard.log(f"[{self.name}] 🚀 Launching Go IDOR Fuzzer on '{param}' (Range {id_range})...", "INFO")
        go_result = await external_tools.run_go_idor_fuzzer(self.url, param, id_range=id_range, baseline_id=original_value)

        self._tested_params.add(key)

        # Guard: Skip if no hits
        if not go_result or not go_result.get("hits"):
            logger.info(f"[{self.name}] ✅ No IDOR found on '{param}' - semantic analysis passed")
            return None

        # Process first hit
        hit = go_result["hits"][0]
        dashboard.log(f"[{self.name}] 🚨 IDOR HIT: ID {hit['id']} ({hit['severity']})", "CRITICAL")
        return self._create_idor_finding(hit, param, original_value)


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


    # =========================================================================
    # Queue Consumption Mode (Phase 20) - WET→DRY Two-Phase Processing
    # =========================================================================

    async def _discover_idor_params(self, url: str) -> Dict[str, str]:
        """
        IDOR-focused parameter discovery.

        Extracts ALL testable parameters from:
        1. URL query string
        2. Path segments (/users/123 → {"user_id": "123"})
        3. HTML forms (input, textarea, select)
        4. Hidden inputs with numeric/UUID values

        Priority: Numeric params, UUIDs, base64 strings, params ending in _id/Id/ID

        Returns:
            Dict mapping param names to default values
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

        # 2. Extract path segments (RESTful IDs)
        # Example: /users/123/profile → {"user_id": "123"}
        # Example: /api/orders/a3f7b9c2 → {"order_id": "a3f7b9c2"}
        try:
            path = parsed.path
            path_segments = [s for s in path.split('/') if s]

            # Look for numeric or ID-like segments
            for i, segment in enumerate(path_segments):
                # Numeric IDs
                if segment.isdigit():
                    # Try to infer param name from previous segment
                    param_name = f"{path_segments[i-1]}_id" if i > 0 else "id"
                    all_params[param_name] = segment
                # UUID-like segments
                elif re.match(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', segment, re.I):
                    param_name = f"{path_segments[i-1]}_id" if i > 0 else "resource_id"
                    all_params[param_name] = segment
                # Hash-like segments (MD5/SHA1)
                elif re.match(r'^[a-f0-9]{32,40}$', segment, re.I):
                    param_name = f"{path_segments[i-1]}_hash" if i > 0 else "hash"
                    all_params[param_name] = segment
        except Exception as e:
            logger.warning(f"[{self.name}] Path segment extraction failed: {e}")

        # 3. Fetch HTML and extract form parameters
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
                            # Skip CSRF tokens
                            if "csrf" not in param_name.lower() and "token" not in param_name.lower():
                                default_value = tag.get("value", "")

                                # IDOR Priority: Focus on ID-like params
                                is_id_param = (
                                    param_name.endswith('_id') or
                                    param_name.endswith('Id') or
                                    param_name.endswith('ID') or
                                    'user' in param_name.lower() or
                                    'account' in param_name.lower() or
                                    'order' in param_name.lower() or
                                    'profile' in param_name.lower()
                                )

                                # Also prioritize if value looks like an ID (numeric, UUID, etc)
                                is_id_value = (
                                    default_value.isdigit() or
                                    re.match(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', default_value, re.I) or
                                    re.match(r'^[a-f0-9]{32,40}$', default_value, re.I) or
                                    re.match(r'^[A-Za-z0-9+/]{20,}={0,2}$', default_value)  # base64
                                )

                                if is_id_param or is_id_value or input_type == "hidden":
                                    all_params[param_name] = default_value

        except Exception as e:
            logger.error(f"[{self.name}] HTML parsing failed: {e}")

        logger.info(f"[{self.name}] 🔍 Discovered {len(all_params)} IDOR params on {url}: {list(all_params.keys())}")
        return all_params

    async def analyze_and_dedup_queue(self) -> List[Dict]:
        """Phase A: WET → DRY with autonomous parameter discovery."""
        import asyncio
        import time
        from bugtrace.core.queue import queue_manager

        logger.info(f"[{self.name}] ===== PHASE A: Analyzing WET list (autonomous discovery) =====")

        queue = queue_manager.get_queue("idor")
        wet_findings = []

        batch_size = settings.IDOR_QUEUE_BATCH_SIZE
        max_wait = settings.IDOR_QUEUE_MAX_WAIT

        # Wait for queue items
        wait_start = time.monotonic()

        while (time.monotonic() - wait_start) < max_wait:
            depth = queue.depth() if hasattr(queue, 'depth') else 0
            if depth > 0:
                logger.info(f"[{self.name}] Phase A: Queue has {depth} items, draining...")
                break
            await asyncio.sleep(0.5)
        else:
            logger.info(f"[{self.name}] Phase A: Queue timeout - no items appeared")
            return []

        # Drain WET queue
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

            if url:
                wet_findings.append({
                    "url": url,
                    "parameter": finding.get("parameter", ""),
                    "original_value": finding.get("original_value", ""),
                    "finding": finding,
                    "scan_context": item.get("scan_context", self._scan_context)
                })

        logger.info(f"[{self.name}] Phase A: Drained {len(wet_findings)} WET findings")

        if not wet_findings:
            return []

        # ========== AUTONOMOUS PARAMETER DISCOVERY ==========
        # Strategy: ALWAYS keep original WET params + ADD discovered params
        logger.info(f"[{self.name}] Phase A: Expanding WET findings with IDOR-focused discovery...")
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
                all_params = await self._discover_idor_params(url)
                if not all_params:
                    continue

                new_count = 0
                for param_name, param_value in all_params.items():
                    if (url, param_name) not in seen_params:
                        seen_params.add((url, param_name))
                        expanded_wet_findings.append({
                            "url": url,
                            "parameter": param_name,
                            "original_value": param_value,
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
        except:
            dry_list = self._fallback_fingerprint_dedup(expanded_wet_findings)

        self._dry_findings = dry_list
        logger.info(f"[{self.name}] Phase A: {len(expanded_wet_findings)} WET → {len(dry_list)} DRY ({len(expanded_wet_findings)-len(dry_list)} duplicates removed)")

        return dry_list


    async def _llm_analyze_and_dedup(self, wet_findings: List[Dict], context: str) -> List[Dict]:
        """LLM-powered intelligent deduplication with autonomous discovery rules."""
        from bugtrace.core.llm_client import llm_client
        import json

        # v3.2: Extract tech stack info for prompt
        tech_stack = getattr(self, '_tech_stack_context', {}) or {}
        lang = tech_stack.get('lang', 'generic')
        frameworks = tech_stack.get('frameworks', [])

        # Get IDOR-specific context prompts
        idor_prime_directive = getattr(self, '_idor_prime_directive', '')
        idor_dedup_context = self.generate_idor_dedup_context(tech_stack) if tech_stack else ''

        system_prompt = f"""You are an expert security analyst specializing in IDOR deduplication.

## DEDUPLICATION RULES

1. **CRITICAL - Autonomous Discovery:**
   - If items have "_discovered": true, they are DIFFERENT PARAMETERS discovered autonomously
   - Even if they share the same "finding" object, treat them as SEPARATE based on "parameter" field
   - Same URL + DIFFERENT param → DIFFERENT (keep all)
   - Same URL + param + DIFFERENT original_value → DIFFERENT (keep both, e.g., /users/1 vs /users/2)

2. **Standard Deduplication:**
   - Same URL + Same parameter + Same original_value → DUPLICATE (keep best)
   - Different endpoints → DIFFERENT (keep both)
   - Path-based IDs vs query-based IDs with same param name → DIFFERENT (keep both)

3. **IDOR-Specific:**
   - Focus on endpoint+resource deduplication
   - /users/123 and /users/456 → DIFFERENT (different resources)
   - /users?id=123 and /users?id=456 → DIFFERENT (different IDs)
   - /users?id=123 and /api/users?id=123 → DIFFERENT (different endpoints)

4. **Prioritization:**
   - Rank by exploitability: numeric IDs > UUIDs > hashes
   - Params ending in _id, Id, ID are HIGH priority
   - Remove findings unlikely to be IDOR (non-ID params)

{idor_prime_directive}"""

        prompt = f"""You are analyzing {len(wet_findings)} potential IDOR findings.

{idor_dedup_context}

## TARGET CONTEXT
- Language: {lang}
- Frameworks: {', '.join(frameworks[:3]) if frameworks else 'None detected'}

## WET LIST ({len(wet_findings)} potential findings):
{json.dumps(wet_findings, indent=2)}

## OUTPUT FORMAT (JSON only):
{{
  "findings": [
    {{
      "url": "...",
      "parameter": "...",
      "original_value": "...",
      "rationale": "why this is unique and exploitable for IDOR",
      "attack_priority": 1-5
    }}
  ],
  "duplicates_removed": <count>,
  "reasoning": "Brief explanation"
}}"""

        response = await llm_client.generate(
            prompt=prompt,
            system_prompt=system_prompt,
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

                    # ===== DEEP EXPLOITATION (Phase 4b) =====
                    if settings.IDOR_ENABLE_DEEP_EXPLOITATION:
                        severity = result.get("severity")
                        threshold = settings.IDOR_EXPLOITER_SEVERITY_THRESHOLD

                        severity_order = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
                        if severity_order.get(severity, 0) >= severity_order.get(threshold, 2):
                            logger.info(f"[{self.name}] 🔬 Starting deep exploitation for {severity} finding...")
                            result = await self._exploit_deep(result)
                    # ========================================

                    validated_findings.append(result)

                    # FINGERPRINT CHECK
                    fingerprint = self._generate_idor_fingerprint(url, parameter)

                    if fingerprint not in self._emitted_findings:
                        self._emitted_findings.add(fingerprint)

                        if settings.WORKER_POOL_EMIT_EVENTS:
                            status = result.get("status", ValidationStatus.VALIDATED_CONFIRMED.value)
                            self._emit_idor_finding({
                                "specialist": "idor",
                                "type": "IDOR",
                                "url": result.get("url"),
                                "parameter": result.get("parameter"),
                                "payload": result.get("payload"),
                                "tested_value": result.get("tested_value", result.get("payload")),
                                "severity": result.get("severity"),
                                "status": status,
                                "evidence": result.get("evidence", {"differential_analysis": True}),
                                "validation_requires_cdp": status == ValidationStatus.PENDING_VALIDATION.value,
                            }, scan_context=self._scan_context)

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

        report_path = results_dir / "idor_results.json"
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

        # v3.2: Load context-aware tech stack for intelligent deduplication
        await self._load_idor_tech_context()

        logger.info(f"[{self.name}] Starting TWO-PHASE queue consumer (WET → DRY)")

        # Get initial queue depth for telemetry
        queue = queue_manager.get_queue("idor")
        initial_depth = queue.depth()
        report_specialist_start(self.name, queue_depth=initial_depth)

        # PHASE A: ANALYSIS & DEDUPLICATION
        logger.info(f"[{self.name}] ===== PHASE A: Analyzing WET list =====")
        dry_list = await self.analyze_and_dedup_queue()

        # Report WET→DRY metrics for integrity verification
        report_specialist_wet_dry(self.name, initial_depth, len(dry_list) if dry_list else 0)
        write_dry_file(self, dry_list, initial_depth, "idor")

        if not dry_list:
            logger.info(f"[{self.name}] No findings to exploit after deduplication")
            report_specialist_done(self.name, processed=0, vulns=0)
            return

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

    async def stop_queue_consumer(self) -> None:
        """Stop queue consumer mode gracefully."""
        if self._worker_pool:
            await self._worker_pool.stop()
            self._worker_pool = None

        self._queue_mode = False
        logger.info(f"[{self.name}] Queue consumer stopped")


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

        # Emit vulnerability_detected event with validation
        if settings.WORKER_POOL_EMIT_EVENTS:
            self._emit_idor_finding({
                "specialist": "idor",
                "type": "IDOR",
                "url": result.get("url"),
                "parameter": result.get("parameter"),
                "payload": result.get("payload"),
                "tested_value": result.get("tested_value", result.get("payload")),
                "status": status,
                "evidence": result.get("evidence", {"differential_analysis": True}),
                "validation_requires_cdp": needs_cdp,
            }, scan_context=self._scan_context)

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

    # =========================================================================
    # TECH CONTEXT LOADING (v3.2)
    # =========================================================================

    async def _load_idor_tech_context(self) -> None:
        """
        Load technology stack context from recon data (v3.2).

        Uses TechContextMixin methods to load and generate context-aware
        prompts for IDOR-specific deduplication (framework ID patterns).
        """
        # Determine report directory
        scan_dir = getattr(self, 'report_dir', None)
        if not scan_dir:
            scan_id = self._scan_context.split("/")[-1] if self._scan_context else ""
            scan_dir = settings.BASE_DIR / "reports" / scan_id if scan_id else None

        if not scan_dir or not Path(scan_dir).exists():
            logger.debug(f"[{self.name}] No report directory found, using generic tech context")
            self._tech_stack_context = {"db": "generic", "server": "generic", "lang": "generic"}
            self._idor_prime_directive = ""
            return

        # Use TechContextMixin methods
        self._tech_stack_context = self.load_tech_stack(Path(scan_dir))
        self._idor_prime_directive = self.generate_idor_context_prompt(self._tech_stack_context)

        lang = self._tech_stack_context.get("lang", "generic")
        frameworks = self._tech_stack_context.get("frameworks", [])

        logger.info(f"[{self.name}] IDOR tech context loaded: lang={lang}, frameworks={frameworks[:3] if frameworks else 'none'}")
