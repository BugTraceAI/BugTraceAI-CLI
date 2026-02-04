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
        
    def _determine_validation_status(self, evidence_type: str, confidence: str) -> str:
        """
        TIER 1 (VALIDATED_CONFIRMED):
            - HIGH confidence differential with sensitive data markers

        TIER 2 (PENDING_VALIDATION):
            - MEDIUM/LOW confidence differential analysis
            - Needs human/CDP verification

        Note: Cookie tampering (horizontal privilege escalation) can be enabled
        via settings.IDOR_ENABLE_COOKIE_TAMPERING for future implementation.
        """
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

    async def analyze_and_dedup_queue(self) -> List[Dict]:
        """Phase A: Streaming analysis of WET list with batched LLM deduplication."""
        import asyncio
        import time
        from bugtrace.core.queue import queue_manager

        logger.info(f"[{self.name}] ===== PHASE A: Analyzing WET list (streaming mode) =====")

        queue = queue_manager.get_queue("idor")
        all_dry_findings = []
        batch = []
        batch_size = settings.IDOR_QUEUE_BATCH_SIZE
        max_wait = settings.IDOR_QUEUE_MAX_WAIT

        # Wait for queue items
        wait_start = time.monotonic()

        while (time.monotonic() - wait_start) < max_wait:
            depth = queue.depth() if hasattr(queue, 'depth') else 0
            if depth > 0:
                logger.info(f"[{self.name}] Phase A: Queue has {depth} items, starting streaming drain...")
                break
            await asyncio.sleep(0.5)
        else:
            logger.info(f"[{self.name}] Phase A: Queue timeout - no items appeared")
            return []

        # Stream items in batches
        empty_count = 0
        max_empty_checks = 10
        total_wet_count = 0

        while empty_count < max_empty_checks:
            item = await queue.dequeue(timeout=0.5)
            if item is None:
                empty_count += 1
                await asyncio.sleep(0.5)

                # Process remaining batch if queue appears empty
                if empty_count >= max_empty_checks and batch:
                    logger.info(f"[{self.name}] Phase A: Processing final batch of {len(batch)} items")
                    dry_batch = await self._dedup_batch(batch)
                    all_dry_findings.extend(dry_batch)
                    batch = []
                continue

            empty_count = 0
            finding = item.get("finding", {})
            url = finding.get("url", "")
            parameter = finding.get("parameter", "")

            if url and parameter:
                batch.append({
                    "url": url,
                    "parameter": parameter,
                    "original_value": finding.get("original_value", ""),
                    "finding": finding,
                    "scan_context": item.get("scan_context", self._scan_context)
                })
                total_wet_count += 1

                # Process batch when full
                if len(batch) >= batch_size:
                    logger.info(f"[{self.name}] Phase A: Processing batch {len(all_dry_findings) // batch_size + 1} ({len(batch)} items)")
                    dry_batch = await self._dedup_batch(batch)
                    all_dry_findings.extend(dry_batch)
                    batch = []

        logger.info(f"[{self.name}] Phase A: Streaming complete. {total_wet_count} WET → {len(all_dry_findings)} DRY")

        self._dry_findings = all_dry_findings
        return all_dry_findings

    async def _dedup_batch(self, batch: List[Dict]) -> List[Dict]:
        """Deduplicate a single batch using LLM with fallback."""
        try:
            return await self._llm_analyze_and_dedup(batch, self._scan_context)
        except Exception as e:
            logger.error(f"[{self.name}] LLM dedup failed for batch: {e}. Using fingerprint fallback")
            return self._fallback_fingerprint_dedup(batch)

    async def _llm_analyze_and_dedup(self, wet_findings: List[Dict], context: str) -> List[Dict]:
        """LLM-powered intelligent deduplication with agent-specific rules."""
        from bugtrace.core.llm_client import llm_client
        import json

        # v3.2: Extract tech stack info for prompt
        tech_stack = getattr(self, '_tech_stack_context', {}) or {}
        lang = tech_stack.get('lang', 'generic')
        frameworks = tech_stack.get('frameworks', [])

        # Get IDOR-specific context prompts
        idor_prime_directive = getattr(self, '_idor_prime_directive', '')
        idor_dedup_context = self.generate_idor_dedup_context(tech_stack) if tech_stack else ''

        prompt = f"""You are analyzing {len(wet_findings)} potential IDOR findings.

{idor_prime_directive}

{idor_dedup_context}

## TARGET CONTEXT
- Language: {lang}
- Frameworks: {', '.join(frameworks[:3]) if frameworks else 'None detected'}

WET LIST:
{json.dumps(wet_findings, indent=2)}

Return JSON array of UNIQUE findings only:
{{"findings": [...]}}
"""

        system_prompt = f"""You are an expert security analyst specializing in IDOR deduplication.

{idor_prime_directive}

Focus on endpoint+resource deduplication. Same resource type = DUPLICATE."""

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
