"""
JWT Agent - Thin Orchestrator

Orchestrates JWT analysis and exploitation using extracted modules.
Delegates pure logic to analysis/attacks/validation/dedup modules
and I/O operations to discovery/exploitation modules.
"""

import asyncio
import json
import time
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from loguru import logger

from bugtrace.agents.base import BaseAgent
from bugtrace.agents.worker_pool import WorkerPool, WorkerConfig
from bugtrace.core.llm_client import llm_client
from bugtrace.core.ui import dashboard
from bugtrace.core.queue import queue_manager
from bugtrace.core.event_bus import EventType
from bugtrace.core.config import settings
from bugtrace.core.validation_status import ValidationStatus
from bugtrace.reporting.standards import (
    get_cwe_for_vuln,
    get_remediation_for_vuln,
    normalize_severity,
)

# v3.2.0: Import TechContextMixin for context-aware detection
from bugtrace.agents.mixins.tech_context import TechContextMixin

# Extracted modules
from bugtrace.agents.jwt.analysis import (
    is_jwt,
    decode_token,
    get_algorithm,
    get_claims,
    analyze_token_response,
    body_shows_privilege_difference,
    extract_names_from_html,
    extract_names_from_recon_cache,
    extract_target_names,
    get_root_url,
)
from bugtrace.agents.jwt.attacks import (
    none_alg_decode_header,
    generate_none_alg_tokens,
    prepare_brute_force,
    test_secret,
    load_jwt_wordlist,
    forge_admin_token_variations,
    build_kid_injection_token,
    forge_key_confusion_token,
    inject_token_into_url_param,
    generate_name_based_secrets,
    sign_forged_payload,
)
from bugtrace.agents.jwt.validation import (
    validate_jwt_finding,
    get_validation_status,
)
from bugtrace.agents.jwt.discovery import (
    check_url_for_tokens,
    check_page_links_for_tokens,
    check_page_text_for_tokens,
    check_page_content_for_tokens,
    check_storage_for_tokens,
    scan_page_for_tokens,
    deduplicate_tokens,
    discover_tokens,
    get_protected_endpoints,
    extract_app_name_from_root,
)
from bugtrace.agents.jwt.exploitation import (
    rate_limit,
    token_make_request,
    token_execute_baseline,
    token_execute_test,
    verify_token_works,
    check_none_algorithm,
    attack_brute_force,
    attack_kid_injection,
    attack_key_confusion,
)
from bugtrace.agents.jwt.dedup import (
    generate_jwt_fingerprint,
    fallback_fingerprint_dedup,
)


class JWTAgent(BaseAgent, TechContextMixin):
    """
    JWTAgent - Expert in JWT analysis and exploitation.
    Follows the V4 Specialist pattern.

    Thin orchestrator: delegates pure logic to jwt.analysis/attacks/validation/dedup
    and I/O to jwt.discovery/exploitation.
    """

    def __init__(self, event_bus=None):
        super().__init__("JWTAgent", "Authentication & Authorization Specialist", event_bus, agent_id="jwt_agent")
        self.intercepted_tokens = []
        self.findings = []
        self.max_brute_attempts = 1000

        # Queue consumption mode (Phase 20)
        self._queue_mode = False

        # FIX (2026-02-16): Cache protected endpoints for token verification
        self._protected_endpoints: List[str] = []
        self._protected_endpoints_scanned = False

        # Expert deduplication: Track emitted findings by fingerprint
        self._emitted_findings: set = set()

        # WET -> DRY transformation (Two-phase processing)
        self._dry_findings: List[Dict] = []

        self._worker_pool: Optional[WorkerPool] = None
        self._scan_context: str = ""

        # v3.2.0: Context-aware tech stack
        self._tech_stack_context: Dict = {}
        self._jwt_prime_directive: str = ""

    # =========================================================================
    # FINDING VALIDATION
    # =========================================================================

    def _validate_before_emit(self, finding: Dict) -> Tuple[bool, str]:
        """JWT-specific validation before emitting finding."""
        is_valid, error = super()._validate_before_emit(finding)
        if not is_valid:
            return False, error
        return validate_jwt_finding(finding)

    def _emit_jwt_finding(self, finding_dict: Dict, scan_context: str = None) -> Optional[Dict]:
        """Helper to emit JWT finding using BaseAgent.emit_finding() with validation."""
        if "type" not in finding_dict:
            finding_dict["type"] = "JWT"
        if scan_context:
            finding_dict["scan_context"] = scan_context
        finding_dict["agent"] = self.name
        return self.emit_finding(finding_dict)

    # =========================================================================
    # EVENT HANDLING
    # =========================================================================

    def _setup_event_subscriptions(self):
        """Subscribe to token discovery events."""
        if self.event_bus:
            self.event_bus.subscribe("auth_token_found", self.handle_new_token)
            logger.info(f"[{self.name}] Subscribed to 'auth_token_found' events.")

    async def handle_new_token(self, data: Dict[str, Any]):
        """Callback when a new token is found by other agents."""
        token = data.get("token")
        source_url = data.get("url")
        location = data.get("location", "unknown")

        if token and token not in self.intercepted_tokens:
            self.intercepted_tokens.append(token)
            self.think(f"Intercepted new JWT from {source_url} ({location})")
            await self._analyze_and_exploit(token, source_url, location)

    # =========================================================================
    # MAIN LOOP / CHECK URL
    # =========================================================================

    async def run_loop(self):
        """Main loop for the agent (if started manually or via TeamOrchestrator)."""
        dashboard.current_agent = self.name
        dashboard.log(f"[{self.name}] JWT Specialist active and listening for tokens...", "INFO")
        while self.running:
            await asyncio.sleep(1)

    async def check_url(self, url: str) -> Dict:
        """Discover tokens on a page and analyze them."""
        tokens = await discover_tokens(url)
        for token, location in tokens:
            await self._analyze_and_exploit(token, url, location)
        return {
            "vulnerable": len(self.findings) > 0,
            "findings": self.findings,
        }

    # =========================================================================
    # DISCOVERY (delegates to jwt.discovery)
    # =========================================================================

    async def _discover_tokens(self, url: str) -> List[Tuple[str, str]]:
        """Use browser to find JWTs. Delegates to discovery module."""  # I/O
        return await discover_tokens(url)

    async def _scan_page_for_tokens(self, page, target_url, jwt_re, discovered):
        """Scan a single page for JWT tokens. Delegates to discovery module."""  # I/O
        await scan_page_for_tokens(page, target_url, jwt_re, discovered)

    async def _check_url_for_tokens(self, url, discovered):
        """Check URL parameters for JWT tokens."""  # I/O
        await check_url_for_tokens(url, discovered)

    async def _check_page_content_for_tokens(self, page, jwt_re, discovered):
        """Check page links and text for JWT tokens."""  # I/O
        await check_page_content_for_tokens(page, jwt_re, discovered)

    def _check_page_links_for_tokens(self, links, discovered):
        """Check page links for JWT tokens."""  # PURE
        check_page_links_for_tokens(links, discovered)

    def _check_page_text_for_tokens(self, jwt_re, data, discovered):
        """Check page text and HTML for JWT tokens."""  # PURE
        check_page_text_for_tokens(jwt_re, data, discovered)

    async def _check_storage_for_tokens(self, page, discovered):
        """Check cookies and localStorage for JWT tokens."""  # I/O
        await check_storage_for_tokens(page, discovered)

    def _get_root_url(self, url: str):
        """Get root URL."""  # PURE
        return get_root_url(url)

    def _deduplicate_tokens(self, discovered):
        """Remove duplicate tokens and log discoveries."""  # PURE
        unique = deduplicate_tokens(discovered)
        for t, loc in unique:
            self.think(f"Discovered token at {loc}: {t[:20]}...")
        return unique

    def _is_jwt(self, token: str) -> bool:
        """Heuristic to check if a string looks like a JWT."""  # PURE
        return is_jwt(token)

    # =========================================================================
    # ANALYSIS (delegates to jwt.analysis)
    # =========================================================================

    def _decode_token(self, token: str) -> Optional[Dict]:
        """Decode JWT parts without verification."""  # PURE
        result = decode_token(token)
        if result is None:
            logger.warning(f"[{self.name}] Failed to decode token")
        return result

    def _base64_decode(self, data: str) -> str:
        """Base64Url decode helper."""  # PURE
        from bugtrace.agents.jwt.analysis import base64url_decode
        return base64url_decode(data)

    def _token_analyze_response(self, base_status, status, base_text, text) -> bool:
        """Analyze response to determine if token validation was bypassed."""  # PURE
        return analyze_token_response(base_status, status, base_text, text)

    def _body_shows_privilege_difference(self, base_text, auth_text) -> bool:
        """Compare response bodies to detect privilege differences."""  # PURE
        return body_shows_privilege_difference(base_text, auth_text)

    def _extract_names_from_html(self, text: str) -> List[str]:
        """Extract potential app/service names from HTML content."""  # PURE
        return extract_names_from_html(text)

    def _extract_names_from_recon_cache(self, report_dir) -> List[str]:
        """Extract app names from cached recon data on disk."""  # PURE
        return extract_names_from_recon_cache(report_dir)

    def _extract_target_names(self, url: str) -> List[str]:
        """Extract potential app/service names from URL."""  # PURE
        report_dir = getattr(self, 'report_dir', None)
        return extract_target_names(url, report_dir)

    def _generate_name_based_secrets(self, names: List[str]) -> List[str]:
        """Generate common secret patterns from extracted app names."""  # PURE
        return generate_name_based_secrets(names)

    def _load_jwt_wordlist(self, url: str = "", extra_names: List[str] = None) -> List[str]:
        """Load JWT secret wordlist."""  # PURE
        wordlist_path = settings.BASE_DIR / "bugtrace" / "data" / "jwt_secrets.txt"
        return load_jwt_wordlist(wordlist_path, url, extra_names)

    # =========================================================================
    # ATTACKS (delegates to jwt.attacks)
    # =========================================================================

    def _none_alg_decode_header(self, parts):
        """Decode JWT header for none algorithm attack."""  # PURE
        return none_alg_decode_header(parts)

    def _none_alg_build_payload(self, parts):
        """Build elevated privilege payload."""  # PURE
        from bugtrace.agents.jwt.attacks import none_alg_build_payload
        return none_alg_build_payload(parts)

    def _prepare_brute_force(self, parts):
        """Prepare signing input and signature for brute force."""  # PURE
        return prepare_brute_force(parts)

    def _test_secret(self, signing_input, signature_actual, secret):
        """Test if secret matches signature."""  # PURE
        return test_secret(signing_input, signature_actual, secret)

    def _forge_admin_token_variations(self, decoded, parts, secret):
        """Forge multiple admin JWT token variations."""  # PURE
        return forge_admin_token_variations(decoded, parts, secret)

    def _sign_forged_payload(self, payload, header_b64, secret):
        """Sign a forged JWT payload."""  # PURE
        return sign_forged_payload(payload, header_b64, secret)

    def _key_confusion_forge_token(self, pub_key_pem, decoded):
        """Forge JWT using public key as HMAC secret."""  # PURE
        return forge_key_confusion_token(pub_key_pem, decoded)

    def _token_inject_param(self, target_url, token, loc, headers):
        """Inject token into URL parameter."""  # PURE
        return inject_token_into_url_param(target_url, token, loc, headers)

    # =========================================================================
    # EXPLOITATION (delegates to jwt.exploitation)
    # =========================================================================

    async def _rate_limit(self):
        """Rate limiting."""  # I/O
        await rate_limit()

    async def _token_make_request(self, target_url, token, loc):
        """Make HTTP request with token."""  # I/O
        return await token_make_request(target_url, token, loc)

    async def _token_execute_baseline(self, url, location):
        """Execute baseline request with invalid token."""  # I/O
        return await token_execute_baseline(url, location)

    async def _token_execute_test(self, url, forged_token, location):
        """Execute test request with forged token."""  # I/O
        return await token_execute_test(url, forged_token, location)

    def _token_log_verification(self, final_url, base_status, status, base_text, text):
        """Log verification attempt details."""
        self.think(f"Requesting: {final_url}")
        self.think(f"Verification: Base Status={base_status} vs Forged Status={status}")
        self.think(f"Base Body: '{base_text[:50]}...' | Forged Body: '{text[:50]}...'")

    async def _verify_token_works(self, forged_token: str, url: str, location: str) -> bool:
        """Sends a request with the forged token to verify validation bypass."""  # I/O
        report_dir = getattr(self, 'report_dir', None)
        verified, self._protected_endpoints, self._protected_endpoints_scanned = await verify_token_works(
            forged_token, url, location, report_dir,
            self._protected_endpoints, self._protected_endpoints_scanned,
        )
        return verified

    async def _get_protected_endpoints(self, source_url: str) -> List[str]:
        """Discover endpoints that require authentication."""  # I/O
        report_dir = getattr(self, 'report_dir', None)
        self._protected_endpoints, self._protected_endpoints_scanned = await get_protected_endpoints(
            source_url, report_dir,
            self._protected_endpoints, self._protected_endpoints_scanned,
        )
        return self._protected_endpoints

    async def _extract_app_name_from_root(self, url: str) -> List[str]:
        """Extract potential app names for JWT secret generation."""  # I/O
        report_dir = getattr(self, 'report_dir', None)
        cached = getattr(self, '_cached_app_names', None)
        names = await extract_app_name_from_root(url, report_dir, cached)
        if names:
            logger.info(f"[{self.name}] Extracted app names for secret generation: {names}")
        else:
            logger.warning(f"[{self.name}] No app names extracted")
        self._cached_app_names = names
        return names

    # =========================================================================
    # ATTACK PIPELINE
    # =========================================================================

    async def _check_none_algorithm(self, token: str, url: str, location: str) -> bool:
        """Attempt 'none' algorithm attack."""  # I/O
        report_dir = getattr(self, 'report_dir', None)
        success, self._protected_endpoints, self._protected_endpoints_scanned = await check_none_algorithm(
            token, url, location, self.findings, report_dir,
            self._protected_endpoints, self._protected_endpoints_scanned,
        )
        if success:
            self.think("SUCCESS: 'none' algorithm bypass confirmed")
        return success

    async def _attack_brute_force(self, token: str, url: str, location: str):
        """Offline dictionary attack on HMAC secret."""  # I/O
        self.think("Starting dictionary attack on HS256 secret...")
        report_dir = getattr(self, 'report_dir', None)
        extra_names = await self._extract_app_name_from_root(url)
        success, self._protected_endpoints, self._protected_endpoints_scanned = await attack_brute_force(
            token, url, location, self.findings, self._scan_context,
            report_dir, extra_names,
            self._protected_endpoints, self._protected_endpoints_scanned,
        )

    async def _attack_kid_injection(self, token: str, url: str, location: str):
        """KID Injection for Directory Traversal."""  # I/O
        report_dir = getattr(self, 'report_dir', None)
        success, self._protected_endpoints, self._protected_endpoints_scanned = await attack_kid_injection(
            token, url, location, self.findings, report_dir,
            self._protected_endpoints, self._protected_endpoints_scanned,
        )
        if success:
            self.think("SUCCESS: KID Directory Traversal confirmed")

    async def _attack_key_confusion(self, token: str, url: str, location: str):
        """Algorithm Confusion Attack (RS256 -> HS256)."""  # I/O
        self.think("Attempting Key Confusion (RS256 -> HS256)...")
        report_dir = getattr(self, 'report_dir', None)
        success, self._protected_endpoints, self._protected_endpoints_scanned = await attack_key_confusion(
            token, url, location, self.findings, report_dir,
            self._protected_endpoints, self._protected_endpoints_scanned,
        )
        if success:
            self.think("SUCCESS: Key Confusion (RS256->HS256) confirmed!")

    async def _analyze_and_exploit(self, token: str, url: str, location: str):
        """Full analysis and exploitation pipeline for a single token."""
        try:
            decoded = decode_token(token)
            if not decoded:
                return

            alg = get_algorithm(decoded)
            claims = get_claims(decoded)
            self.think(f"Token Analysis: Alg={alg}, Claims={claims}")

            await self._check_none_algorithm(token, url, location)

            if alg == 'HS256':
                await self._attack_brute_force(token, url, location)

            if 'kid' in decoded['header']:
                await self._attack_kid_injection(token, url, location)

            if alg == 'RS256':
                await self._attack_key_confusion(token, url, location)

        except Exception as e:
            logger.error(f"[{self.name}] Token analysis failed: {e}", exc_info=True)

    # =========================================================================
    # DEDUP (delegates to jwt.dedup)
    # =========================================================================

    def _generate_jwt_fingerprint(self, url: str, vuln_type: str, token: str = None) -> tuple:
        """Generate JWT finding fingerprint."""  # PURE
        return generate_jwt_fingerprint(url, vuln_type, token)

    def _fallback_fingerprint_dedup(self, wet_findings: List[Dict]) -> List[Dict]:
        """Fallback fingerprint-based deduplication."""  # PURE
        return fallback_fingerprint_dedup(wet_findings)

    # =========================================================================
    # VALIDATION STATUS (delegates to jwt.validation)
    # =========================================================================

    def _get_validation_status(self, finding: Dict) -> str:
        """Determine tiered validation status for JWT finding."""  # PURE
        return get_validation_status(finding)

    # =========================================================================
    # WET -> DRY Two-Phase Processing
    # =========================================================================

    async def analyze_and_dedup_queue(self) -> List[Dict]:
        """PHASE A: Drain WET findings from queue and deduplicate using LLM + fingerprint fallback."""  # I/O
        logger.info(f"[{self.name}] ===== PHASE A: Analyzing WET list =====")

        queue = queue_manager.get_queue("jwt")
        wet_findings = []

        wait_start = time.monotonic()
        while (time.monotonic() - wait_start) < 300.0:
            if queue.depth() if hasattr(queue, 'depth') else 0 > 0:
                break
            await asyncio.sleep(0.5)

        logger.info(f"[{self.name}] Phase A: Queue has {queue.depth() if hasattr(queue, 'depth') else 0} items, starting drain...")

        stable_empty_count = 0
        drain_start = time.monotonic()

        while stable_empty_count < 10 and (time.monotonic() - drain_start) < 300.0:
            item = await queue.dequeue(timeout=0.5)
            if item is None:
                stable_empty_count += 1
                continue
            stable_empty_count = 0
            finding = item.get("finding", {}) if isinstance(item, dict) else {}
            if finding:
                wet_findings.append(finding)

        logger.info(f"[{self.name}] Phase A: Drained {len(wet_findings)} WET findings from queue")

        if not wet_findings:
            logger.info(f"[{self.name}] Phase A: No findings to process")
            return []

        dry_list = await self._llm_analyze_and_dedup(wet_findings, self._scan_context)
        self._dry_findings = dry_list

        logger.info(f"[{self.name}] Phase A: Deduplication complete. {len(wet_findings)} WET -> {len(dry_list)} DRY")
        return dry_list

    async def _llm_analyze_and_dedup(self, wet_findings: List[Dict], context: str) -> List[Dict]:
        """Use LLM to intelligently deduplicate JWT findings."""  # I/O
        tech_stack = getattr(self, '_tech_stack_context', {}) or {}
        lang = tech_stack.get('lang', 'generic')

        jwt_prime_directive = getattr(self, '_jwt_prime_directive', '')
        jwt_dedup_context = self.generate_jwt_dedup_context(tech_stack) if tech_stack else ''
        jwt_lib = self._infer_jwt_library(lang)

        prompt = f"""You are analyzing {len(wet_findings)} potential JWT vulnerability findings.

{jwt_prime_directive}

{jwt_dedup_context}

## TARGET CONTEXT
- Language: {lang}
- Likely JWT Library: {jwt_lib}

WET FINDINGS (may contain duplicates):
{json.dumps(wet_findings, indent=2)}

Return ONLY unique findings in JSON format:
{{
  "findings": [
    {{"url": "...", "token": "...", "vuln_type": "...", ...}},
    ...
  ]
}}"""

        system_prompt = f"""You are an expert JWT deduplication analyst.

{jwt_prime_directive}

Your job is to identify and remove duplicate JWT vulnerabilities while preserving unique token-based attacks. Focus on domain-level deduplication."""

        try:
            response = await llm_client.generate(
                prompt=prompt,
                system_prompt=system_prompt,
                module_name="JWT_DEDUP",
                temperature=0.2,
            )
            result = json.loads(response)
            dry_list = result.get("findings", [])
            if dry_list:
                logger.info(f"[{self.name}] LLM deduplication successful: {len(wet_findings)} -> {len(dry_list)}")
                return dry_list
            else:
                logger.warning(f"[{self.name}] LLM returned empty list, using fallback")
                return fallback_fingerprint_dedup(wet_findings)
        except Exception as e:
            logger.warning(f"[{self.name}] LLM deduplication failed: {e}, using fallback")
            return fallback_fingerprint_dedup(wet_findings)

    async def exploit_dry_list(self) -> List[Dict]:
        """PHASE B: Exploit all DRY findings and emit validated vulnerabilities."""  # I/O
        logger.info(f"[{self.name}] ===== PHASE B: Exploiting DRY list =====")
        logger.info(f"[{self.name}] Phase B: Exploiting {len(self._dry_findings)} DRY findings...")

        # Pre-fetch app names
        first_url = None
        for f in self._dry_findings:
            if isinstance(f, dict) and f.get("url"):
                first_url = f["url"]
                break
        if first_url:
            logger.info(f"[{self.name}] Pre-fetching app names for secret generation...")
            self._cached_app_names = await self._extract_app_name_from_root(first_url)

        validated_findings = []

        for idx, finding in enumerate(self._dry_findings, 1):
            if not isinstance(finding, dict):
                logger.warning(f"[{self.name}] Phase B: Skipping non-dict finding at index {idx}")
                continue
            url = finding.get("url", "")
            token = finding.get("token", "")
            vuln_type = finding.get("vuln_type", finding.get("type", "JWT"))

            logger.info(f"[{self.name}] Phase B: [{idx}/{len(self._dry_findings)}] Testing {url} type={vuln_type}")

            fingerprint = generate_jwt_fingerprint(url, vuln_type, token)
            if fingerprint in self._emitted_findings:
                continue

            try:
                result = await self._test_single_item_from_queue(url, token, finding)
                if result:
                    self._emitted_findings.add(fingerprint)
                    if not isinstance(result, dict):
                        result = {
                            "url": url, "token": token, "type": "JWT",
                            "vuln_type": vuln_type, "severity": "HIGH", "validated": True,
                        }
                    validated_findings.append(result)

                    self._emit_jwt_finding({
                        "type": "JWT",
                        "url": result.get("url", url),
                        "vulnerability_type": result.get("vuln_type", vuln_type),
                        "attack_type": result.get("vuln_type", vuln_type),
                        "severity": result.get("severity", "HIGH"),
                        "token": result.get("token", ""),
                        "evidence": result.get("evidence", {}),
                    }, scan_context=self._scan_context)

                    logger.info(f"[{self.name}] JWT vulnerability confirmed: {url} type={vuln_type}")

            except Exception as e:
                logger.opt(exception=True).error(f"[{self.name}] Phase B: Exploitation failed: {e}")

        # Capture post-exploitation findings
        validated_urls = {f.get("url", "") + f.get("type", "") for f in validated_findings}
        for f in self.findings:
            if not isinstance(f, dict):
                continue
            if f.get("_post_exploit") and (f.get("url", "") + f.get("type", "")) not in validated_urls:
                validated_findings.append(f)
                self._emit_jwt_finding({
                    "type": f.get("type", "JWT"),
                    "url": f.get("url", ""),
                    "vulnerability_type": f.get("type", "JWT"),
                    "attack_type": f.get("type", "JWT"),
                    "severity": f.get("severity", "CRITICAL"),
                    "evidence": f.get("evidence", ""),
                }, scan_context=self._scan_context)
                logger.info(f"[{self.name}] Post-exploit finding captured: {f.get('type')} on {f.get('url')}")

        logger.info(f"[{self.name}] Phase B: Exploitation complete. {len(validated_findings)} validated findings")
        return validated_findings

    async def _generate_specialist_report(self, validated_findings: List[Dict]) -> None:
        """Generate specialist report for JWT findings."""  # I/O
        import aiofiles

        scan_dir = getattr(self, 'report_dir', None)
        if not scan_dir:
            scan_id = self._scan_context.split("/")[-1] if "/" in self._scan_context else self._scan_context
            scan_dir = settings.BASE_DIR / "reports" / scan_id
        results_dir = scan_dir / "specialists" / "results"
        results_dir.mkdir(parents=True, exist_ok=True)

        report = {
            "agent": f"{self.name}",
            "vulnerability_type": "JWT",
            "scan_context": self._scan_context,
            "phase_a": {
                "wet_count": len(self._dry_findings) + (len(validated_findings) - len(self._dry_findings)),
                "dry_count": len(self._dry_findings),
                "deduplication_method": "LLM + fingerprint fallback (netloc-only)",
            },
            "phase_b": {
                "exploited_count": len(self._dry_findings),
                "validated_count": len(validated_findings),
            },
            "findings": validated_findings,
            "summary": {
                "total_validated": len(validated_findings),
                "vuln_types_found": list(set(f.get("vuln_type", "JWT") for f in validated_findings)),
            },
        }

        report_path = results_dir / "jwt_results.json"
        async with aiofiles.open(report_path, "w") as f:
            await f.write(json.dumps(report, indent=2))

        logger.info(f"[{self.name}] Specialist report saved: {report_path}")

    # =========================================================================
    # QUEUE CONSUMER
    # =========================================================================

    async def start_queue_consumer(self, scan_context: str) -> None:
        """TWO-PHASE queue consumer (WET -> DRY). NO infinite loop."""  # I/O
        from bugtrace.agents.specialist_utils import (
            report_specialist_start,
            report_specialist_done,
            report_specialist_wet_dry,
            write_dry_file,
        )

        self._queue_mode = True
        self._scan_context = scan_context

        await self._load_jwt_tech_context()

        logger.info(f"[{self.name}] Starting TWO-PHASE queue consumer (WET -> DRY)")

        queue = queue_manager.get_queue("jwt")
        initial_depth = queue.depth()
        report_specialist_start(self.name, queue_depth=initial_depth)

        # PHASE A
        logger.info(f"[{self.name}] ===== PHASE A: Analyzing WET list =====")
        dry_list = await self.analyze_and_dedup_queue()

        report_specialist_wet_dry(self.name, initial_depth, len(dry_list) if dry_list else 0)
        write_dry_file(self, dry_list, initial_depth, "jwt")

        if not dry_list:
            logger.info(f"[{self.name}] No findings to exploit after deduplication")
            report_specialist_done(self.name, processed=0, vulns=0)
            return

        # PHASE B
        logger.info(f"[{self.name}] ===== PHASE B: Exploiting DRY list =====")
        results = await self.exploit_dry_list()

        vulns_count = len([r for r in results if r]) if results else 0

        if results or self._dry_findings:
            await self._generate_specialist_report(results)

        report_specialist_done(self.name, processed=len(dry_list), vulns=vulns_count)
        logger.info(f"[{self.name}] Queue consumer complete: {len(results)} validated findings")

    async def _process_queue_item(self, item: dict) -> Optional[Dict]:
        """Process a single item from the jwt queue."""
        finding = item.get("finding", {})
        url = finding.get("url")
        token = finding.get("token")
        if not url and not token:
            logger.warning(f"[{self.name}] Invalid queue item: missing url or token")
            return None
        return await self._test_single_item_from_queue(url, token, finding)

    async def _test_single_item_from_queue(self, url: str, token: str, finding: dict) -> Optional[Dict]:
        """Test a single item from queue for JWT vulnerabilities."""  # I/O
        try:
            if token:
                await self._analyze_and_exploit(token, url, "queue")
                if self.findings:
                    last = self.findings[-1]
                    return last if isinstance(last, dict) else None
            elif url:
                result = await self.check_url(url)
                if isinstance(result, dict) and result.get("vulnerable") and result.get("findings"):
                    first = result["findings"][0]
                    return first if isinstance(first, dict) else None
            return None
        except Exception as e:
            logger.error(f"[{self.name}] Queue item test failed: {e}")
            return None

    async def _handle_queue_result(self, item: dict, result: Optional[Dict]) -> None:
        """Handle completed queue item processing."""
        if result is None:
            return

        status = get_validation_status(result)
        url = result.get("url")
        token = result.get("token", "")
        vuln_type = result.get("vulnerability_type", result.get("type"))
        fingerprint = generate_jwt_fingerprint(url, vuln_type, token)

        if fingerprint in self._emitted_findings:
            logger.info(f"[{self.name}] Skipping duplicate JWT finding")
            return

        self._emitted_findings.add(fingerprint)

        if settings.WORKER_POOL_EMIT_EVENTS:
            self._emit_jwt_finding({
                "specialist": "jwt",
                "type": "JWT",
                "url": result.get("url"),
                "vulnerability_type": result.get("vulnerability_type", result.get("type")),
                "attack_type": result.get("vulnerability_type", result.get("type")),
                "severity": result.get("severity"),
                "token": result.get("token", ""),
                "status": status,
                "evidence": result.get("evidence", {}),
                "validation_requires_cdp": status == ValidationStatus.PENDING_VALIDATION.value,
            }, scan_context=self._scan_context)

        logger.info(f"[{self.name}] Confirmed JWT vulnerability: {result.get('vulnerability_type', result.get('type', 'unknown'))} [status={status}]")

    async def _on_work_queued(self, data: dict) -> None:
        """Handle work_queued_jwt notification (logging only)."""
        logger.debug(f"[{self.name}] Work queued: {data.get('finding', {}).get('url', 'unknown')}")

    async def stop_queue_consumer(self) -> None:
        """Stop queue consumer mode gracefully."""
        if self._worker_pool:
            await self._worker_pool.stop()
            self._worker_pool = None
        if self.event_bus:
            self.event_bus.unsubscribe(EventType.WORK_QUEUED_JWT.value, self._on_work_queued)
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

    async def _load_jwt_tech_context(self) -> None:
        """Load technology stack context from recon data (v3.2)."""  # I/O
        scan_id = self._scan_context.split("/")[-1] if self._scan_context else ""
        scan_dir = settings.BASE_DIR / "reports" / scan_id if scan_id else None

        if not scan_dir or not Path(scan_dir).exists():
            logger.debug(f"[{self.name}] No report directory found, using generic tech context")
            self._tech_stack_context = {"db": "generic", "server": "generic", "lang": "generic"}
            self._jwt_prime_directive = ""
            return

        self._tech_stack_context = self.load_tech_stack(Path(scan_dir))
        self._jwt_prime_directive = self.generate_jwt_context_prompt(self._tech_stack_context)

        lang = self._tech_stack_context.get("lang", "generic")
        jwt_lib = self._infer_jwt_library(lang)
        logger.info(f"[{self.name}] JWT tech context loaded: lang={lang}, jwt_lib={jwt_lib}")


async def run_jwt_analysis(token: str, url: str) -> Dict:
    """Convenience function for standalone analysis."""
    agent = JWTAgent()
    await agent._analyze_and_exploit(token, url, "manual")
    return {"findings": agent.findings}
