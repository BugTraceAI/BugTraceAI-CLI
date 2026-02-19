"""
Mass Assignment Agent - Detects mass assignment / overposting vulnerabilities.

Tests API endpoints for parameter pollution by injecting privilege-escalation
fields (role, is_admin, price, etc.) into POST/PUT/PATCH requests and checking
if the server accepts and persists them.

Universal design — works against any web app, not specific to any target.
"""

import asyncio
import json
import time
import logging
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode
from datetime import datetime

import httpx
import aiofiles

from bugtrace.agents.base import BaseAgent
from bugtrace.agents.mixins.tech_context import TechContextMixin
from bugtrace.core.queue import queue_manager
from bugtrace.core.config import settings
from bugtrace.core.ui import dashboard
from bugtrace.core.event_bus import EventType
from bugtrace.core.verbose_events import create_emitter
from bugtrace.core.validation_status import ValidationStatus
from bugtrace.reporting.standards import (
    get_cwe_for_vuln,
    get_remediation_for_vuln,
    normalize_severity,
)

logger = logging.getLogger(__name__)


# Privilege-escalation fields to inject — universal across frameworks
PRIVILEGE_FIELDS = {
    # Role / permission escalation
    "role": "admin",
    "is_admin": True,
    "isAdmin": True,
    "admin": True,
    "is_staff": True,
    "isStaff": True,
    "is_superuser": True,
    "isSuperuser": True,
    "user_type": "admin",
    "userType": "admin",
    "permissions": ["admin", "write", "delete"],
    "group": "administrators",
    "groups": ["admin"],
    "privilege": "elevated",
    "access_level": 999,
    "accessLevel": 999,

    # Financial manipulation
    "price": 0.01,
    "total": 0.01,
    "amount": 0.01,
    "discount": 100,
    "balance": 999999,

    # Account status manipulation
    "verified": True,
    "is_verified": True,
    "isVerified": True,
    "email_verified": True,
    "emailVerified": True,
    "active": True,
    "is_active": True,
    "isActive": True,
    "approved": True,
    "status": "active",
    "account_status": "premium",

    # ID tampering
    "user_id": 1,
    "userId": 1,
    "owner_id": 1,
    "ownerId": 1,
    "created_by": 1,
    "createdBy": 1,
}


class MassAssignmentAgent(BaseAgent, TechContextMixin):
    """
    Specialist Agent for Mass Assignment / Overposting vulnerabilities.

    Strategy:
    1. Discover POST/PUT/PATCH endpoints from queue findings + HTML forms
    2. Inject PRIVILEGE_FIELDS into requests alongside legitimate fields
    3. Check if injected fields are accepted (appear in response or persist)
    """

    def __init__(self, url: str = "", params: List[str] = None,
                 report_dir: Path = None, event_bus: Any = None):
        super().__init__(
            name="MassAssignmentAgent",
            role="Mass Assignment Specialist",
            event_bus=event_bus,
            agent_id="mass_assignment_agent"
        )
        self.url = url
        self.params = params or []
        self.report_dir = report_dir or Path("./reports")

        # Queue consumption mode
        self._queue_mode = False
        self._scan_context: str = ""

        # Expert deduplication
        self._emitted_findings: set = set()

        # WET → DRY
        self._dry_findings: List[Dict] = []

        # v3.2.0: Context-aware tech stack
        self._tech_stack_context: Dict = {}

    def _setup_event_subscriptions(self):
        """No event subscriptions needed — queue-driven specialist."""
        pass

    async def run_loop(self):
        """Main agent loop — no-op for queue-driven specialist."""
        dashboard.current_agent = self.name
        self.think("MassAssignmentAgent initialized...")
        while self.running:
            await asyncio.sleep(1)

    # =========================================================================
    # QUEUE CONSUMER (v3.2 Pipeline)
    # =========================================================================

    async def start_queue_consumer(self, scan_context: str) -> None:
        """TWO-PHASE queue consumer (WET → DRY). NO infinite loop."""
        from bugtrace.agents.specialist_utils import (
            report_specialist_start,
            report_specialist_done,
            report_specialist_wet_dry,
            write_dry_file,
        )

        self._queue_mode = True
        self._scan_context = scan_context
        self._v = create_emitter("MassAssignmentAgent", self._scan_context)

        # Load tech context
        await self._load_mass_assignment_tech_context()

        logger.info(f"[{self.name}] Starting TWO-PHASE queue consumer (WET → DRY)")

        # Get initial queue depth
        queue = queue_manager.get_queue("mass_assignment")
        initial_depth = queue.depth()
        self._wet_count = initial_depth
        report_specialist_start(self.name, queue_depth=initial_depth)

        self._v.emit("exploit.specialist.started", {
            "agent": "MassAssignment", "queue_depth": initial_depth
        })

        # PHASE A: ANALYSIS & DEDUPLICATION
        dry_list = await self.analyze_and_dedup_queue()

        report_specialist_wet_dry(self.name, initial_depth, len(dry_list) if dry_list else 0)
        write_dry_file(self, dry_list, initial_depth, "mass_assignment")

        if not dry_list:
            logger.info(f"[{self.name}] No findings to exploit after deduplication")
            report_specialist_done(self.name, processed=0, vulns=0)
            self._v.emit("exploit.specialist.completed", {
                "agent": "MassAssignment", "dry_count": 0, "vulns": 0
            })
            return

        # PHASE B: EXPLOITATION
        results = await self.exploit_dry_list()

        vulns_count = len([r for r in results if r and r.get("validated")]) if results else 0

        # Always generate report (even 0 vulns documents what was tested)
        await self._generate_specialist_report(results or [])

        report_specialist_done(
            self.name,
            processed=len(dry_list),
            vulns=vulns_count
        )

        self._v.emit("exploit.specialist.completed", {
            "agent": "MassAssignment",
            "dry_count": len(dry_list),
            "vulns": vulns_count
        })

        logger.info(f"[{self.name}] Queue consumer complete: {vulns_count} validated findings")

    # =========================================================================
    # PHASE A: WET → DRY
    # =========================================================================

    async def analyze_and_dedup_queue(self) -> List[Dict]:
        """Drain mass_assignment queue and deduplicate by endpoint."""
        logger.info(f"[{self.name}] ===== PHASE A: Analyzing WET list =====")
        queue = queue_manager.get_queue("mass_assignment")
        wet_findings = []

        # Wait up to 5 min for first item
        wait_start = time.monotonic()
        while (time.monotonic() - wait_start) < 300.0:
            if queue.depth() > 0:
                break
            await asyncio.sleep(0.5)
        else:
            return []

        # Drain queue
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
                    "finding": finding,
                    "scan_context": item.get("scan_context", self._scan_context)
                })

        logger.info(f"[{self.name}] Phase A: Drained {len(wet_findings)} WET findings")

        if not wet_findings:
            return []

        # Discover additional POST/PUT/PATCH endpoints from target
        all_urls = set()
        for wf in wet_findings:
            all_urls.add(wf["url"])

        # Also discover writable endpoints from the target
        if all_urls:
            sample_url = next(iter(all_urls))
            discovered = await self._discover_writable_endpoints(sample_url)
            all_urls.update(discovered)

        # Deduplicate by normalized endpoint path
        seen = set()
        for url in all_urls:
            parsed = urlparse(url)
            dedup_key = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if dedup_key not in seen:
                seen.add(dedup_key)
                self._dry_findings.append({
                    "url": url,
                    "parameter": "",
                    "finding": {"url": url, "type": "mass assignment"},
                    "scan_context": self._scan_context
                })

        logger.info(f"[{self.name}] Phase A: {len(wet_findings)} WET → {len(self._dry_findings)} DRY")
        return self._dry_findings

    # =========================================================================
    # PHASE B: EXPLOITATION
    # =========================================================================

    async def exploit_dry_list(self) -> List[Dict]:
        """Test each DRY endpoint for mass assignment vulnerabilities."""
        logger.info(f"[{self.name}] ===== PHASE B: Exploiting {len(self._dry_findings)} DRY findings =====")
        validated = []

        for idx, f in enumerate(self._dry_findings, 1):
            url = f.get("url", "")

            if hasattr(self, '_v'):
                self._v.emit("exploit.specialist.param.started", {
                    "agent": "MassAssignment", "param": "privilege_fields",
                    "url": url, "idx": idx, "total": len(self._dry_findings)
                })

            try:
                results = await self._test_endpoint_mass_assignment(url)
                for result in results:
                    if result.get("validated"):
                        fp = self._generate_fingerprint(url, result.get("field", ""))
                        if fp not in self._emitted_findings:
                            self._emitted_findings.add(fp)
                            validated.append(result)
            except Exception as e:
                logger.error(f"[{self.name}] Error testing {url}: {e}")

        logger.info(f"[{self.name}] Phase B: {len(validated)} mass assignment vulns found")
        return validated

    # =========================================================================
    # CORE TESTING LOGIC
    # =========================================================================

    async def _test_endpoint_mass_assignment(self, url: str) -> List[Dict]:
        """
        Test a single endpoint for mass assignment by:
        1. GET the endpoint to understand its current state
        2. POST/PUT/PATCH with injected PRIVILEGE_FIELDS
        3. GET again to check if fields persisted
        """
        findings = []

        # Get auth headers from scan context (JWT tokens discovered by JWTAgent)
        auth_headers = {}
        try:
            from bugtrace.services.scan_context import get_scan_auth_headers
            auth_headers = get_scan_auth_headers(self._scan_context, role="user") or {}
        except Exception:
            pass

        headers = {"Content-Type": "application/json"}
        headers.update(auth_headers)

        async with httpx.AsyncClient(
            timeout=10, verify=False, follow_redirects=True, headers=headers
        ) as client:
            # Step 1: Baseline GET to understand response structure
            baseline_body = await self._get_baseline(client, url)
            if baseline_body is None:
                # Retry with admin role if user auth failed
                if auth_headers:
                    try:
                        admin_headers = get_scan_auth_headers(self._scan_context, role="admin") or {}
                        if admin_headers and admin_headers != auth_headers:
                            headers.update(admin_headers)
                            async with httpx.AsyncClient(
                                timeout=10, verify=False, follow_redirects=True, headers=headers
                            ) as admin_client:
                                baseline_body = await self._get_baseline(admin_client, url)
                                if baseline_body is not None:
                                    client = admin_client
                    except Exception:
                        pass
                if baseline_body is None:
                    return findings

            # Step 2: Try each HTTP method that accepts body
            for method in ["POST", "PUT", "PATCH"]:
                method_findings = await self._test_method_with_fields(
                    client, url, method, baseline_body
                )
                findings.extend(method_findings)

                # Stop after first successful method to avoid noise
                if method_findings:
                    break

        return findings

    async def _get_baseline(self, client: httpx.AsyncClient, url: str) -> Optional[Dict]:
        """GET the endpoint to establish baseline response."""
        try:
            resp = await client.get(url)
            if resp.status_code in (200, 201):
                try:
                    return resp.json()
                except Exception as e:
                    logger.debug(f"[{self.name}] JSON parse failed for {url}: {e}")
                    return {}
            elif resp.status_code in (401, 403):
                logger.debug(f"[{self.name}] Auth required for {url} (status {resp.status_code})")
                return None
            return {}
        except Exception as e:
            logger.debug(f"[{self.name}] Baseline GET failed for {url}: {e}")
            return None

    async def _test_method_with_fields(
        self, client: httpx.AsyncClient, url: str, method: str,
        baseline_body: Dict
    ) -> List[Dict]:
        """Test a specific HTTP method by injecting privilege fields."""
        findings = []

        # Build payload: merge baseline fields (if any) + privilege fields
        # This simulates a legitimate request with extra fields injected
        payload = {}
        if isinstance(baseline_body, dict):
            payload.update(baseline_body)

        # Inject privilege fields in batches to avoid overwhelming the server
        field_groups = self._group_privilege_fields()

        for group_name, fields in field_groups.items():
            test_payload = {**payload, **fields}

            try:
                resp = await client.request(
                    method, url,
                    json=test_payload,
                    headers={"Content-Type": "application/json"}
                )

                # Check 1: Direct response analysis
                accepted_fields = self._check_field_acceptance(
                    resp, fields, baseline_body
                )

                # Check 2: Follow-up GET to detect silent persistence
                # Some servers (e.g. Pydantic) silently ignore unknown fields
                # in the response, but the ORM may still persist them
                if not accepted_fields and resp.status_code in (200, 201, 204):
                    followup_fields = await self._check_followup_get(
                        client, url, fields, baseline_body
                    )
                    accepted_fields.extend(followup_fields)

                for field_name, field_value in accepted_fields:
                    finding = self._build_finding(
                        url, method, field_name, field_value, resp
                    )
                    findings.append(finding)
                    dashboard.log(
                        f"  MASS ASSIGNMENT: {field_name}={field_value} "
                        f"accepted via {method} on {url}",
                        "CRITICAL"
                    )
                    # Store in knowledge graph
                    try:
                        from bugtrace.memory.manager import memory_manager
                        memory_manager.add_node(
                            "Finding",
                            f"MASS_ASSIGNMENT_{field_name}_{urlparse(url).path}",
                            properties={
                                "type": "MASS_ASSIGNMENT",
                                "url": url,
                                "parameter": field_name,
                                "payload": str(field_value)[:100],
                                "details": f"Field '{field_name}' accepted via {method}"
                            }
                        )
                    except Exception:
                        pass

            except httpx.TimeoutException:
                logger.debug(f"[{self.name}] Timeout on {method} {url}")
            except Exception as e:
                logger.debug(f"[{self.name}] {method} {url} failed: {e}")

        return findings

    async def _check_followup_get(
        self, client: httpx.AsyncClient, url: str,
        injected_fields: Dict[str, Any], baseline_body: Dict
    ) -> List[Tuple[str, Any]]:
        """
        Follow-up GET after mutation to detect silent field persistence.
        Compares baseline vs post-mutation GET response for injected fields.
        """
        accepted = []
        try:
            resp = await client.get(url)
            if resp.status_code not in (200, 201):
                return accepted
            followup_body = resp.json() if resp.text.strip() else {}
        except Exception:
            return accepted

        if not isinstance(followup_body, dict):
            return accepted

        # Compare each injected field against baseline
        for field_name, field_value in injected_fields.items():
            baseline_val = baseline_body.get(field_name) if isinstance(baseline_body, dict) else None
            followup_val = followup_body.get(field_name)

            if followup_val is None:
                continue

            # Field exists in follow-up — check if it changed to our injected value
            injected_str = str(field_value).lower()
            followup_str = str(followup_val).lower()
            baseline_str = str(baseline_val).lower() if baseline_val is not None else ""

            if followup_str == injected_str and followup_str != baseline_str:
                logger.info(f"[{self.name}] Follow-up GET confirms mass assignment: "
                           f"{field_name} changed from '{baseline_str}' to '{followup_str}'")
                accepted.append((field_name, field_value))

        return accepted

    def _group_privilege_fields(self) -> Dict[str, Dict[str, Any]]:
        """Group PRIVILEGE_FIELDS into logical test batches."""
        return {
            "role_escalation": {
                k: v for k, v in PRIVILEGE_FIELDS.items()
                if any(kw in k.lower() for kw in
                       ["role", "admin", "staff", "super", "priv", "access",
                        "group", "permission", "user_type", "userType"])
            },
            "financial": {
                k: v for k, v in PRIVILEGE_FIELDS.items()
                if any(kw in k.lower() for kw in
                       ["price", "total", "amount", "discount", "balance"])
            },
            "account_status": {
                k: v for k, v in PRIVILEGE_FIELDS.items()
                if any(kw in k.lower() for kw in
                       ["verified", "active", "approved", "status"])
            },
            "id_tampering": {
                k: v for k, v in PRIVILEGE_FIELDS.items()
                if any(kw in k.lower() for kw in
                       ["user_id", "userId", "owner", "created"])
            },
        }

    def _check_field_acceptance(
        self, resp: httpx.Response, injected_fields: Dict[str, Any],
        baseline_body: Dict
    ) -> List[Tuple[str, Any]]:
        """
        Check if the server accepted any injected fields.

        Acceptance indicators:
        1. Field appears in response body (wasn't there in baseline)
        2. Response is 200/201 and response body contains the injected value
        3. Response doesn't contain validation error for the field
        """
        accepted = []

        if resp.status_code not in (200, 201, 204):
            return accepted

        try:
            resp_body = resp.json() if resp.text.strip() else {}
        except Exception as e:
            logger.debug(f"[{self.name}] JSON parse failed in acceptance check: {e}")
            resp_body = {}

        if not isinstance(resp_body, dict):
            return accepted

        resp_text = resp.text.lower()

        for field_name, field_value in injected_fields.items():
            # Check if field appears in response
            field_in_response = field_name in resp_body

            # Check if field was NOT in baseline (new field accepted)
            field_was_absent = field_name not in baseline_body if isinstance(baseline_body, dict) else True

            # Check if the value matches what we sent
            value_matches = False
            if field_in_response:
                resp_val = resp_body.get(field_name)
                value_matches = (resp_val == field_value) or (str(resp_val).lower() == str(field_value).lower())

            # Acceptance: field in response AND (wasn't in baseline OR value matches our injection)
            if field_in_response and (field_was_absent or value_matches):
                accepted.append((field_name, field_value))
            elif resp.status_code in (200, 201) and field_was_absent:
                # Even if field not explicitly in response, a 200 on a PUT/PATCH
                # with extra fields suggests the server didn't reject them.
                # Check for error keywords that indicate rejection
                rejection_keywords = ["invalid", "not allowed", "unknown field",
                                      "unexpected", "validation error"]
                if not any(kw in resp_text for kw in rejection_keywords):
                    # Server silently accepted — report as potential (lower confidence)
                    pass  # Don't report silent acceptance — too many false positives

        return accepted

    def _build_finding(
        self, url: str, method: str, field_name: str,
        field_value: Any, resp: httpx.Response
    ) -> Dict:
        """Build a validated mass assignment finding."""
        return {
            "validated": True,
            "type": "Mass Assignment",
            "severity": "HIGH",
            "url": url,
            "method": method,
            "parameter": field_name,
            "injected_value": str(field_value),
            "status_code": resp.status_code,
            "status": ValidationStatus.VALIDATED_CONFIRMED.value,
            "description": (
                f"Mass assignment vulnerability: the field '{field_name}' was "
                f"accepted via {method} request. An attacker can modify "
                f"privileged fields by including them in the request body."
            ),
            "reproduction": (
                f"curl -X {method} '{url}' "
                f"-H 'Content-Type: application/json' "
                f"-d '{{\"{ field_name}\": {json.dumps(field_value)}}}'"
            ),
            "cwe": "CWE-915",
            "remediation": (
                "Implement allowlisting (whitelist) of accepted fields in your "
                "API endpoint handlers. Use DTOs or serializer classes that "
                "explicitly define which fields are writable. Never bind "
                "request body directly to database models."
            ),
        }

    # =========================================================================
    # ENDPOINT DISCOVERY
    # =========================================================================

    async def _discover_writable_endpoints(self, base_url: str) -> List[str]:
        """
        Discover POST/PUT/PATCH endpoints from HTML forms and common API paths.

        Universal discovery — probes common patterns, not target-specific.
        """
        discovered = []
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Common API paths that accept POST/PUT/PATCH
        common_api_paths = [
            "/api/profile", "/api/user", "/api/account",
            "/api/settings", "/api/preferences",
            "/api/v1/profile", "/api/v1/user", "/api/v1/account",
            "/api/v1/users/me", "/api/me",
            "/api/auth/register", "/api/auth/signup",
            "/api/users", "/api/products", "/api/orders",
        ]

        async with httpx.AsyncClient(
            timeout=5, verify=False, follow_redirects=True
        ) as client:
            for path in common_api_paths:
                test_url = f"{base}{path}"
                try:
                    # OPTIONS to check if endpoint exists and accepts POST/PUT
                    resp = await client.options(test_url)
                    allow = resp.headers.get("allow", "").upper()
                    if any(m in allow for m in ["POST", "PUT", "PATCH"]):
                        discovered.append(test_url)
                        continue

                    # Fallback: try GET to see if endpoint exists
                    resp = await client.get(test_url)
                    if resp.status_code in (200, 201, 401, 403):
                        discovered.append(test_url)
                except Exception:
                    continue

        if discovered:
            logger.info(f"[{self.name}] Discovered {len(discovered)} writable endpoints")

        return discovered

    # =========================================================================
    # HELPERS
    # =========================================================================

    def _generate_fingerprint(self, url: str, field: str) -> tuple:
        """Generate dedup fingerprint for mass assignment finding."""
        parsed = urlparse(url)
        return ("MASS_ASSIGNMENT", parsed.netloc, parsed.path.rstrip('/'), field.lower())

    async def _load_mass_assignment_tech_context(self) -> None:
        """Load technology stack context from recon data."""
        scan_dir = getattr(self, 'report_dir', None)
        if not scan_dir:
            scan_id = self._scan_context.split("/")[-1] if self._scan_context else ""
            scan_dir = settings.BASE_DIR / "reports" / scan_id if scan_id else None

        if not scan_dir or not Path(scan_dir).exists():
            logger.debug(f"[{self.name}] No report directory found, using generic tech context")
            self._tech_stack_context = {"db": "generic", "server": "generic", "lang": "generic"}
            return

        self._tech_stack_context = self.load_tech_stack(scan_dir)
        logger.info(f"[{self.name}] Loaded tech context: {self._tech_stack_context.get('lang', 'generic')}")

    async def _generate_specialist_report(self, findings: List[Dict]) -> str:
        """Write specialist results to unified report directory."""
        scan_dir = getattr(self, 'report_dir', None) or (
            settings.BASE_DIR / "reports" / self._scan_context.split("/")[-1]
        )
        results_dir = scan_dir / "specialists" / "results"
        results_dir.mkdir(parents=True, exist_ok=True)
        report_path = results_dir / "mass_assignment_results.json"

        async with aiofiles.open(report_path, 'w') as f:
            await f.write(json.dumps({
                "agent": self.name,
                "timestamp": datetime.now().isoformat(),
                "scan_context": self._scan_context,
                "phase_a": {
                    "wet_count": getattr(self, '_wet_count', len(self._dry_findings)),
                    "dry_count": len(self._dry_findings),
                    "dedup_method": "endpoint_normalization"
                },
                "phase_b": {
                    "validated_count": len([x for x in findings if x and x.get("validated")]),
                    "total_findings": len(findings)
                },
                "findings": findings
            }, indent=2))

        logger.info(f"[{self.name}] Report saved: {report_path}")
        return str(report_path)


# Export
__all__ = ["MassAssignmentAgent"]
