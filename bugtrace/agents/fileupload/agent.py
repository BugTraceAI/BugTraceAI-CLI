"""
File Upload Agent — Thin Orchestrator.

Inherits from BaseAgent and delegates all logic to pure (core.py) and
I/O (testing.py) modules. This class owns only:
- Agent lifecycle (init, run_loop)
- State wiring (url, found_forms, tested endpoints)
- Phase orchestration (discover -> test)
"""

import logging
from typing import Dict, List, Optional, Any
import aiohttp
from bugtrace.agents.base import BaseAgent
from bugtrace.core.ui import dashboard

from bugtrace.agents.fileupload.testing import (
    discover_upload_forms,
    test_form,
)

logger = logging.getLogger(__name__)


class FileUploadAgent(BaseAgent):
    """
    File Upload Vulnerability Specialist.

    AUTONOMOUS SPECIALIST (v3.1):
    ==============================
    Does NOT rely on DASTySAST for parameter discovery.
    Performs its OWN deep discovery of upload endpoints.

    Discovery Strategy:
    -------------------
    1. HTML Forms: Extracts ALL <input type="file"> with metadata
    2. Drag-and-drop: Detects data-upload attributes, dropzone classes
    3. Metadata Extraction: enctype, method, all required fields

    Testing Strategy:
    -----------------
    - Phase A: Discover ALL upload endpoints (deduplicated)
    - Phase B: Test each with LLM-guided bypass attempts
    - Max bypass rounds: 5

    Deduplication:
    --------------
    - By upload endpoint URL (not form ID)
    """

    name = "FileUploadAgent"

    def __init__(self, url: str):
        super().__init__(
            name="FileUploadAgent",
            role="File Upload Specialist",
            agent_id="fileupload_agent",
        )
        self.url = url
        self.found_forms: List[Dict] = []
        self.upload_path = None
        self.MAX_BYPASS_ATTEMPTS = 5

        # Queue consumer state (V3)
        self._scan_context = ""
        self._dry_findings = []
        self._wet_count = 0

        # Deduplication
        self._tested_params: set = set()  # Legacy (not used)
        self._tested_upload_endpoints: set = set()

        # Authentication support (v3.4)
        self.cookies: List[Dict] = []
        self.headers: Dict[str, str] = {}

    async def run_loop(self) -> Dict:
        """Main execution loop for FileUpload testing.

        AUTONOMOUS SPECIALIST PATTERN:
        - Phase A: Discover ALL upload forms/endpoints (already deduped)
        - Phase B: Test each form with bypass attempts
        """
        logger.info(f"[{self.name}] Initiating AUTONOMOUS File Upload discovery for {self.url}")

        # Phase A: AUTONOMOUS DISCOVERY
        forms, self._tested_upload_endpoints = await discover_upload_forms(
            self.url, self._tested_upload_endpoints
        )

        if not forms:
            logger.info(f"[{self.name}] No upload forms found.")
            return {"vulnerable": False, "findings": []}

        logger.info(f"[{self.name}] Testing {len(forms)} unique upload endpoints")

        # Phase B: TESTING
        findings: List[Dict] = []
        for form in forms:
            result = await test_form(
                form,
                base_url=self.url,
                system_prompt=self.system_prompt,
                max_bypass_attempts=self.MAX_BYPASS_ATTEMPTS,
                log_fn=lambda msg, lvl: dashboard.log(f"[{self.name}] {msg}", lvl),
            )
            if result:
                findings.append(result)

        return {
            "vulnerable": len(findings) > 0,
            "findings": findings,
        }

    # =========================================================================
    # QUEUE CONSUMER INTERFACE (V3)
    # =========================================================================

    async def start_queue_consumer(self, scan_context: str) -> None:
        """Start FileUploadAgent in TWO-PHASE queue consumer mode."""
        from bugtrace.agents.specialist_utils import (
            report_specialist_start,
            report_specialist_done,
            report_specialist_wet_dry,
            write_dry_file,
        )
        from bugtrace.core.queue import queue_manager
        from bugtrace.core.verbose_events import create_emitter

        self._scan_context = scan_context
        self._v = create_emitter("FileUploadAgent", self._scan_context)

        # Load authentication context (v3.4)
        await self._load_auth_context()

        logger.info(f"[{self.name}] Starting TWO-PHASE queue consumer (WET -> DRY)")
        self._v.emit("exploit.fileupload.started", {"url": self.url})

        queue = queue_manager.get_queue("file_upload")
        self._wet_count = queue.depth()
        report_specialist_start(self.name, queue_depth=self._wet_count)

        # PHASE A: Discover / Deduplicate
        logger.info(f"[{self.name}] ===== PHASE A: Identifying Upload Forms =====")
        dry_list = await self.analyze_and_dedup_queue()
        
        report_specialist_wet_dry(self.name, self._wet_count, len(dry_list))
        write_dry_file(self, dry_list, self._wet_count, "file_upload")

        if not dry_list:
            logger.info(f"[{self.name}] No upload forms found to exploit.")
            report_specialist_done(self.name, processed=0, vulns=0)
            return

        # PHASE B: Exploit
        logger.info(f"[{self.name}] ===== PHASE B: Testing {len(dry_list)} forms =====")
        results = await self.exploit_dry_list()
        
        vulns_count = len(results)
        report_specialist_done(self.name, processed=len(dry_list), vulns=vulns_count)
        
        self._v.emit("exploit.fileupload.completed", {
            "dry_count": len(dry_list),
            "vulns": vulns_count
        })

    async def analyze_and_dedup_queue(self) -> List[Dict]:
        """Discovery phase: Find all unique upload forms on the target."""
        # For FileUpload, we are autonomous: we ignore the WET hints and just discover
        forms, self._tested_upload_endpoints = await discover_upload_forms(
            self.url, self._tested_upload_endpoints
        )
        
        # Convert forms to DRY items
        dry_list = []
        for form in forms:
            dry_list.append({
                "url": form.get("action") or self.url,
                "parameter": "file",
                "finding": {
                    "type": "File Upload",
                    "form": form
                }
            })
            
        self._dry_findings = dry_list
        return dry_list

    async def exploit_dry_list(self) -> List[Dict]:
        """Testing phase: Run bypasses on each discovered form."""
        findings: List[Dict] = []
        
        for item in self._dry_findings:
            form = item.get("finding", {}).get("form")
            if not form:
                continue
                
            dashboard.log(f"[{self.name}] Testing form: {form.get('action') or 'current page'}", "INFO")
            
            result = await test_form(
                form,
                base_url=self.url,
                system_prompt=self.system_prompt,
                max_bypass_attempts=self.MAX_BYPASS_ATTEMPTS,
                log_fn=lambda msg, lvl: dashboard.log(f"[{self.name}] {msg}", lvl),
                cookies=self.cookies,
                headers=self.headers,
            )
            
            if result:
                # Emit finding for UI/Reporting
                self.emit_finding(result)
                findings.append(result)
                dashboard.add_finding("File Upload", f"RCE via {form.get('action')}", "CRITICAL")
                
        return findings

    # =========================================================================
    # AUTHENTICATION SUPPORT (v3.4)
    # =========================================================================

    def _configure_session(self, session: aiohttp.ClientSession):
        """Configure session with cookies and headers from authentication."""
        if hasattr(self, 'cookies') and self.cookies:
            cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in self.cookies])
            session.cookie_jar.update_cookies({"Cookie": cookie_str})
            logger.debug(f"[{self.name}] Applied {len(self.cookies)} cookies to session")
        
        if hasattr(self, 'headers') and self.headers:
            session._default_headers.update(self.headers)

    async def _load_auth_context(self) -> None:
        """Load authentication context from scan context."""
        try:
            from bugtrace.services.scan_context import get_scan_auth_headers
            auth_headers = get_scan_auth_headers(self._scan_context, role="admin") or {}
            if auth_headers:
                self.headers = auth_headers
                # Extract cookies from Cookie header if present
                if "Cookie" in auth_headers:
                    cookie_str = auth_headers["Cookie"]
                    self.cookies = []
                    for cookie_part in cookie_str.split("; "):
                        if "=" in cookie_part:
                            name, value = cookie_part.split("=", 1)
                            self.cookies.append({"name": name, "value": value})
                logger.info(f"[{self.name}] Loaded auth context: {len(self.cookies)} cookies, {len(self.headers)} headers")
        except Exception as e:
            logger.debug(f"[{self.name}] Failed to load auth context: {e}")
