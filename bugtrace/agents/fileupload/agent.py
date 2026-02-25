"""
File Upload Agent — Thin Orchestrator.

Inherits from BaseAgent and delegates all logic to pure (core.py) and
I/O (testing.py) modules. This class owns only:
- Agent lifecycle (init, run_loop)
- State wiring (url, found_forms, tested endpoints)
- Phase orchestration (discover -> test)
"""

import logging
from typing import Dict, List, Optional
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

        # Deduplication
        self._tested_params: set = set()  # Legacy (not used)
        self._tested_upload_endpoints: set = set()

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
