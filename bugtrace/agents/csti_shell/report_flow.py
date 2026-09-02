"""CSTI specialist report shell.

Shell mixin; hard max 2000 LOC, prefer ~800-1500.
"""

from __future__ import annotations

import asyncio
import aiohttp
import re
from typing import Any, Dict, List, Optional, Tuple
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from dataclasses import dataclass, field, asdict

from bugtrace.agents.base import BaseAgent
from bugtrace.agents.worker_pool import WorkerPool, WorkerConfig
from bugtrace.agents.mixins.tech_context import TechContextMixin
from bugtrace.core.ui import dashboard
from bugtrace.core.job_manager import JobStatus
from bugtrace.core.event_bus import EventType
from bugtrace.core.http_manager import http_manager, ConnectionProfile
from bugtrace.core.llm_client import llm_client
from bugtrace.core.config import settings
from bugtrace.core.validation_status import ValidationStatus, requires_cdp_validation
from bugtrace.core.verbose_events import create_emitter
from bugtrace.schemas.validation_feedback import ValidationFeedback, FailureReason
from bugtrace.utils.logger import get_logger
from bugtrace.utils.parsers import XmlParser
from bugtrace.agents.specialist_utils import load_full_payload_from_json, load_full_finding_data
from bugtrace.tools.manipulator.orchestrator import ManipulatorOrchestrator
from bugtrace.tools.manipulator.models import MutableRequest, MutationStrategy

logger = get_logger(__name__)

from bugtrace.agents.csti.types import CSTIFinding
from bugtrace.agents.csti.payloads import PAYLOAD_LIBRARY

class CSTIReportMixin:
    async def _generate_specialist_report(self, validated_findings: List[Dict]) -> None:
        """
        Generate specialist report for CSTI findings.

        Report structure:
        - phase_a: WET → DRY deduplication stats
        - phase_b: Exploitation results
        - findings: All validated CSTI findings
        """
        import json
        import aiofiles
        from bugtrace.core.config import settings

        # v3.1: Use unified report_dir if injected, else fallback to scan_context
        scan_dir = getattr(self, 'report_dir', None)
        if not scan_dir:
            scan_id = self._scan_context.split("/")[-1] if "/" in self._scan_context else self._scan_context
            scan_dir = settings.BASE_DIR / "reports" / scan_id
        # v3.2: Write to specialists/results/ for unified wet→dry→results flow
        results_dir = scan_dir / "specialists" / "results"
        results_dir.mkdir(parents=True, exist_ok=True)

        report = {
            "agent": f"{self.name}",
            "vulnerability_type": "CSTI",
            "scan_context": self._scan_context,
            "phase_a": {
                "wet_count": len(self._dry_findings) + (len(validated_findings) - len(self._dry_findings)),  # Approximate
                "dry_count": len(self._dry_findings),
                "deduplication_method": "LLM + fingerprint fallback"
            },
            "phase_b": {
                "exploited_count": len(self._dry_findings),
                "validated_count": len(validated_findings)
            },
            "findings": validated_findings,
            "summary": {
                "total_validated": len(validated_findings),
                "template_engines_found": list(set(f.get("template_engine", "unknown") for f in validated_findings))
            }
        }

        report_path = results_dir / "csti_results.json"

        async with aiofiles.open(report_path, "w") as f:
            await f.write(json.dumps(report, indent=2))

        logger.info(f"[{self.name}] Specialist report saved: {report_path}")

