"""
Mass Assignment Agent — Thin Orchestrator.

Inherits from BaseAgent + TechContextMixin and delegates all logic to
pure (core.py) and I/O (testing.py) modules. This class owns only:
- Agent lifecycle (init, run_loop, queue consumer)
- State wiring (scan_context, report_dir, emitted_findings)
- Report generation
"""

import asyncio
import json
import time
import logging
from typing import Dict, List, Any
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime

import aiofiles

from bugtrace.agents.base import BaseAgent
from bugtrace.agents.mixins.tech_context import TechContextMixin
from bugtrace.core.queue import queue_manager
from bugtrace.core.config import settings
from bugtrace.core.ui import dashboard
from bugtrace.core.verbose_events import create_emitter

from bugtrace.agents.mass_assignment.core import (
    generate_fingerprint,
)
from bugtrace.agents.mass_assignment.testing import (
    test_endpoint_mass_assignment,
    test_method_with_fields,
    discover_writable_endpoints,
)

logger = logging.getLogger(__name__)


class MassAssignmentAgent(BaseAgent, TechContextMixin):
    """
    Specialist Agent for Mass Assignment / Overposting vulnerabilities.

    Strategy:
    1. Discover POST/PUT/PATCH endpoints from queue findings + HTML forms
    2. Inject PRIVILEGE_FIELDS into requests alongside legitimate fields
    3. Check if injected fields are accepted (appear in response or persist)
    """

    def __init__(
        self,
        url: str = "",
        params: List[str] = None,
        report_dir: Path = None,
        event_bus: Any = None,
    ):
        super().__init__(
            name="MassAssignmentAgent",
            role="Mass Assignment Specialist",
            event_bus=event_bus,
            agent_id="mass_assignment_agent",
        )
        self.url = url
        self.params = params or []
        self.report_dir = report_dir or Path("./reports")

        # Queue consumption mode
        self._queue_mode = False
        self._scan_context: str = ""

        # Expert deduplication
        self._emitted_findings: set = set()

        # WET -> DRY
        self._dry_findings: List[Dict] = []

        # v3.2.0: Context-aware tech stack
        self._tech_stack_context: Dict = {}

    def _setup_event_subscriptions(self):
        """No event subscriptions needed -- queue-driven specialist."""
        pass

    async def run_loop(self):
        """Main agent loop -- no-op for queue-driven specialist."""
        dashboard.current_agent = self.name
        self.think("MassAssignmentAgent initialized...")
        while self.running:
            await asyncio.sleep(1)

    # =========================================================================
    # QUEUE CONSUMER (v3.2 Pipeline)
    # =========================================================================

    async def start_queue_consumer(self, scan_context: str) -> None:
        """TWO-PHASE queue consumer (WET -> DRY). NO infinite loop."""
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

        logger.info(f"[{self.name}] Starting TWO-PHASE queue consumer (WET -> DRY)")

        # Get initial queue depth
        queue = queue_manager.get_queue("mass_assignment")
        initial_depth = queue.depth()
        self._wet_count = initial_depth
        report_specialist_start(self.name, queue_depth=initial_depth)

        self._v.emit("exploit.specialist.started", {
            "agent": "MassAssignment", "queue_depth": initial_depth,
        })

        # PHASE A: ANALYSIS & DEDUPLICATION
        dry_list = await self.analyze_and_dedup_queue()

        report_specialist_wet_dry(self.name, initial_depth, len(dry_list) if dry_list else 0)
        write_dry_file(self, dry_list, initial_depth, "mass_assignment")

        if not dry_list:
            logger.info(f"[{self.name}] No findings to exploit after deduplication")
            report_specialist_done(self.name, processed=0, vulns=0)
            self._v.emit("exploit.specialist.completed", {
                "agent": "MassAssignment", "dry_count": 0, "vulns": 0,
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
            vulns=vulns_count,
        )

        self._v.emit("exploit.specialist.completed", {
            "agent": "MassAssignment",
            "dry_count": len(dry_list),
            "vulns": vulns_count,
        })

        logger.info(f"[{self.name}] Queue consumer complete: {vulns_count} validated findings")

    # =========================================================================
    # PHASE A: WET -> DRY
    # =========================================================================

    async def analyze_and_dedup_queue(self) -> List[Dict]:
        """Drain mass_assignment queue and deduplicate by endpoint."""
        logger.info(f"[{self.name}] ===== PHASE A: Analyzing WET list =====")
        queue = queue_manager.get_queue("mass_assignment")
        wet_findings: List[Dict] = []

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
                    "scan_context": item.get("scan_context", self._scan_context),
                })

        logger.info(f"[{self.name}] Phase A: Drained {len(wet_findings)} WET findings")

        if not wet_findings:
            return []

        # Discover additional POST/PUT/PATCH endpoints from target
        all_urls: set = set()
        for wf in wet_findings:
            all_urls.add(wf["url"])

        # Also discover writable endpoints from the target
        if all_urls:
            sample_url = next(iter(all_urls))
            discovered = await discover_writable_endpoints(sample_url)
            all_urls.update(discovered)

        # Deduplicate by normalized endpoint path
        seen: set = set()
        for url in all_urls:
            parsed = urlparse(url)
            dedup_key = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if dedup_key not in seen:
                seen.add(dedup_key)
                self._dry_findings.append({
                    "url": url,
                    "parameter": "",
                    "finding": {"url": url, "type": "mass assignment"},
                    "scan_context": self._scan_context,
                })

        logger.info(
            f"[{self.name}] Phase A: {len(wet_findings)} WET -> {len(self._dry_findings)} DRY"
        )
        return self._dry_findings

    # =========================================================================
    # PHASE B: EXPLOITATION
    # =========================================================================

    async def exploit_dry_list(self) -> List[Dict]:
        """Test each DRY endpoint for mass assignment vulnerabilities."""
        logger.info(
            f"[{self.name}] ===== PHASE B: Exploiting {len(self._dry_findings)} DRY findings ====="
        )
        validated: List[Dict] = []

        # Build auth headers callback
        def _get_auth(ctx: str, role: str = "user"):
            try:
                from bugtrace.services.scan_context import get_scan_auth_headers
                return get_scan_auth_headers(ctx, role=role)
            except Exception:
                return {}

        for idx, f in enumerate(self._dry_findings, 1):
            url = f.get("url", "")

            if hasattr(self, '_v'):
                self._v.emit("exploit.specialist.param.started", {
                    "agent": "MassAssignment", "param": "privilege_fields",
                    "url": url, "idx": idx, "total": len(self._dry_findings),
                })

            try:
                results = await test_endpoint_mass_assignment(
                    url,
                    scan_context=self._scan_context,
                    auth_headers_fn=_get_auth,
                )
                for result in results:
                    if result.get("validated"):
                        fp = generate_fingerprint(url, result.get("field", result.get("parameter", "")))
                        if fp not in self._emitted_findings:
                            self._emitted_findings.add(fp)
                            validated.append(result)

                            # Store in knowledge graph
                            self._store_finding_in_memory(url, result)
            except Exception as e:
                logger.error(f"[{self.name}] Error testing {url}: {e}")

        logger.info(f"[{self.name}] Phase B: {len(validated)} mass assignment vulns found")
        return validated

    # =========================================================================
    # HELPERS
    # =========================================================================

    def _store_finding_in_memory(self, url: str, result: Dict) -> None:
        """Store a finding in the knowledge graph."""
        try:
            from bugtrace.memory.manager import memory_manager
            field_name = result.get("parameter", "")
            method = result.get("method", "")
            field_value = result.get("injected_value", "")
            memory_manager.add_node(
                "Finding",
                f"MASS_ASSIGNMENT_{field_name}_{urlparse(url).path}",
                properties={
                    "type": "MASS_ASSIGNMENT",
                    "url": url,
                    "parameter": field_name,
                    "payload": str(field_value)[:100],
                    "details": f"Field '{field_name}' accepted via {method}",
                },
            )
        except Exception:
            pass

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
        logger.info(
            f"[{self.name}] Loaded tech context: {self._tech_stack_context.get('lang', 'generic')}"
        )

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
                    "dedup_method": "endpoint_normalization",
                },
                "phase_b": {
                    "validated_count": len([x for x in findings if x and x.get("validated")]),
                    "total_findings": len(findings),
                },
                "findings": findings,
            }, indent=2))

        logger.info(f"[{self.name}] Report saved: {report_path}")
        return str(report_path)


# Export
__all__ = ["MassAssignmentAgent"]
