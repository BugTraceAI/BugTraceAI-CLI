"""run/run_loop orchestration.

Shell mixin; hard max 2000 LOC.
"""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Set
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from bugtrace.agents.base import BaseAgent
from bugtrace.core.config import settings
from bugtrace.core.ui import dashboard
from bugtrace.core.llm_client import llm_client
from bugtrace.core.http_manager import http_manager, ConnectionProfile
from bugtrace.core.event_bus import event_bus, EventType
from bugtrace.core.verbose_events import create_emitter
from bugtrace.utils.logger import get_logger

logger = get_logger(__name__)

class AnalysisRunMixin:
    async def run_loop(self):
        """Standard run loop executing the DAST+SAST analysis."""
        return await self.run()

    async def run(self) -> Dict:
        """Performs 6-approach analysis on the URL (DAST+SAST) with event emission."""
        import time as _time
        self._v = create_emitter("DASTySAST", self.scan_context)
        self._run_start = _time.time()
        # Include `total` so the WEB template "[DAST] Analyzing URL {index}/{total}" renders
        # a full "i/N" (it was omitted → "Analyzing URL 3/" garbled + the graph's per-URL
        # counter regex couldn't match).
        self._v.emit("discovery.url.started", {"url": self.url, "index": self.url_index, "total": self.url_total})
        dashboard.current_agent = self.name
        dashboard.log(f"[{self.name}] Running DAST+SAST Analysis on {self.url[:50]}...", "INFO")

        # Use phase-specific analysis semaphore for tracking (v2.4)
        phase_ctx = None
        try:
            from bugtrace.core.phase_semaphores import phase_semaphores, ScanPhase
            phase_semaphores.initialize()
            phase_ctx = phase_semaphores.acquire(ScanPhase.ANALYSIS)
        except ImportError:
            pass

        try:
            if phase_ctx:
                await phase_ctx.__aenter__()

            # 1. Prepare Context
            context = await self._run_prepare_context()

            # 2. Parallel Analysis
            valid_analyses = await self._run_execute_analyses(context)
            if not valid_analyses:
                dashboard.log(f"[{self.name}] All analysis approaches failed.", "ERROR")
                # Emit event even on failure (empty findings)
                await self._emit_url_analyzed([])
                return {"error": "Analysis failed", "vulnerabilities": []}

            # 3. Consolidate & Review
            consolidated = self._consolidate(valid_analyses)
            # 3.5 Auto-inject candidates for file/redirect params the LLM may have missed
            consolidated = self._inject_param_based_candidates(consolidated)
            vulnerabilities = await self._skeptical_review(consolidated)

            # 4. Save Results
            await self._run_save_results(vulnerabilities)

            # 5. Emit url_analyzed event (Phase 17: DISC-04)
            import time as _time2
            self._v.emit("discovery.url.completed", {
                "url": self.url, "findings_count": len(vulnerabilities),
                "duration_ms": int((_time2.time() - self._run_start) * 1000),
            })
            await self._emit_url_analyzed(vulnerabilities)

            # Determine base filename based on url_index
            if self.url_index is not None:
                base_filename = str(self.url_index)
            else:
                # Fallback for compatibility with old calls
                base_filename = f"vulnerabilities_{self._get_safe_name()}"

            return {
                "url": self.url,
                "vulnerabilities": vulnerabilities,
                "json_report_file": str(self.report_dir / f"{base_filename}.json"),
                "url_index": self.url_index,
                "fp_stats": {
                    "total_findings": len(vulnerabilities),
                    "high_confidence": len([v for v in vulnerabilities if v.get('fp_confidence', 0) >= 0.7]),
                    "medium_confidence": len([v for v in vulnerabilities if 0.5 <= v.get('fp_confidence', 0) < 0.7]),
                    "low_confidence": len([v for v in vulnerabilities if v.get('fp_confidence', 0) < 0.5])
                }
            }

        except Exception as e:
            logger.error(f"DASTySASTAgent failed: {e}", exc_info=True)
            # Emit event even on exception (empty findings)
            try:
                await self._emit_url_analyzed([])
            except Exception:
                pass  # Best effort
            return {"error": str(e), "vulnerabilities": []}
        finally:
            # Release phase semaphore (v2.4)
            if phase_ctx:
                try:
                    await phase_ctx.__aexit__(None, None, None)
                except Exception:
                    pass  # Semaphore already released or never acquired

    async def _run_execute_analyses(self, context: Dict) -> List[Dict]:
        """Execute parallel analyses with all approaches.

        Modes:
            ALL  — Run all enabled approaches in parallel (default).
            AUTO — Wave 1 (pentester + bug_bounty) first; if no findings,
                   Wave 2 (code_auditor + red_team). Researcher skipped.
                   SQLi/Cookie probes always run with Wave 1.
        """
        core_approaches = [a for a in self.approaches if a != "skeptical_agent"]

        if self.approach_mode == "AUTO":
            valid_analyses = await self._run_auto_waves(context, core_approaches)
        else:
            valid_analyses = await self._run_all_approaches(context, core_approaches)

        # Run skeptical_agent AFTER to review findings from core approaches
        if "skeptical_agent" in self.approaches:
            skeptical_result = await self._run_skeptical_approach(context, valid_analyses)
            if skeptical_result and not skeptical_result.get("error"):
                valid_analyses.append(skeptical_result)

        return valid_analyses

    async def _run_auto_waves(self, context: Dict, core_approaches: List[str]) -> List[Dict]:
        """AUTO mode: wave 1 first, wave 2 only if wave 1 found nothing."""
        # Wave 1: high-yield approaches + probes (always run)
        wave1_names = ["pentester", "bug_bounty"]
        wave1 = [a for a in core_approaches if a in wave1_names]
        if not wave1:
            wave1 = core_approaches[:2]  # Fallback if those were disabled

        self._v.emit("discovery.llm.started", {"url": self.url, "approaches": wave1, "mode": "AUTO/wave1"})
        tasks = [self._analyze_with_approach(context, a) for a in wave1]
        tasks.append(self._check_sqli_probes())
        tasks.append(self._check_cookie_sqli_probes())

        results = await asyncio.gather(*tasks, return_exceptions=True)
        valid = [r for r in results if isinstance(r, dict) and not r.get("error")]
        self._v.emit("discovery.llm.completed", {"url": self.url, "valid_analyses": len(valid), "total": len(results), "mode": "AUTO/wave1"})

        # Check if wave 1 found any vulnerabilities
        wave1_has_findings = any(
            r.get("vulnerabilities") for r in valid if isinstance(r, dict)
        )

        if wave1_has_findings:
            logger.info(f"[AUTO] Wave 1 found findings for {self.url[:50]}, skipping wave 2")
            return valid

        # Wave 2: deeper approaches (skip researcher — lowest yield)
        wave2_names = ["code_auditor", "red_team"]
        wave2 = [a for a in core_approaches if a in wave2_names and a not in wave1]
        if not wave2:
            return valid

        logger.info(f"[AUTO] Wave 1 empty for {self.url[:50]}, launching wave 2: {wave2}")
        self._v.emit("discovery.llm.started", {"url": self.url, "approaches": wave2, "mode": "AUTO/wave2"})
        tasks2 = [self._analyze_with_approach(context, a) for a in wave2]
        results2 = await asyncio.gather(*tasks2, return_exceptions=True)
        valid2 = [r for r in results2 if isinstance(r, dict) and not r.get("error")]
        self._v.emit("discovery.llm.completed", {"url": self.url, "valid_analyses": len(valid2), "total": len(results2), "mode": "AUTO/wave2"})

        return valid + valid2

