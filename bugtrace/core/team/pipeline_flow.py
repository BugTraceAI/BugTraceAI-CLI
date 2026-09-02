"""Sequential pipeline and phase-2 batch DAST shell.

Shell mixin; hard max 2000 LOC, prefer ~800-1500.
"""

from __future__ import annotations

import asyncio
import json
import hashlib
import re
import signal
import sys
import uuid
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from shutil import move, rmtree
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qs

import httpx
from loguru import logger
from rich.live import Live

from bugtrace.core.config import settings
from bugtrace.core.ui import dashboard
from bugtrace.core.event_bus import event_bus
from bugtrace.core.http_manager import http_manager
from bugtrace.core.state_manager import get_state_manager
from bugtrace.core.pipeline import PipelineLifecycle, PipelinePhase, PipelineState
from bugtrace.core.phase_semaphores import (
    phase_semaphores, ScanPhase,
    get_exploitation_semaphore, get_analysis_semaphore, get_validation_semaphore,
    get_reporting_semaphore,
)
from bugtrace.core.batch_metrics import batch_metrics, reset_batch_metrics

# Agents / tools referenced by orchestrator shell methods
from bugtrace.agents.base import BaseAgent
from bugtrace.agents.nuclei_agent import NucleiAgent
from bugtrace.agents.gospider_agent import GoSpiderAgent
from bugtrace.agents.analysis_agent import DASTySASTAgent
from bugtrace.agents.xss import XSSAgent
from bugtrace.agents.csti_agent import CSTIAgent
from bugtrace.agents.sqlmap_agent import SQLMapAgent
from bugtrace.agents.jwt_agent import JWTAgent
from bugtrace.agents.fileupload_agent import FileUploadAgent
from bugtrace.agents.asset_discovery_agent import AssetDiscoveryAgent
from bugtrace.agents.api_security_agent import APISecurityAgent
from bugtrace.agents.openredirect_agent import OpenRedirectAgent
from bugtrace.agents.prototype_pollution_agent import PrototypePollutionAgent
from bugtrace.agents.reattack import ReAttackAgent
from bugtrace.utils.token_scanner import find_jwts
from bugtrace.core.conductor import conductor
from bugtrace.core.verbose_events import create_emitter, install_ui_bridge
from bugtrace.core.surface import (
    ControlModel, ProbeObservation, build_control_model, differs_from_control,
    drop_insecure_duplicate_origins, names_a_resource,
)


class TeamPipelineMixin:
    async def _run_sequential_pipeline(self, dashboard):
        """Implements the V3 Batch Processing Pipeline Flow."""
        logger.info("Entering V3 Batch Processing Pipeline")
        start_time = datetime.now()

        # Initialize HTTP client manager (v2.4 - prevents hung connections)
        await http_manager.start()
        logger.info("[HTTPClientManager] Connection pools initialized")

        # Initialize batch metrics
        reset_batch_metrics()
        batch_metrics.start_scan()

        # Initialize and start pipeline
        self._init_pipeline()
        await self._start_pipeline()
        
        # Start ReAttackAgent background task (Task 4)
        if hasattr(self, 'reattack_agent'):
            asyncio.create_task(self.reattack_agent.start())
            logger.info("[Pipeline] ReAttackAgent started (background loops active)")

        self._v.emit("pipeline.initializing", {"target": self.target, "scan_id": self.scan_id})

        conductor.notify_phase_change("reconnaissance", 0.0, "Pipeline started")
        self._sync_scan_context("RECONNAISSANCE", "ReconAgent")

        # Setup directories
        scan_dir, recon_dir, analysis_dir, captures_dir = self._setup_scan_directory(start_time)
        logger.info(f"Scan directory created: {scan_dir.name}")

        # Update ThinkingConsolidationAgent with correct scan_dir
        self.thinking_agent.scan_dir = scan_dir

        # V3.2: Set scan_dir in state_manager for file-based findings
        self.state_manager.set_scan_dir(scan_dir)

        # ========== PHASE 1: DISCOVERY ==========
        # GoSpider crawls target, discovers URLs
        self._v.emit("pipeline.phase_transition", {"phase": "reconnaissance", "target": self.target})
        self._v.emit("recon.started", {"target": self.target})
        await self._phase_1_reconnaissance(dashboard, recon_dir)

        # Update dashboard with discovery metrics
        dashboard.set_progress_metrics(
            urls_discovered=len(self.urls_to_scan),
            urls_total=len(self.urls_to_scan),
            scan_id=self.scan_id
        )
        self._v.emit("recon.completed", {"urls_found": len(self.urls_to_scan)})
        conductor.notify_phase_change("reconnaissance", 1.0, f"{len(self.urls_to_scan)} URLs discovered")
        conductor.notify_metrics(urls_discovered=len(self.urls_to_scan))
        self._sync_scan_context("RECONNAISSANCE", "ReconAgent", progress=10)
        self._record_phase_complete("reconnaissance")

        await self._lifecycle.signal_phase_complete(
            PipelinePhase.RECONNAISSANCE,
            {'urls_found': len(self.urls_to_scan)}
        )

        if await self._check_stop_requested(dashboard):
            return

        if not self.urls_to_scan:
            logger.warning("[Pipeline] Recon found 0 URLs — aborting pipeline")
            self._v.emit("pipeline.error", {"error": "Recon found 0 URLs to scan"})
            return

        # ========== API DETAIL ENDPOINT ENRICHMENT ==========
        # Discover detail URLs from API list endpoints (e.g., /api/threads → /api/threads/1)
        pre_enrich_count = len(self.urls_to_scan)
        self.urls_to_scan = await self._enrich_api_detail_endpoints(self.urls_to_scan)
        if len(self.urls_to_scan) > pre_enrich_count:
            added = len(self.urls_to_scan) - pre_enrich_count
            logger.info(f"[API Enrichment] Added {added} detail endpoints ({pre_enrich_count} → {len(self.urls_to_scan)} URLs)")

        # ========== COMMON ENDPOINT DISCOVERY ==========
        # Probe for well-known endpoints not found by crawling (redirect, admin, debug, etc.)
        pre_discover_count = len(self.urls_to_scan)
        self.urls_to_scan = await self._discover_common_vuln_endpoints(self.urls_to_scan)
        if len(self.urls_to_scan) > pre_discover_count:
            added = len(self.urls_to_scan) - pre_discover_count
            logger.info(f"[Endpoint Discovery] Added {added} common endpoints ({pre_discover_count} → {len(self.urls_to_scan)} URLs)")

        # ========== SPA → API INFERENCE ==========
        # Infer API endpoints from SPA frontend routes (e.g., /forum/thread/1 → /api/forum/threads/1)
        pre_spa_count = len(self.urls_to_scan)
        self.urls_to_scan = await self._infer_api_from_frontend_routes(self.urls_to_scan)
        if len(self.urls_to_scan) > pre_spa_count:
            added = len(self.urls_to_scan) - pre_spa_count
            logger.info(f"[SPA→API] Added {added} API endpoints ({pre_spa_count} → {len(self.urls_to_scan)} URLs)")

        # ========== RE-PRIORITIZE after enrichment, BEFORE the MAX_URLS trim ==========
        # Enrichment (_enrich_api_detail_endpoints / _discover_common_vuln_endpoints /
        # _infer_api_from_frontend_routes) APPENDS high-value endpoints (auth/login/
        # register, admin, param-rich APIs) at the TAIL of urls_to_scan. Without
        # re-scoring, the [:max_urls] trim below guillotines exactly those tail
        # endpoints — e.g. /api/auth/register — starving AuthDiscovery of the
        # registration endpoint it needs to obtain the initial JWT, which silently
        # breaks the whole auto-auth chain at any realistic max_urls. Re-prioritizing
        # the FULL enriched list keeps high-value endpoints above the cut.
        # Generic (not target-specific): url_prioritizer ranks auth/login/register/
        # admin/api/param-rich URLs high for ANY target.
        if settings.URL_PRIORITIZATION_ENABLED:
            self.urls_to_scan = self._prioritize_urls(self.urls_to_scan)

        # ========== RE-ENFORCE MAX_URLS after enrichment ==========
        # The user's target URL MUST always be first, even if GoSpider didn't find it
        target_norm = self.target.rstrip('/')
        remaining = [u for u in self.urls_to_scan if u.rstrip('/') != target_norm]
        self.urls_to_scan = [self.target] + remaining

        if len(self.urls_to_scan) > self.max_urls:
            logger.info(f"Enforcing MAX_URLS={self.max_urls} after enrichment: Trimming {len(self.urls_to_scan)} -> {self.max_urls} URLs")
            self.urls_to_scan = self.urls_to_scan[:self.max_urls]

        # ========== URL PATTERN DEDUP (collapse /products/1, /products/2 → /products/1) ==========
        if getattr(settings, 'URL_PATTERN_DEDUP', True):
            self.urls_to_scan = self._dedup_url_patterns(self.urls_to_scan)

        # ========== LONEWOLF: Background autonomous agent ==========
        self._lonewolf_task = None
        if settings.LONEWOLF_ENABLED:
            from bugtrace.agents.lone_wolf import LoneWolf
            wolf = LoneWolf(self.target, self.scan_dir)
            self._lonewolf_task = asyncio.create_task(wolf.run())
            logger.info("[Pipeline] LoneWolf launched in background")

        # ========== PHASE 2: DISCOVERY (Batch DAST) ==========
        # DASTySASTAgent analyzes ALL URLs in parallel
        # ThinkingConsolidationAgent deduplicates and distributes to queues
        logger.info("=== PHASE 2: DISCOVERY (Batch DAST) ===")
        self._v.emit("pipeline.phase_transition", {"phase": "discovery", "urls_count": len(self.urls_to_scan)})
        self._v.emit("discovery.started", {"urls_count": len(self.urls_to_scan)})
        logger.info(f"🔬 Running batch DAST on {len(self.urls_to_scan)} URLs")
        dashboard.set_phase("🔬 HUNTING VULNS")
        dashboard.set_status("Running", "Analysis in progress...")
        conductor.notify_phase_change("discovery", 0.0, f"Analyzing {len(self.urls_to_scan)} URLs")
        self._sync_scan_context("DISCOVERY", "DASTySAST", progress=15)

        # Run batch DAST - this is the actual DISCOVERY work
        self.vulnerabilities_by_url = await self._phase_2_batch_dast(dashboard, analysis_dir, recon_dir)

        # ========== INTEGRITY CHECKPOINT 1: Discovery ==========
        dastysast_dir = self.scan_dir / "dastysast"
        urls_count = len(self.urls_to_scan)
        reports_generated = len(list(dastysast_dir.glob("*.json"))) if dastysast_dir.exists() else 0
        errors_count = urls_count - reports_generated  # FIX: count by actual JSON files, not in-memory dict

        self._v.emit("pipeline.checkpoint", {"phase": "discovery", "urls": urls_count, "reports": reports_generated, "errors": errors_count})
        self._record_phase_complete("discovery")
        conductor.verify_integrity("discovery",
            {'urls_count': urls_count},
            {'dast_reports_count': reports_generated, 'errors': errors_count})

        # PIPELINE GATE: Warn if not all URLs have JSON files, but continue
        # Nuclei findings and other data are still valid even if DAST failed on some URLs
        if errors_count > 0:
            if reports_generated == 0:
                dashboard.log(
                    f"⚠ All {urls_count} URLs failed DAST analysis — continuing with Nuclei findings only",
                    "WARNING"
                )
            else:
                dashboard.log(
                    f"⚠ {errors_count}/{urls_count} URLs missing DAST JSON — continuing with {reports_generated} reports",
                    "WARNING"
                )
            logger.warning(
                f"[Pipeline] {errors_count}/{urls_count} URLs have no dastysast JSON. "
                f"Reports generated: {reports_generated}. Continuing to STRATEGY..."
            )

        # Signal DISCOVERY complete AFTER batch DAST finishes
        self._v.emit("discovery.completed", {"urls_analyzed": reports_generated, "urls_total": urls_count})
        conductor.notify_phase_change("discovery", 1.0, f"{reports_generated} URLs analyzed")
        conductor.notify_metrics(urls_discovered=len(self.urls_to_scan), urls_analyzed=reports_generated)
        self._sync_scan_context("DISCOVERY", "DASTySAST", progress=35)
        await self._lifecycle.signal_phase_complete(
            PipelinePhase.DISCOVERY,
            {'urls_analyzed': reports_generated}
        )

        if await self._check_stop_requested(dashboard):
            return

        # ========== PHASE 3: STRATEGY (Batch Processing) ==========
        # ThinkingAgent reads JSON files, deduplicates, and distributes to queues
        logger.info("=== PHASE 3: STRATEGY (Deduplication & Queue Distribution) ===")
        self._v.emit("pipeline.phase_transition", {"phase": "strategy"})
        self._v.emit("strategy.started", {})
        logger.info("🧠 ThinkingAgent processing findings batch")
        dashboard.set_phase("🧠 STRATEGY")
        dashboard.set_status("Running", "Deduplication in progress...")
        conductor.notify_phase_change("strategy", 0.0, "Deduplication in progress")
        self._sync_scan_context("STRATEGY", "ThinkingAgent", progress=40)
        conductor.notify_log("INFO", "[STRATEGY] ThinkingAgent processing findings batch")

        # Process all JSON files from scan_dir/dastysast/ (where Phase 2 saves them)
        # ThinkingAgent processes batch, fills queues, and TERMINATES
        # NOTE: Phase 2 saves to self.scan_dir/dastysast/, NOT analysis_dir/dastysast/
        analysis_json_dir = self.scan_dir / "dastysast"
        findings_count = await self._phase_3_strategy(dashboard, analysis_json_dir)

        logger.info("ThinkingConsolidationAgent finished - queues ready for specialists")
        conductor.notify_log("INFO", f"[STRATEGY] {findings_count} findings distributed to specialist queues")

        # ========== INTEGRITY CHECKPOINT 2: Strategy ==========
        dast_findings = batch_metrics.findings_dast
        auth_findings = batch_metrics.findings_auth
        total_raw = batch_metrics.findings_before_dedup
        wet_queue_count = findings_count  # Items distributed to specialist queues

        if not conductor.verify_integrity("strategy",
            {
                'raw_findings_count': total_raw,
                'dast_findings': dast_findings,
                'auth_findings': auth_findings
            },
            {'wet_queue_count': wet_queue_count}):
            logger.warning("❌ Integrity mismatch: Strategy phase")
            logger.warning(
                f"[Pipeline] Integrity check FAILED for Strategy. "
                f"DAST: {dast_findings}, Auth: {auth_findings}, Total: {total_raw}, WET: {wet_queue_count}"
            )

        # Signal STRATEGY complete
        self._v.emit("strategy.completed", {"findings_distributed": findings_count})
        conductor.notify_phase_change("strategy", 1.0, f"{findings_count} findings distributed")
        self._sync_scan_context("STRATEGY", "ThinkingAgent", findings_count=findings_count, progress=50)
        await self._lifecycle.signal_phase_complete(
            PipelinePhase.STRATEGY,
            {'findings_processed': findings_count}
        )

        if await self._check_stop_requested(dashboard):
            return

        # ========== PHASE 4: EXPLOITATION (Queue Consumption) ==========
        # Specialists consume from queues in true parallel
        logger.info("=== PHASE 4: EXPLOITATION (Specialist Queue Processing) ===")
        self._v.emit("pipeline.phase_transition", {"phase": "exploitation"})
        logger.info(f"⚡ Specialists processing findings from queues")
        conductor.notify_phase_change("exploitation", 0.0, "Specialists attacking")
        self._sync_scan_context("EXPLOITATION", "Specialists", findings_count=findings_count, progress=55)

        # Initialize specialist workers NOW (consume WET → create DRY → attack DRY)
        if not self._specialist_workers_started:
            await self._init_specialist_workers()
            self._specialist_workers_started = True
            logger.info("Specialist worker pools initialized and consuming queues")

        # Collect final queue stats (specialists already awaited via asyncio.gather)
        batch_metrics.start_queue_drain()
        queue_results = await self._wait_for_specialist_queues(dashboard, timeout=5.0)
        batch_metrics.end_queue_drain(
            findings_distributed=queue_results.get('items_distributed', 0),
            by_specialist=queue_results.get('by_specialist', {})
        )
        self._record_phase_complete("exploitation")

        # ========== INTEGRITY CHECKPOINT 3: Exploitation (WET → DRY) ==========
        wet_processed = batch_metrics.wet_processed
        dry_generated = batch_metrics.dry_generated

        if not conductor.verify_integrity("exploitation",
            {'wet_processed': wet_processed},
            {'dry_generated': dry_generated}):
            dashboard.log("❌ Integrity mismatch: Exploitation phase (possible hallucination)", "CRITICAL")
            logger.error(f"[Pipeline] Integrity check FAILED for Exploitation. WET: {wet_processed}, DRY: {dry_generated}")

        dashboard.log(
            f"Specialist execution complete: {queue_results.get('items_distributed', 0)} items processed",
            "INFO"
        )

        # Log batch summary from ThinkingAgent
        if self.thinking_agent and hasattr(self.thinking_agent, 'log_batch_summary'):
            self.thinking_agent.log_batch_summary()

        await self._checkpoint("Batch Analysis & Queue-based Exploitation")

        # Signal EXPLOITATION complete AFTER queue drain finishes
        self._v.emit("exploit.phase_stats", {
            "items_distributed": queue_results.get('items_distributed', 0),
            "by_specialist": queue_results.get('by_specialist', {}),
        })
        exploitation_findings = len(self.state_manager.get_findings()) if self.state_manager else 0
        conductor.notify_phase_change("exploitation", 1.0, f"{queue_results.get('items_distributed', 0)} items processed")
        self._sync_scan_context("EXPLOITATION", "Specialists", findings_count=exploitation_findings, progress=75)
        await self._lifecycle.signal_phase_complete(
            PipelinePhase.EXPLOITATION,
            {'findings_exploited': self.thinking_agent.get_stats().get('distributed', 0) if self.thinking_agent else 0}
        )

        if await self._check_stop_requested(dashboard):
            return

        # ========== PHASE 5: VALIDATION ==========
        all_findings_for_review = self.state_manager.get_findings()
        logger.info("=== PHASE 5: VALIDATION (Global Review) ===")
        self._v.emit("pipeline.phase_transition", {"phase": "validation", "findings_count": len(all_findings_for_review)})
        self._v.emit("validation.started", {"findings_to_review": len(all_findings_for_review)})
        conductor.notify_phase_change("validation", 0.0, f"Reviewing {len(all_findings_for_review)} findings")
        conductor.notify_log("INFO", f"[VALIDATION] Reviewing {len(all_findings_for_review)} findings")
        self._sync_scan_context("VALIDATION", "Validator", findings_count=len(all_findings_for_review), progress=80)
        # Decoupled CDP stage: heavy single-session CDP confirmation over the hard-cola
        # (XSS/CSTI/SSTI the fast Playwright pass left PENDING/NEEDS_CDP). Fully fail-safe
        # — any error is swallowed and the scan continues with specialist verdicts intact.
        await self._phase_cdp_validation(dashboard, scan_dir)
        await self._phase_3_global_review(dashboard, scan_dir)
        self._record_phase_complete("validation")  # mark complete AFTER validation actually runs
        self._v.emit("validation.completed", {"findings_reviewed": len(all_findings_for_review)})
        conductor.notify_phase_change("validation", 1.0, "Review complete")
        conductor.notify_log("INFO", "[VALIDATION] Global review complete")
        self._sync_scan_context("VALIDATION", "Validator", progress=85)
        await self._lifecycle.signal_phase_complete(
            PipelinePhase.VALIDATION,
            {'findings_reviewed': len(all_findings_for_review)}
        )

        if await self._check_stop_requested(dashboard):
            return

        # ========== AWAIT LONEWOLF BEFORE REPORTING ==========
        if self._lonewolf_task and not self._lonewolf_task.done():
            logger.info("[Pipeline] Waiting for LoneWolf to finish before reporting...")
            try:
                await asyncio.wait_for(self._lonewolf_task, timeout=30)
            except asyncio.TimeoutError:
                logger.warning("[Pipeline] LoneWolf timed out after 30s, proceeding with partial results")
                self._lonewolf_task.cancel()
            except Exception as e:
                logger.warning(f"[Pipeline] LoneWolf error: {e}")

        # ========== PHASE 6: REPORTING ==========
        logger.info("=== PHASE 6: REPORTING ===")
        self._v.emit("pipeline.phase_transition", {"phase": "reporting"})
        self._v.emit("reporting.started", {})
        conductor.notify_phase_change("reporting", 0.0, "Generating reports")
        conductor.notify_log("INFO", "[REPORTING] Generating final reports")
        self._sync_scan_context("REPORTING", "ReportingAgent", progress=90)
        await self._phase_4_reporting(dashboard, scan_dir)
        self._v.emit("reporting.completed", {})
        conductor.notify_phase_change("reporting", 1.0, "Reports generated")
        conductor.notify_log("INFO", "[REPORTING] Reports generated")
        self._sync_scan_context("COMPLETE", "System", progress=100)
        await self._lifecycle.signal_phase_complete(
            PipelinePhase.REPORTING,
            {'report_generated': True}
        )
        await self._stop_pipeline()

        # Cleanup
        await self._shutdown_specialist_workers()

        # End metrics and log performance summary
        all_findings = self.state_manager.get_findings()
        batch_metrics.end_scan(findings_exploited=len(all_findings))
        batch_metrics.log_summary()

        duration = (datetime.now() - start_time).total_seconds()
        self._v.emit("pipeline.completed", {
            "duration_s": round(duration, 1),
            "total_findings": len(all_findings),
        })
        conductor.notify_complete(len(all_findings), duration)
        logger.info(f"=== V3 BATCH PIPELINE COMPLETE in {duration:.1f}s ===")
        logger.info(f"V3 Batch Pipeline: {batch_metrics.time_saved_percent:.1f}% faster than sequential")

    async def _wait_for_specialist_queues(self, dashboard, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Collect final specialist queue stats after specialists have completed.

        Specialists are already awaited via asyncio.gather() in dispatch_specialists(),
        so this is primarily for dashboard/logging. Short timeout (5s) for 1-2 status checks.

        Args:
            dashboard: UI dashboard for status updates
            timeout: Maximum seconds to collect stats (default 5s)

        Returns:
            Dict of specialist -> items_processed counts
        """
        from bugtrace.core.queue import queue_manager
        import time

        start_time = time.monotonic()
        check_interval = 3.0  # 1-2 checks within 5s timeout
        last_log_time = start_time

        logger.info("Collecting specialist queue stats...")
        conductor.notify_log("INFO", "[EXPLOITATION] Collecting final specialist stats...")

        while (time.monotonic() - start_time) < timeout:
            # Get queue depths
            queue_stats = {}
            total_pending = 0

            for specialist in ["xss", "sqli", "csti", "lfi", "idor", "rce", "ssrf", "xxe", "jwt", "openredirect", "prototype_pollution"]:
                try:
                    queue = queue_manager.get_queue(specialist)
                    depth = queue.depth() if hasattr(queue, 'depth') else 0
                    total_enqueued = queue.total_enqueued if hasattr(queue, 'total_enqueued') else 0
                    total_dequeued = queue.total_dequeued if hasattr(queue, 'total_dequeued') else 0
                    queue_stats[specialist] = {
                        'depth': depth,
                        'processed': total_dequeued
                    }
                    total_pending += depth
                except Exception:
                    queue_stats[specialist] = {'depth': 0, 'processed': 0}

            # Update dashboard with queue stats in real-time
            self._v.emit("exploit.specialist.queue_progress", {
                "total_pending": total_pending, "queue_stats": queue_stats,
            })
            dashboard.set_progress_metrics(queue_stats=queue_stats, scan_id=self.scan_id)

            # Emit agent updates for WEB dashboard
            for specialist, stats in queue_stats.items():
                depth = stats.get('depth', 0)
                processed = stats.get('processed', 0)
                status = "active" if depth > 0 else ("complete" if processed > 0 else "idle")
                conductor.notify_agent_update(
                    agent=specialist.upper(),
                    status=status,
                    queue=depth,
                    processed=processed,
                )

            # Log progress every 5 seconds with detailed breakdown
            if (time.monotonic() - last_log_time) >= 5.0:
                # Build breakdown of non-empty queues
                non_empty = [f"{s.upper()}:{queue_stats[s]['depth']}"
                            for s in queue_stats if queue_stats[s]['depth'] > 0]
                if non_empty:
                    breakdown = ", ".join(non_empty)
                    logger.info(f"Queues pending: {breakdown} ({total_pending} total)")
                    conductor.notify_log("INFO", f"[EXPLOITATION] Queues pending: {breakdown} ({total_pending} total)")
                else:
                    logger.info(f"Queues: {total_pending} items pending")
                    conductor.notify_log("INFO", f"[EXPLOITATION] {total_pending} items pending")
                last_log_time = time.monotonic()

            if total_pending == 0:
                logger.info("All specialist queues drained")
                conductor.notify_log("INFO", "[EXPLOITATION] All specialist queues drained")
                break

            await asyncio.sleep(check_interval)

        elapsed = time.monotonic() - start_time

        if total_pending > 0:
            logger.warning(f"Queue drain timeout after {elapsed:.1f}s, {total_pending} items remaining")
            conductor.notify_log("WARNING", f"[EXPLOITATION] Queue drain timeout after {elapsed:.1f}s, {total_pending} items remaining")

        # Collect ThinkingAgent stats
        stats = self.thinking_agent.get_stats() if self.thinking_agent else {}

        return {
            "elapsed_seconds": elapsed,
            "items_distributed": stats.get("distributed", 0),
            "by_specialist": stats.get("by_specialist", {}),
            "pending_at_timeout": total_pending
        }

    async def _auto_pause_and_wait(self, reason: str, dashboard) -> bool:
        """Auto-pause scan and wait for manual resume, stop, or auto-resume after delay.

        Uses ScanContext (connected to the API pause/resume endpoints) instead of
        PipelineLifecycle, which is designed for phase-boundary pauses only.

        Behavior:
            - Pauses the scan and updates DB to PAUSED.
            - Waits up to DAST_AUTO_RESUME_DELAY seconds (default 300 = 5 min).
            - If user resumes manually → continues immediately.
            - If user stops → returns True (caller should abort).
            - If timeout expires → auto-resumes and continues.

        Returns:
            True if user stopped the scan (caller should abort).
            False if scan resumed (manually or auto).
        """
        from bugtrace.schemas.db_models import ScanStatus
        from bugtrace.core.conductor import conductor

        scan_ctx = getattr(self, '_scan_context', None)
        if scan_ctx is None:
            logger.warning("[DAST] No scan context — cannot auto-pause")
            return False

        delay = getattr(settings, 'DAST_AUTO_RESUME_DELAY', 300)

        # 1. Pause: set scan status, update DB, clear resume event
        scan_ctx.request_pause()
        self.db.update_scan_status(self.scan_id, ScanStatus.PAUSED)
        logger.critical(f"[DAST] {reason}")
        dashboard.log(f"⏸ {reason}", "CRITICAL")
        conductor.notify_log("CRITICAL", f"[DAST] {reason}")

        # 2. Wait for manual resume/stop OR auto-resume after delay
        mins = delay // 60
        logger.info(f"[DAST] Scan paused — auto-resume in {mins}min (or resume/stop manually)...")
        dashboard.log(f"⏸ Paused. Auto-resume in {mins}min or resume manually.", "WARNING")

        try:
            await asyncio.wait_for(scan_ctx._resume_event.wait(), timeout=delay)
        except asyncio.TimeoutError:
            # Auto-resume: nobody touched it in time
            logger.info(f"[DAST] Auto-resuming after {mins}min pause.")
            logger.info(f"▶ Auto-resuming after {mins}min pause.")
            scan_ctx.request_resume()
            self.db.update_scan_status(self.scan_id, ScanStatus.RUNNING)
            return False

        # 3. Manual action — check if user stopped instead of resumed
        if scan_ctx.stop_event.is_set():
            logger.info("[DAST] Scan was stopped while paused.")
            dashboard.log("⏹ Scan stopped by user.", "WARNING")
            return True

        # 4. Manual resume — DB already updated to RUNNING by scan_service.resume_scan()
        logger.info("[DAST] Pipeline resumed manually. Retrying timed-out URLs.")
        logger.info("▶ Scan resumed. Retrying timed-out URLs.")
        return False

    async def _phase_2_batch_dast(self, dashboard, analysis_dir, recon_dir=None) -> Dict[str, list]:
        """Run Phase 2: DISCOVERY - Parallel execution of DAST + Reconnaissance.

        Includes retry logic: after initial parallel run, checks which URL indices
        are missing dastysast JSON files and retries them with reduced concurrency.
        Pipeline stops if any URLs still missing after DAST_MAX_RETRIES rounds.
        """

        batch_metrics.start_dast()

        # ========== SETUP ==========
        dastysast_dir = self.scan_dir / "dastysast"
        dastysast_dir.mkdir(exist_ok=True)
        total_urls = len(self.urls_to_scan)
        analysis_timeout = getattr(settings, 'DAST_ANALYSIS_TIMEOUT', 180.0)
        max_retries = getattr(settings, 'DAST_MAX_RETRIES', 5)
        completed_count = {"value": 0}

        # Circuit breaker: auto-pause on excessive timeouts (target may be down)
        timeout_tracker = {"consecutive": 0, "total": 0, "auto_paused": False, "pause_reason": ""}
        consecutive_limit = getattr(settings, 'DAST_CONSECUTIVE_TIMEOUT_LIMIT', 5)
        percent_limit = getattr(settings, 'DAST_TIMEOUT_PERCENT_LIMIT', 50)

        # Build index: url_index (1-based) → url
        url_index_map = {idx + 1: url for idx, url in enumerate(self.urls_to_scan)}

        # ========== TASK 1: DASTySAST Analysis ==========
        async def _run_dast_batch(url_indices: list, concurrency_limit: int) -> list:
            """Run DAST analysis on a batch of URL indices with given concurrency."""
            semaphore = asyncio.Semaphore(concurrency_limit)

            async def _bounded_analyze(url_index: int) -> tuple:
                url = url_index_map[url_index]

                # Circuit breaker: skip remaining URLs if auto-paused
                if timeout_tracker["auto_paused"]:
                    return (url, [])

                async with semaphore:
                    # Re-check after acquiring semaphore (may have been set while waiting)
                    if timeout_tracker["auto_paused"]:
                        return (url, [])

                    logger.info(f"[DAST] ▶ Starting: {url[:60]}")
                    conductor.notify_log("INFO", f"[DAST] Analyzing URL {url_index}/{total_urls}: {url[:80]}")

                    dast = DASTySASTAgent(
                        url, self.tech_profile, dastysast_dir,
                        state_manager=self.state_manager,
                        scan_context=str(self.scan_id),
                        url_index=url_index,
                        url_total=total_urls
                    )

                    try:
                        result = await asyncio.wait_for(dast.run(), timeout=analysis_timeout)
                        vulns = result.get("vulnerabilities", [])
                        timeout_tracker["consecutive"] = 0  # Reset on success
                    except asyncio.TimeoutError:
                        logger.warning(f"[DAST] Analysis timed out after {analysis_timeout}s: {url[:50]}...")
                        vulns = []
                        timeout_tracker["consecutive"] += 1
                        timeout_tracker["total"] += 1

                        # Check circuit breaker thresholds
                        # Skip auto-pause for small scans (< 5 URLs) — not enough data points
                        pct = (timeout_tracker["total"] / total_urls) * 100 if total_urls > 0 else 0
                        if (not timeout_tracker["auto_paused"]
                                and total_urls >= 5
                                and (timeout_tracker["consecutive"] >= consecutive_limit
                                     or pct >= percent_limit)):
                            timeout_tracker["auto_paused"] = True
                            timeout_tracker["pause_reason"] = (
                                f"Auto-paused: {timeout_tracker['consecutive']} consecutive timeouts "
                                f"({timeout_tracker['total']}/{total_urls} total, {pct:.0f}%). "
                                f"Target may be down."
                            )
                    except Exception as e:
                        logger.error(f"[DAST] Analysis failed for {url[:50]}: {e}")
                        vulns = []

                    logger.info(f"[DAST] ✓ Completed ({len(vulns)} findings): {url[:60]}")
                    completed_count["value"] += 1
                    dashboard.set_progress_metrics(urls_analyzed=completed_count["value"], scan_id=self.scan_id)
                    conductor.notify_log("INFO", f"[DAST] URL {completed_count['value']}/{total_urls} complete ({len(vulns)} findings)")
                    conductor.notify_metrics(urls_analyzed=completed_count["value"], urls_discovered=total_urls)

                    return (url, vulns)

            tasks = [_bounded_analyze(idx) for idx in url_indices]
            return await asyncio.gather(*tasks, return_exceptions=True)

        def _get_missing_indices() -> list:
            """Check dastysast/ dir and return URL indices that have no JSON file."""
            existing = {int(f.stem) for f in dastysast_dir.glob("*.json") if f.stem.isdigit()}
            expected = set(url_index_map.keys())
            return sorted(expected - existing)

        # ========== TASK 2-4: Reconnaissance in Parallel ==========
        async def run_nuclei_parallel():
            logger.info("🔬 Running Nuclei tech profiling...")
            tech_profile = await self._run_nuclei_tech_profile(recon_dir)
            self.tech_profile = tech_profile
            logger.info(f"✓ Nuclei: {len(tech_profile.get('frameworks', []))} frameworks")

            # Emit misconfigurations as findings (HSTS, cookie flags, etc.)
            from bugtrace.core.event_bus import EventType
            misconfigs = tech_profile.get("misconfigurations", [])
            if misconfigs:
                logger.info(f"Misconfigurations: {len(misconfigs)} detected (HSTS, cookies, etc.)")
                for misconfig in misconfigs:
                    finding_data = {
                        "type": "MISCONFIGURATION",
                        "category": misconfig.get("tags", ["SECURITY_HEADER"])[0] if misconfig.get("tags") else "SECURITY_HEADER",
                        "severity": misconfig.get("severity", "low").upper(),
                        "url": misconfig.get("matched_at", self.target),
                        "parameter": misconfig.get("name", ""),
                        "description": misconfig.get("description", ""),
                        "remediation": "",
                        "cwe_id": "",
                        "validated": True,
                        "status": "VALIDATED_CONFIRMED",
                        "scan_context": self.scan_context,
                        "evidence": {
                            "nuclei_template": misconfig.get("template_id", ""),
                            "detection_method": "nuclei_passive",
                            "tags": misconfig.get("tags", [])
                        }
                    }
                    await self.event_bus.emit(
                        EventType.VULNERABILITY_DETECTED,
                        finding_data
                    )
                    logger.info(f"[Nuclei] Emitted misconfiguration: {misconfig.get('name', '')[:60]}")

            # Emit JS vulnerabilities as findings
            js_vulns = tech_profile.get("js_vulnerabilities", [])
            if js_vulns:
                logger.warning(f"Vulnerable JS: {len(js_vulns)} libraries detected")
                for vuln in js_vulns:
                    # Build fix version string from 'below' threshold
                    below = vuln.get("below", [0, 0, 0])
                    fix_version = f"{below[0]}.{below[1]}.{below[2]}" if isinstance(below, (list, tuple)) and len(below) >= 3 else "latest"

                    cves = vuln.get("cves", [])
                    finding_data = {
                        "type": "VULNERABLE_DEPENDENCY",
                        "category": "JS_LIBRARY",
                        "severity": vuln.get("severity", "low").upper(),
                        "url": self.target,
                        "library": vuln.get("name", "unknown"),
                        "version": vuln.get("version", "unknown"),
                        "cves": cves,
                        "description": (
                            f"{vuln.get('name', 'unknown')} {vuln.get('version', '')} has known vulnerabilities. "
                            f"Affected by: {', '.join(cves) if cves else 'Unknown CVE'}. "
                            f"{'This library is End-of-Life. ' if vuln.get('eol') else ''}"
                        ),
                        "remediation": (
                            f"Update {vuln.get('name', 'unknown')} to version {fix_version} or later. "
                            f"{'Consider migrating to a supported framework.' if vuln.get('eol') else ''}"
                        ),
                        "cwe_id": "CWE-1035",
                        "validated": True,
                        "status": "VALIDATED_CONFIRMED",
                        "scan_context": self.scan_context,
                        "evidence": {
                            "script_src": vuln.get("script_src", ""),
                            "version": vuln.get("version", ""),
                            "detection_method": "version_fingerprint",
                            "below_version": fix_version
                        }
                    }
                    await self.event_bus.emit(
                        EventType.VULNERABILITY_DETECTED,
                        finding_data
                    )
                    logger.info(f"[Nuclei] Emitted JS vulnerability: {vuln.get('name')} {vuln.get('version')}")

            return tech_profile

        async def run_auth_discovery_parallel():
            logger.info("🔑 Running authentication discovery...")
            auth_results = await self._run_auth_discovery(recon_dir, self.urls_to_scan)
            logger.info(f"✓ AuthDiscovery: {len(auth_results['jwts'])} JWTs, {len(auth_results['cookies'])} cookies")
            return auth_results

        async def run_asset_discovery_parallel():
            if getattr(settings, 'ENABLE_ASSET_DISCOVERY', False):
                logger.info("🌐 Running asset discovery...")
                return await self._run_asset_discovery(recon_dir)
            return {"subdomains": [], "endpoints": []}

        # ========== VERIFY HTTP SESSIONS BEFORE PARALLEL EXECUTION ==========
        try:
            from bugtrace.core.http_orchestrator import orchestrator, DestinationType
            await orchestrator.get_client(DestinationType.TARGET)._ensure_session()
            await orchestrator.get_client(DestinationType.LLM)._ensure_session()
            logger.debug("[Phase 2] HTTP sessions verified for current event loop")
        except Exception as e:
            logger.warning(f"[Phase 2] HTTP session verification failed: {e}")

        # ========== INITIAL RUN: ALL DAST + RECON IN PARALLEL ==========
        initial_concurrency = settings.MAX_CONCURRENT_ANALYSIS
        all_indices = sorted(url_index_map.keys())
        dast_batch_task = _run_dast_batch(all_indices, initial_concurrency)

        if recon_dir:
            logger.info("[Phase 2] Starting parallel execution: DAST + Nuclei + AuthDiscovery")
            parallel_results = await asyncio.gather(
                dast_batch_task,
                run_nuclei_parallel(),
                run_auth_discovery_parallel(),
                run_asset_discovery_parallel(),
                return_exceptions=True
            )

            dast_results = parallel_results[0] if not isinstance(parallel_results[0], Exception) else []
            nuclei_result = parallel_results[1]
            auth_result = parallel_results[2]

            if isinstance(parallel_results[0], Exception):
                logger.error(f"DAST batch task failed: {parallel_results[0]}")
                dast_results = []

            # Handle reconnaissance errors
            if isinstance(nuclei_result, Exception):
                logger.error(f"Nuclei failed in Phase 2: {nuclei_result}")
                self.tech_profile = {"frameworks": [], "infrastructure": []}

            if isinstance(auth_result, Exception):
                logger.error(f"AuthDiscovery failed in Phase 2: {auth_result}")
        else:
            # Deprecated path: no recon_dir, DAST only
            logger.info("[Phase 2] Starting DAST-only execution (deprecated path)")
            dast_results = await dast_batch_task
            if isinstance(dast_results, Exception):
                logger.error(f"DAST batch task failed: {dast_results}")
                dast_results = []

        # Aggregate initial DAST results
        vulnerabilities_by_url = {}
        for result in (dast_results if isinstance(dast_results, list) else []):
            if isinstance(result, Exception):
                logger.error(f"DAST batch error: {result}")
                continue
            url, vulns = result
            vulnerabilities_by_url[url] = vulns
            self.processed_urls.add(url)

        # ========== CIRCUIT BREAKER: Auto-pause if too many timeouts ==========
        scan_stopped = False
        if timeout_tracker["auto_paused"]:
            scan_stopped = await self._auto_pause_and_wait(
                timeout_tracker["pause_reason"], dashboard
            )

        # ========== RETRY LOOP: Missing URLs with Adaptive Concurrency ==========
        missing_indices = _get_missing_indices() if not scan_stopped else []

        if missing_indices:
            logger.warning(
                f"[DAST Retry] {len(missing_indices)}/{total_urls} URLs missing JSON files after initial run. "
                f"Will retry up to {max_retries} rounds."
            )
            dashboard.log(
                f"⚠ {len(missing_indices)} URLs timed out - retrying with reduced concurrency",
                "WARNING"
            )

        for retry_round in range(1, max_retries + 1):
            if scan_stopped:
                break

            # Reset circuit breaker for this retry round
            timeout_tracker["auto_paused"] = False
            timeout_tracker["consecutive"] = 0

            missing_indices = _get_missing_indices()
            if not missing_indices:
                break

            # Adaptive concurrency: reduce each round
            # Round 1: initial/2, Round 2: initial/3, Round 3+: 1
            if retry_round <= 2:
                retry_concurrency = max(1, initial_concurrency // (retry_round + 1))
            else:
                retry_concurrency = 1

            logger.info(
                f"[DAST Retry] Round {retry_round}/{max_retries}: "
                f"{len(missing_indices)} missing URLs, concurrency={retry_concurrency}"
            )
            dashboard.log(
                f"🔄 Retry {retry_round}/{max_retries}: {len(missing_indices)} URLs (concurrency={retry_concurrency})",
                "WARNING"
            )
            conductor.notify_log(
                "WARNING",
                f"[DAST] Retry round {retry_round}: {len(missing_indices)} URLs, concurrency={retry_concurrency}"
            )

            # Reset completed_count for progress tracking in retry
            completed_count["value"] = total_urls - len(missing_indices)

            retry_results = await _run_dast_batch(missing_indices, retry_concurrency)

            for result in retry_results:
                if isinstance(result, Exception):
                    logger.error(f"DAST retry error: {result}")
                    continue
                url, vulns = result
                vulnerabilities_by_url[url] = vulns
                self.processed_urls.add(url)

            # Circuit breaker triggered during retry — pause and wait for resume
            if timeout_tracker["auto_paused"]:
                scan_stopped = await self._auto_pause_and_wait(
                    timeout_tracker["pause_reason"], dashboard
                )
                if scan_stopped:
                    break  # User stopped the scan instead of resuming

        # ========== FINAL CHECK: Pipeline gate ==========
        final_missing = _get_missing_indices()
        if final_missing:
            missing_urls = [url_index_map[idx] for idx in final_missing]
            logger.error(
                f"[DAST] FATAL: {len(final_missing)}/{total_urls} URLs still missing after "
                f"{max_retries} retry rounds. Missing indices: {final_missing}"
            )
            for idx in final_missing:
                logger.error(f"[DAST] Missing index {idx}: {url_index_map[idx][:80]}")
            dashboard.log(
                f"❌ FATAL: {len(final_missing)} URLs failed after {max_retries} retries - pipeline will stop",
                "CRITICAL"
            )
            conductor.notify_log(
                "CRITICAL",
                f"[DAST] {len(final_missing)} URLs permanently failed. Pipeline stopping before STRATEGY."
            )

        total_vulns = sum(len(v) for v in vulnerabilities_by_url.values())
        reports_generated = len(list(dastysast_dir.glob("*.json")))
        dashboard.log(
            f"Phase 2 complete: {total_vulns} findings from {reports_generated}/{total_urls} URLs",
            "INFO"
        )

        batch_metrics.end_dast(urls_analyzed=reports_generated, findings_count=total_vulns)

        return vulnerabilities_by_url

    async def _phase_2_analysis(self, dashboard, analysis_dir):
        """Execute Phase 2: Batch DAST Analysis + Queue-based Specialist Execution.

        DEPRECATED: This method is no longer called from _run_sequential_pipeline.
        The logic is now inlined for proper phase signal timing.
        Kept for backward compatibility with non-batch pipelines.
        """
        dashboard.set_phase("🔬 HUNTING VULNS")

        # Phase 2A: Batch DAST Discovery (runs in parallel)
        self.vulnerabilities_by_url = await self._phase_2_batch_dast(dashboard, analysis_dir)

        # Phase 2B: Collect final queue stats (specialists already awaited via asyncio.gather)
        batch_metrics.start_queue_drain()
        queue_results = await self._wait_for_specialist_queues(dashboard, timeout=5.0)
        batch_metrics.end_queue_drain(
            findings_distributed=queue_results.get('items_distributed', 0),
            by_specialist=queue_results.get('by_specialist', {})
        )

        dashboard.log(
            f"Specialist execution complete: {queue_results.get('items_distributed', 0)} items processed",
            "INFO"
        )

        # Log batch summary from ThinkingAgent
        if self.thinking_agent and hasattr(self.thinking_agent, 'log_batch_summary'):
            self.thinking_agent.log_batch_summary()

        await self._checkpoint("Batch Analysis & Queue-based Exploitation")

