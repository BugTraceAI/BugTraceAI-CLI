"""Recon/hunter ops and remaining medium helpers.

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

from bugtrace.core.team.recon_ops_html import TeamReconHtmlMixin
from bugtrace.core.team.recon_ops_hitl import TeamReconHitlMixin
from bugtrace.core.team.recon_ops_dispatch import TeamReconDispatchMixin

class TeamReconOpsMixin(TeamReconHtmlMixin, TeamReconHitlMixin, TeamReconDispatchMixin):
    def _set_scan_context_from_scan_id(self):
        """Keep scan_context parseable by service event routing."""
        self.scan_context = str(self.scan_id) if self.scan_id is not None else ""
        if hasattr(self, "thinking_agent"):
            self.thinking_agent.scan_context = self.scan_context
    def _record_phase_complete(self, phase_name: str) -> None:
        """
        Record that a phase has completed for scan resumption tracking.
        
        Args:
            phase_name: Name of the phase that completed (e.g., "reconnaissance", "discovery")
        """
        self._last_phase = phase_name
        
        # Update DB with last completed phase
        try:
            from bugtrace.schemas.db_models import ScanTable
            from bugtrace.core.database import get_db_manager
            from sqlmodel import select
            
            db = get_db_manager()
            with db.get_session() as session:
                scan = session.exec(
                    select(ScanTable).where(ScanTable.id == self.scan_id)
                ).first()
                if scan:
                    scan.last_phase_completed = phase_name
                    session.add(scan)
                    session.commit()
                    logger.debug(f"Recorded phase complete: {phase_name}")
        except Exception as e:
            logger.warning(f"Failed to record phase complete: {e}")
    def _sync_scan_context(self, phase: str, agent: str = "System",
                          findings_count: Optional[int] = None,
                          progress: Optional[int] = None) -> None:
        """Update ScanContext so the Status API reflects real-time state."""
        ctx = getattr(self, '_scan_context', None)
        if ctx is None:
            return
        ctx.phase = phase
        ctx.active_agent = agent
        if findings_count is not None:
            ctx.findings_count = findings_count
        if progress is not None:
            ctx.progress = progress
    async def _start_pipeline(self) -> None:
        """Start the pipeline (transition to RECONNAISSANCE and emit event)."""
        from bugtrace.core.event_bus import EventType

        if not self._pipeline_state:
            logger.warning("[TeamOrchestrator] Pipeline not initialized")
            return

        # Transition to RECONNAISSANCE
        self._pipeline_state.transition(PipelinePhase.RECONNAISSANCE, "Pipeline started")

        # Emit pipeline started event
        await self.event_bus.emit(EventType.PIPELINE_STARTED, {
            "scan_context": self.scan_context,
            "scan_id": str(self.scan_id),
            "phase": PipelinePhase.RECONNAISSANCE.value
        })

        logger.info(f"[TeamOrchestrator] Pipeline started for scan {self.scan_id}")
    async def _stop_pipeline(self) -> None:
        """Stop the pipeline (transition to COMPLETE and emit event)."""
        from bugtrace.core.event_bus import EventType

        if not self._pipeline_state:
            logger.warning("[TeamOrchestrator] Pipeline not initialized")
            return

        # Transition to COMPLETE if not already terminal
        current = self._pipeline_state.current_phase
        if current not in (PipelinePhase.COMPLETE, PipelinePhase.ERROR):
            try:
                if self._pipeline_state.can_transition(PipelinePhase.COMPLETE):
                    self._pipeline_state.transition(PipelinePhase.COMPLETE, "Pipeline stopped")
            except ValueError:
                logger.warning(f"[TeamOrchestrator] Could not transition to COMPLETE from {current}")

        # Emit pipeline complete event
        await self.event_bus.emit(EventType.PIPELINE_COMPLETE, {
            "scan_context": self.scan_context,
            "scan_id": str(self.scan_id),
            "final_phase": self._pipeline_state.current_phase.value,
            "total_duration": self._pipeline_state.get_total_duration(),
            "transitions": len(self._pipeline_state.transitions)
        })

        logger.info(f"[TeamOrchestrator] Pipeline stopped for scan {self.scan_id}")
    def _unsubscribe_events(self):
        """Remove this orchestrator's EventBus subscriptions (idempotent, pure of
        external effects beyond detaching the handler)."""
        try:
            from bugtrace.core.event_bus import EventType
            self.event_bus.unsubscribe(
                EventType.VULNERABILITY_DETECTED.value, self._on_vulnerability_detected
            )
            logger.debug("EventBus VULNERABILITY_DETECTED handler unsubscribed for this scan")
        except Exception as e:
            logger.debug(f"Event unsubscribe warning: {e}")
    def _setup_dashboard_sink(self):
        """Setup dashboard log sink."""
        def dashboard_sink(message):
            try:
                record = message.record
                level = record["level"].name
                text = record["message"]
                if level in ["INFO", "SUCCESS", "WARNING", "ERROR", "CRITICAL"]:
                    dashboard.log(text, level)
            except Exception as e:
                logger.debug(f"Dashboard sink error: {e}")

        self._dashboard_sink = dashboard_sink
    def _setup_signal_handlers(self):
        """Setup signal handlers for HITL mode."""
        loop = asyncio.get_running_loop()
        self.sigint_count = 0
        self.hitl_active = False
        self.current_findings = []

        def handle_sigint():
            self.sigint_count += 1
            if self.sigint_count >= 3:
                dashboard.log("Forced Shutdown initiated by user.", "CRITICAL")
                sys.exit(1)
            elif self.sigint_count == 2:
                logger.warning("Press Ctrl+C again to force quit.")
            else:
                self.hitl_active = True
                asyncio.create_task(self._enter_hitl_mode())

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, handle_sigint)
            except NotImplementedError:
                pass
    def _configure_logging(self):
        """Configure logging for dashboard and file."""
        import sys

        logger.remove()

        is_tty = sys.stdout.isatty()

        if is_tty:
            # Interactive: send to dashboard
            logger.add(self._dashboard_sink, level="INFO")
        else:
            # Non-interactive: send to stdout for redirection
            logger.add(sys.stdout, level="INFO", format="{time:HH:mm:ss} | {level} | {message}")

        # Always log to file
        logger.add("logs/execution.log", rotation="10 MB", level="DEBUG")
    async def _run_hunter_core(self):
        """Core Hunter logic separated from UI lifecycle."""
        # Register scan context with conductor for EventBus routing
        conductor.set_scan_context(self.scan_id)

        # Verbose event emitter for pipeline-level narration
        self._v = create_emitter("pipeline", str(self.scan_id))

        # Bridge verbose events to CLI TUI (conductor → LogPanel)
        install_ui_bridge()

        dashboard.set_target(self.target)
        dashboard.set_status("Running", "Pipeline starting...")

        # Run diagnostics
        if not await self._run_diagnostics():
            return

        dashboard.set_phase("🤖 ASSEMBLING CREW")
        dashboard.set_status("Running", "Assembling team...")

        if not self.resume:
            self.state_manager.clear()

        # Authentication phase
        await self._handle_authentication()

        # Propagate scan-level default headers (CLI/API + .conf + auth discovery)
        # into the shared HTTP orchestrator so every specialist request picks
        # them up without each agent having to know about the merge order.
        # Idempotent and cheap to call again after re-auth.
        try:
            from bugtrace.core.http_orchestrator import orchestrator
            orchestrator.set_default_headers(self.get_effective_headers())
        except Exception as exc:
            # The HTTP orchestrator is best-effort here; specialists that build
            # their own sessions still receive headers directly.
            logger.debug(f"[{self.__class__.__name__}] set_default_headers skipped: {exc}")

        # Same propagation, but for the Playwright-based validator path.
        # The browser manager is shared across XSS / CSTI / SSRF confirmation
        # rounds; set once, valid until re-auth or shutdown.
        try:
            from bugtrace.tools.visual.browser import browser_manager
            browser_manager.set_default_headers(self.get_effective_headers())
        except Exception as exc:
            logger.debug(f"[{self.__class__.__name__}] browser_manager.set_default_headers skipped: {exc}")

        # Sequential pipeline execution
        logger.info("🔒 Enforcing Sequential Hunter Loop for stability")

        if await self._check_stop_requested(dashboard):
            return

        await self._run_sequential_pipeline(dashboard)

        dashboard.set_phase("🏆 MISSION COMPLETE")
        dashboard.set_status("Complete", "Scan finished")
        await asyncio.sleep(2)
    async def _run_diagnostics(self) -> bool:
        """Run system diagnostics."""
        from bugtrace.core.diagnostics import diagnostics
        if not await diagnostics.run_all():
            dashboard.log("❌ CRITICAL SYSTEM FAILURE: Diagnostics failed. Aborting.", "CRITICAL")
            raise RuntimeError("Diagnostics failed (AI connectivity or System checks) — check your .env and Internet access")
        return True
    def _setup_scan_directory(self, start_time: datetime) -> tuple:
        """Setup scan folder with organized structure using unified report_dir."""
        # v3.1: Use unified report_dir created in __init__
        scan_dir = self.report_dir
        self.scan_dir = scan_dir

        recon_dir = scan_dir / "recon"
        analysis_dir = scan_dir / "analysis"
        captures_dir = scan_dir / "captures"
        recon_dir.mkdir(exist_ok=True)
        analysis_dir.mkdir(exist_ok=True)
        captures_dir.mkdir(exist_ok=True)

        return scan_dir, recon_dir, analysis_dir, captures_dir
    async def _check_target_health(self, dashboard) -> bool:
        """Check if target is reachable and stable."""
        async with httpx.AsyncClient() as client:
            try:
                resp = await client.get(self.target, timeout=10.0)
                if resp.status_code >= 500:
                    logger.error(f"Target {self.target} is unstable (HTTP {resp.status_code}). Aborting scan.")
                    return False
                return True
            except Exception as e:
                logger.error(f"Target {self.target} is unreachable. Skipping engagement. Error: {e}")
                return False
    async def _run_reconnaissance(self, dashboard, recon_dir) -> list:
        """Run reconnaissance phase and return discovered URLs."""
        if self.resume and self.url_queue:
            logger.info(f"⏩ Skipping Recon: Resuming with {len(self.url_queue)} URLs found in DB.")
            loaded_state = self.state_manager.load_state()
            self.tech_profile = loaded_state.get("tech_profile", self.tech_profile)
            return self.url_queue

        # ========== URL List Mode (NEW) ==========
        if self.url_list_provided:
            logger.info(f"[RECON] URL List Mode: Using {len(self.url_list_provided)} provided URLs")
            logger.info(f"📋 URL List Mode: Using {len(self.url_list_provided)} provided URLs")
            logger.info("⏩ Bypassing GoSpider (list provided)")

            # NOTE: Nuclei and AuthDiscovery moved to Phase 2

            # Use provided URLs directly
            urls_to_scan = self.url_list_provided
            await self._scan_for_tokens(urls_to_scan)

            return self._normalize_urls(urls_to_scan)

        # ========== Normal Mode (GoSpider) ==========
        logger.info("Starting Phase 1: URL Discovery (GoSpider only)")

        try:
            # Run GoSpider ONLY
            urls_to_scan = await self._run_gospider(recon_dir)

            # NOTE: Nuclei and AuthDiscovery moved to Phase 2

            # Legacy token scanning (kept for backward compatibility)
            await self._scan_for_tokens(urls_to_scan)
        except Exception as e:
            logger.error(f"URL discovery failed: {e}", exc_info=True)
            urls_to_scan = [self.target]

        return self._normalize_urls(urls_to_scan)
    async def _run_gospider(self, recon_dir) -> list:
        """Run GoSpider agent for URL discovery."""
        logger.info(f"Triggering GoSpiderAgent for {self.target}")
        self._v.emit("recon.gospider.started", {"target": self.target})

        gospider = GoSpiderAgent(
            self.target,
            recon_dir,
            max_depth=self.max_depth,
            max_urls=self.max_urls,
            cookies=self.captured_session.get("cookies", []),
            headers=self.get_effective_headers(),
        )
        urls_to_scan = await gospider.run()

        # If YAML auth config is present, seed URL list with login_url and its parent paths
        # Example: login_url=/WebPA/UserOverview → add /WebPA/UserOverview AND /WebPA/
        if self.auth_config and isinstance(self.auth_config, dict):
            from urllib.parse import urlparse
            base_url = urlparse(self.target)
            base = f"{base_url.scheme}://{base_url.netloc}"

            login_url = self.auth_config.get("login_url", "")
            if login_url:
                # Normalize login path
                login_path = login_url if login_url.startswith("/") else "/" + login_url

                # Extract path segments and build parent paths
                # /WebPA/UserOverview → ["/WebPA/UserOverview", "/WebPA"]
                segments = [s for s in login_path.split("/") if s]
                paths_to_add = []

                for i in range(len(segments), 0, -1):
                    path = "/" + "/".join(segments[:i])
                    paths_to_add.append(path)

                # Add each path to URL list (most specific first)
                for path in paths_to_add:
                    full_url = base + path
                    if full_url not in urls_to_scan:
                        urls_to_scan.insert(0, full_url)
                        logger.info(f"[Auth] Added auth path to scan list: {full_url}")

        self._v.emit("recon.gospider.completed", {"urls_found": len(urls_to_scan)})
        logger.info(f"GoSpiderAgent finished. Found {len(urls_to_scan)} URLs")
        return urls_to_scan
    async def _run_nuclei_tech_profile(self, recon_dir: Path) -> Dict:
        """Run Nuclei for technology detection.
        Returns tech_profile dict with frameworks, infrastructure, etc."""
        try:
            self._v.emit("recon.nuclei.started", {"target": self.target})
            nuclei_agent = NucleiAgent(
                self.target,
                recon_dir,
                cookies=self.captured_session.get("cookies", []),
                headers=self.get_effective_headers(),
            )
            tech_profile = await nuclei_agent.run()
            self._v.emit("recon.nuclei.completed", {
                "frameworks": tech_profile.get('frameworks', []),
                "infrastructure_count": len(tech_profile.get('infrastructure', [])),
            })
            logger.info(
                f"[Recon] Tech Profile: {len(tech_profile.get('frameworks', []))} frameworks, "
                f"{len(tech_profile.get('infrastructure', []))} infrastructure components"
            )
            return tech_profile
        except Exception as e:
            logger.warning(f"Nuclei detection failed: {e}")
            return {"frameworks": [], "infrastructure": []}
    async def _run_asset_discovery(self, recon_dir: Path) -> Dict:
        """Run AssetDiscoveryAgent (optional).
        Returns dict with discovered assets."""
        logger.info("[AssetDiscovery] Skipped (not yet implemented)")
        return {"subdomains": [], "endpoints": []}
    @staticmethod
    @staticmethod
    def _canonicalize_path(path: str) -> str:
        """Pure owner: surface_url_policy.canonicalize_path."""
        from bugtrace.core.surface_url_policy import canonicalize_path as _canon

        return _canon(path)

    @staticmethod
    def _load_data_lines(filename: str) -> List[str]:
        """Load non-empty, non-comment lines from a data file in bugtrace/data/.

        Returns an empty list if the file doesn't exist (graceful fallback).
        """
        from bugtrace.core.package_paths import bugtrace_data_dir

        filepath = bugtrace_data_dir() / filename
        if not filepath.exists():
            logger.warning(f"[DataLoader] File not found: {filepath}")
            return []
        lines = []
        with open(filepath, "r") as f:
            for line in f:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    lines.append(stripped)
        return lines

    @staticmethod
    def _load_endpoint_names(filename: str) -> List[str]:
        """Load an endpoint wordlist, keeping only entries that NAME A RESOURCE.

        A wordlist may guess *where* something lives; it must never ship the parameters
        or payloads to send there. An entry like `health?cmd=id` is not discovery — it is
        one target's attack surface hardcoded into the scanner, and it gets requested
        verbatim against every unrelated site. Parameters must come from observed forms,
        links, API schemas, JavaScript call sites or live responses. Enforced here rather
        than trusted to a comment in the data file, because that comment already existed
        and the file drifted anyway.
        """
        entries = TeamReconOpsMixin._load_data_lines(filename)
        kept = [entry for entry in entries if names_a_resource(entry)]
        dropped = len(entries) - len(kept)
        if dropped:
            logger.warning(
                f"[DataLoader] {filename}: dropped {dropped} entr{'y' if dropped == 1 else 'ies'} "
                f"carrying a query string — wordlists name resources, not attacks"
            )
        return kept
    async def _phase_1_reconnaissance(self, dashboard, recon_dir):
        """Execute Phase 1: Reconnaissance."""
        dashboard.set_phase("👁️ RECON MODE")
        dashboard.set_status("Running", "Discovery in progress...")

        # Skip health check if URL list provided (user knows what they're doing)
        if not self.url_list_provided and not await self._check_target_health(dashboard):
            return

        self.tech_profile = {"frameworks": [], "server": "unknown"}
        self.urls_to_scan = await self._run_reconnaissance(dashboard, recon_dir)
    async def _spa_shell_signature(self, url: str) -> Optional[str]:
        """Cheap signature of a SPA route's served shell, used to dedup synthetic
        '_auto_discover' CSTI probes across routes that render the same client-side app.

        Client-side (Angular/Vue) CSTI reached via an arbitrary query param is a property
        of the SPA shell + framework bootstrap, which is identical across all routes that
        serve the same shell (typical client-side-routed SPA). So one representative
        browser validation covers them all — no recall loss, big speedup.

        Returns a normalized hash (per-request tokens/digits stripped so the same shell
        hashes equally), or None on any error (caller treats None as 'not deduped' → the
        route is still dispatched, so this can never introduce a false negative).
        """
        try:
            from bugtrace.core.http_manager import ConnectionProfile
            async with http_manager.isolated_session(ConnectionProfile.PROBE) as session:
                async with session.get(url, timeout=8) as resp:
                    status = resp.status
                    body = await resp.text()
            # Strip long hex tokens, digits and whitespace so token/timestamp variance
            # between requests doesn't split an otherwise-identical shell into two signatures.
            norm = re.sub(r"[0-9a-fA-F]{16,}", "", body)
            norm = re.sub(r"\d+", "", norm)
            norm = re.sub(r"\s+", " ", norm)
            return hashlib.sha256(f"{status}:{norm}".encode("utf-8", "ignore")).hexdigest()
        except Exception as e:
            logger.debug(f"[Auto-Dispatch] shell signature failed for {url}: {e}")
            return None
    async def _check_stop_requested(self, dashboard) -> bool:
        """Check if stop was requested and update scan status.
        Also blocks here while scan is paused (resume unblocks)."""
        # Pause checkpoint: blocks if scan is paused, returns immediately if not
        scan_ctx = getattr(self, '_scan_context', None)
        if scan_ctx is not None:
            await scan_ctx.wait_if_paused()

        if dashboard.stop_requested or self._stop_event.is_set():
            logger.warning("🛑 Stop requested. Skipping remaining phases.")
            from bugtrace.schemas.db_models import ScanStatus
            self.db.update_scan_status(self.scan_id, ScanStatus.STOPPED)
            return True
        return False
