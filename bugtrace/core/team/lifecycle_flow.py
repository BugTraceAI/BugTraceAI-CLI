"""Workers, database, start/init shell (except __init__).

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

from bugtrace.agents.jwt_agent import JWTAgent
from bugtrace.agents.asset_discovery_agent import AssetDiscoveryAgent
from bugtrace.agents.api_security_agent import APISecurityAgent
from bugtrace.agents.fileupload_agent import FileUploadAgent
from bugtrace.agents.nuclei_agent import NucleiAgent
from bugtrace.agents.gospider_agent import GoSpiderAgent
from bugtrace.agents.analysis_agent import DASTySASTAgent
from bugtrace.agents.xss import XSSAgent
from bugtrace.agents.csti_agent import CSTIAgent
from bugtrace.agents.sqlmap_agent import SQLMapAgent
from bugtrace.agents.openredirect_agent import OpenRedirectAgent
from bugtrace.agents.prototype_pollution_agent import PrototypePollutionAgent
from bugtrace.agents.reattack import ReAttackAgent
from bugtrace.core.conductor import conductor
from bugtrace.core.verbose_events import create_emitter, install_ui_bridge
from bugtrace.core.surface import (
    ControlModel, ProbeObservation, build_control_model, differs_from_control,
    drop_insecure_duplicate_origins, names_a_resource,
)


class TeamLifecycleMixin:
    def _init_specialist_agents(self):
        """Initialize specialist agent instances."""
        self.jwt_agent = JWTAgent(event_bus=event_bus)
        self.asset_discovery_agent = AssetDiscoveryAgent(event_bus=event_bus)
        self.api_security_agent = APISecurityAgent(event_bus=event_bus)
        self.event_bus = event_bus
        logger.info("Event Bus integrated into TeamOrchestrator")
        logger.info("Phase 1 Agents loaded: AssetDiscovery, APISecurity")

        # Subscribe to findings for TUI updates
        from bugtrace.core.event_bus import EventType
        self.event_bus.subscribe(EventType.VULNERABILITY_DETECTED.value, self._on_vulnerability_detected)
        logger.info("EventBus -> TUI bridge registered for VULNERABILITY_DETECTED")

        # Initialize ThinkingConsolidationAgent for V3 pipeline
        from bugtrace.agents.thinking_consolidation_agent import ThinkingConsolidationAgent
        self.thinking_agent = ThinkingConsolidationAgent(scan_context=self.scan_context)
        
        # Initialize ReAttackAgent for auth chaining (Task 4) - MOVED TO _init_state

        
        self.captured_session = {"cookies": [], "headers": {}}

        logger.info("ThinkingConsolidationAgent initialized - V3 event-driven pipeline active")

        # Specialist worker pools will be initialized async in _run_hunter_core
        self._specialist_workers_started = False

        # Pipeline orchestration (v2.3, simplified in Sprint 5)
        # PipelineState directly managed by TeamOrchestrator (no more PipelineOrchestrator wrapper)
        self._pipeline_state: Optional[PipelineState] = None
        self._lifecycle: Optional[PipelineLifecycle] = None
        logger.info("Pipeline orchestration infrastructure initialized")

    async def _init_specialist_workers(self):
        """Initialize specialist worker pools for V3 pipeline."""
        from bugtrace.agents.sqli_agent import SQLiAgent
        from bugtrace.agents.xss import XSSAgent  # Use package, not monolith
        from bugtrace.agents.csti_agent import CSTIAgent
        from bugtrace.agents.lfi_agent import LFIAgent
        from bugtrace.agents.idor_agent import IDORAgent
        from bugtrace.agents.rce_agent import RCEAgent
        from bugtrace.agents.ssrf_agent import SSRFAgent
        from bugtrace.agents.xxe_agent import XXEAgent
        from bugtrace.agents.openredirect_agent import OpenRedirectAgent
        from bugtrace.agents.prototype_pollution_agent import PrototypePollutionAgent
        from bugtrace.agents.header_injection_agent import HeaderInjectionAgent
        from bugtrace.agents.mass_assignment_agent import MassAssignmentAgent
        from bugtrace.agents.fileupload import FileUploadAgent

        # Initialize specialist agents with minimal parameters
        # url parameter required but will be overridden by queue work items
        # report_dir is set post-init for unified output (v3.1)
        self.sqli_worker_agent = SQLiAgent(url="", event_bus=self.event_bus)
        self.xss_worker_agent = XSSAgent(url="", event_bus=self.event_bus)
        self.csti_worker_agent = CSTIAgent(url="", event_bus=self.event_bus)
        self.lfi_worker_agent = LFIAgent(url="", event_bus=self.event_bus)
        self.idor_worker_agent = IDORAgent(url="", event_bus=self.event_bus)
        self.rce_worker_agent = RCEAgent(url="", event_bus=self.event_bus)
        self.ssrf_worker_agent = SSRFAgent(url="", event_bus=self.event_bus)
        self.xxe_worker_agent = XXEAgent(url="", event_bus=self.event_bus)
        self.open_redirect_worker_agent = OpenRedirectAgent(url="", event_bus=self.event_bus)
        self.prototype_pollution_worker_agent = PrototypePollutionAgent(url="", event_bus=self.event_bus)
        self.header_injection_worker_agent = HeaderInjectionAgent(url="", event_bus=self.event_bus)
        self.api_security_worker_agent = APISecurityAgent(url="", event_bus=self.event_bus)
        self.mass_assignment_worker_agent = MassAssignmentAgent(url="", event_bus=self.event_bus)
        self.fileupload_worker_agent = FileUploadAgent(url="")
        self.fileupload_worker_agent.event_bus = self.event_bus

        # Inject unified report_dir into all specialists (v3.1 - fixes data fragmentation)
        for agent in [
            self.sqli_worker_agent, self.xss_worker_agent, self.csti_worker_agent,
            self.lfi_worker_agent, self.idor_worker_agent, self.rce_worker_agent,
            self.ssrf_worker_agent, self.xxe_worker_agent, self.open_redirect_worker_agent,
            self.prototype_pollution_worker_agent, self.header_injection_worker_agent,
            self.api_security_worker_agent, self.mass_assignment_worker_agent,
            self.fileupload_worker_agent,
            self.jwt_agent  # Also inject into JWT agent
        ]:
            agent.report_dir = self.report_dir
            # Inject captured session (cookies/headers) into specialists
            if self.captured_session and (
                self.captured_session.get("cookies")
                or self.captured_session.get("headers")
            ):
                agent.cookies = self.captured_session.get("cookies", [])
                if hasattr(agent, "headers"):
                    agent.headers.update(self.captured_session.get("headers", {}))
                logger.debug(f"Injected auth session into {agent.name}")

        logger.info(f"Injected unified report_dir and session into 15 specialist agents")

        # Use specialist dispatcher to check queues and start necessary specialists
        from bugtrace.core.specialist_dispatcher import dispatch_specialists

        scan_ctx = self.scan_context or "scan_global"

        # Map queue names to specialist agents
        specialist_map = {
            "sqli": self.sqli_worker_agent,
            "xss": self.xss_worker_agent,
            "csti": self.csti_worker_agent,
            "lfi": self.lfi_worker_agent,
            "idor": self.idor_worker_agent,
            "rce": self.rce_worker_agent,
            "ssrf": self.ssrf_worker_agent,
            "xxe": self.xxe_worker_agent,
            "jwt": self.jwt_agent,
            "openredirect": self.open_redirect_worker_agent,
            "prototype_pollution": self.prototype_pollution_worker_agent,
            "header_injection": self.header_injection_worker_agent,
            "api_security": self.api_security_worker_agent,
            "mass_assignment": self.mass_assignment_worker_agent,
            "file_upload": self.fileupload_worker_agent,
        }

        # Set scan depth on exploitation agents before dispatch
        self.sqli_worker_agent._scan_depth = self._scan_depth
        self.xss_worker_agent._scan_depth = self._scan_depth

        # JWT head start (stable 891f012): crack/forge admin token BEFORE other
        # specialists so store_auth_token() is available to auth-dependent agents.
        # If JWT exceeds JWT_HEAD_START_TIMEOUT, remaining specialists start anyway.
        import asyncio

        max_concurrent = settings.MAX_CONCURRENT_SPECIALISTS  # From bugtraceaicli.conf [PARALLELIZATION]
        jwt_agent = specialist_map.pop("jwt", None)
        jwt_task = None
        if jwt_agent is not None:
            jwt_map = {"jwt": jwt_agent}
            jwt_task = asyncio.create_task(
                dispatch_specialists(jwt_map, scan_ctx, max_concurrent=1)
            )
            done, _ = await asyncio.wait(
                {jwt_task}, timeout=float(getattr(settings, "JWT_HEAD_START_TIMEOUT", 300))
            )
            if jwt_task in done:
                logger.info("[PHASE 4] JWT head start finished within window")
            else:
                logger.info(
                    f"[PHASE 4] JWT head start still running after "
                    f"{getattr(settings, 'JWT_HEAD_START_TIMEOUT', 300)}s, "
                    "starting remaining specialists without waiting further"
                )

        dispatch_result = await dispatch_specialists(
            specialist_map, scan_ctx, max_concurrent=max_concurrent
        )

        jwt_result = {"activated": [], "specialists_dispatched": 0}
        if jwt_task is not None:
            jwt_result = await jwt_task

        activated = list(dispatch_result.get("activated") or []) + list(
            jwt_result.get("activated") or []
        )
        specialists_dispatched = int(dispatch_result.get("specialists_dispatched") or 0) + int(
            jwt_result.get("specialists_dispatched") or 0
        )

        if specialists_dispatched > 0:
            for spec_name in activated:
                self._v.emit("exploit.specialist.activated", {"specialist": spec_name})
            logger.info(f"[PHASE 4] Specialists completed: {', '.join(activated)}")
        else:
            logger.warning("[PHASE 4] No specialists were dispatched (no work in queues)")

    async def _shutdown_specialist_workers(self):
        """Shutdown specialist worker pools gracefully."""
        logger.info("Shutting down specialist worker pools...")

        # Stop ThinkingConsolidationAgent first
        if hasattr(self.thinking_agent, 'stop'):
            try:
                await self.thinking_agent.stop()
                logger.info("ThinkingConsolidationAgent stopped")
            except Exception as e:
                logger.error(f"Failed to stop ThinkingAgent: {e}")

        # Stop auxiliary agents (v2.6 fix: these were missing from shutdown)
        auxiliary_agents = [
            # ('chain_discovery_agent', 'ChainDiscoveryAgent'),  # disabled: no-op agent
            ('api_security_agent', 'APISecurityAgent'),
            ('agentic_validator', 'AgenticValidator'),
            ('reattack_agent', 'ReAttackAgent'),
        ]

        for attr_name, display_name in auxiliary_agents:
            if hasattr(self, attr_name):
                agent = getattr(self, attr_name)
                if hasattr(agent, 'stop'):
                    try:
                        await agent.stop()
                        logger.info(f"{display_name} stopped")
                    except Exception as e:
                        logger.error(f"Failed to stop {display_name}: {e}")

        # Stop specialist workers
        shutdown_tasks = [
            self.sqli_worker_agent.stop_queue_consumer(),
            self.xss_worker_agent.stop_queue_consumer(),
            self.csti_worker_agent.stop_queue_consumer(),
            self.lfi_worker_agent.stop_queue_consumer(),
            self.idor_worker_agent.stop_queue_consumer(),
            self.rce_worker_agent.stop_queue_consumer(),
            self.ssrf_worker_agent.stop_queue_consumer(),
            self.xxe_worker_agent.stop_queue_consumer(),
            self.jwt_agent.stop_queue_consumer(),
            self.open_redirect_worker_agent.stop_queue_consumer(),
            self.prototype_pollution_worker_agent.stop_queue_consumer(),
        ]
        await asyncio.gather(*shutdown_tasks, return_exceptions=True)
        self._v.emit("exploit.specialist.deactivated", {"specialists": "all"})
        logger.info("All specialist worker pools shutdown complete")

        # Shutdown HTTP client manager (v2.4)
        await http_manager.shutdown()

    def _init_vertical_mode(self, use_vertical_agents: bool):
        """Initialize vertical agent architecture settings."""
        self.use_vertical_agents = use_vertical_agents

        # Initialize phase-specific semaphores (v2.4)
        phase_semaphores.initialize()

        # Keep url_semaphore for backward compatibility (maps to EXPLOITATION phase)
        self.url_semaphore = get_exploitation_semaphore()

        if use_vertical_agents:
            logger.info(
                f"Sequential Pipeline (V2) ENABLED "
                f"(Analysis={settings.MAX_CONCURRENT_ANALYSIS}, "
                f"Specialists={settings.MAX_CONCURRENT_SPECIALISTS}, "
                f"Validation=1 (CDP hardcoded))"
            )

    def _init_database(self, resume: bool, existing_scan_id: Optional[int] = None):
        """Initialize database and resumption logic.

        Args:
            resume: Whether to resume an existing scan
            existing_scan_id: Pre-created scan ID from ScanService (avoids duplicate creation)
        """
        from bugtrace.core.database import get_db_manager
        self.db = get_db_manager()

        # If scan_id provided by ScanService, use it directly (avoids duplicate scan creation)
        if existing_scan_id is not None:
            self.scan_id = existing_scan_id
            logger.info(f"Using existing scan ID: {self.scan_id} (from ScanService)")
        else:
            # Always create new scan (DB = write-only, no reads)
            # Resume state comes from files, not DB
            self.scan_id = self.db.create_new_scan(
                self.target,
                origin="cli",
                max_depth=self.max_depth,
                max_urls=self.max_urls,
            )

        # Register report_dir in DB early so that even crashed/failed scans
        # have a trackable output directory for partial artifact recovery.
        self.db.update_scan_report_dir(self.scan_id, str(self.report_dir))

        self._set_scan_context_from_scan_id()
        logger.info(f"TeamOrchestrator initialized for Scan ID: {self.scan_id}")

        # State Manager (Database backed)
        self.state_manager = get_state_manager(self.target)
        self.state_manager.set_scan_id(self.scan_id)

        # Initialize state
        self.processed_urls = set()

        # Initialize scan state (url_queue, etc.)
        self._init_state()

    def _init_state(self):
        """Initialize scan state attributes."""
        # Inject scan_id into ThinkingConsolidationAgent for DB persistence
        if hasattr(self, 'thinking_agent'):
            self.thinking_agent.scan_id = self.scan_id
            self.thinking_agent.scan_context = self.scan_context
            logger.info(f"Injected Scan ID {self.scan_id} into ThinkingConsolidationAgent")

        # Initialize ReAttackAgent for auth chaining (Task 4)
        # We do it here because scan_id is now available
        self.reattack_agent = ReAttackAgent(event_bus=self.event_bus, scan_context=str(self.scan_id))
        logger.info(f"ReAttackAgent initialized with scan_id: {self.scan_id}")

        self.url_queue = []
        self.vulnerabilities_by_url: Dict[str, list] = {}

        # Reset class-level dedup sets for per-scan state
        from bugtrace.agents.analysis_agent import DASTySASTAgent
        DASTySASTAgent._emitted_cookie_configs = set()
        DASTySASTAgent._emitted_cookie_sqli = set()

        # Load active state if resuming
        if self.resume:
            state = self.state_manager.load_state()
            if state:
                self.processed_urls = set(state.get("processed_urls", []))
                self.url_queue = state.get("url_queue", [])
                logger.info(f"Resumed scan: {len(self.processed_urls)} URLs already processed, {len(self.url_queue)} pending.")

    def _init_pipeline(self):
        """Initialize 6-phase pipeline state machine (Sprint 5 simplified)."""
        # Create PipelineState directly (no wrapper needed)
        self._pipeline_state = PipelineState(scan_id=str(self.scan_id))
        self._lifecycle = PipelineLifecycle(
            state=self._pipeline_state,
            event_bus=self.event_bus
        )
        logger.info(f"[TeamOrchestrator] Pipeline state initialized for scan {self.scan_id}")

    async def start(self):
        """Starts the Multi-Agent Team."""
        # Setup dashboard sink
        self._setup_dashboard_sink()

        # Setup signal handlers
        self._setup_signal_handlers()

        # Configure logging
        self._configure_logging()

        # Register scan context early for WebSocket event routing (auth events need this)
        conductor.begin_scan(self.scan_id)
        dashboard.reset_controls()

        try:
            # Execute authentication if config provided
            if self.auth_config:
                logger.info(f"[TeamOrchestrator] Auth config detected, starting authentication...")
                await self._perform_authentication()
                logger.info(f"[TeamOrchestrator] Authentication phase completed")
            else:
                logger.info(f"[TeamOrchestrator] No auth config provided, skipping authentication")

            # Run main logic
            if not dashboard.active:
                import sys
                is_tty = sys.stdout.isatty()

                if is_tty:
                    # Interactive mode: use full Rich dashboard with alternate screen
                    # Reduced from 4 to 2 FPS to prevent freeze with high log volume
                    with Live(dashboard, refresh_per_second=2, screen=True) as live:
                        dashboard.active = True
                        await self._run_hunter_core()
                        dashboard.active = False
                else:
                    # Non-interactive mode (piped/redirected): log-only mode
                    logger.info("Running in non-interactive mode (output redirected)")
                    dashboard.active = False  # Disable dashboard updates
                    await self._run_hunter_core()
            else:
                await self._run_hunter_core()
        finally:
            # Detach this orchestrator's handler from the global EventBus singleton.
            # Subscriptions are made in __init__ and were never removed, so on a
            # long-lived API/MCP server a later scan's VULNERABILITY_DETECTED event
            # would also fire THIS finished scan's handler and persist the finding
            # under the wrong scan_id/target (plus an unbounded subscriber leak).
            self._unsubscribe_events()
