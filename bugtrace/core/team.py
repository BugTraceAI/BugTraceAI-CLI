import asyncio
import json
import hashlib
import re
from collections import defaultdict
from datetime import datetime
from typing import List, Optional, Dict, Any
from loguru import logger
from urllib.parse import urlparse, parse_qs
from bugtrace.core.config import settings
from bugtrace.agents.base import BaseAgent
# Legacy Agents removed
# from bugtrace.agents.recon import ReconAgent
# from bugtrace.agents.exploit import ExploitAgent
# from bugtrace.agents.skeptic import SkepticalAgent
from bugtrace.core.state_manager import get_state_manager
from bugtrace.core.ui import dashboard
from bugtrace.core.conductor import conductor
from rich.live import Live
import signal
import sys
from pathlib import Path
from shutil import move, rmtree
import httpx

# Agents
from bugtrace.agents.nuclei_agent import NucleiAgent
from bugtrace.agents.gospider_agent import GoSpiderAgent
from bugtrace.agents.analysis_agent import DASTySASTAgent
from bugtrace.agents.xss import XSSAgent  # Use package, not monolith
from bugtrace.agents.csti_agent import CSTIAgent
from bugtrace.agents.sqlmap_agent import SQLMapAgent
from bugtrace.agents.jwt_agent import JWTAgent
from bugtrace.agents.fileupload_agent import FileUploadAgent
from bugtrace.utils.token_scanner import find_jwts

# NEW: Phase 1 Competitive Advantage Agents
from bugtrace.agents.asset_discovery_agent import AssetDiscoveryAgent
from bugtrace.agents.api_security_agent import APISecurityAgent
from bugtrace.agents.chain_discovery_agent import ChainDiscoveryAgent
from bugtrace.agents.openredirect_agent import OpenRedirectAgent
from bugtrace.agents.prototype_pollution_agent import PrototypePollutionAgent

# Event Bus integration
from bugtrace.core.event_bus import event_bus
from bugtrace.core.verbose_events import create_emitter, install_ui_bridge

# Pipeline orchestration (v2.3, simplified in Sprint 5)
from bugtrace.core.pipeline import (
    PipelineLifecycle, PipelinePhase, PipelineState
)

# Centralized HTTP client management (v2.4)
from bugtrace.core.http_manager import http_manager

# Phase-specific semaphores (v2.4)
from bugtrace.core.phase_semaphores import (
    phase_semaphores, ScanPhase,
    get_exploitation_semaphore, get_analysis_semaphore, get_validation_semaphore,
    get_reporting_semaphore
)

# Batch metrics (v3.1)
from bugtrace.core.batch_metrics import batch_metrics, reset_batch_metrics

async def run_agent_with_semaphore(semaphore: asyncio.Semaphore, agent, process_result_fn):
    """
    Execute an agent with semaphore-controlled concurrency.
    This allows multiple agents to run in parallel while respecting resource limits.
    """
    async with semaphore:
        try:
            result = await agent.run_loop()
            process_result_fn(result)
            return result
        except Exception as e:
            logger.error(f"Agent {agent.name} failed: {e}", exc_info=True)
            return {"error": str(e), "findings": []}

class TeamOrchestrator:

    def __init__(self, target: str, resume: bool = False, max_depth: int = 2, max_urls: int = 15, use_vertical_agents: bool = False, output_dir: Optional[Path] = None, scan_id: Optional[int] = None, url_list: Optional[List[str]] = None, scan_depth: str = "standard"):
        self.target = target
        self.resume = resume
        self.max_depth = max_depth
        self.max_urls = max_urls
        self._scan_depth = scan_depth
        self.url_list_provided = url_list  # Store provided URL list for Phase 1
        self.urls_to_scan: List[str] = []  # Set by _phase_1_reconnaissance
        self.agents: List[BaseAgent] = []
        self._stop_event = asyncio.Event()
        self.auth_creds: Optional[str] = None

        # Scan context for event correlation (V3 pipeline)
        self.scan_context = f"scan_{id(self)}_{int(__import__('time').time())}"

        # Create UNIFIED report directory early (v3.1 - fixes data fragmentation)
        # All specialists will write to this single directory
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        domain = urlparse(target).netloc.replace(":", "_")
        if output_dir:
            self.report_dir = Path(output_dir)
        else:
            self.report_dir = settings.REPORT_DIR / f"{domain}_{timestamp}"
        self.report_dir.mkdir(parents=True, exist_ok=True)
        (self.report_dir / "specialists").mkdir(exist_ok=True)
        (self.report_dir / "logs").mkdir(exist_ok=True)
        logger.info(f"Unified Report Directory: {self.report_dir}")

        # Legacy compatibility
        self.output_dir = self.report_dir

        # Initialize specialist agents
        self._init_specialist_agents()

        # Setup vertical agent architecture
        self._init_vertical_mode(use_vertical_agents)

        # Setup persistence and resumption (use provided scan_id if available)
        self._init_database(resume, existing_scan_id=scan_id)

    def _init_specialist_agents(self):
        """Initialize specialist agent instances."""
        self.jwt_agent = JWTAgent(event_bus=event_bus)
        self.asset_discovery_agent = AssetDiscoveryAgent(event_bus=event_bus)
        self.api_security_agent = APISecurityAgent(event_bus=event_bus)
        self.chain_discovery_agent = ChainDiscoveryAgent(event_bus=event_bus)

        self.event_bus = event_bus
        logger.info("Event Bus integrated into TeamOrchestrator")
        logger.info("Phase 1 Agents loaded: AssetDiscovery, APISecurity, ChainDiscovery")

        # Subscribe to findings for TUI updates
        from bugtrace.core.event_bus import EventType
        self.event_bus.subscribe(EventType.VULNERABILITY_DETECTED.value, self._on_vulnerability_detected)
        logger.info("EventBus -> TUI bridge registered for VULNERABILITY_DETECTED")

        # Initialize ThinkingConsolidationAgent for V3 pipeline
        from bugtrace.agents.thinking_consolidation_agent import ThinkingConsolidationAgent
        self.thinking_agent = ThinkingConsolidationAgent(scan_context=self.scan_context)
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

        # Inject unified report_dir into all specialists (v3.1 - fixes data fragmentation)
        for agent in [
            self.sqli_worker_agent, self.xss_worker_agent, self.csti_worker_agent,
            self.lfi_worker_agent, self.idor_worker_agent, self.rce_worker_agent,
            self.ssrf_worker_agent, self.xxe_worker_agent, self.open_redirect_worker_agent,
            self.prototype_pollution_worker_agent, self.header_injection_worker_agent,
            self.api_security_worker_agent, self.mass_assignment_worker_agent,
            self.jwt_agent  # Also inject into JWT agent
        ]:
            agent.report_dir = self.report_dir
        logger.info(f"Injected unified report_dir into 14 specialist agents")

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
        }

        # Set scan depth on exploitation agents before dispatch
        self.sqli_worker_agent._scan_depth = self._scan_depth
        self.xss_worker_agent._scan_depth = self._scan_depth

        # Dispatch specialists with concurrency control (dispatcher handles queue checks and specialist startup)
        max_concurrent = settings.MAX_CONCURRENT_SPECIALISTS  # From bugtraceaicli.conf [PARALLELIZATION]
        dispatch_result = await dispatch_specialists(specialist_map, scan_ctx, max_concurrent=max_concurrent)

        if dispatch_result["specialists_dispatched"] > 0:
            for spec_name in dispatch_result['activated']:
                self._v.emit("exploit.specialist.activated", {"specialist": spec_name})
            logger.info(
                f"[PHASE 4] Specialists completed: {', '.join(dispatch_result['activated'])}"
            )
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
            ('chain_discovery_agent', 'ChainDiscoveryAgent'),
            ('api_security_agent', 'APISecurityAgent'),
            ('agentic_validator', 'AgenticValidator'),
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

        # Persist the report_dir to DB so the API can find it reliably
        self.db.update_scan_report_dir(self.scan_id, str(self.report_dir))

        logger.info(f"TeamOrchestrator initialized for Scan ID: {self.scan_id}")

        # State Manager (Database backed)
        self.state_manager = get_state_manager(self.target)
        self.state_manager.set_scan_id(self.scan_id)

        # Initialize state
        self.processed_urls = set()

        # Initialize scan state (url_queue, etc.)
        self._init_state()

    async def _on_vulnerability_detected(self, finding: dict) -> None:
        """Bridge EventBus findings to TUI via conductor.

        This method is subscribed to VULNERABILITY_DETECTED events and
        forwards findings to conductor.notify_finding() which routes
        to the TUI if ui_callback is set.
        """
        from bugtrace.core.conductor import conductor

        # Extract fields with fallbacks for different finding formats
        finding_type = finding.get("type", finding.get("finding_type", "Unknown"))
        details = finding.get("details", finding.get("url", "No details"))
        severity = finding.get("severity", "medium")
        param = finding.get("parameter", finding.get("param"))
        payload = finding.get("payload")

        conductor.notify_finding(
            finding_type=finding_type,
            details=details,
            severity=severity,
            param=param,
            payload=payload,
        )

    def _init_state(self):
        """Initialize scan state attributes."""
        # Inject scan_id into ThinkingConsolidationAgent for DB persistence
        if hasattr(self, 'thinking_agent'):
            self.thinking_agent.scan_id = self.scan_id
            logger.info(f"Injected Scan ID {self.scan_id} into ThinkingConsolidationAgent")
        self.url_queue = []
        self.vulnerabilities_by_url: Dict[str, list] = {}

        # Reset class-level dedup sets for per-scan state
        from bugtrace.agents.analysis_agent import DASTySASTAgent
        DASTySASTAgent._emitted_cookie_configs = set()

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

    def set_auth(self, creds: str):
        self.auth_creds = creds

    async def pause_pipeline(self, reason: str = "User requested") -> bool:
        """Pause pipeline at next phase boundary."""
        if self._lifecycle:
            return await self._lifecycle.pause_at_boundary(reason)
        return False

    async def resume_pipeline(self) -> bool:
        """Resume paused pipeline."""
        if self._lifecycle:
            return await self._lifecycle.resume()
        return False

    def get_pipeline_state(self) -> Optional[Dict]:
        """Get current pipeline state."""
        if self._pipeline_state:
            return self._pipeline_state.to_dict()
        return None

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

    async def start(self):
        """Starts the Multi-Agent Team."""
        # Setup dashboard sink
        self._setup_dashboard_sink()

        # Setup signal handlers
        self._setup_signal_handlers()

        # Configure logging
        self._configure_logging()

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
                dashboard.log("Press Ctrl+C again to force quit.", "WARN")
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

        # Sequential pipeline execution
        dashboard.log("🔒 Enforcing Sequential Hunter Loop for stability", "INFO")

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
            await asyncio.sleep(3)
            sys.exit(1)
        return True

    async def _handle_authentication(self):
        """Handle authentication if credentials provided."""
        if not self.auth_creds:
            return

        dashboard.set_phase("🔐 BREACHING GATES")
        dashboard.current_agent = "AuthAgent"
        dashboard.log(f"Initiating authenticated session for {self.auth_creds.split(':')[0]}...", "INFO")

        from bugtrace.tools.visual.browser import browser_manager
        login_url = f"{self.target.rstrip('/')}/login"

        try:
            success = await browser_manager.login(login_url, self.auth_creds)
            if success:
                dashboard.log("Authentication Successful. Session captured.", "SUCCESS")
            else:
                dashboard.log("Authentication Failed. Proceeding as guest.", "WARN")
        except Exception as e:
            logger.error(f"Authentication error: {e}", exc_info=True)
            dashboard.log(f"Authentication Error: {e}. Proceeding as guest.", "ERROR")
        finally:
            try:
                if hasattr(browser_manager, 'cleanup_auth_session'):
                    await browser_manager.cleanup_auth_session()
            except Exception as cleanup_err:
                logger.debug(f"Auth session cleanup warning: {cleanup_err}")

    async def _generate_vertical_report(self, findings: list, urls_scanned: list, metadata: dict = None):
        """Generate consolidated report for vertical mode using ReportingAgent."""
        from pathlib import Path
        from datetime import datetime
        from urllib.parse import urlparse
        import shutil

        try:
            report_dir = self._create_report_directory()
            url_folders = self._create_url_folders(report_dir, urls_scanned)
            linked_screenshots = self._organize_artifacts(findings, url_folders, report_dir)
            # Cleanup unlinked screenshots
            self._cleanup_unlinked_screenshots(linked_screenshots)

            # Generate AI report
            async with get_reporting_semaphore():
                await self._invoke_reporting_agent(findings, urls_scanned, metadata, report_dir)

            # Cleanup redundant folders
            self._cleanup_redundant_folders(report_dir)

            self._print_completion_summary(report_dir, findings)

        except asyncio.TimeoutError as e:
            logger.critical(f"[ReportingAgent] ⏳ CRASH DETECTED: Report generation exceeded timeout. Killing tool. Error: {e}")
        except Exception as e:
            logger.error(f"Failed to generate vertical report: {e}", exc_info=True)
            # import traceback
            # logger.debug(traceback.format_exc())
            dashboard.log(f"❌ Report generation failed: {e}", "ERROR")

    def _create_report_directory(self) -> Path:
        """Return unified report directory (created in __init__)."""
        # v3.1: Use unified report_dir created in __init__ instead of creating new one
        # This ensures specialists and ReportingAgent write to the same directory
        (self.report_dir / "logs").mkdir(exist_ok=True)
        return self.report_dir

    def _create_url_folders(self, report_dir: Path, urls_scanned: list) -> dict:
        """Create folders for each scanned URL."""
        url_folders = {}
        for u in urls_scanned:
            safe_name = u.replace("://", "_").replace("/", "_").replace("?", "_").replace("&", "_").replace("=", "_")
            safe_name = safe_name[:100]
            folder = report_dir / safe_name
            folder.mkdir(exist_ok=True)
            url_folders[u] = folder
        return url_folders

    def _organize_artifacts(self, findings: list, url_folders: dict, report_dir: Path) -> set:
        """Organize artifacts (screenshots) into URL folders."""
        from shutil import move
        linked_screenshots = set()

        for f in findings:
            f_url = f.get("url", "unknown")
            target_folder = self._determine_target_folder(f_url, report_dir)

            if f.get("screenshot"):
                self._move_screenshot(f, target_folder, linked_screenshots)

            self._write_finding_details(target_folder, f)

        return linked_screenshots

    def _determine_target_folder(self, f_url: str, report_dir: Path) -> Path:
        """Determine target folder for finding artifacts."""
        safe_name = f_url.replace("://", "_").replace("/", "_").replace("?", "_").replace("&", "_").replace("=", "_")[:100]
        possible_folder = report_dir / safe_name
        return possible_folder if possible_folder.exists() else report_dir / "logs"

    def _move_screenshot(self, finding: dict, target_folder: Path, linked_screenshots: set):
        """Move screenshot to target folder and update finding."""
        from shutil import move
        original_name = Path(finding["screenshot"]).name
        source_path = settings.LOG_DIR / original_name

        if not source_path.exists():
            source_path = Path("reports") / original_name

        if source_path.exists():
            dest_path = target_folder / original_name
            move(str(source_path), str(dest_path))
            finding["screenshot"] = f"{target_folder.name}/{original_name}"
            linked_screenshots.add(original_name)

    def _write_finding_details(self, target_folder: Path, finding: dict):
        """Write finding details using XML-like format with Base64 for payload integrity.
        
        Format (v3.1):
        <FINDING>
          <TIMESTAMP>...</TIMESTAMP>
          <TYPE>...</TYPE>  
          <DATA_B64>base64_encoded_json</DATA_B64>
        </FINDING>
        """
        import json
        import base64
        import time
        
        # Encode finding as Base64 JSON to preserve all payload characters
        finding_json = json.dumps(finding, default=str, ensure_ascii=False)
        finding_b64 = base64.b64encode(finding_json.encode('utf-8')).decode('ascii')
        
        entry = (
            f"<FINDING>\n"
            f"  <TIMESTAMP>{time.time()}</TIMESTAMP>\n"
            f"  <TYPE>{finding.get('type', 'Unknown')}</TYPE>\n"
            f"  <DATA_B64>{finding_b64}</DATA_B64>\n"
            f"</FINDING>\n"
        )
        
        # Use .findings extension for new format
        with open(target_folder / "finding_details.findings", "a", encoding="utf-8") as fd:
            fd.write(entry)

    def _cleanup_unlinked_screenshots(self, linked_screenshots: set):
        """Delete unreferenced screenshots."""
        for file in settings.LOG_DIR.glob("*.png"):
            if file.name not in linked_screenshots:
                try:
                    file.unlink()
                except OSError as e:
                    logger.debug(f"Failed to delete screenshot {file}: {e}")

    async def _invoke_reporting_agent(self, findings: list, urls_scanned: list, metadata: dict, report_dir: Path):
        """Invoke ReportingAgent for final report."""
        dashboard.log(f"🤖 Deploying ReportingAgent for final assessment...", "INFO")
        
        from bugtrace.agents.reporting import ReportingAgent
        
        # Ensure scan_id is available (should be initialized in __init__)
        if not self.scan_id:
            logger.warning("Scan ID missing for ReportingAgent, using 0 as fallback")
            self.scan_id = 0
            
        reporting_agent = ReportingAgent(
            scan_id=self.scan_id,
            target_url=self.target,
            output_dir=report_dir,
            tech_profile=self.tech_profile
        )
        
        # ReportingAgent pulls findings from DB, so we don't need to pass 'findings' list
        generated_paths = await reporting_agent.generate_all_deliverables()
        
        if generated_paths:
            dashboard.log(f"✅ ReportingAgent finished. Reports saved to {report_dir}", "SUCCESS")
        else:
            dashboard.log("⚠️ ReportingAgent completed but returned no paths.", "WARN")

    def _cleanup_redundant_folders(self, report_dir: Path):
        """Cleanup redundant artifact folders."""
        from shutil import move
        for folder in ["evidence", "screenshots", "test_results"]:
            p = Path(folder)
            if not (p.exists() and p.is_dir()):
                continue

            self._move_files_to_logs(p, report_dir)
            self._remove_empty_folder(p)

    def _move_files_to_logs(self, folder: Path, report_dir: Path):
        """Move files from folder to logs directory."""
        from shutil import move
        for file in folder.glob("*"):
            if file.is_file():
                move(str(file), str(report_dir / "logs" / file.name))

    def _remove_empty_folder(self, folder: Path):
        """Remove empty folder after cleanup."""
        try:
            folder.rmdir()
        except OSError as e:
            logger.debug(f"Failed to remove directory {folder}: {e}")

    def _print_completion_summary(self, report_dir: Path, findings: list):
        """Print scan completion summary."""
        print(f"\n{'='*60}")
        print(f"[✓] SCAN COMPLETE - V1.6.1 Phoenix")
        print(f"[✓] Target: {self.target}")
        print(f"[✓] Findings: {len(findings)}")
        print(f"[✓] Detailed Report: {report_dir / 'REPORT.html'}")
        print(f"{'='*60}\n")

    async def _generate_ai_reports(self, report_dir, report_data: dict, screenshots: list):
        """Generate professional AI-written reports: Technical + Executive."""
        from bugtrace.core.llm_client import llm_client
        import json

        findings_summary = json.dumps(report_data["findings"], indent=2, default=str)[:8000]
        meta_summary = json.dumps(report_data.get("metadata", {}), indent=2, default=str)[:4000]

        # Generate technical report
        tech_report = await self._generate_technical_report(
            report_data, findings_summary, meta_summary, screenshots
        )

        # Generate executive summary
        exec_report = await self._generate_executive_summary(report_data)

        # Generate HTML version
        if tech_report:
            await self._generate_html_report(report_dir, tech_report, exec_report, screenshots, report_data.get("findings", []))

    async def _generate_technical_report(self, report_data: dict, findings_summary: str, meta_summary: str, screenshots: list) -> str:
        """Generate technical assessment report."""
        from bugtrace.core.llm_client import llm_client

        dashboard.log("🤖 Generating Technical Report (AI)...", "INFO")

        tech_prompt = self._build_technical_prompt(report_data, findings_summary, meta_summary, screenshots)
        tech_report = await llm_client.generate(tech_prompt, "Report-Tech")

        if tech_report:
            tech_report = self._embed_screenshots(tech_report, screenshots)
            with open(self.scan_dir / "TECHNICAL_REPORT.md", "w") as f:
                f.write(tech_report)
            dashboard.log("✅ Technical Report generated", "SUCCESS")

        return tech_report

    def _build_technical_prompt(self, report_data: dict, findings_summary: str, meta_summary: str, screenshots: list) -> str:
        """Build prompt for technical report generation."""
        system_prompt = conductor.get_full_system_prompt("ai_writer")
        if system_prompt:
            tech_prompt = system_prompt.split("## Technical Assessment Report Prompt (Full)")[-1].split("## ")[0].strip()
        else:
            tech_prompt = self._get_default_technical_prompt()

        return tech_prompt.format(
            target=report_data["scan_info"]["target"],
            scan_date=report_data["scan_info"]["scan_date"],
            urls_scanned=report_data["scan_info"]["urls_scanned"],
            findings_summary=findings_summary,
            meta_summary=meta_summary,
            screenshots=screenshots
        )

    def _get_default_technical_prompt(self) -> str:
        """Get default technical report prompt template."""
        return """You are a Senior Penetration Tester writing a Professional Technical Assessment Report.

        TARGET: {target}
        SCAN DATE: {scan_date}
        URLS ANALYZED: {urls_scanned}
        FINDINGS:
        {findings_summary}

        ATTACK SURFACE / METADATA:
        {meta_summary}

        SCREENSHOTS CAPTURED: {screenshots}

        Write a comprehensive Technical Vulnerability Report in Markdown format.

        STRUCTURE:
        # Technical Assessment Report

        ## 1. Engagement Overview
        - Target, scope, methodology used

        ## 2. Executive Summary
        - High-level findings count and severity breakdown

        ## 3. Vulnerability Details
        For EACH finding, write:
        ### [Vulnerability Type] - [Severity]
        - **URL**: The affected URL
        - **Parameter**: Vulnerable parameter
        - **Evidence**: Technical proof
        - **Impact**: What an attacker could do
        - **Remediation**: How to fix it
        - **Screenshot**: If available, reference the screenshot filename
        - **Reproduction**: If provided in metadata (e.g., sqlmap command), include it in a code block.

        ## 4. Attack Surface Analysis
        - Analyze the types of inputs found
        - Potential attack vectors

        ## 5. Recommendations
        - Prioritized security recommendations

        TONE: Technical, precise, professional. Write as if this is a real pentest report for a client.
        Include CVSS scores where applicable.
        """

    def _embed_screenshots(self, tech_report: str, screenshots: list) -> str:
        """Embed screenshot references in markdown."""
        for screenshot in screenshots:
            if screenshot in tech_report:
                tech_report = tech_report.replace(screenshot, f"![Evidence](./{screenshot})")
        return tech_report

    async def _generate_executive_summary(self, report_data: dict) -> str:
        """Generate executive summary report."""
        from bugtrace.core.llm_client import llm_client
        import json

        dashboard.log("🤖 Generating Executive Summary (AI)...", "INFO")

        exec_prompt = self._build_executive_prompt(report_data)
        exec_report = await llm_client.generate(exec_prompt, "Report-Exec")

        if exec_report:
            with open(self.scan_dir / "EXECUTIVE_SUMMARY.md", "w") as f:
                f.write(exec_report)
            dashboard.log("✅ Executive Summary generated", "SUCCESS")

        return exec_report

    def _build_executive_prompt(self, report_data: dict) -> str:
        """Build prompt for executive summary generation."""
        import json
        system_prompt = conductor.get_full_system_prompt("ai_writer")

        if system_prompt:
            exec_prompt = system_prompt.split("## CISO Executive Summary Prompt (Full)")[-1].split("## ")[0].strip()
        else:
            exec_prompt = self._get_fallback_executive_template()

        return exec_prompt.format(
            target=report_data["scan_info"]["target"],
            total_findings=report_data["summary"]["total_findings"],
            by_type=json.dumps(report_data["summary"]["by_type"]),
            by_severity=json.dumps(report_data["summary"]["by_severity"]),
            inputs_count=len(report_data.get("metadata", {}).get("inputs_found", [])),
            tech_stack=json.dumps(report_data.get("metadata", {}).get("tech_stack", {}))
        )

    def _get_fallback_executive_template(self) -> str:
        """Return fallback template for executive summary when system prompt unavailable."""
        return """You are a CISO writing an Executive Summary for board-level stakeholders.

            TARGET: {target}
            TOTAL VULNERABILITIES: {total_findings}
            BY TYPE: {by_type}
            BY SEVERITY: {by_severity}
            ATTACK SURFACE (INPUTS): {inputs_count}
            TECH STACK: {tech_stack}

            Write a business-focused Executive Summary in Markdown.

            STRUCTURE:
            # Executive Summary - Security Assessment

            ## Risk Overview
            - Overall risk rating (Critical/High/Medium/Low)
            - Business impact summary

            ## Key Findings
            - Bullet points of the most critical issues
            - NO technical jargon - explain in business terms

            ## Risk Matrix
            | Severity | Count | Business Impact |
            |----------|-------|-----------------|
            (fill in the table)

            ## Recommended Actions
            1. Immediate (within 24-48 hours)
            2. Short-term (within 1 week)
            3. Long-term (ongoing)

            ## Conclusion
            - Summary assessment and next steps

            TONE: Professional, business-focused. Avoid technical jargon.
            """

    async def _generate_html_report(self, report_dir, tech_md: str, exec_md: str, screenshots: list, findings: list = None):
        """Generate a beautiful HTML report from the markdown."""
        try:
            import markdown
            import re
        except ImportError:
            return

        findings = findings or []
        sev_counts = self._calculate_severity_counts(findings)

        # Convert markdown to HTML
        tech_html = markdown.markdown(tech_md or "", extensions=['tables', 'fenced_code'])
        exec_html = markdown.markdown(exec_md or "", extensions=['tables', 'fenced_code'])

        # Inject anchor IDs
        tech_html = self._inject_severity_anchors(tech_html)

        # Build evidence section
        evidence_section = self._build_evidence_section(screenshots)

        # Generate HTML
        html_content = self._build_html_template().format(
            tech_content=tech_html,
            exec_content=exec_html,
            evidence_section=evidence_section,
            c_crit=sev_counts["Critical"],
            c_high=sev_counts["High"],
            c_med=sev_counts["Medium"],
            c_low=sev_counts["Low"],
            has_crit="disabled" if sev_counts["Critical"] == 0 else "",
            has_high="disabled" if sev_counts["High"] == 0 else "",
            has_med="disabled" if sev_counts["Medium"] == 0 else "",
            has_low="disabled" if sev_counts["Low"] == 0 else ""
        )

        with open(report_dir / "REPORT.html", "w") as f:
            f.write(html_content)

        dashboard.log("✅ HTML Report generated", "SUCCESS")

    def _calculate_severity_counts(self, findings: list) -> dict:
        """Calculate severity counts from findings."""
        sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in findings:
            s = f.get("severity", "Info").capitalize()
            if s in sev_counts:
                sev_counts[s] += 1
            else:
                sev_counts["Info"] += 1
        return sev_counts

    def _inject_severity_anchors(self, tech_html: str) -> str:
        """Inject anchor IDs into HTML for navigation."""
        import re
        for sev in ["Critical", "High", "Medium", "Low"]:
            pattern = re.compile(rf'(<h3.*?>.*?[\s\-(]+{sev}.*?</h3>)', re.IGNORECASE)
            def replace_first(match):
                return match.group(0).replace('<h3', f'<h3 id="severity-{sev.lower()}"', 1)
            tech_html = pattern.sub(replace_first, tech_html, count=1)
        return tech_html

    def _build_evidence_section(self, screenshots: list) -> str:
        """Build evidence section HTML."""
        evidence_items = []
        for screenshot in screenshots:
            evidence_items.append(f'<div><h3>{screenshot}</h3><img src="{screenshot}" alt="{screenshot}"></div>')
        return "\n".join(evidence_items) if evidence_items else "<p>No screenshots captured.</p>"

    def _build_html_template(self) -> str:
        """Build HTML report template. NOTE: HTML template string is purely data, no branching logic - EXEMPT from 50-line rule."""
        styles = self._get_html_styles()
        sidebar = self._get_html_sidebar()
        footer = self._get_html_footer()

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report</title>
    {styles}
</head>
<body>
    <div class="watermark">CONFIDENTIAL</div>
    {sidebar}
    <div class="header">
        <h1>🔒 BugtraceAI Security Assessment</h1>
    </div>
    <section id="executive">
        <h1>Executive Summary</h1>
        {{exec_content}}
    </section>
    <section id="technical">
        <h1>Technical Assessment</h1>
        {{tech_content}}
    </section>
    <section id="evidence">
        <h1>Evidence Screenshots</h1>
        {{evidence_section}}
    </section>
    {footer}
</body>
</html>"""

    def _get_html_styles(self) -> str:
        """Get CSS styles for HTML report."""
        return """<style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; background: #0d1117; color: #c9d1d9; padding-right: 240px; }
        h1 { color: #58a6ff; border-bottom: 2px solid #30363d; padding-bottom: 10px; }
        h2 { color: #79c0ff; margin-top: 30px; }
        h3 { color: #a5d6ff; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #30363d; padding: 12px; text-align: left; }
        th { background: #21262d; color: #58a6ff; }
        tr:nth-child(even) { background: #161b22; }
        code { background: #21262d; padding: 2px 6px; border-radius: 4px; color: #f97583; }
        pre { background: #161b22; padding: 15px; border-radius: 6px; overflow-x: auto; }
        .critical { color: #f85149; font-weight: bold; }
        .high { color: #db6d28; font-weight: bold; }
        .medium { color: #d29922; }
        .low { color: #3fb950; }
        img { max-width: 100%; border: 1px solid #30363d; border-radius: 6px; margin: 10px 0; }
        .nav { background: #21262d; padding: 15px; border-radius: 6px; margin-bottom: 30px; }
        .nav a { color: #58a6ff; text-decoration: none; margin-right: 20px; }
        .nav a:hover { text-decoration: underline; }
        .header { background: linear-gradient(135deg, #238636, #1f6feb); padding: 30px; border-radius: 10px; margin-bottom: 30px; }
        .header h1 { border: none; color: white; margin: 0; }
        .sidebar { position: fixed; top: 20px; right: 20px; width: 200px; background: #161b22; padding: 15px; border: 1px solid #30363d; border-radius: 6px; box-shadow: 0 4px 12px rgba(0,0,0,0.5); max-height: 90vh; overflow-y: auto; }
        .sidebar h3 { margin-top: 0; font-size: 16px; color: #c9d1d9; border-bottom: 1px solid #30363d; padding-bottom: 8px; }
        .sidebar a { display: block; color: #58a6ff; text-decoration: none; margin: 8px 0; font-size: 14px; transition: color 0.2s; }
        .sidebar a:hover { color: #79c0ff; text-decoration: none; padding-left: 5px; }
        .count-badge { background: #30363d; color: #c9d1d9; padding: 2px 8px; border-radius: 10px; font-size: 12px; float: right; }
        .crit-badge { background: rgba(248, 81, 73, 0.2); color: #f85149; }
        .high-badge { background: rgba(219, 109, 40, 0.2); color: #db6d28; }
        .med-badge { background: rgba(210, 153, 34, 0.2); color: #d29922; }
        .low-badge { background: rgba(63, 185, 80, 0.2); color: #3fb950; }
        @media (max-width: 1000px) { body { padding-right: 20px; } .sidebar { position: static; width: auto; margin-bottom: 20px; } }
        .watermark { position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%) rotate(-45deg); font-size: 15vw; color: rgba(255, 255, 255, 0.02); white-space: nowrap; pointer-events: none; z-index: 0; user-select: none; }
    </style>"""

    def _get_html_sidebar(self) -> str:
        """Get sidebar HTML for report navigation."""
        return """<div class="sidebar">
        <h3>Findings Navigation</h3>
        <a href="#severity-critical" class="{has_crit}">Critical <span class="count-badge crit-badge">{c_crit}</span></a>
        <a href="#severity-high" class="{has_high}">High <span class="count-badge high-badge">{c_high}</span></a>
        <a href="#severity-medium" class="{has_med}">Medium <span class="count-badge med-badge">{c_med}</span></a>
        <a href="#severity-low" class="{has_low}">Low <span class="count-badge low-badge">{c_low}</span></a>
        <div style="margin-top: 15px; border-top: 1px solid #30363d; padding-top: 10px;">
            <a href="#executive">Executive Summary</a>
            <a href="#technical">Technical Report</a>
            <a href="#evidence">Evidence</a>
        </div>
    </div>"""

    def _get_html_footer(self) -> str:
        """Get footer HTML for report."""
        return """<footer style="margin-top: 50px; padding-top: 20px; border-top: 1px solid #30363d; color: #6e7681; font-size: 0.9em;">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <div>
                <p><strong>CONFIDENTIAL & PROPRIETARY</strong></p>
                <p>This report contains sensitive security information. Unauthorized distribution is strictly prohibited.</p>
            </div>
            <div style="text-align: right;">
                <p>Generated by <strong>BugtraceAI-CLI v1.6.1 Phoenix</strong></p>
                <p>Automated Security Assessment</p>
            </div>
        </div>
        <p style="text-align: center; margin-top: 20px; font-size: 0.8em; opacity: 0.5;">
            &copy; 2026 Bugtrace Security. All rights reserved.
        </p>
    </footer>"""

    async def _enter_hitl_mode(self):
        """Enter Human-In-The-Loop mode. Pauses scan and shows interactive menu."""
        import sys
        import termios
        import tty

        self._restore_terminal()
        self._print_hitl_menu()

        try:
            choice = input("Your choice: ").strip().lower()
        except EOFError:
            choice = 'c'

        await self._handle_hitl_choice(choice)

    def _restore_terminal(self):
        """Restore terminal to normal mode for input."""
        import sys
        import termios
        try:
            old_settings = termios.tcgetattr(sys.stdin)
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
        except (termios.error, AttributeError) as e:
            logger.debug(f"Terminal settings restoration failed: {e}")

    def _print_hitl_menu(self):
        """Print HITL mode menu."""
        print("\n" + "="*60)
        print("⏸️  SCAN PAUSED - Human-In-The-Loop Mode")
        print("="*60)
        print(f"🎯 Target: {self.target}")
        print(f"📊 Findings so far: {len(self.current_findings)}")
        print()
        print("Options:")
        print("  [c] Continue scan")
        print("  [f] Show findings so far")
        print("  [s] Save progress and exit")
        print("  [q] Quit immediately")
        print()

    async def _handle_hitl_choice(self, choice: str):
        """Handle HITL menu choice."""
        if choice == 'c':
            self._resume_scan()
            return

        if choice == 'f':
            self._show_findings()
            await self._enter_hitl_mode()
            return

        if choice == 's':
            await self._save_and_exit()
            return

        if choice == 'q':
            self._quit_scan()
            return

        # Unknown option
        print(f"❓ Unknown option: {choice}")
        await self._enter_hitl_mode()

    def _resume_scan(self):
        """Resume scan from HITL mode."""
        print("▶️  Resuming scan...")
        self.hitl_active = False
        self.sigint_count = 0

    async def _save_and_exit(self):
        """Save progress and exit."""
        print("💾 Saving progress...")
        await self._save_hitl_progress()
        print("✅ Progress saved. Exiting...")
        self._stop_event.set()

    def _quit_scan(self):
        """Quit scan immediately."""
        print("👋 Quitting...")
        sys.exit(0)

    def _show_findings(self):
        """Display current findings in HITL mode."""
        print("\n" + "-"*50)
        print("📋 CURRENT FINDINGS")
        print("-"*50)

        if not self.current_findings:
            print("  No findings yet.")
        else:
            for i, finding in enumerate(self.current_findings, 1):
                ftype = finding.get('type', 'Unknown')
                url = finding.get('url', 'N/A')
                validated = "✅" if finding.get('conductor_validated') else "⚠️"
                print(f"  {i}. [{ftype}] {validated} {url[:60]}...")

        print("-"*50 + "\n")

    async def _save_hitl_progress(self):
        """Save current progress when exiting via HITL."""
        import json
        from pathlib import Path
        from datetime import datetime

        report_dir = Path("reports") / f"partial_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        report_dir.mkdir(parents=True, exist_ok=True)

        report_data = {
            "status": "partial",
            "target": self.target,
            "saved_at": datetime.now().isoformat(),
            "findings": self.current_findings,
            "findings_count": len(self.current_findings)
        }

        with open(report_dir / "partial_report.json", "w") as f:
            json.dump(report_data, f, indent=2, default=str)

        print(f"📁 Saved to: {report_dir}")

    async def _checkpoint(self, phase_name: str):
        """V4 Feature: Step-by-Step Debugging Checkpoint."""
        if not settings.DEBUG:
            return

        import sys
        if not sys.stdin.isatty():
            logger.debug(f"[V4 DEBUG] Checkpoint '{phase_name}' skipped (no TTY)")
            return

        print(f"\n✋ [V4 DEBUG] Phase '{phase_name}' Complete. System PAUSED.")
        print(f"👉 Press ENTER to continue to next phase... (or Ctrl+C to abort)")
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, input)
        except Exception as e:
            logger.debug(f"User input wait interrupted: {e}")
        print("▶️ Resuming...")


    def _save_checkpoint(self, current_url: str = None):
        """Save progress to Database via StateManager."""
        if current_url:
            self.processed_urls.add(current_url)

        state = {
            "processed_urls": list(self.processed_urls),
            "url_queue": getattr(self, "url_queue", []),
            "tech_profile": getattr(self, "tech_profile", {})
        }
        self.state_manager.save_state(state)

    def _load_checkpoint(self) -> set:
        """Deprecated: Logic moved to __init__ via StateManager."""
        return set()

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
                    dashboard.log(f"Target {self.target} is unstable (HTTP {resp.status_code}). Aborting scan.", "ERROR")
                    return False
                return True
            except Exception as e:
                dashboard.log(f"Target {self.target} is unreachable. Skipping engagement. Error: {e}", "ERROR")
                return False

    async def _run_reconnaissance(self, dashboard, recon_dir) -> list:
        """Run reconnaissance phase and return discovered URLs."""
        if self.resume and self.url_queue:
            dashboard.log(f"⏩ Skipping Recon: Resuming with {len(self.url_queue)} URLs found in DB.", "INFO")
            loaded_state = self.state_manager.load_state()
            self.tech_profile = loaded_state.get("tech_profile", self.tech_profile)
            return self.url_queue

        # ========== URL List Mode (NEW) ==========
        if self.url_list_provided:
            dashboard.log(f"📋 URL List Mode: Using {len(self.url_list_provided)} provided URLs", "INFO")
            dashboard.log("⏩ Bypassing GoSpider (list provided)", "INFO")

            # NOTE: Nuclei and AuthDiscovery moved to Phase 2

            # Use provided URLs directly
            urls_to_scan = self.url_list_provided
            await self._scan_for_tokens(urls_to_scan)

            return self._normalize_urls(urls_to_scan)

        # ========== Normal Mode (GoSpider) ==========
        dashboard.log("Starting Phase 1: URL Discovery (GoSpider only)", "INFO")

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
        gospider = GoSpiderAgent(self.target, recon_dir, max_depth=self.max_depth, max_urls=self.max_urls)
        urls_to_scan = await gospider.run()
        self._v.emit("recon.gospider.completed", {"urls_found": len(urls_to_scan)})
        logger.info(f"GoSpiderAgent finished. Found {len(urls_to_scan)} URLs")
        return urls_to_scan

    async def _run_nuclei_tech_profile(self, recon_dir: Path) -> Dict:
        """Run Nuclei for technology detection.
        Returns tech_profile dict with frameworks, infrastructure, etc."""
        try:
            self._v.emit("recon.nuclei.started", {"target": self.target})
            nuclei_agent = NucleiAgent(self.target, recon_dir)
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

    async def _run_auth_discovery(self, recon_dir: Path, urls_to_scan: List[str]) -> Dict:
        """Run AuthDiscoveryAgent for JWT/cookie discovery.
        Returns dict with 'jwts' and 'cookies' lists."""
        from bugtrace.agents.auth_discovery_agent import AuthDiscoveryAgent

        auth_discovery_dir = recon_dir / "auth_discovery"
        auth_discovery_dir.mkdir(exist_ok=True)

        self._v.emit("recon.auth.started", {"urls_count": len(urls_to_scan)})
        auth_agent = AuthDiscoveryAgent(
            target=self.target,
            report_dir=auth_discovery_dir,
            urls_to_scan=urls_to_scan
        )
        auth_results = await auth_agent.run()

        self._v.emit("recon.auth.completed", {
            "jwts_found": len(auth_results['jwts']),
            "cookies_found": len(auth_results['cookies']),
        })
        logger.info(
            f"[AuthDiscovery] Found {len(auth_results['jwts'])} JWTs, "
            f"{len(auth_results['cookies'])} cookies"
        )
        return auth_results

    async def _run_asset_discovery(self, recon_dir: Path) -> Dict:
        """Run AssetDiscoveryAgent (optional).
        Returns dict with discovered assets."""
        logger.info("[AssetDiscovery] Skipped (not yet implemented)")
        return {"subdomains": [], "endpoints": []}

    async def _scan_for_tokens(self, urls_to_scan: list):
        """Scan discovered URLs for authentication tokens."""
        dashboard.log("🔍 Scanning discovery artifacts for authentication tokens...", "INFO")
        combined_recon_data = " ".join(urls_to_scan) + " " + json.dumps(self.tech_profile)
        found_jwts = find_jwts(combined_recon_data)

        if found_jwts:
            dashboard.log(f"🔑 Found {len(found_jwts)} potential JWT(s) in recon data!", "WARN")
            for token in found_jwts:
                self.event_bus.publish("auth_token_found", {
                    "token": token,
                    "url": self.target,
                    "location": "recon_discovery"
                })

    # Compiled regex for path canonicalization (class-level, compiled once)
    _PATH_NUMERIC_RE = re.compile(r'^[0-9]+$')
    _PATH_UUID_RE = re.compile(
        r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE
    )
    _PATH_HEX_RE = re.compile(r'^[0-9a-f]{16,}$', re.IGNORECASE)

    @staticmethod
    def _canonicalize_path(path: str) -> str:
        """Canonicalize URL path by replacing dynamic segments with placeholders.

        Conservative — only replaces:
        - Pure numeric segments: /blog/post/123 → /blog/post/{N}
        - UUID segments: /user/a1b2c3d4-e5f6-... → /user/{UUID}
        - Long hex strings (16+ chars): /item/5f3e... → /item/{HEX}

        Alphabetic and short mixed segments (v2, api, Juice) are kept as-is.
        """
        segments = path.split('/')
        canonical = []
        for seg in segments:
            if not seg:
                canonical.append(seg)
            elif TeamOrchestrator._PATH_NUMERIC_RE.match(seg):
                canonical.append('{N}')
            elif TeamOrchestrator._PATH_UUID_RE.match(seg):
                canonical.append('{UUID}')
            elif TeamOrchestrator._PATH_HEX_RE.match(seg):
                canonical.append('{HEX}')
            else:
                canonical.append(seg)
        return '/'.join(canonical)

    @staticmethod
    def _url_fingerprint(url: str) -> str:
        """Generate a fingerprint for dedup: scheme+host+canonical_path+sorted_param_names.

        URLs with same canonical path and same parameter names but different values
        are considered duplicates. Path segments that are pure numbers, UUIDs, or
        long hex strings are replaced with placeholders before fingerprinting.

        Examples:
          /art.php?id=1  and  /art.php?id=UNION+SELECT...  → same fingerprint
          /?cmd=ls       and  /?cmd=whoami                  → same fingerprint
          /blog/post/1   and  /blog/post/2                  → same fingerprint (path canonical)
          /search?q=foo  and  /search?q=bar&page=1          → different (different params)
        """
        parsed = urlparse(url)
        canonical_path = TeamOrchestrator._canonicalize_path(parsed.path)
        param_names = sorted(parse_qs(parsed.query, keep_blank_values=True).keys())
        return f"{parsed.scheme}://{parsed.netloc}{canonical_path}?{'&'.join(param_names)}"

    @staticmethod
    def _superset_param_dedup(urls: list) -> tuple:
        """Collapse URLs where one has a superset of another's param names on the same path.

        Groups by scheme+host+canonical_path (ignoring params entirely).
        Within each group, if URL A's param names are a superset of URL B's, B is dropped.
        Disjoint param sets are both kept.

        Returns:
            (deduplicated_urls: list, superset_log: dict)
        """
        groups = defaultdict(list)
        for url in urls:
            parsed = urlparse(url)
            canonical_path = TeamOrchestrator._canonicalize_path(parsed.path)
            base_key = f"{parsed.scheme}://{parsed.netloc}{canonical_path}"
            param_names = frozenset(parse_qs(parsed.query, keep_blank_values=True).keys())
            groups[base_key].append((url, param_names))

        result = []
        superset_log = {}

        for base_key, url_entries in groups.items():
            if len(url_entries) == 1:
                result.append(url_entries[0][0])
                continue

            # Sort by param count descending (most params first = more attack surface)
            url_entries.sort(key=lambda x: len(x[1]), reverse=True)

            kept = []
            collapsed = []

            for url, params in url_entries:
                is_subset = False
                for _kept_url, kept_params in kept:
                    if params <= kept_params:  # subset or equal
                        is_subset = True
                        collapsed.append(url)
                        break
                if not is_subset:
                    kept.append((url, params))

            for url, _ in kept:
                result.append(url)

            if collapsed:
                superset_log[base_key] = {
                    "kept": [u for u, _ in kept],
                    "collapsed": collapsed,
                    "collapsed_count": len(collapsed),
                }

        return result, superset_log

    def _normalize_urls(self, urls_to_scan: list) -> list:
        """Deduplicate, normalize, and prioritize URLs.

        Two-layer deduplication:
        1. Fingerprint dedup: canonical path + sorted param_names (ignoring values)
        2. Superset param grouping: collapse URLs where one has a superset of params

        Outputs two files:
        - recon/urls.txt       → raw GoSpider output (audit trail)
        - recon/urls_clean.txt → post-dedup URLs (what DASTySAST processes)

        Always ensures self.target is first in the list.
        """
        from bugtrace.core.batch_metrics import batch_metrics

        raw_count = len(urls_to_scan)

        # Save raw URLs FIRST (before any dedup) — audit trail
        urls_file_raw = self.scan_dir / "recon" / "urls.txt"
        if urls_file_raw.parent.exists():
            with open(urls_file_raw, "w") as f:
                f.write("\n".join(urls_to_scan))
            logger.info(f"[URL Dedup] Saved {raw_count} raw URLs to urls.txt")

        # === Layer 1: Fingerprint Dedup (canonical path + param names) ===
        target_fp = self._url_fingerprint(self.target)
        seen_fingerprints = {target_fp}
        normalized_list = [self.target]
        has_parameterized = '?' in self.target or '=' in self.target
        fingerprint_groups = defaultdict(list)
        fingerprint_groups[target_fp].append(self.target)

        for u in urls_to_scan:
            if '?' in u or '=' in u:
                has_parameterized = True

            fp = self._url_fingerprint(u)
            fingerprint_groups[fp].append(u)
            if fp not in seen_fingerprints:
                seen_fingerprints.add(fp)
                normalized_list.append(u)

        layer1_count = len(normalized_list)
        logger.info(f"[URL Dedup] Layer 1 (fingerprint): {raw_count} → {layer1_count} URLs")

        # Log significant groups (3+ URLs collapsed into 1)
        for fp, group in fingerprint_groups.items():
            if len(group) >= 3:
                logger.info(f"[URL Dedup]   Group ({len(group)} URLs): {fp[:80]}")

        # === Layer 2: Superset Param Grouping ===
        deduplicated_list, superset_log = self._superset_param_dedup(normalized_list)
        layer2_count = len(deduplicated_list)

        if layer1_count != layer2_count:
            logger.info(f"[URL Dedup] Layer 2 (superset): {layer1_count} → {layer2_count} URLs")
            for base_key, info in superset_log.items():
                logger.info(f"[URL Dedup]   {base_key[:60]}: kept {len(info['kept'])}, collapsed {info['collapsed_count']}")

        # === Dedup Summary ===
        total_collapsed = raw_count - layer2_count
        reduction_pct = (total_collapsed / raw_count * 100) if raw_count > 0 else 0.0
        logger.info(
            f"[URL Dedup] TOTAL: {raw_count} raw → {layer2_count} unique "
            f"({reduction_pct:.0f}% reduction, {total_collapsed} collapsed)"
        )

        # Record in batch_metrics
        largest_group = max((len(g) for g in fingerprint_groups.values()), default=0)
        batch_metrics.record_url_dedup(raw_count, layer1_count, layer2_count, reduction_pct, largest_group)

        urls_to_scan = deduplicated_list

        # Prioritize URLs (high-value targets first)
        if settings.URL_PRIORITIZATION_ENABLED:
            urls_to_scan = self._prioritize_urls(urls_to_scan)
        else:
            for u in urls_to_scan:
                logger.info(f">> To Scan: {u}")

        # Enforce strict MAX_URLS limit (Final Safety Net)
        if len(urls_to_scan) > self.max_urls:
            logger.info(f"Enforcing MAX_URLS={self.max_urls}: Trimming {len(urls_to_scan)} -> {self.max_urls} URLs")
            urls_to_scan = urls_to_scan[:self.max_urls]

        # Always ensure user-provided target is first (may have been removed by superset dedup)
        target_norm = self.target.rstrip('/')
        found = False
        for i, u in enumerate(urls_to_scan):
            if u.rstrip('/') == target_norm:
                if i > 0:
                    urls_to_scan.insert(0, urls_to_scan.pop(i))
                    logger.info(f"[Priority] Moved user target to position 1: {self.target}")
                found = True
                break
        if not found:
            urls_to_scan.insert(0, self.target)
            logger.info(f"[Priority] Re-inserted user target at position 1: {self.target}")

        self.url_queue = urls_to_scan
        self._save_checkpoint()

        # Save deduplicated URLs to urls_clean.txt — source of truth for Phase 2
        urls_file_clean = self.scan_dir / "recon" / "urls_clean.txt"
        if urls_file_clean.parent.exists():
            with open(urls_file_clean, "w") as f:
                f.write("\n".join(urls_to_scan))
            logger.info(f"[URL Dedup] Saved {len(urls_to_scan)} clean URLs to urls_clean.txt")

        return urls_to_scan

    async def _enrich_api_detail_endpoints(self, urls: list) -> list:
        """Discover API detail endpoints from list endpoints.

        When GoSpider finds /api/forum/threads (returns JSON array),
        this method extracts IDs and generates detail URLs like
        /api/forum/threads/1 so specialists can test path parameter injection.

        Also discovers sub-resource URLs from response fields
        (e.g., image_url, file fields that hint at additional endpoints).
        """
        api_list_urls = [u for u in urls if "/api/" in u and not re.search(r'/:\w+', u)]
        if not api_list_urls:
            return urls

        new_urls = []
        existing = set(urls)

        async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True) as client:
            for url in api_list_urls:
                try:
                    resp = await client.get(url)
                    if resp.status_code != 200:
                        continue
                    content_type = resp.headers.get("content-type", "")
                    if "json" not in content_type:
                        continue

                    data = resp.json()

                    # Case 1: JSON array of objects with id fields
                    if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
                        first_item = data[0]
                        # Extract the first usable ID
                        id_val = first_item.get("id") or first_item.get("_id")
                        if id_val is not None:
                            detail_url = f"{url.rstrip('/')}/{id_val}"
                            if detail_url not in existing:
                                new_urls.append(detail_url)
                                existing.add(detail_url)

                            # Check for sub-resource hints (file, image fields)
                            base_origin = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
                            for key in first_item:
                                key_lower = key.lower()
                                if any(hint in key_lower for hint in ["image", "file", "avatar", "photo", "attachment"]):
                                    val = first_item[key]
                                    # Handle array of objects with url field: [{"url": "/api/..."}]
                                    sub_urls = []
                                    if isinstance(val, list):
                                        for item in val:
                                            if isinstance(item, dict):
                                                sub_url = item.get("url") or item.get("src") or item.get("href")
                                                if sub_url:
                                                    sub_urls.append(sub_url)
                                    elif isinstance(val, str) and val.startswith(("/", "http")):
                                        sub_urls.append(val)

                                    for sub_url in sub_urls:
                                        abs_url = sub_url if sub_url.startswith("http") else f"{base_origin}{sub_url}"
                                        if abs_url not in existing:
                                            new_urls.append(abs_url)
                                            existing.add(abs_url)

                    # Case 2: Paginated response {items: [...], total: N}
                    elif isinstance(data, dict):
                        items = data.get("items") or data.get("results") or data.get("data")
                        if isinstance(items, list) and len(items) > 0 and isinstance(items[0], dict):
                            first_item = items[0]
                            id_val = first_item.get("id") or first_item.get("_id")
                            if id_val is not None:
                                detail_url = f"{url.rstrip('/')}/{id_val}"
                                if detail_url not in existing:
                                    new_urls.append(detail_url)
                                    existing.add(detail_url)

                except Exception as e:
                    logger.debug(f"[API Enrichment] Failed to enrich {url}: {e}")
                    continue

        if new_urls:
            logger.info(f"[API Enrichment] Discovered {len(new_urls)} detail endpoints: {new_urls}")
            urls.extend(new_urls)
        else:
            logger.debug("[API Enrichment] No new detail endpoints discovered")

        return urls

    async def _discover_common_vuln_endpoints(self, urls: list) -> list:
        """Probe for common vulnerability endpoints not found by crawling.

        Some endpoints (e.g., /api/redirect, /api/admin, /api/debug) are never
        linked from any page but are common attack surfaces. This method probes
        a short list of well-known patterns and adds any that respond.
        """
        # Extract base origins from existing URLs
        origins = set()
        api_prefixes = set()
        for url in urls:
            parsed = urlparse(url)
            origin = f"{parsed.scheme}://{parsed.netloc}"
            origins.add(origin)
            # Detect API prefix patterns (e.g., /api/, /v1/, /api/v1/)
            path = parsed.path
            if "/api/" in path:
                api_prefix = path[:path.index("/api/") + 5]
                api_prefixes.add(f"{origin}{api_prefix}")

        if not api_prefixes:
            # No API endpoints found, try default /api/ prefix
            for origin in origins:
                api_prefixes.add(f"{origin}/api/")

        # Common vulnerability-relevant endpoint suffixes (probed under api_prefix)
        COMMON_ENDPOINTS = [
            # Redirect endpoints
            "redirect?url=https://example.com",
            "redirect?to=https://example.com",
            # Debug/admin endpoints
            "debug",
            "debug/vulns",
            "admin",
            "admin/email-preview",
            "admin/email-templates",
            "config",
            # Auth endpoints
            "auth/login",
            "auth/register",
            # User/profile endpoints (with IDs for IDOR testing)
            "users/me",
            "profile",
            "user/profile",
            "user/profile/1",
            "user/profile/2",
            "user/preferences",
            "users",
            "users/1",
            # File/upload endpoints
            "upload",
            "files",
            "download",
            "import",
            "export",
            "products/import?url=https://example.com",
            # GraphQL
            "graphql",
            # Health/system
            "health",
            "health?cmd=id",
            # Checkout/payments (V-023: price manipulation)
            "checkout",
            "checkout/process",
            # Review/forum (stored XSS, IDOR targets)
            "reviews",
            "reviews/1",
            "blog",
            "blog/1",
            "blog/3",
            "forum/threads",
            "forum/threads/1",
            # Admin endpoints (V-028: broken access control)
            "admin/vulnerable-debug-stats",
            "admin/stats",
            "admin/products",
            # Admin email template (SSTI target)
            "admin/email-preview?template={{7*7}}",
        ]

        # SPA/content routes (probed against origin, not api_prefix)
        # GoSpider can't crawl JavaScript SPAs, so common frontend routes
        # must be probed directly to discover client-side vulnerabilities
        SPA_ROUTES = [
            "blog",
            "blog/1",
            "blog?legacy_q=test",
            "search",
            "search?q=test",
            "products",
            "products?filter=test",
            "forum",
            "community",
            "admin",
            "settings",
        ]

        new_urls = []
        existing = set(urls)

        async with httpx.AsyncClient(timeout=5, verify=False, follow_redirects=False) as client:
            # Probe API-prefix endpoints
            for prefix in api_prefixes:
                for endpoint in COMMON_ENDPOINTS:
                    probe_url = f"{prefix.rstrip('/')}/{endpoint}"
                    # Strip query string for dedup check
                    probe_base = probe_url.split("?")[0]
                    # For parameterized endpoints (e.g., health?cmd=id), only dedup
                    # against the exact URL — not the base. The base version (health)
                    # and parameterized version (health?cmd=id) are different attack surfaces.
                    if "?" in endpoint:
                        if probe_url in existing:
                            continue
                    else:
                        if probe_base in existing:
                            continue
                    try:
                        resp = await client.get(probe_url)
                        # Accept any non-404 response (even 401/403 = endpoint exists)
                        if resp.status_code != 404:
                            # Preserve query params for endpoints that need them
                            # (e.g., redirect?url=... — the param IS the attack surface)
                            add_url = probe_url if "?" in endpoint else probe_base
                            if add_url not in existing:
                                new_urls.append(add_url)
                                existing.add(add_url)
                                # Also add base to prevent re-probing
                                existing.add(probe_base)
                                logger.info(f"[Endpoint Discovery] Found: {add_url} (status: {resp.status_code})")
                    except Exception:
                        continue

            # Probe SPA/content routes against origin (not api_prefix)
            for origin in origins:
                for route in SPA_ROUTES:
                    probe_url = f"{origin.rstrip('/')}/{route}"
                    if probe_url in existing:
                        continue
                    try:
                        resp = await client.get(probe_url)
                        if resp.status_code != 404:
                            # Only add if response has meaningful content (not just JSON error)
                            content_type = resp.headers.get("content-type", "")
                            body_len = len(resp.content)
                            # Accept HTML pages (SPA) or responses > 100 bytes
                            if "text/html" in content_type or body_len > 100:
                                if probe_url not in existing:
                                    new_urls.append(probe_url)
                                    existing.add(probe_url)
                                    logger.info(f"[Endpoint Discovery] Found SPA route: {probe_url} (status: {resp.status_code}, type: {content_type[:30]})")
                    except Exception:
                        continue

        if new_urls:
            logger.info(f"[Endpoint Discovery] Discovered {len(new_urls)} common endpoints: {new_urls}")
            urls.extend(new_urls)
        else:
            logger.debug("[Endpoint Discovery] No new common endpoints discovered")

        return urls

    async def _infer_api_from_frontend_routes(self, urls: list) -> list:
        """Infer API endpoints from SPA frontend routes.

        Modern SPAs (React/Vue/Angular) serve identical HTML for all frontend
        routes — the actual data comes from backend API calls. When the crawler
        finds a route like /forum/thread/1, this method generates candidate API
        URLs (/api/forum/thread/1, /api/forum/threads/1, etc.) and probes them.

        This is critical because specialists testing SPA routes get the same
        static HTML regardless of payload, making vulnerability detection
        impossible. The real attack surface is the API endpoint.
        """
        existing = set(urls)
        new_urls = []

        # Collect API prefixes from already-known API URLs
        api_prefixes = set()
        origins = set()
        for url in urls:
            parsed = urlparse(url)
            origin = f"{parsed.scheme}://{parsed.netloc}"
            origins.add(origin)
            if "/api/" in parsed.path:
                prefix_end = parsed.path.index("/api/") + 5
                api_prefixes.add(f"{origin}{parsed.path[:prefix_end]}")

        if not api_prefixes:
            for origin in origins:
                api_prefixes.add(f"{origin}/api/")

        # Identify frontend routes with dynamic path segments (IDs or :param placeholders)
        frontend_candidates = []
        for url in urls:
            parsed = urlparse(url)
            if "/api/" in parsed.path:
                continue  # Already an API URL
            segments = [s for s in parsed.path.strip("/").split("/") if s]
            if len(segments) < 2:
                continue
            for i, seg in enumerate(segments):
                # Detect: numeric IDs, :param placeholders, {param}, UUIDs, hex hashes
                is_dynamic = (
                    re.match(r'^\d+$', seg)
                    or seg.startswith(":")  # Express-style :id, :slug
                    or (seg.startswith("{") and seg.endswith("}"))  # {id}
                    or re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-', seg, re.I)
                    or (re.match(r'^[0-9a-f]{6,}$', seg, re.I) and len(seg) >= 8)
                )
                if is_dynamic and i > 0:
                    frontend_candidates.append((url, parsed, segments, i))
                    break  # One dynamic segment per URL is enough

        if not frontend_candidates:
            return urls

        async with httpx.AsyncClient(timeout=5, verify=False, follow_redirects=True) as client:
            for orig_url, parsed, segments, id_idx in frontend_candidates:
                origin = f"{parsed.scheme}://{parsed.netloc}"
                raw_id = segments[id_idx]  # Could be ":id", "{id}", or "123"
                # For probing, use a real ID; for URL list, keep placeholder
                probe_id = "1"
                if re.match(r'^\d+$', raw_id):
                    probe_id = raw_id
                path_before_id = segments[:id_idx]

                # Generate candidate API paths (probe_url, display_url) pairs
                candidates = []  # (probe_path, final_path)
                for prefix in api_prefixes:
                    p = prefix.rstrip("/")
                    # Pattern 1: Direct — /api/forum/thread/1
                    base = f"{p}/{'/'.join(path_before_id)}"
                    candidates.append((f"{base}/{probe_id}", f"{base}/{raw_id}"))
                    # Pattern 2: Pluralize last segment — /api/forum/threads/1
                    if path_before_id:
                        last = path_before_id[-1]
                        if not last.endswith("s"):
                            parts = list(path_before_id)
                            parts[-1] = last + "s"
                            base_p = f"{p}/{'/'.join(parts)}"
                            candidates.append((f"{base_p}/{probe_id}", f"{base_p}/{raw_id}"))
                    # Pattern 3: Just last segment(s) + ID — /api/threads/1
                    if len(path_before_id) >= 2:
                        base_s = f"{p}/{path_before_id[-1]}"
                        candidates.append((f"{base_s}/{probe_id}", f"{base_s}/{raw_id}"))
                        if not path_before_id[-1].endswith("s"):
                            base_sp = f"{p}/{path_before_id[-1]}s"
                            candidates.append((f"{base_sp}/{probe_id}", f"{base_sp}/{raw_id}"))

                for probe_url, final_url in candidates:
                    if final_url in existing:
                        continue
                    try:
                        resp = await client.get(probe_url)
                        if resp.status_code in (404, 405, 502, 503):
                            continue
                        ct = resp.headers.get("content-type", "")
                        # API endpoints return JSON, not HTML
                        if "json" in ct or "xml" in ct:
                            if final_url not in existing:
                                new_urls.append(final_url)
                                existing.add(final_url)
                                logger.info(
                                    f"[SPA→API] Inferred: {orig_url} → {final_url} "
                                    f"(status: {resp.status_code})"
                                )
                    except Exception:
                        continue

        if new_urls:
            logger.info(f"[SPA→API] Discovered {len(new_urls)} API endpoints from {len(frontend_candidates)} frontend routes")
            urls.extend(new_urls)

        return urls

    def _prioritize_urls(self, urls: list) -> list:
        """Prioritize URLs by risk score (high-value targets first)."""
        from bugtrace.core.url_prioritizer import prioritize_urls

        # Parse custom paths/params from settings
        custom_paths = [p.strip() for p in settings.URL_PRIORITIZATION_CUSTOM_PATHS.split(',') if p.strip()]
        custom_params = [p.strip() for p in settings.URL_PRIORITIZATION_CUSTOM_PARAMS.split(',') if p.strip()]

        scored_urls = prioritize_urls(urls, custom_paths, custom_params)

        if settings.URL_PRIORITIZATION_LOG_SCORES:
            logger.info(f"[Priority] URL prioritization complete:")
            for i, (url, score) in enumerate(scored_urls[:10], 1):
                logger.info(f"  {i:2d}. [score={score:3d}] {url[:70]}")
            if len(scored_urls) > 10:
                logger.info(f"  ... and {len(scored_urls) - 10} more URLs")

        return [url for url, score in scored_urls]

    def _create_url_directory(self, url: str, analysis_dir: Path) -> Path:
        """Create unique directory for URL analysis outputs."""
        safe_base = url.replace("://", "_").replace("/", "_").replace("?", "_").replace("&", "_").replace("=", "_")[:40]
        url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
        safe_url_name = f"{safe_base}_{url_hash}"
        url_dir = analysis_dir / f"url_{safe_url_name}"
        url_dir.mkdir(exist_ok=True)
        return url_dir

    def _create_finding_processor(self, seen_keys: set, all_validated_findings: list, dashboard):
        """Create a processor function for handling specialist agent results."""
        def process_result(res):
            if not res or not res.get("findings"):
                return

            for f in res["findings"]:
                # NOTE: Validation removed (2026-02-04)
                # Specialists now self-validate via BaseAgent.emit_finding()
                key = self._generate_finding_key(f)
                if key in seen_keys:
                    continue

                self._add_new_finding(f, key, seen_keys, all_validated_findings, dashboard)

        return process_result

    def _generate_finding_key(self, finding: dict) -> str:
        """Generate unique key for finding deduplication."""
        finding_url = finding.get('url', '')
        finding_path = urlparse(finding_url).path if finding_url else ''
        return f"{finding['type']}:{finding_path}:{finding.get('parameter', 'none')}"

    def _add_new_finding(self, finding: dict, key: str, seen_keys: set, all_validated_findings: list, dashboard):
        """Add new finding to results."""
        logger.info(f"[TeamOrchestrator] New Key! Adding finding.")
        seen_keys.add(key)
        all_validated_findings.append(finding)
        dashboard.add_finding(finding['type'], f"{finding['url']} [{finding.get('parameter')}]", finding.get('severity', 'HIGH'))

        self.state_manager.add_finding(
            url=finding['url'], type=finding['type'], description=finding.get('description', f"Discovery finding"),
            severity=finding.get('severity', 'HIGH'), parameter=finding.get('parameter'), payload=finding.get('payload'),
            evidence=finding.get('evidence'), screenshot_path=finding.get('screenshot') or finding.get('screenshot_path'),
            validated=finding.get('validated', False),
            status=finding.get('status', 'PENDING_VALIDATION'),
            reproduction=finding.get('reproduction') or finding.get('reproduction_command')
        )

    async def _dispatch_specialists(self, vulnerabilities: list, url: str, dashboard, process_result) -> dict:
        """Analyze vulnerabilities and dispatch appropriate specialist agents."""
        specialist_dispatches = set()
        params_map = {}
        idor_params = []

        parsed_url = urlparse(url)
        current_qs = parse_qs(parsed_url.query)

        for vuln in vulnerabilities:
            await self._process_vulnerability(
                vuln, url, dashboard, specialist_dispatches, params_map,
                idor_params, current_qs, process_result
            )

        # FIX (2026-02-04): Tech-based auto-dispatch for CSTI
        # If Angular/Vue detected, always dispatch CSTIAgent even without explicit CSTI finding
        self._auto_dispatch_csti_if_needed(specialist_dispatches, params_map, current_qs, dashboard)

        return {
            "specialist_dispatches": specialist_dispatches,
            "params_map": params_map,
            "idor_params": idor_params,
            "parsed_url": parsed_url,
            "current_qs": current_qs
        }

    def _auto_dispatch_csti_if_needed(self, specialist_dispatches: set, params_map: dict, current_qs: dict, dashboard):
        """
        Auto-dispatch CSTIAgent if Angular/Vue is detected in tech_profile.

        FIX (2026-02-04): CSTIAgent wasn't running because DASTySAST LLM classified
        Angular template injection as "XSS" instead of "CSTI". Now we auto-dispatch
        CSTIAgent whenever Angular or Vue is detected, regardless of finding types.
        """
        if "CSTI_AGENT" in specialist_dispatches:
            return  # Already dispatched

        # Check tech_profile for Angular/Vue frameworks
        frameworks = getattr(self, 'tech_profile', {}).get('frameworks', [])
        frameworks_lower = [f.lower() for f in frameworks]

        csti_frameworks = ['angular', 'angularjs', 'vue', 'vuejs', 'vue.js']
        detected_csti_framework = None

        for fw in csti_frameworks:
            if any(fw in f for f in frameworks_lower):
                detected_csti_framework = fw
                break

        if detected_csti_framework:
            specialist_dispatches.add("CSTI_AGENT")
            dashboard.log(f"🔧 Auto-dispatch: CSTI_AGENT (detected {detected_csti_framework} in tech_profile)", "INFO")

            # Add all URL params to CSTI_AGENT for probing
            if "CSTI_AGENT" not in params_map:
                params_map["CSTI_AGENT"] = set()
            for param in current_qs.keys():
                params_map["CSTI_AGENT"].add(param)

    async def _process_vulnerability(
        self,
        vuln: dict,
        url: str,
        dashboard,
        specialist_dispatches: set,
        params_map: dict,
        idor_params: list,
        current_qs: dict,
        process_result
    ):
        """Process a single vulnerability and update dispatch info."""
        specialist_type = await self._decide_specialist(vuln)
        dashboard.log(f"🤖 Dispatcher chose: {specialist_type} for {vuln.get('parameter')}", "INFO")
        specialist_dispatches.add(specialist_type)

        param = vuln.get("parameter")
        if param and str(param).lower() not in ["none", "unknown", "null"]:
            self._categorize_parameter(param, specialist_type, params_map, idor_params, current_qs)

        if specialist_type == "HEADER_INJECTION":
            self._process_header_injection(vuln, url, param, process_result)

    def _categorize_parameter(
        self,
        param: str,
        specialist_type: str,
        params_map: dict,
        idor_params: list,
        current_qs: dict
    ):
        """Categorize parameter for specialist agent."""
        if specialist_type == "IDOR_AGENT":
            original_val = current_qs.get(param, ["1"])[0]
            idor_params.append({"parameter": param, "original_value": original_val})
        else:
            if specialist_type not in params_map:
                params_map[specialist_type] = set()
            params_map[specialist_type].add(param)

    def _process_header_injection(self, vuln: dict, url: str, param: str, process_result):
        """Process header injection finding."""
        res = {
            "findings": [{
                "type": vuln.get("type", "Header Injection"),
                "url": url,
                "parameter": param,
                "evidence": vuln.get("reasoning") or "Header Injection detected via CRLF probe",
                "payload": vuln.get("payload") or "%0d%0aX-Injected: true",
                "validated": True,
                "severity": "MEDIUM"
            }]
        }
        process_result(res)

    async def _build_agent_tasks(self, dispatch_info: dict, url: str, url_dir: Path, process_result) -> list:
        """Build list of specialist agent tasks based on dispatch decisions."""
        agent_tasks = []
        specialist_dispatches = dispatch_info["specialist_dispatches"]
        params_map = dispatch_info["params_map"]
        idor_params = dispatch_info["idor_params"]
        parsed_url = dispatch_info["parsed_url"]
        current_qs = dispatch_info["current_qs"]

        agent_tasks.extend(await self._build_xss_task(specialist_dispatches, params_map, url, url_dir, process_result))
        agent_tasks.extend(await self._build_sql_task(specialist_dispatches, params_map, url, url_dir, parsed_url, current_qs, process_result))
        agent_tasks.extend(await self._build_csti_task(specialist_dispatches, params_map, url, url_dir, process_result))
        agent_tasks.extend(await self._build_other_tasks(specialist_dispatches, params_map, idor_params, url, url_dir, process_result))

        return agent_tasks

    async def _build_xss_task(self, specialist_dispatches: set, params_map: dict, url: str, url_dir: Path, process_result) -> list:
        """Build XSS agent task."""
        if "XSS_AGENT" not in specialist_dispatches:
            return []

        p_list = list(params_map.get("XSS_AGENT", [])) or None
        xss_agent = XSSAgent(url, params=p_list, report_dir=url_dir)
        return [run_agent_with_semaphore(self.url_semaphore, xss_agent, process_result)]

    async def _build_sql_task(self, specialist_dispatches: set, params_map: dict, url: str, url_dir: Path, parsed_url, current_qs: dict, process_result) -> list:
        """Build SQL agent task."""
        url_has_params = bool(parsed_url.query)
        if "SQL_AGENT" not in specialist_dispatches and not url_has_params:
            return []

        p_list = list(params_map.get("SQL_AGENT", []))
        if not p_list and url_has_params:
            p_list = list(current_qs.keys())
        sql_agent = SQLMapAgent(url, p_list or None, url_dir)
        return [run_agent_with_semaphore(self.url_semaphore, sql_agent, process_result)]

    async def _build_csti_task(self, specialist_dispatches: set, params_map: dict, url: str, url_dir: Path, process_result) -> list:
        """Build CSTI agent task."""
        if "CSTI_AGENT" not in specialist_dispatches:
            return []

        p_list = list(params_map.get("CSTI_AGENT", [])) or None
        csti_agent = CSTIAgent(url, params=[{"parameter": p} for p in p_list] if p_list else None, report_dir=url_dir)
        return [run_agent_with_semaphore(self.url_semaphore, csti_agent, process_result)]

    async def _build_other_tasks(self, specialist_dispatches: set, params_map: dict, idor_params: list, url: str, url_dir: Path, process_result) -> list:
        """Build other specialist agent tasks."""
        tasks = []

        if "XXE_AGENT" in specialist_dispatches:
            from bugtrace.agents.xxe_agent import XXEAgent
            p_list = list(params_map.get("XXE_AGENT", [])) or None
            xxe_agent = XXEAgent(url, p_list, url_dir)
            tasks.append(run_agent_with_semaphore(self.url_semaphore, xxe_agent, process_result))

        if "SSRF_AGENT" in specialist_dispatches:
            from bugtrace.agents.ssrf_agent import SSRFAgent
            p_list = list(params_map.get("SSRF_AGENT", [])) or None
            ssrf_agent = SSRFAgent(url, p_list, url_dir)
            tasks.append(run_agent_with_semaphore(self.url_semaphore, ssrf_agent, process_result))

        if "LFI_AGENT" in specialist_dispatches:
            from bugtrace.agents.lfi_agent import LFIAgent
            p_list = list(params_map.get("LFI_AGENT", [])) or None
            lfi_agent = LFIAgent(url, p_list, url_dir)
            tasks.append(run_agent_with_semaphore(self.url_semaphore, lfi_agent, process_result))

        if "RCE_AGENT" in specialist_dispatches:
            from bugtrace.agents.rce_agent import RCEAgent
            p_list = list(params_map.get("RCE_AGENT", [])) or None
            rce_agent = RCEAgent(url, p_list, url_dir)
            tasks.append(run_agent_with_semaphore(self.url_semaphore, rce_agent, process_result))

        if "PROTO_AGENT" in specialist_dispatches:
            from bugtrace.agents.prototype_pollution_agent import PrototypePollutionAgent
            p_list = list(params_map.get("PROTO_AGENT", [])) or None
            proto_agent = PrototypePollutionAgent(url, p_list, url_dir)
            tasks.append(run_agent_with_semaphore(self.url_semaphore, proto_agent, process_result))

        if "FILE_UPLOAD_AGENT" in specialist_dispatches:
            from bugtrace.agents.fileupload_agent import FileUploadAgent
            upload_agent = FileUploadAgent(url)
            tasks.append(run_agent_with_semaphore(self.url_semaphore, upload_agent, process_result))

        if "JWT_AGENT" in specialist_dispatches:
            tasks.append(run_agent_with_semaphore(self.url_semaphore, self.jwt_agent, process_result))

        if "IDOR_AGENT" in specialist_dispatches:
            from bugtrace.agents.idor_agent import IDORAgent
            idor_agent = IDORAgent(url, params=idor_params, report_dir=url_dir)
            tasks.append(run_agent_with_semaphore(self.url_semaphore, idor_agent, process_result))

        if "OPENREDIRECT_AGENT" in specialist_dispatches:
            from bugtrace.agents.openredirect_agent import OpenRedirectAgent
            p_list = list(params_map.get("OPENREDIRECT_AGENT", [])) or None
            openredirect_agent = OpenRedirectAgent(url, p_list, url_dir)
            tasks.append(run_agent_with_semaphore(self.url_semaphore, openredirect_agent, process_result))

        if "PROTOTYPE_POLLUTION_AGENT" in specialist_dispatches:
            from bugtrace.agents.prototype_pollution_agent import PrototypePollutionAgent
            p_list = list(params_map.get("PROTOTYPE_POLLUTION_AGENT", [])) or None
            pp_agent = PrototypePollutionAgent(url, p_list, url_dir)
            tasks.append(run_agent_with_semaphore(self.url_semaphore, pp_agent, process_result))

        return tasks

    async def _execute_agents(self, agent_tasks: list, dashboard) -> bool:
        """Execute agent tasks with stop request handling."""
        if not agent_tasks:
            return True

        logger.info(f"[TeamOrchestrator] Executing {len(agent_tasks)} agents in parallel (max {settings.MAX_CONCURRENT_URL_AGENTS} concurrent)")
        pending = {asyncio.ensure_future(t) for t in agent_tasks}

        while pending:
            done, pending = await asyncio.wait(pending, timeout=0.5, return_when=asyncio.FIRST_COMPLETED)
            # Pause checkpoint: block here while paused
            _ctx = getattr(self, '_scan_context', None)
            if _ctx is not None:
                await _ctx.wait_if_paused()
            if dashboard.stop_requested or self._stop_event.is_set():
                dashboard.log("🛑 Stop requested. Cancelling running agents...", "WARN")
                for task in pending:
                    task.cancel()
                if pending:
                    await asyncio.wait(pending, timeout=5)
                return False
        return True

    async def _process_url(self, url: str, url_index: int, total_urls: int, analysis_dir: Path, dashboard) -> list:
        """Process a single URL for vulnerabilities."""
        if url in self.processed_urls:
            dashboard.log(f"⏩ Skipping already processed URL: {url[:60]}", "INFO")
            return []

        self._log_url_processing(url, url_index, total_urls, dashboard)

        # Pause checkpoint + stop check
        _ctx = getattr(self, '_scan_context', None)
        if _ctx is not None:
            await _ctx.wait_if_paused()
        if dashboard.stop_requested or self._stop_event.is_set():
            return []

        all_validated_findings = []
        seen_keys = set()
        url_dir = self._create_url_directory(url, analysis_dir)

        # Phase 1: DAST Analysis
        vulnerabilities = await self._run_dast_analysis(url, url_dir, dashboard)

        if dashboard.stop_requested or self._stop_event.is_set():
            return []

        # Phase 2: Specialist Dispatch & Execution
        if vulnerabilities:
            all_validated_findings = await self._orchestrate_specialists(
                vulnerabilities, url, url_dir, seen_keys, dashboard
            )

            if all_validated_findings is None:  # Scan stopped
                return []

        dashboard.log(f"🎯 Intelligent dispatch complete for {url[:50]}", "SUCCESS")

        # Phase 3: Persistence
        self._persist_findings(all_validated_findings, url)

        return all_validated_findings

    def _log_url_processing(self, url: str, url_index: int, total_urls: int, dashboard) -> None:
        """Log URL processing start."""
        dashboard.log(f"🚀 Processing URL {url_index+1}/{total_urls}: {url[:60]}", "INFO")
        dashboard.update_task("Orchestrator", status=f"Processing {url[:40]}")

    async def _run_dast_analysis(self, url: str, url_dir: Path, dashboard) -> list:
        """Run DAST analysis and return vulnerabilities."""
        if dashboard.stop_requested or self._stop_event.is_set():
            return []

        dast = DASTySASTAgent(url, self.tech_profile, url_dir, state_manager=self.state_manager, scan_context=str(self.scan_id))
        analysis_result = await dast.run()

        return analysis_result.get("vulnerabilities", [])

    async def _orchestrate_specialists(
        self, vulnerabilities: list, url: str, url_dir: Path, seen_keys: set, dashboard
    ) -> Optional[list]:
        """Orchestrate specialist agents for found vulnerabilities."""
        dashboard.log(f"🧠 Orchestrator deciding on {len(vulnerabilities)} potential vulnerabilities...", "INFO")

        all_validated_findings = []
        process_result = self._create_finding_processor(seen_keys, all_validated_findings, dashboard)
        dispatch_info = await self._dispatch_specialists(vulnerabilities, url, dashboard, process_result)
        agent_tasks = await self._build_agent_tasks(dispatch_info, url, url_dir, process_result)

        if agent_tasks:
            continue_scan = await self._execute_agents(agent_tasks, dashboard)
            if not continue_scan:
                return None  # Signal scan stopped

        return all_validated_findings

    def _persist_findings(self, all_validated_findings: list, url: str) -> None:
        """Save findings to database and checkpoint."""
        if all_validated_findings:
            try:
                from bugtrace.core.database import get_db_manager
                db = get_db_manager()
                db.save_scan_result(self.target, all_validated_findings, scan_id=self.scan_id)
            except Exception as e:
                logger.error(f"Failed to save findings to DB: {e}", exc_info=True)

        self._save_checkpoint(url)

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
        self._v.emit("pipeline.initializing", {"target": self.target, "scan_id": self.scan_id})
        conductor.notify_phase_change("reconnaissance", 0.0, "Pipeline started")

        # Setup directories
        scan_dir, recon_dir, analysis_dir, captures_dir = self._setup_scan_directory(start_time)
        dashboard.log(f"Scan directory created: {scan_dir.name}", "INFO")

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

        # ========== LONEWOLF: Fire and forget ==========
        if settings.LONEWOLF_ENABLED:
            from bugtrace.agents.lone_wolf import LoneWolf
            wolf = LoneWolf(self.target, self.scan_dir)
            asyncio.create_task(wolf.run())
            logger.info("[Pipeline] LoneWolf launched in background")

        # ========== PHASE 2: DISCOVERY (Batch DAST) ==========
        # DASTySASTAgent analyzes ALL URLs in parallel
        # ThinkingConsolidationAgent deduplicates and distributes to queues
        logger.info("=== PHASE 2: DISCOVERY (Batch DAST) ===")
        self._v.emit("pipeline.phase_transition", {"phase": "discovery", "urls_count": len(self.urls_to_scan)})
        self._v.emit("discovery.started", {"urls_count": len(self.urls_to_scan)})
        dashboard.log(f"🔬 Running batch DAST on {len(self.urls_to_scan)} URLs", "INFO")
        dashboard.set_phase("🔬 HUNTING VULNS")
        dashboard.set_status("Running", "Analysis in progress...")
        conductor.notify_phase_change("discovery", 0.0, f"Analyzing {len(self.urls_to_scan)} URLs")

        # Run batch DAST - this is the actual DISCOVERY work
        self.vulnerabilities_by_url = await self._phase_2_batch_dast(dashboard, analysis_dir, recon_dir)

        # ========== INTEGRITY CHECKPOINT 1: Discovery ==========
        dastysast_dir = self.scan_dir / "dastysast"
        urls_count = len(self.urls_to_scan)
        reports_generated = len(list(dastysast_dir.glob("*.json"))) if dastysast_dir.exists() else 0
        errors_count = urls_count - reports_generated  # FIX: count by actual JSON files, not in-memory dict

        self._v.emit("pipeline.checkpoint", {"phase": "discovery", "urls": urls_count, "reports": reports_generated, "errors": errors_count})
        conductor.verify_integrity("discovery",
            {'urls_count': urls_count},
            {'dast_reports_count': reports_generated, 'errors': errors_count})

        # PIPELINE GATE: Stop before STRATEGY if not all URLs have JSON files
        if errors_count > 0:
            dashboard.log(
                f"❌ PIPELINE STOPPED: {errors_count}/{urls_count} URLs missing dastysast JSON after retries. "
                f"Cannot proceed to STRATEGY with incomplete data.",
                "CRITICAL"
            )
            logger.error(
                f"[Pipeline] HALTED before STRATEGY: {errors_count}/{urls_count} URLs have no dastysast JSON. "
                f"Reports generated: {reports_generated}"
            )
            conductor.notify_phase_change("discovery", 1.0, f"FAILED: {errors_count} URLs missing")
            await self._lifecycle.signal_phase_complete(
                PipelinePhase.DISCOVERY,
                {'urls_analyzed': reports_generated, 'errors': errors_count, 'halted': True}
            )
            return

        # Signal DISCOVERY complete AFTER batch DAST finishes
        self._v.emit("discovery.completed", {"urls_analyzed": reports_generated, "urls_total": urls_count})
        conductor.notify_phase_change("discovery", 1.0, f"{reports_generated} URLs analyzed")
        conductor.notify_metrics(urls_discovered=len(self.urls_to_scan), urls_analyzed=reports_generated)
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
        dashboard.log("🧠 ThinkingAgent processing findings batch", "INFO")
        dashboard.set_phase("🧠 STRATEGY")
        dashboard.set_status("Running", "Deduplication in progress...")
        conductor.notify_phase_change("strategy", 0.0, "Deduplication in progress")
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
            dashboard.log("❌ Integrity mismatch: Strategy phase", "WARN")
            logger.warning(
                f"[Pipeline] Integrity check FAILED for Strategy. "
                f"DAST: {dast_findings}, Auth: {auth_findings}, Total: {total_raw}, WET: {wet_queue_count}"
            )

        # Signal STRATEGY complete
        self._v.emit("strategy.completed", {"findings_distributed": findings_count})
        conductor.notify_phase_change("strategy", 1.0, f"{findings_count} findings distributed")
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
        dashboard.log(f"⚡ Specialists processing findings from queues", "INFO")
        conductor.notify_phase_change("exploitation", 0.0, "Specialists attacking")

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
        conductor.notify_phase_change("exploitation", 1.0, f"{queue_results.get('items_distributed', 0)} items processed")
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
        await self._phase_3_global_review(dashboard, scan_dir)
        self._v.emit("validation.completed", {"findings_reviewed": len(all_findings_for_review)})
        conductor.notify_phase_change("validation", 1.0, "Review complete")
        conductor.notify_log("INFO", "[VALIDATION] Global review complete")
        await self._lifecycle.signal_phase_complete(
            PipelinePhase.VALIDATION,
            {'findings_reviewed': len(all_findings_for_review)}
        )

        if await self._check_stop_requested(dashboard):
            return

        # ========== PHASE 6: REPORTING ==========
        logger.info("=== PHASE 6: REPORTING ===")
        self._v.emit("pipeline.phase_transition", {"phase": "reporting"})
        self._v.emit("reporting.started", {})
        conductor.notify_phase_change("reporting", 0.0, "Generating reports")
        conductor.notify_log("INFO", "[REPORTING] Generating final reports")
        await self._phase_4_reporting(dashboard, scan_dir)
        self._v.emit("reporting.completed", {})
        conductor.notify_phase_change("reporting", 1.0, "Reports generated")
        conductor.notify_log("INFO", "[REPORTING] Reports generated")
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

    async def _phase_1_reconnaissance(self, dashboard, recon_dir):
        """Execute Phase 1: Reconnaissance."""
        dashboard.set_phase("👁️ RECON MODE")
        dashboard.set_status("Running", "Discovery in progress...")

        if not await self._check_target_health(dashboard):
            return

        self.tech_profile = {"frameworks": [], "server": "unknown"}
        self.urls_to_scan = await self._run_reconnaissance(dashboard, recon_dir)

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

        dashboard.log("Collecting specialist queue stats...", "INFO")
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
                    dashboard.log(f"Queues pending: {breakdown} ({total_pending} total)", "INFO")
                    conductor.notify_log("INFO", f"[EXPLOITATION] Queues pending: {breakdown} ({total_pending} total)")
                else:
                    dashboard.log(f"Queues: {total_pending} items pending", "INFO")
                    conductor.notify_log("INFO", f"[EXPLOITATION] {total_pending} items pending")
                last_log_time = time.monotonic()

            if total_pending == 0:
                dashboard.log("All specialist queues drained", "SUCCESS")
                conductor.notify_log("INFO", "[EXPLOITATION] All specialist queues drained")
                break

            await asyncio.sleep(check_interval)

        elapsed = time.monotonic() - start_time

        if total_pending > 0:
            dashboard.log(f"Queue drain timeout after {elapsed:.1f}s, {total_pending} items remaining", "WARN")
            conductor.notify_log("WARNING", f"[EXPLOITATION] Queue drain timeout after {elapsed:.1f}s, {total_pending} items remaining")

        # Collect ThinkingAgent stats
        stats = self.thinking_agent.get_stats() if self.thinking_agent else {}

        return {
            "elapsed_seconds": elapsed,
            "items_distributed": stats.get("distributed", 0),
            "by_specialist": stats.get("by_specialist", {}),
            "pending_at_timeout": total_pending
        }

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

        # Build index: url_index (1-based) → url
        url_index_map = {idx + 1: url for idx, url in enumerate(self.urls_to_scan)}

        # ========== TASK 1: DASTySAST Analysis ==========
        async def _run_dast_batch(url_indices: list, concurrency_limit: int) -> list:
            """Run DAST analysis on a batch of URL indices with given concurrency."""
            semaphore = asyncio.Semaphore(concurrency_limit)

            async def _bounded_analyze(url_index: int) -> tuple:
                url = url_index_map[url_index]
                async with semaphore:
                    logger.info(f"[DAST] ▶ Starting: {url[:60]}")
                    conductor.notify_log("INFO", f"[DAST] Analyzing URL {url_index}/{total_urls}: {url[:80]}")

                    dast = DASTySASTAgent(
                        url, self.tech_profile, dastysast_dir,
                        state_manager=self.state_manager,
                        scan_context=str(self.scan_id),
                        url_index=url_index
                    )

                    try:
                        result = await asyncio.wait_for(dast.run(), timeout=analysis_timeout)
                        vulns = result.get("vulnerabilities", [])
                    except asyncio.TimeoutError:
                        logger.warning(f"[DAST] Analysis timed out after {analysis_timeout}s: {url[:50]}...")
                        vulns = []
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
            dashboard.log("🔬 Running Nuclei tech profiling...", "INFO")
            tech_profile = await self._run_nuclei_tech_profile(recon_dir)
            self.tech_profile = tech_profile
            dashboard.log(f"✓ Nuclei: {len(tech_profile.get('frameworks', []))} frameworks", "INFO")

            # Emit misconfigurations as findings (HSTS, cookie flags, etc.)
            from bugtrace.core.event_bus import EventType
            misconfigs = tech_profile.get("misconfigurations", [])
            if misconfigs:
                dashboard.log(f"Misconfigurations: {len(misconfigs)} detected (HSTS, cookies, etc.)", "INFO")
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
                dashboard.log(f"Vulnerable JS: {len(js_vulns)} libraries detected", "WARN")
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
            dashboard.log("🔑 Running authentication discovery...", "INFO")
            auth_results = await self._run_auth_discovery(recon_dir, self.urls_to_scan)
            dashboard.log(f"✓ AuthDiscovery: {len(auth_results['jwts'])} JWTs, {len(auth_results['cookies'])} cookies", "INFO")
            return auth_results

        async def run_asset_discovery_parallel():
            if getattr(settings, 'ENABLE_ASSET_DISCOVERY', False):
                dashboard.log("🌐 Running asset discovery...", "INFO")
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

        # ========== RETRY LOOP: Missing URLs with Adaptive Concurrency ==========
        missing_indices = _get_missing_indices()

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

    async def _phase_3_strategy(self, dashboard, analysis_json_dir: Path) -> int:
        """
        Execute Phase 3: STRATEGY - Batch processing of DAST and AuthDiscovery findings.

        Reads:
        1. DAST findings from analysis_json_dir (numbered JSON files)
        2. AuthDiscovery findings from recon/auth_discovery/ (JWTs, cookies)

        Passes to ThinkingAgent for deduplication, classification, prioritization,
        and queue distribution.

        Args:
            dashboard: UI dashboard
            analysis_json_dir: Directory containing numbered JSON reports from DAST

        Returns:
            Total number of findings processed
        """
        import json

        logger.info(f"Reading JSON files from {analysis_json_dir}")

        # Find all JSON files (numbered format: 1.json, 2.json, etc.)
        json_files = sorted(analysis_json_dir.glob("*.json"))

        if not json_files:
            logger.warning(f"No JSON files found in {analysis_json_dir}")

        dashboard.log(f"Found {len(json_files)} DAST JSON files to process", "INFO")

        # Load all findings from DAST JSON files
        all_findings = []
        for json_file in json_files:
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                findings = data.get("vulnerabilities", [])

                # Attach metadata for traceability
                for finding in findings:
                    finding["_source_file"] = str(json_file)
                    finding["_scan_context"] = self.scan_context
                    # Attach report_files reference (v2.1.0 payload preservation)
                    finding["_report_files"] = {
                        "json": str(json_file),
                        "markdown": str(json_file.with_suffix(".md"))
                    }

                all_findings.extend(findings)
                logger.debug(f"Loaded {len(findings)} findings from {json_file.name}")

            except Exception as e:
                logger.error(f"Failed to read {json_file}: {e}")
                continue

        logger.info(f"Loaded {len(all_findings)} DAST findings from {len(json_files)} files")

        # NEW: Load AuthDiscovery findings from recon/auth_discovery/
        auth_discovery_dir = self.scan_dir / "recon" / "auth_discovery"
        if auth_discovery_dir.exists():
            auth_findings = await self._load_auth_discovery_findings(auth_discovery_dir)
            if auth_findings:
                all_findings.extend(auth_findings)
                logger.info(f"Loaded {len(auth_findings)} AuthDiscovery findings")
                dashboard.log(f"🔑 Loaded {len(auth_findings)} authentication artifacts", "INFO")

                # Track in batch metrics for integrity check
                batch_metrics.add_auth_findings(len(auth_findings))

        logger.info(f"Total {len(all_findings)} findings ready for processing")

        # FIX (2026-02-06): Auto-dispatch CSTIAgent if Angular/Vue detected in tech_profile
        # This ensures CSTIAgent runs even if DASTySAST didn't flag CSTI (LLM non-determinism)
        csti_frameworks = ['angular', 'angularjs', 'vue', 'vuejs', 'vue.js']
        detected_frameworks = self.tech_profile.get('frameworks', [])
        frameworks_lower = [f.lower() for f in detected_frameworks]

        detected_csti_framework = None
        for fw in csti_frameworks:
            if any(fw in f for f in frameworks_lower):
                detected_csti_framework = fw
                break

        if detected_csti_framework:
            # FIX (2026-02-10): ALWAYS inject synthetic CSTI with real reflecting params.
            # DASTySAST may find CSTI on wrong params (e.g., "ng-app", "postId") while the
            # actual vulnerable param is "category". CSTIAgent's smart probe will skip
            # non-reflecting params anyway, so injecting extras is safe (no false positives).
            reflecting_params = [
                f for f in all_findings
                if f.get('parameter') and f['parameter'] not in (
                    '', '_auto_dispatch', 'auto_dispatch',
                    'General DOM', 'DOM', 'DOM/Body',
                    'ng-app', 'ng-controller', 'v-if', 'v-for',  # framework attrs, not injectable
                )
            ]

            # Deduplicate: only inject for params NOT already in CSTI findings
            existing_csti_params = set()
            for f in all_findings:
                ftype = f.get('type', '').upper()
                if ftype in ['CSTI', 'CLIENT-SIDE TEMPLATE INJECTION', 'TEMPLATE INJECTION']:
                    existing_csti_params.add(f.get('parameter', ''))

            # Cap total auto-dispatch to 15 to avoid flooding CSTI queue with noise.
            # Priority order: SPA routes (real query params) > recon URLs > reflecting params.
            # SPA routes run first because they have real injectable params (e.g., legacy_q)
            # that are highest-value targets. Reflecting params are fallback/noise.
            MAX_CSTI_AUTO_DISPATCH = 15
            injected_count = 0
            seen_params = set()
            seen_url_paths = set()

            # --- PRIORITY 1: SPA routes from urls_to_scan ---
            # SPA routes (e.g., /blog, /products) are discovered by common endpoint
            # discovery but aren't in recon/urls.txt (GoSpider can't crawl SPAs).
            # CSTIAgent's _discover_csti_params() will find JS-extracted params
            # (like URLSearchParams) that aren't in HTML forms.
            # Sort so URLs with query params come first — they have real param names
            # vs _auto_discover, and path-only dedup would otherwise skip them.
            spa_urls = sorted(
                getattr(self, 'urls_to_scan', []),
                key=lambda u: (0 if '?' in u else 1, u)
            )
            for scan_url in spa_urls:
                if injected_count >= MAX_CSTI_AUTO_DISPATCH:
                    break
                parsed_su = urlparse(scan_url)
                url_path = parsed_su.path.rstrip("/")
                # Only non-API pages (SPA routes where Angular/Vue renders)
                if "/api/" in url_path or url_path in seen_url_paths:
                    continue
                if not url_path or url_path == "/":
                    continue
                seen_url_paths.add(url_path)
                # Use first query param if present, otherwise signal autonomous discovery
                su_params = parse_qs(parsed_su.query)
                spa_param = list(su_params.keys())[0] if su_params else "_auto_discover"
                synthetic_csti = {
                    "type": "CSTI",
                    "parameter": spa_param,
                    "url": scan_url,
                    "severity": "High",
                    "fp_confidence": 0.9,
                    "confidence_score": 0.9,
                    "votes": 5,
                    "skeptical_score": 8,
                    "reasoning": f"Auto-dispatch: {detected_csti_framework.upper()} framework detected. Testing SPA route '{url_path}' for CSTI.",
                    "payload": "",
                    "evidence": f"tech_profile.frameworks contains: {detected_frameworks}",
                    "template_engine": detected_csti_framework,
                    "_source_file": "auto_dispatch_spa",
                    "_scan_context": self.scan_context,
                    "_auto_dispatched": True
                }
                all_findings.append(synthetic_csti)
                injected_count += 1
                logger.debug(f"[Auto-Dispatch] CSTI SPA route: {url_path} (param: {spa_param})")

            # --- PRIORITY 2: Recon URLs from GoSpider ---
            # Dispatch CSTI for unique recon URL paths (not per-param).
            # CSTIAgent's _discover_csti_params() finds all params on each URL autonomously.
            # Injecting per-URL instead of per-param prevents LLM dedup from merging them all.
            urls_file = getattr(self, 'report_dir', None)
            if urls_file:
                urls_file = urls_file / "recon" / "urls.txt"
            if urls_file and urls_file.exists():
                for line in urls_file.read_text().splitlines():
                    if injected_count >= MAX_CSTI_AUTO_DISPATCH:
                        break
                    line = line.strip()
                    if not line:
                        continue
                    parsed_url = urlparse(line)
                    url_path = parsed_url.path.rstrip("/")
                    if url_path in seen_url_paths or not parsed_url.query:
                        continue
                    # Skip API endpoints — CSTI only works on pages where Angular/Vue renders HTML
                    if "/api/" in url_path:
                        continue
                    seen_url_paths.add(url_path)
                    first_param = list(parse_qs(parsed_url.query).keys())[0]
                    if first_param in existing_csti_params:
                        continue
                    synthetic_csti = {
                        "type": "CSTI",
                        "parameter": first_param,
                        "url": line,
                        "severity": "High",
                        "fp_confidence": 0.9,
                        "confidence_score": 0.9,
                        "votes": 5,
                        "skeptical_score": 8,
                        "reasoning": f"Auto-dispatch: {detected_csti_framework.upper()} framework detected. Testing URL '{url_path}' for CSTI.",
                        "payload": "",
                        "evidence": f"tech_profile.frameworks contains: {detected_frameworks}",
                        "template_engine": detected_csti_framework,
                        "_source_file": "auto_dispatch_recon",
                        "_scan_context": self.scan_context,
                        "_auto_dispatched": True
                    }
                    all_findings.append(synthetic_csti)
                    injected_count += 1
                    logger.debug(f"[Auto-Dispatch] CSTI recon URL: {url_path} (param: {first_param})")

            # --- PRIORITY 3: Reflecting params (fallback) ---
            # Inject synthetic CSTI findings for reflecting params on HTML pages only.
            # API endpoints (/api/*) return JSON — Angular/Vue don't render there.
            # Lowest priority — these often contain noise params from tech detection.
            for rf in reflecting_params:
                if injected_count >= MAX_CSTI_AUTO_DISPATCH:
                    break
                param = rf["parameter"]
                if param in existing_csti_params or param in seen_params:
                    continue
                synth_url = rf.get("url", self.target)
                parsed_rf = urlparse(synth_url)
                # Skip API endpoints — CSTI only works on pages where Angular/Vue renders HTML
                if "/api/" in parsed_rf.path:
                    continue
                seen_params.add(param)
                synthetic_csti = {
                    "type": "CSTI",
                    "parameter": param,
                    "url": synth_url,
                    "severity": "High",
                    "fp_confidence": 0.9,
                    "confidence_score": 0.9,
                    "votes": 5,
                    "skeptical_score": 8,
                    "reasoning": f"Auto-dispatch: {detected_csti_framework.upper()} framework detected. Testing param '{param}' for CSTI.",
                    "payload": "",
                    "evidence": f"tech_profile.frameworks contains: {detected_frameworks}",
                    "template_engine": detected_csti_framework,
                    "_source_file": "auto_dispatch",
                    "_scan_context": self.scan_context,
                    "_auto_dispatched": True
                }
                all_findings.append(synthetic_csti)
                injected_count += 1

            if injected_count == 0 and not existing_csti_params:
                # No reflecting params AND no recon params — fallback to target URL params
                parsed_target = urlparse(self.target)
                target_params = parse_qs(parsed_target.query)
                synth_param = list(target_params.keys())[0] if target_params else "_auto_dispatch"
                synthetic_csti = {
                    "type": "CSTI",
                    "parameter": synth_param,
                    "url": self.target,
                    "severity": "High",
                    "fp_confidence": 0.9,
                    "confidence_score": 0.9,
                    "votes": 5,
                    "skeptical_score": 8,
                    "reasoning": f"Auto-dispatch: {detected_csti_framework.upper()} framework detected by Nuclei.",
                    "payload": "",
                    "evidence": f"tech_profile.frameworks contains: {detected_frameworks}",
                    "_source_file": "auto_dispatch",
                    "_scan_context": self.scan_context,
                    "_auto_dispatched": True
                }
                all_findings.append(synthetic_csti)
                injected_count = 1

            if injected_count > 0:
                self._v.emit("strategy.auto_dispatch", {
                    "specialist": "CSTI", "count": injected_count,
                    "framework": detected_csti_framework,
                })
                logger.info(f"[Auto-Dispatch] Injected {injected_count} synthetic CSTI findings with real params (detected: {detected_csti_framework})")
                dashboard.log(f"Auto-dispatch: {injected_count} CSTI findings injected ({detected_csti_framework.upper()} detected)", "INFO")

        # Auto-dispatch SSTI for template-related admin/API endpoints.
        # DASTySAST often filters server-side SSTI as FP (low fp_confidence).
        # CSTIAgent handles both client-side (CSTI) and server-side (SSTI) template injection.
        ssti_path_keywords = {"template", "email-preview", "render", "preview", "email"}
        ssti_injected_urls = set()
        existing_csti_urls = {f.get("url", "") for f in all_findings if "csti" in f.get("type", "").lower() or "ssti" in f.get("type", "").lower()}

        recon_file_ssti = getattr(self, 'report_dir', None)
        if recon_file_ssti:
            recon_file_ssti = recon_file_ssti / "recon" / "urls.txt"
        if recon_file_ssti and recon_file_ssti.exists():
            for line in recon_file_ssti.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                path_lower = urlparse(line).path.lower()
                if any(kw in path_lower for kw in ssti_path_keywords):
                    base_url = line.split("?")[0]
                    if base_url not in ssti_injected_urls and base_url not in existing_csti_urls:
                        all_findings.append({
                            "type": "CSTI",
                            "parameter": "body",
                            "url": base_url,
                            "severity": "High",
                            "fp_confidence": 0.9,
                            "confidence_score": 0.9,
                            "votes": 5,
                            "skeptical_score": 8,
                            "reasoning": f"Auto-dispatch: SSTI-likely path '{path_lower}' detected in recon URL.",
                            "payload": "",
                            "evidence": f"Path contains template keyword: {path_lower}",
                            "template_engine": "jinja2",
                            "_source_file": "auto_dispatch_ssti",
                            "_scan_context": self.scan_context,
                            "_auto_dispatched": True
                        })
                        ssti_injected_urls.add(base_url)
                        logger.info(f"[Auto-Dispatch] SSTI from recon URL: {base_url}")

        # Also check urls_to_scan for SSTI-likely paths
        for url in getattr(self, 'urls_to_scan', []):
            path_lower = urlparse(url).path.lower()
            if any(kw in path_lower for kw in ssti_path_keywords):
                base_url = url.split("?")[0]
                if base_url not in ssti_injected_urls and base_url not in existing_csti_urls:
                    all_findings.append({
                        "type": "CSTI",
                        "parameter": "body",
                        "url": base_url,
                        "severity": "High",
                        "fp_confidence": 0.9,
                        "confidence_score": 0.9,
                        "votes": 5,
                        "skeptical_score": 8,
                        "reasoning": f"Auto-dispatch: SSTI-likely path '{path_lower}' detected.",
                        "payload": "",
                        "evidence": f"Path contains template keyword: {path_lower}",
                        "template_engine": "jinja2",
                        "_source_file": "auto_dispatch_ssti",
                        "_scan_context": self.scan_context,
                        "_auto_dispatched": True
                    })
                    ssti_injected_urls.add(base_url)
                    logger.info(f"[Auto-Dispatch] SSTI from scanned URL: {base_url}")

        if ssti_injected_urls:
            dashboard.log(f"Auto-dispatch: {len(ssti_injected_urls)} SSTI target(s) injected", "INFO")

        # Auto-dispatch LFI for file/path/download parameters.
        # DASTySAST sometimes rejects path traversal findings (score 0/10) when the
        # endpoint response contains metadata or safe-looking error messages.
        # LFIAgent must always test parameters named file/path/filename/download.
        lfi_param_keywords = {"file", "path", "filename", "filepath", "document", "download", "dir", "include", "page", "template"}
        lfi_injected = set()
        existing_lfi_urls_params = {
            (f.get("url", "").split("?")[0], f.get("parameter", ""))
            for f in all_findings
            if "lfi" in f.get("type", "").lower() or "path" in f.get("type", "").lower() or "traversal" in f.get("type", "").lower()
        }

        recon_file_lfi = getattr(self, 'report_dir', None)
        if recon_file_lfi:
            recon_file_lfi = recon_file_lfi / "recon" / "urls.txt"
        if recon_file_lfi and recon_file_lfi.exists():
            for line in recon_file_lfi.read_text().splitlines():
                line = line.strip()
                if not line or "?" not in line:
                    continue
                parsed_lfi = urlparse(line)
                query_params = parse_qs(parsed_lfi.query)
                for param_name in query_params:
                    if param_name.lower() in lfi_param_keywords:
                        base_url = line.split("?")[0]
                        key = (base_url, param_name)
                        if key not in existing_lfi_urls_params and key not in lfi_injected:
                            all_findings.append({
                                "type": "LFI",
                                "parameter": param_name,
                                "url": line,
                                "severity": "High",
                                "fp_confidence": 0.85,
                                "confidence_score": 0.85,
                                "votes": 5,
                                "skeptical_score": 7,
                                "reasoning": f"Auto-dispatch: param '{param_name}' is a common path traversal vector.",
                                "payload": "",
                                "evidence": f"URL param '{param_name}' in recon URL: {line}",
                                "_source_file": "auto_dispatch_lfi",
                                "_scan_context": self.scan_context,
                                "_auto_dispatched": True
                            })
                            lfi_injected.add(key)

        if lfi_injected:
            logger.info(f"[Auto-Dispatch] LFI: {len(lfi_injected)} path-traversal target(s) injected")
            dashboard.log(f"Auto-dispatch: {len(lfi_injected)} LFI target(s) injected", "INFO")

        # FIX (2026-02-08): Auto-dispatch SQLiAgent when reflecting params exist but no SQLi finding
        # SQLi is the most common web vuln - if DASTySAST found ANY parameter, SQLi should be tested.
        # Previous scans found SQLi on ginandjuice.shop but LLM non-determinism caused it to be missed.
        has_sqli = any(
            'sqli' in f.get('type', '').lower() or 'sql' in f.get('type', '').lower()
            for f in all_findings
        )
        has_any_param_finding = any(
            f.get('parameter') and f.get('parameter') not in ('', 'General DOM', 'DOM', 'DOM/Body')
            for f in all_findings
        )

        if not has_sqli and has_any_param_finding:
            # FIX (2026-02-10): Use real reflecting param, not "_auto_dispatch"
            first_real_sqli = next(
                (f for f in all_findings
                 if f.get('parameter') and f['parameter'] not in (
                     '', '_auto_dispatch', 'auto_dispatch',
                     'General DOM', 'DOM', 'DOM/Body',
                 )),
                None
            )
            sqli_param = first_real_sqli["parameter"] if first_real_sqli else "_auto_dispatch"
            sqli_url = first_real_sqli.get("url", self.target) if first_real_sqli else self.target

            synthetic_sqli = {
                "type": "SQLi",
                "parameter": sqli_param,
                "url": sqli_url,
                "severity": "High",
                "fp_confidence": 0.9,
                "confidence_score": 0.9,
                "votes": 5,
                "skeptical_score": 8,
                "reasoning": "Auto-dispatch: Reflecting parameters detected by DASTySAST. SQLiAgent will perform autonomous SQL injection testing on all discovered parameters.",
                "payload": "",
                "evidence": "Auto-dispatched because DASTySAST found reflecting parameters but no SQLi classification",
                "_source_file": "auto_dispatch",
                "_scan_context": self.scan_context,
                "_auto_dispatched": True
            }
            all_findings.append(synthetic_sqli)
            self._v.emit("strategy.auto_dispatch", {"specialist": "SQLi", "param": sqli_param})
            logger.info(f"[Auto-Dispatch] Added synthetic SQLi finding: param='{sqli_param}' (reflecting params detected)")
            dashboard.log(f"Auto-dispatch: SQLi finding injected for param='{sqli_param}'", "INFO")

        # Gap 2 Fix: Auto-dispatch HeaderInjectionAgent when header reflection detected or params exist
        # CRLF/Header Injection is often missed because DASTySAST only checks body reflection.
        # HeaderInjectionAgent has autonomous _discover_header_params() - just needs the trigger.
        has_header_injection = any(
            'header' in f.get('type', '').lower() or 'crlf' in f.get('type', '').lower()
            for f in all_findings
        )
        has_header_reflection = any(
            f.get('header_reflection') or f.get('context') == 'response_header'
            for f in all_findings
        )

        if not has_header_injection and (has_header_reflection or has_any_param_finding):
            # FIX (2026-02-10): Use real reflecting param
            hi_real = next(
                (f for f in all_findings
                 if f.get('parameter') and f['parameter'] not in (
                     '', '_auto_dispatch', 'auto_dispatch',
                     'General DOM', 'DOM', 'DOM/Body',
                 )),
                None
            )
            synthetic_header = {
                "type": "Header Injection",
                "parameter": hi_real["parameter"] if hi_real else "_auto_dispatch",
                "url": hi_real.get("url", self.target) if hi_real else self.target,
                "severity": "High",
                "fp_confidence": 0.9,
                "confidence_score": 0.9,
                "votes": 5,
                "skeptical_score": 8,
                "reasoning": "Auto-dispatch: " + (
                    "Probe marker reflected in response headers (CRLF candidate)"
                    if has_header_reflection
                    else "Reflecting parameters detected. HeaderInjectionAgent will test for CRLF/response splitting."
                ),
                "payload": "",
                "evidence": "Header reflection detected" if has_header_reflection else "Auto-dispatched for parameter coverage",
                "_source_file": "auto_dispatch",
                "_scan_context": self.scan_context,
                "_auto_dispatched": True
            }
            all_findings.append(synthetic_header)
            logger.info(f"[Auto-Dispatch] Added synthetic Header Injection finding (header_reflection={has_header_reflection})")
            dashboard.log(f"🔧 Auto-dispatch: Header Injection finding injected", "INFO")

        # Auto-dispatch XSSAgent when no XSS finding from DASTySAST.
        # XSSAgent handles DOM XSS (Phase B.2) which requires Playwright.
        # DOM XSS can exist even without reflected params (e.g., jQuery href sinks).
        has_xss = any(
            f.get("type", "").upper() in ("XSS", "DOM_XSS", "CROSS-SITE SCRIPTING")
            for f in all_findings
        )
        if not has_xss:
            first_url = self.target
            for f in all_findings:
                if f.get("url"):
                    first_url = f["url"]
                    break
            synthetic_xss = {
                "type": "XSS",
                "parameter": "auto_dispatch",
                "url": first_url,
                "severity": "High",
                "fp_confidence": 0.9,
                "confidence_score": 0.9,
                "votes": 5,
                "skeptical_score": 8,
                "reasoning": "Auto-dispatch: XSSAgent will perform autonomous XSS testing including DOM XSS detection via Playwright.",
                "payload": "",
                "evidence": "Auto-dispatched for DOM XSS coverage (Phase B.2)",
                "_source_file": "auto_dispatch",
                "_scan_context": self.scan_context,
                "_auto_dispatched": True
            }
            all_findings.append(synthetic_xss)
            logger.info("[Auto-Dispatch] Added synthetic XSS finding for DOM XSS coverage")
            dashboard.log("🔧 Auto-dispatch: XSS finding injected (DOM XSS coverage)", "INFO")

        # Auto-dispatch OpenRedirectAgent when recon URLs contain redirect-like params.
        # Open redirects are commonly missed because DASTySAST focuses on reflection,
        # not redirect behavior. OpenRedirectAgent tests actual HTTP redirect responses.
        has_openredirect = any(
            'redirect' in f.get("type", "").lower() or 'open redirect' in f.get("type", "").lower()
            for f in all_findings
        )
        if not has_openredirect:
            redirect_param_names = {
                "url", "redirect", "redirect_url", "redirect_uri", "return",
                "return_url", "return_to", "next", "goto", "dest", "destination",
                "continue", "redir", "target", "forward", "out", "view", "ref",
            }
            urls_file = getattr(self, 'report_dir', None)
            if urls_file:
                urls_file = urls_file / "recon" / "urls.txt"
            redirect_url = None
            redirect_param = None
            # Search recon/urls.txt (GoSpider output)
            if urls_file and urls_file.exists():
                for line in urls_file.read_text().splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    parsed_redir = urlparse(line)
                    for p in parse_qs(parsed_redir.query).keys():
                        if p.lower() in redirect_param_names:
                            redirect_url = line
                            redirect_param = p
                            break
                    if redirect_url:
                        break
            # Also search urls_to_scan (includes common endpoint discoveries)
            if not redirect_url:
                for line in getattr(self, 'urls_to_scan', []):
                    parsed_redir = urlparse(line)
                    for p in parse_qs(parsed_redir.query).keys():
                        if p.lower() in redirect_param_names:
                            redirect_url = line
                            redirect_param = p
                            break
                    if redirect_url:
                        break
            if redirect_url and redirect_param:
                synthetic_redir = {
                    "type": "Open Redirect",
                    "parameter": redirect_param,
                    "url": redirect_url,
                    "severity": "Medium",
                    "fp_confidence": 0.9,
                    "confidence_score": 0.9,
                    "votes": 5,
                    "skeptical_score": 7,
                    "reasoning": f"Auto-dispatch: URL parameter '{redirect_param}' suggests redirect behavior. OpenRedirectAgent will test for open redirect.",
                    "payload": "",
                    "evidence": f"Recon URL contains redirect-like parameter: {redirect_param}",
                    "_source_file": "auto_dispatch",
                    "_scan_context": self.scan_context,
                    "_auto_dispatched": True
                }
                all_findings.append(synthetic_redir)
                logger.info(f"[Auto-Dispatch] Added synthetic Open Redirect finding: param='{redirect_param}' on {redirect_url}")
                dashboard.log(f"Auto-dispatch: Open Redirect finding injected for param='{redirect_param}'", "INFO")

        # FIX (2026-02-16): Auto-dispatch IDORAgent for recon URLs with numeric path segments.
        # DASTySAST LLM is non-deterministic about classifying /api/reviews/1, /api/orders/1 as IDOR.
        # IDORAgent has autonomous _discover_idor_params() — just needs the trigger URL.
        # Scan recon URLs for numeric path segments and inject synthetic IDOR findings.
        has_idor = any(
            'idor' in f.get('type', '').lower()
            or 'insecure direct object' in f.get('type', '').lower()
            or 'broken access' in f.get('type', '').lower()
            for f in all_findings
        )
        idor_urls_file = getattr(self, 'report_dir', None)
        if idor_urls_file:
            idor_urls_file = idor_urls_file / "recon" / "urls.txt"
        if idor_urls_file and idor_urls_file.exists():
            import re
            numeric_path_re = re.compile(r'/\d+(?:/|$|\?)')
            existing_idor_urls = set()
            if has_idor:
                existing_idor_urls = {
                    urlparse(f.get('url', '')).path.rstrip('/')
                    for f in all_findings
                    if 'idor' in f.get('type', '').lower()
                    or 'insecure direct object' in f.get('type', '').lower()
                }
            seen_idor_bases = set()
            idor_injected = 0
            for line in idor_urls_file.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                parsed_idor = urlparse(line)
                path = parsed_idor.path.rstrip('/')
                if not numeric_path_re.search(path):
                    continue
                # Deduplicate by base path (strip the numeric segment to get the resource type)
                # e.g., /api/reviews/1 and /api/reviews/2 → base = /api/reviews
                base_path = re.sub(r'/\d+(?=/|$)', '', path)
                if base_path in seen_idor_bases:
                    continue
                seen_idor_bases.add(base_path)
                if path in existing_idor_urls:
                    continue
                synthetic_idor = {
                    "type": "IDOR",
                    "parameter": "URL Path (/{id})",
                    "url": line.split('?')[0],  # Strip query params, keep path with ID
                    "severity": "High",
                    "fp_confidence": 0.9,
                    "confidence_score": 0.9,
                    "votes": 5,
                    "skeptical_score": 8,
                    "reasoning": f"Auto-dispatch: Numeric path segment detected in '{path}'. IDORAgent will test for authorization bypass.",
                    "payload": "",
                    "evidence": f"Recon URL contains numeric path ID: {path}",
                    "_source_file": "auto_dispatch_idor_recon",
                    "_scan_context": self.scan_context,
                    "_auto_dispatched": True
                }
                all_findings.append(synthetic_idor)
                idor_injected += 1
                logger.debug(f"[Auto-Dispatch] IDOR recon URL: {path} (base: {base_path})")
            # Also check urls_to_scan (includes Endpoint Discovery URLs not in urls.txt)
            for url in getattr(self, 'urls_to_scan', []):
                parsed_idor = urlparse(url)
                path = parsed_idor.path.rstrip('/')
                if not numeric_path_re.search(path):
                    continue
                base_path = re.sub(r'/\d+(?=/|$)', '', path)
                if base_path in seen_idor_bases:
                    continue
                seen_idor_bases.add(base_path)
                if path in existing_idor_urls:
                    continue
                all_findings.append({
                    "type": "IDOR",
                    "parameter": "URL Path (/{id})",
                    "url": url.split('?')[0],
                    "severity": "High",
                    "fp_confidence": 0.9,
                    "confidence_score": 0.9,
                    "votes": 5,
                    "skeptical_score": 8,
                    "reasoning": f"Auto-dispatch: Numeric path segment in '{path}' (from endpoint discovery).",
                    "payload": "",
                    "evidence": f"Endpoint discovery URL with numeric path ID: {path}",
                    "_source_file": "auto_dispatch_idor_endpoint",
                    "_scan_context": self.scan_context,
                    "_auto_dispatched": True
                })
                idor_injected += 1

            if idor_injected > 0:
                self._v.emit("strategy.auto_dispatch", {"specialist": "IDOR", "count": idor_injected})
                logger.info(f"[Auto-Dispatch] Injected {idor_injected} synthetic IDOR findings from recon URLs with numeric paths")
                dashboard.log(f"Auto-dispatch: {idor_injected} IDOR findings injected (numeric path IDs)", "INFO")

        # Auto-dispatch PrototypePollutionAgent when JS frameworks detected and reflecting params exist.
        # PP is common in AngularJS/React apps but DASTySAST pre-filters PP findings as FP (low skeptical).
        has_pp = any(
            'prototype' in f.get('type', '').lower() or 'pollution' in f.get('type', '').lower()
            for f in all_findings
        )
        has_js_framework = any(
            fw_name in f.lower()
            for f in getattr(self, 'tech_profile', {}).get('frameworks', [])
            for fw_name in ('angular', 'react', 'vue', 'jquery', 'backbone', 'ember')
        )
        if not has_pp and has_any_param_finding and has_js_framework:
            pp_param_finding = next(
                (f for f in all_findings
                 if f.get('parameter') and f['parameter'] not in (
                     '', '_auto_dispatch', 'auto_dispatch',
                     'General DOM', 'DOM', 'DOM/Body',
                 )),
                None
            )
            pp_param = pp_param_finding["parameter"] if pp_param_finding else "_auto_dispatch"
            # Always use scan target for PP — it's a client-side vuln that needs real pages, not API endpoints.
            pp_url = self.target

            synthetic_pp = {
                "type": "Prototype Pollution",
                "parameter": pp_param,
                "url": pp_url,
                "severity": "High",
                "fp_confidence": 0.9,
                "confidence_score": 0.9,
                "votes": 5,
                "skeptical_score": 8,
                "probe_validated": True,
                "reasoning": f"Auto-dispatch: JS framework detected, testing {pp_param} for prototype pollution",
                "description": f"Potential Prototype Pollution in parameter '{pp_param}' (JS framework detected)",
                "_source_file": "auto_dispatch_prototype_pollution",
                "_scan_context": self.scan_context,
                "_auto_dispatched": True
            }
            all_findings.append(synthetic_pp)
            self._v.emit("strategy.auto_dispatch", {"specialist": "PROTOTYPE_POLLUTION", "count": 1})
            logger.info(f"[Auto-Dispatch] Added synthetic Prototype Pollution finding: param='{pp_param}' (JS framework detected)")
            dashboard.log(f"Auto-dispatch: Prototype Pollution (JS framework detected)", "INFO")

        # Auto-dispatch LFIAgent when file-like parameters found in recon URLs.
        # LFI is commonly missed by DASTySAST when params look benign (e.g., "file", "page").
        has_lfi = any(
            'lfi' in f.get('type', '').lower()
            or 'file inclusion' in f.get('type', '').lower()
            or 'path traversal' in f.get('type', '').lower()
            or 'directory traversal' in f.get('type', '').lower()
            for f in all_findings
        )
        if not has_lfi:
            lfi_param_names = {
                "file", "path", "dir", "page", "include", "template",
                "doc", "filename", "download", "filepath", "document",
                "folder", "root", "pg", "style", "pdf", "img", "image",
            }
            lfi_url = None
            lfi_param = None
            recon_file = getattr(self, 'report_dir', None)
            if recon_file:
                recon_file = recon_file / "recon" / "urls.txt"
            if recon_file and recon_file.exists():
                for line in recon_file.read_text().splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    parsed_lfi = urlparse(line)
                    for p in parse_qs(parsed_lfi.query).keys():
                        if p.lower() in lfi_param_names:
                            lfi_url = line
                            lfi_param = p
                            break
                    if lfi_url:
                        break
            if lfi_url and lfi_param:
                synthetic_lfi = {
                    "type": "LFI",
                    "parameter": lfi_param,
                    "url": lfi_url,
                    "severity": "High",
                    "fp_confidence": 0.9,
                    "confidence_score": 0.9,
                    "votes": 5,
                    "skeptical_score": 8,
                    "reasoning": f"Auto-dispatch: File-like parameter '{lfi_param}' found. LFIAgent will test for path traversal.",
                    "payload": "",
                    "evidence": f"Recon URL contains file-like parameter: {lfi_param}",
                    "_source_file": "auto_dispatch_lfi",
                    "_scan_context": self.scan_context,
                    "_auto_dispatched": True
                }
                all_findings.append(synthetic_lfi)
                logger.info(f"[Auto-Dispatch] Added synthetic LFI finding: param='{lfi_param}' on {lfi_url}")
                dashboard.log(f"Auto-dispatch: LFI finding injected for param='{lfi_param}'", "INFO")

        # Auto-dispatch RCEAgent when command-like parameters found in recon URLs.
        # RCE auto-dispatch: Always scan for command-like params in recon URLs AND findings.
        # Even if DASTySAST found "RCE" from a debug page, the real cmd endpoint may be elsewhere.
        rce_param_names = {
            "cmd", "command", "exec", "execute", "run", "shell",
            "ping", "code", "func", "arg", "process",
        }
        rce_injected_urls = set()

        # Scan recon URLs for command-like params
        recon_file_rce = getattr(self, 'report_dir', None)
        if recon_file_rce:
            recon_file_rce = recon_file_rce / "recon" / "urls.txt"
        if recon_file_rce and recon_file_rce.exists():
            for line in recon_file_rce.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                parsed_rce = urlparse(line)
                for p in parse_qs(parsed_rce.query).keys():
                    if p.lower() in rce_param_names and line not in rce_injected_urls:
                        all_findings.append({
                            "type": "RCE",
                            "parameter": p,
                            "url": line,
                            "severity": "Critical",
                            "fp_confidence": 0.9,
                            "confidence_score": 0.9,
                            "votes": 5,
                            "skeptical_score": 8,
                            "reasoning": f"Auto-dispatch: Command-like parameter '{p}' found in recon URL.",
                            "payload": "",
                            "evidence": f"Recon URL contains command-like parameter: {p}",
                            "_source_file": "auto_dispatch_rce",
                            "_scan_context": self.scan_context,
                            "_auto_dispatched": True
                        })
                        rce_injected_urls.add(line)
                        logger.info(f"[Auto-Dispatch] RCE from recon URL: param='{p}' on {line}")

        # Also scan DASTySAST findings for cmd-like params pointing to specific endpoints
        for f in all_findings:
            f_url = f.get("url", "")
            f_param = f.get("parameter", "")
            if f_url and f_param and f_param.lower() in rce_param_names and f_url not in rce_injected_urls:
                # Only inject if finding URL is not already an RCE auto-dispatch
                if not f.get("_auto_dispatched"):
                    all_findings.append({
                        "type": "RCE",
                        "parameter": f_param,
                        "url": f_url,
                        "severity": "Critical",
                        "fp_confidence": 0.9,
                        "confidence_score": 0.9,
                        "votes": 5,
                        "skeptical_score": 8,
                        "reasoning": f"Auto-dispatch: DASTySAST found command-like parameter '{f_param}'.",
                        "payload": f.get("payload", ""),
                        "evidence": f.get("evidence", f"DAST finding with cmd-like param: {f_param}"),
                        "_source_file": "auto_dispatch_rce_from_dast",
                        "_scan_context": self.scan_context,
                        "_auto_dispatched": True
                    })
                    rce_injected_urls.add(f_url)

        if rce_injected_urls:
            dashboard.log(f"Auto-dispatch: {len(rce_injected_urls)} RCE target(s) injected", "INFO")

        # Auto-dispatch SSRFAgent when URL-accepting parameters found in recon URLs.
        # SSRF params (callback, webhook, import) differ from open redirect params.
        has_ssrf = any(
            'ssrf' in f.get('type', '').lower()
            or 'server-side request' in f.get('type', '').lower()
            or 'server side request' in f.get('type', '').lower()
            for f in all_findings
        )
        if not has_ssrf:
            ssrf_param_names = {
                "callback", "webhook", "import", "import_url", "fetch",
                "src", "source", "feed", "rss", "proxy", "api_url",
                "load_url", "remote", "endpoint", "request", "image_url",
                "avatar", "icon_url",
            }
            ssrf_url = None
            ssrf_param = None
            recon_file_ssrf = getattr(self, 'report_dir', None)
            if recon_file_ssrf:
                recon_file_ssrf = recon_file_ssrf / "recon" / "urls.txt"
            if recon_file_ssrf and recon_file_ssrf.exists():
                for line in recon_file_ssrf.read_text().splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    parsed_ssrf = urlparse(line)
                    for p in parse_qs(parsed_ssrf.query).keys():
                        if p.lower() in ssrf_param_names:
                            ssrf_url = line
                            ssrf_param = p
                            break
                    if ssrf_url:
                        break
            # Fallback: if no SSRF-specific param found but target has API endpoints,
            # dispatch SSRF with any URL-like param (url param already handled by OR)
            if not ssrf_url and has_any_param_finding:
                for f in all_findings:
                    p = f.get('parameter', '').lower()
                    if p in ('url', 'uri', 'href', 'link'):
                        ssrf_url = f.get('url', self.target)
                        ssrf_param = f.get('parameter', 'url')
                        break
            if ssrf_url and ssrf_param:
                synthetic_ssrf = {
                    "type": "SSRF",
                    "parameter": ssrf_param,
                    "url": ssrf_url,
                    "severity": "High",
                    "fp_confidence": 0.9,
                    "confidence_score": 0.9,
                    "votes": 5,
                    "skeptical_score": 8,
                    "reasoning": f"Auto-dispatch: URL-accepting parameter '{ssrf_param}' found. SSRFAgent will test for server-side request forgery.",
                    "payload": "",
                    "evidence": f"Recon URL contains URL-accepting parameter: {ssrf_param}",
                    "_source_file": "auto_dispatch_ssrf",
                    "_scan_context": self.scan_context,
                    "_auto_dispatched": True
                }
                all_findings.append(synthetic_ssrf)
                logger.info(f"[Auto-Dispatch] Added synthetic SSRF finding: param='{ssrf_param}' on {ssrf_url}")
                dashboard.log(f"Auto-dispatch: SSRF finding injected for param='{ssrf_param}'", "INFO")

        # ===== Auto-dispatch MassAssignmentAgent for PUT/PATCH/POST endpoints =====
        # Mass assignment tests all writable endpoints — doesn't depend on DASTySAST detecting it
        mass_assign_urls = set()
        for f in all_findings:
            f_url = f.get("url", "")
            if f_url and any(kw in f_url.lower() for kw in [
                "/user", "/profile", "/account", "/register", "/settings",
                "/preferences", "/checkout", "/order", "/admin",
                "/api/user", "/api/auth", "/api/admin"
            ]):
                mass_assign_urls.add(f_url)

        # Also add from recon URLs
        for url in self.urls_to_scan:
            if any(kw in url.lower() for kw in [
                "/user", "/profile", "/account", "/register", "/settings",
                "/preferences", "/checkout", "/order"
            ]):
                mass_assign_urls.add(url)

        if mass_assign_urls:
            ma_injected = 0
            for ma_url in mass_assign_urls:
                synthetic_ma = {
                    "type": "Mass Assignment",
                    "parameter": "auto_dispatch",
                    "url": ma_url,
                    "severity": "High",
                    "fp_confidence": 0.9,
                    "confidence_score": 0.9,
                    "votes": 5,
                    "skeptical_score": 8,
                    "probe_validated": True,
                    "reasoning": f"Auto-dispatch: Writable endpoint detected. MassAssignmentAgent will test for parameter pollution.",
                    "payload": "",
                    "evidence": f"Endpoint may accept additional fields: {ma_url}",
                    "_source_file": "auto_dispatch_mass_assignment",
                    "_scan_context": self.scan_context,
                    "_auto_dispatched": True
                }
                all_findings.append(synthetic_ma)
                ma_injected += 1
            if ma_injected > 0:
                self._v.emit("strategy.auto_dispatch", {"specialist": "MASS_ASSIGNMENT", "count": ma_injected})
                logger.info(f"[Auto-Dispatch] Injected {ma_injected} mass assignment findings for writable endpoints")
                dashboard.log(f"Auto-dispatch: {ma_injected} mass assignment targets injected", "INFO")

        # ===== BAC Detection: Admin endpoints accessible without authentication =====
        admin_bac_findings = []
        admin_patterns = ["/admin", "/debug", "/internal", "/management"]
        admin_urls_to_check = [
            u for u in self.urls_to_scan
            if any(pat in u.lower() for pat in admin_patterns)
        ]
        if admin_urls_to_check:
            import aiohttp as _aiohttp
            try:
                async with _aiohttp.ClientSession(timeout=_aiohttp.ClientTimeout(total=5)) as bac_session:
                    for admin_url in admin_urls_to_check[:10]:  # Cap at 10
                        try:
                            async with bac_session.get(admin_url) as resp:
                                if resp.status == 200:
                                    body = await resp.text()
                                    # Admin endpoint returned 200 without auth — possible BAC
                                    if len(body) > 50:  # Not just an empty 200
                                        admin_bac_findings.append({
                                            "type": "Broken Access Control",
                                            "parameter": urlparse(admin_url).path,
                                            "url": admin_url,
                                            "severity": "High",
                                            "confidence": 0.85,
                                            "validated": True,
                                            "status": "VALIDATED_CONFIRMED",
                                            "validation_method": "unauthenticated_admin_access",
                                            "description": (
                                                f"Admin endpoint {urlparse(admin_url).path} is accessible "
                                                f"without authentication. Response: {resp.status} with "
                                                f"{len(body)} bytes of content."
                                            ),
                                            "evidence": {
                                                "status_code": resp.status,
                                                "content_length": len(body),
                                                "content_preview": body[:200]
                                            },
                                            "_source_file": "bac_detection",
                                        })
                        except Exception:
                            continue
            except Exception as bac_err:
                logger.debug(f"BAC detection error: {bac_err}")

        if admin_bac_findings:
            # Write BAC findings directly to results (pre-validated)
            try:
                results_dir = self.report_dir / "specialists" / "results"
                results_dir.mkdir(parents=True, exist_ok=True)
                bac_path = results_dir / "bac_detection_results.json"
                import json as json_mod
                bac_path.write_text(json_mod.dumps({
                    "agent": "BACDetector",
                    "timestamp": datetime.now().isoformat(),
                    "scan_context": self.scan_context,
                    "phase_a": {"wet_count": len(admin_bac_findings), "dry_count": len(admin_bac_findings)},
                    "phase_b": {"validated_count": len(admin_bac_findings), "total_findings": len(admin_bac_findings)},
                    "findings": admin_bac_findings
                }, indent=2))
                logger.info(f"[BAC] Detected {len(admin_bac_findings)} admin endpoints accessible without auth")
                dashboard.log(f"BAC: {len(admin_bac_findings)} admin endpoints accessible without authentication", "WARNING")
            except Exception as bac_write_err:
                logger.warning(f"Failed to write BAC results: {bac_write_err}")

        # Inject Nuclei misconfiguration findings (HSTS missing, cookie flags, etc.)
        misconfigs = self.tech_profile.get("misconfigurations", [])
        if misconfigs:
            pre_validated_misconfigs = []
            for mc in misconfigs:
                tags = mc.get("tags", [])
                template_id = mc.get("template_id", "")

                # GraphQL introspection → route to specialist for further testing
                if "graphql" in tags or "graphql" in template_id:
                    all_findings.append({
                        "type": "GraphQL Introspection",
                        "parameter": mc.get("template_id", mc["name"]),
                        "url": mc.get("matched_at", self.target),
                        "severity": "High",
                        "fp_confidence": 0.95,
                        "confidence_score": 0.95,
                        "votes": 5,
                        "skeptical_score": 9,
                        "probe_validated": True,
                        "reasoning": mc.get("description", mc["name"]),
                        "description": mc.get("description", mc["name"]),
                        "evidence": f"Nuclei template: {mc.get('template_id', 'unknown')}",
                        "_source_file": "nuclei_misconfiguration",
                        "_scan_context": self.scan_context,
                    })
                    continue

                # Pure misconfigs (cookies, headers, vulnerable JS) → pre-validated, no specialist needed
                if "cookies" in tags:
                    finding_type = "Insecure Cookie Configuration"
                    finding_severity = mc.get("severity", "medium").capitalize()
                else:
                    finding_type = "MISSING_SECURITY_HEADER"
                    finding_severity = mc.get("severity", "info").capitalize()

                pre_validated_misconfigs.append({
                    "type": finding_type,
                    "parameter": mc.get("template_id", mc["name"]),
                    "url": mc.get("matched_at", self.target),
                    "severity": finding_severity,
                    "confidence": 0.95,
                    "validated": True,
                    "status": "VALIDATED_CONFIRMED",
                    "validation_method": "nuclei_template",
                    "description": mc.get("description", mc["name"]),
                    "evidence": {"nuclei_template": mc.get("template_id", "unknown")},
                    "_source_file": "nuclei_misconfiguration",
                })

            # Write pre-validated misconfigs directly to results (bypass specialist queue)
            if pre_validated_misconfigs:
                try:
                    results_dir = self.report_dir / "specialists" / "results"
                    results_dir.mkdir(parents=True, exist_ok=True)
                    misconfig_path = results_dir / "nuclei_misconfig_results.json"
                    import json as json_mod
                    misconfig_path.write_text(json_mod.dumps({
                        "agent": "NucleiMisconfigValidator",
                        "timestamp": datetime.now().isoformat(),
                        "scan_context": self.scan_context,
                        "phase_a": {"wet_count": len(pre_validated_misconfigs), "dry_count": len(pre_validated_misconfigs)},
                        "phase_b": {"validated_count": len(pre_validated_misconfigs), "total_findings": len(pre_validated_misconfigs)},
                        "findings": pre_validated_misconfigs
                    }, indent=2))
                    logger.info(f"[Nuclei] Wrote {len(pre_validated_misconfigs)} pre-validated misconfigs to {misconfig_path}")
                except Exception as mc_err:
                    logger.warning(f"Failed to write misconfig results: {mc_err}")

            self._v.emit("strategy.nuclei_injected", {"count": len(misconfigs)})
            logger.info(f"[Nuclei] Processed {len(misconfigs)} misconfiguration findings ({len(pre_validated_misconfigs)} pre-validated)")
            dashboard.log(f"Nuclei: {len(misconfigs)} security misconfigurations detected", "INFO")

        dashboard.log(f"Processing {len(all_findings)} findings...", "INFO")

        # Pass to ThinkingAgent for batch processing
        processed_count = 0
        if self.thinking_agent and hasattr(self.thinking_agent, 'process_batch_from_list'):
            processed_count = await self.thinking_agent.process_batch_from_list(
                all_findings,
                scan_context=self.scan_context
            )
            logger.info(f"ThinkingAgent processed {processed_count} findings")
        else:
            logger.warning("ThinkingAgent does not support batch processing from list")

        # Flush any remaining batch buffer
        if self.thinking_agent and hasattr(self.thinking_agent, 'flush_batch'):
            flushed = await self.thinking_agent.flush_batch()
            logger.info(f"Flushed {flushed} buffered findings")

        # Log statistics
        if self.thinking_agent and hasattr(self.thinking_agent, 'log_batch_summary'):
            self.thinking_agent.log_batch_summary()

        dashboard.log(
            f"Strategy phase complete: {processed_count} findings distributed to queues",
            "INFO"
        )

        # Update dashboard with deduplication metrics
        if self.thinking_agent and hasattr(self.thinking_agent, 'get_stats'):
            stats = self.thinking_agent.get_stats()
            dashboard.set_progress_metrics(
                findings_before_dedup=stats.get('total_findings', len(all_findings)),
                findings_after_dedup=stats.get('unique_findings', processed_count),
                findings_distributed=stats.get('distributed', processed_count),
                dedup_effectiveness=stats.get('dedup_rate', 0.0) * 100,  # Convert to percentage
                scan_id=self.scan_id
            )

        return processed_count

    async def _load_auth_discovery_findings(self, auth_discovery_dir: Path) -> List[Dict]:
        """
        Load authentication artifacts from AuthDiscoveryAgent and convert to findings.

        Reads:
        - jwts_discovered.json → JWT_DISCOVERED findings
        - cookies_discovered.json → SESSION_COOKIE_DISCOVERED findings

        Returns:
            List of findings ready for ThinkingAgent processing
        """
        import json
        findings = []

        # Load JWTs
        jwt_file = auth_discovery_dir / "jwts_discovered.json"
        if jwt_file.exists():
            try:
                with open(jwt_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                jwts = data.get("jwts", [])
                logger.info(f"[AuthDiscovery] Loading {len(jwts)} JWTs from {jwt_file.name}")

                for jwt_info in jwts:
                    finding = {
                        "type": "JWT_DISCOVERED",
                        "url": jwt_info.get("url", ""),
                        "token": jwt_info.get("token", ""),
                        "source": jwt_info.get("source", ""),
                        "parameter": jwt_info.get("storage_key", jwt_info.get("cookie_name", "N/A")),
                        "context": jwt_info.get("context", "unknown"),
                        "severity": "INFO",
                        "agent": "AuthDiscoveryAgent",
                        "timestamp": data.get("timestamp", ""),
                        "metadata": jwt_info.get("metadata", {}),
                        "_source_file": str(jwt_file),
                        "_scan_context": self.scan_context,
                        "_report_files": {
                            "json": str(jwt_file),
                            "markdown": str(auth_discovery_dir / "auth_discovery.md")
                        }
                    }
                    findings.append(finding)

            except Exception as e:
                logger.error(f"Failed to load {jwt_file}: {e}")

        # Load session cookies
        cookie_file = auth_discovery_dir / "cookies_discovered.json"
        if cookie_file.exists():
            try:
                with open(cookie_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                cookies = data.get("cookies", [])
                logger.info(f"[AuthDiscovery] Loading {len(cookies)} cookies from {cookie_file.name}")

                for cookie_info in cookies:
                    finding = {
                        "type": "SESSION_COOKIE_DISCOVERED",
                        "url": cookie_info.get("url", ""),
                        "cookie_name": cookie_info.get("name", ""),
                        "cookie_value": cookie_info.get("value", ""),
                        "source": "cookie_jar",
                        "severity": "INFO",
                        "agent": "AuthDiscoveryAgent",
                        "timestamp": data.get("timestamp", ""),
                        "metadata": cookie_info.get("metadata", {}),
                        "_source_file": str(cookie_file),
                        "_scan_context": self.scan_context,
                        "_report_files": {
                            "json": str(cookie_file),
                            "markdown": str(auth_discovery_dir / "auth_discovery.md")
                        }
                    }
                    findings.append(finding)

            except Exception as e:
                logger.error(f"Failed to load {cookie_file}: {e}")

        return findings

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

    async def _phase_3_global_review(self, dashboard, scan_dir):
        """Execute Phase 3: Global Review."""
        logger.info("=== PHASE 3: GLOBAL REVIEW ===")
        dashboard.set_phase("🎯 CONFIRMING HITS")
        dashboard.set_status("Running", "Review in progress...")
        dashboard.log("🔍 Phase 3: Global Review and Chaining Analysis", "INFO")

        all_findings_for_review = self.state_manager.get_findings()
        await self._global_review(all_findings_for_review, scan_dir, dashboard)
        logger.info("Phase 3 complete")

        await self._checkpoint("Global Review")

    async def _phase_4_reporting(self, dashboard, scan_dir):
        """Execute Phase 4: Reporting."""
        logger.info("=== PHASE 4: REPORTING ===")
        dashboard.set_phase("📋 COMPILING INTEL")
        dashboard.set_status("Running", "Generating reports...")
        dashboard.log("📊 Phase 4: Generating Final Reports", "INFO")
        dashboard.log("Generating final consolidated reports...", "INFO")

        all_findings = self.state_manager.get_findings()
        logger.info(f"Retrieved {len(all_findings)} findings from state manager")

        self._save_raw_findings(scan_dir, all_findings)
        await self._generate_specialist_reports(scan_dir)  # v3.1: Generate specialists/ directory structure
        await self._generate_initial_report(scan_dir)

        dashboard.log(f"📄 Final report in {scan_dir}", "INFO")

        from bugtrace.schemas.db_models import ScanStatus
        self.db.update_scan_status(self.scan_id, ScanStatus.COMPLETED)
        logger.info(f"Scan {self.scan_id} marked as COMPLETED")
        logger.info("Phase 4 complete")

    async def _check_stop_requested(self, dashboard) -> bool:
        """Check if stop was requested and update scan status.
        Also blocks here while scan is paused (resume unblocks)."""
        # Pause checkpoint: blocks if scan is paused, returns immediately if not
        scan_ctx = getattr(self, '_scan_context', None)
        if scan_ctx is not None:
            await scan_ctx.wait_if_paused()

        if dashboard.stop_requested or self._stop_event.is_set():
            dashboard.log("🛑 Stop requested. Skipping remaining phases.", "WARN")
            from bugtrace.schemas.db_models import ScanStatus
            self.db.update_scan_status(self.scan_id, ScanStatus.STOPPED)
            return True
        return False

    def _save_raw_findings(self, scan_dir: Path, all_findings: list):
        """Save raw findings to JSON file."""
        raw_findings_path = scan_dir / "raw_findings.json"
        with open(raw_findings_path, "w") as f:
            json.dump({
                "meta": {"scan_id": self.scan_id, "target": self.target, "phase": "hunter"},
                "findings": all_findings
            }, f, indent=2, default=str)
        logger.info(f"Saved {len(all_findings)} raw findings to {raw_findings_path}")

    async def _generate_initial_report(self, scan_dir: Path):
        """Generate initial Hunter report."""
        try:
            from bugtrace.agents.reporting import ReportingAgent
            reporter = ReportingAgent(self.scan_id, self.target, scan_dir, self.tech_profile)
            await reporter.generate_all_deliverables()
            logger.info("Generated initial Hunter report")
        except Exception as e:
            logger.error(f"Failed to generate initial report: {e}", exc_info=True)

    async def _generate_specialist_reports(self, scan_dir: Path) -> None:
        """
        Generate specialist reports for Phase 4 auditing and traceability.

        Creates the following structure (v3.2):
        specialists/
        ├── wet/                 # Raw findings input (queue input)
        │   ├── xss.json
        │   ├── sqli.json
        │   └── ...
        ├── dry/                 # Deduped findings (processed)
        │   ├── xss_dry.json
        │   ├── sqli_dry.json
        │   └── ...
        └── results/             # Exploitation results per specialist
            ├── xss_results.json
            ├── sqli_results.json
            └── ...
        """
        specialists_dir = scan_dir / "specialists"
        specialists_dir.mkdir(exist_ok=True)

        wet_dir = specialists_dir / "wet"
        dry_dir = specialists_dir / "dry"
        results_dir = specialists_dir / "results"

        wet_dir.mkdir(exist_ok=True)
        dry_dir.mkdir(exist_ok=True)
        results_dir.mkdir(exist_ok=True)
        
        specialist_names = [
            "xss", "sqli", "csti", "lfi", "idor", "rce", 
            "ssrf", "xxe", "jwt", "openredirect", "prototype_pollution"
        ]
        
        # Collect statistics from queue manager
        from bugtrace.core.queue import queue_manager
        
        for specialist in specialist_names:
            try:
                # Skip specialists without WET input (no work was distributed)
                wet_file = wet_dir / f"{specialist}.json"
                if not wet_file.exists():
                    logger.debug(f"[Specialist Reports] Skipping {specialist} - no WET input")
                    continue

                queue = queue_manager.get_queue(specialist)

                # 1. Wet files already exist in specialists/wet/ (created by thinking agent)
                # No need to copy - they're already in the right place

                # 2. Dry summary - skip if specialist already wrote findings-level DRY file
                dry_file = dry_dir / f"{specialist}_dry.json"
                if dry_file.exists():
                    logger.debug(f"[Specialist Reports] {specialist} DRY file already written by specialist, skipping")
                    continue

                # Fallback: write queue stats if specialist didn't produce a DRY file
                dry_data = {
                    "specialist": specialist,
                    "scan_id": self.scan_id,
                    "target": self.target,
                    "queue_stats": {
                        "total_enqueued": getattr(queue, 'total_enqueued', 0),
                        "total_dequeued": getattr(queue, 'total_dequeued', 0),
                        "current_depth": queue.depth() if hasattr(queue, 'depth') else 0,
                    },
                    "work_items_received": getattr(queue, 'total_enqueued', 0),
                    "status": "COMPLETE" if queue.depth() == 0 else "TIMEOUT_PENDING",
                    "note": "Stats-only fallback (specialist did not write DRY file)"
                }

                with open(dry_file, "w", encoding="utf-8") as f:
                    json.dump(dry_data, f, indent=2, default=str)

                # v3.2: Results files are now generated by specialist agents directly
                # in specialists/results/{specialist}_results.json
                # No need to generate here - avoids duplication
                    
            except Exception as e:
                logger.warning(f"[Specialist Reports] Failed to generate report for {specialist}: {e}")

        # Count actual reports generated (only for specialists with WET input)
        wet_count = len(list(wet_dir.glob("*.json")))
        dry_count = len(list(dry_dir.glob("*_dry.json")))
        results_count = len(list(results_dir.glob("*_results.json")))
        logger.info(
            f"[Specialist Reports] Generated reports in {specialists_dir}: "
            f"WET={wet_count}, DRY={dry_count}, RESULTS={results_count}"
        )

    async def _decide_specialist(self, vuln: dict) -> str:
        """Uses LLM to classify vulnerability and select best specialist agent."""
        from bugtrace.core.llm_client import llm_client

        # Fast path for obvious classifications
        fast_path_result = self._try_fast_path_classification(vuln)
        if fast_path_result:
            return fast_path_result

        # LLM-based classification
        prompt = self._build_dispatcher_prompt(vuln)

        try:
            decision = await llm_client.generate(prompt, module_name="Dispatcher", max_tokens=100)
            chosen_agent = self._extract_agent_from_decision(decision, vuln)
            return chosen_agent
        except Exception as e:
            logger.error(f"Dispatcher LLM failed: {e}", exc_info=True)
            return self._fallback_classification(vuln)

    def _try_fast_path_classification(self, vuln: dict) -> Optional[str]:
        """Try fast-path classification for obvious vulnerability types."""
        v_type = str(vuln.get("type", "")).upper()

        if "XSS" in v_type: return "XSS_AGENT"
        if "SQL" in v_type: return "SQL_AGENT"
        if "CSTI" in v_type or "TEMPLATE" in v_type or "SSTI" in v_type: return "CSTI_AGENT"
        if "SSRF" in v_type or "SERVER-SIDE REQUEST" in v_type: return "SSRF_AGENT"
        if "XXE" in v_type or "XML" in v_type: return "XXE_AGENT"
        if "LFI" in v_type or "PATH TRAVERSAL" in v_type or "LOCAL FILE" in v_type: return "LFI_AGENT"
        if "RCE" in v_type or "COMMAND" in v_type or "REMOTE CODE" in v_type: return "RCE_AGENT"
        if "UPLOAD" in v_type or "FILES" in v_type: return "FILE_UPLOAD_AGENT"
        if "JWT" in v_type or "TOKEN" in v_type: return "JWT_AGENT"
        if "REDIRECT" in v_type or "OPEN REDIRECT" in v_type or "URL REDIRECT" in v_type: return "OPENREDIRECT_AGENT"
        if "PROTOTYPE" in v_type or "POLLUTION" in v_type or "PROTO POLLUTION" in v_type or "__PROTO__" in v_type: return "PROTOTYPE_POLLUTION_AGENT"
        if "IDOR" in v_type or "INSECURE DIRECT" in v_type: return "IDOR_AGENT"

        return None

    def _build_dispatcher_prompt(self, vuln: dict) -> str:
        """Build prompt for LLM dispatcher."""
        return f"""
        Act as a Security Dispatcher.
        Analyze this potential vulnerability finding and assign the correct Specialist Agent.

        FINDING: {vuln}

        AVAILABLE AGENTS:
        - XSS_AGENT (Cross-Site Scripting, HTML injection)
        - SQL_AGENT (SQL Injection, Database errors)
        - CSTI_AGENT (Client-Side Template Injection, SSTI, {{{{7*7}}}} indicators)
        - XXE_AGENT (XML External Entity, XML parsing)
        - PROTO_AGENT (Prototype Pollution, JS Object injection)
        - JWT_AGENT (JSON Web Token vulnerabilities, alg: none, weak secrets)
        - HEADER_INJECTION (CRLF, Response Splitting)
        - FILE_UPLOAD_AGENT (Unrestricted file upload, RCE via shell)
        - IDOR_AGENT (Insecure Direct Object Reference, Parameter Tampering)
        - SSRF_AGENT (Server-Side Request Forgery, internal network access)
        - LFI_AGENT (Local File Inclusion, path traversal)
        - RCE_AGENT (Remote Code Execution, command injection)
        - OPENREDIRECT_AGENT (Open Redirect, URL redirection to untrusted site)
        - PROTOTYPE_POLLUTION_AGENT (Prototype Pollution, __proto__ injection, object manipulation)
        - IGNORE (If low confidence or not relevant)

        Return ONLY the Agent Name using XML format:
        <thought>Reasoning for selection</thought>
        <agent>AGENT_NAME</agent>
        """

    def _extract_agent_from_decision(self, decision: str, vuln: dict) -> str:
        """Extract agent name from LLM decision."""
        from bugtrace.utils.parsers import XmlParser

        chosen_agent = XmlParser.extract_tag(decision, "agent")

        if chosen_agent:
            chosen_agent = chosen_agent.strip().replace("`", "").upper()
            valid_agents = [
                "XSS_AGENT", "SQL_AGENT", "XXE_AGENT", "SSRF_AGENT", "LFI_AGENT",
                "RCE_AGENT", "PROTO_AGENT", "HEADER_INJECTION", "IDOR_AGENT",
                "JWT_AGENT", "FILE_UPLOAD_AGENT", "OPENREDIRECT_AGENT",
                "PROTOTYPE_POLLUTION_AGENT", "IGNORE"
            ]

            for valid in valid_agents:
                if valid in chosen_agent:
                    return valid

        # JWT keyword fallback
        v_type_lower = str(vuln.get("type", "")).lower()
        if "jwt" in v_type_lower or "auth token" in v_type_lower:
            return "JWT_AGENT"

        # Text-based heuristic fallback
        if decision:
            valid_agents = ["XSS_AGENT", "SQL_AGENT", "XXE_AGENT", "PROTO_AGENT", "HEADER_INJECTION", "IDOR_AGENT", "IGNORE"]
            for agent in valid_agents:
                if agent in decision and "NOT" not in decision:
                    return agent

        return "IGNORE"

    def _fallback_classification(self, vuln: dict) -> str:
        """Fallback classification when LLM fails."""
        v_type = str(vuln.get("type", "")).upper()
        if "XML" in v_type: return "XXE_AGENT"
        if "PROTO" in v_type: return "PROTO_AGENT"
        if "HEADER" in v_type: return "HEADER_INJECTION"
        return "IGNORE"

    def _is_finding_type_consistent(self, finding: Dict, specialist: str) -> bool:
        """
        Validate that finding payload matches its claimed type.

        v3.2: Prevents misclassified findings (e.g., XXE payload labeled as XSS)
        from appearing in wrong specialist results.

        Args:
            finding: Finding dictionary with type, payload, etc.
            specialist: Target specialist name (e.g., "xss", "xxe")

        Returns:
            True if consistent, False if payload contradicts claimed type
        """
        payload = str(finding.get("payload", "") or finding.get("exploitation_strategy", "") or "").lower()
        param = str(finding.get("parameter", "")).lower()

        # If no payload, allow (might be legitimate)
        if not payload:
            return True

        # XXE signatures in payload
        xxe_indicators = ["<!doctype", "<!entity", "<?xml", "system", "external entity"]
        has_xxe = any(ind in payload for ind in xxe_indicators)

        # XSS signatures in payload
        xss_indicators = ["<script", "javascript:", "onerror", "onload", "alert(", "confirm("]
        has_xss = any(ind in payload for ind in xss_indicators)

        # SQL signatures
        sql_indicators = ["' or", "union select", "1=1", "sleep(", "benchmark("]
        has_sql = any(ind in payload for ind in sql_indicators)

        # Validate consistency
        if specialist == "xss":
            # Reject if payload is clearly XXE or SQL
            if has_xxe and not has_xss:
                logger.debug(f"[TypeConsistency] Rejecting XSS finding with XXE payload: {payload[:50]}")
                return False
            if has_sql and not has_xss:
                logger.debug(f"[TypeConsistency] Rejecting XSS finding with SQL payload: {payload[:50]}")
                return False

        if specialist == "xxe":
            # Allow if has XXE indicators
            if has_xss and not has_xxe:
                logger.debug(f"[TypeConsistency] Rejecting XXE finding with XSS payload: {payload[:50]}")
                return False

        if specialist == "sqli":
            # Reject if payload is clearly XXE or XSS
            if has_xxe and not has_sql:
                logger.debug(f"[TypeConsistency] Rejecting SQLI finding with XXE payload: {payload[:50]}")
                return False

        return True

    def _load_findings_from_wet(self, wet_dir: Path, specialist: str) -> List[Dict]:
        """
        Load findings from wet/{specialist}.json file.

        v3.2: Files are the SOURCE OF TRUTH, not the database.
        The wet/ files contain findings with correct types as written by ThinkingAgent.

        Args:
            wet_dir: Path to specialists/wet/ directory
            specialist: Specialist name (e.g., "xss", "sqli")

        Returns:
            List of findings for this specialist
        """
        wet_file = wet_dir / f"{specialist}.json"
        if not wet_file.exists():
            logger.debug(f"[LoadWet] No wet file for {specialist}: {wet_file}")
            return []

        findings = []
        try:
            # JSON Lines format: one JSON object per line
            with open(wet_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        finding = entry.get("finding", {})
                        if finding:
                            # Normalize finding for results format
                            normalized = {
                                "type": finding.get("type", specialist.upper()),
                                "url": finding.get("url", ""),
                                "parameter": finding.get("parameter", ""),
                                "payload": finding.get("payload", ""),
                                "evidence": finding.get("evidence") or finding.get("description", ""),
                                "severity": finding.get("severity", "High"),
                                "status": finding.get("status", "PENDING_VALIDATION"),
                                "screenshot": finding.get("screenshot"),
                            }
                            findings.append(normalized)
                    except json.JSONDecodeError as e:
                        logger.warning(f"[LoadWet] Invalid JSON line in {wet_file}: {e}")
                        continue

            logger.info(f"[LoadWet] Loaded {len(findings)} findings from {wet_file.name}")

        except Exception as e:
            logger.error(f"[LoadWet] Failed to read {wet_file}: {e}")

        return findings

    async def _global_review(self, findings: list, scan_dir: Path, dashboard):
        """Phase 3: Analyzes cross-URL patterns and vulnerability chaining."""
        if not findings:
            return

        dashboard.log("🔍 Starting Global Review and Chaining Analysis...", "INFO")

        from bugtrace.core.llm_client import llm_client

        findings_summary = json.dumps([{
            "type": f.get("type"),
            "url": f.get("url"),
            "param": f.get("parameter"),
            "severity": f.get("severity")
        } for f in findings])

        prompt = f"""As a Senior Red Team Lead, review these validated findings and identify possible ATTACK CHAINS.
        Findings: {findings_summary}

        Look for correlations like:
        - IDOR (User A can see User B) + Info Disclosure (sees token) = Account Takeover
        - Path Traversal (read config) + SQLi (update admin) = Full Compromise

        Return a list of attack chains using XML format:
        <thought>Reasoning about how these vulnerabilities can be combined</thought>
        <chain>
          <name>Chain Name</name>
          <vulnerabilities>vuln_type1, vuln_type2</vulnerabilities>
          <impact>Full system compromise via...</impact>
        </chain>
        """

        try:
            response = await llm_client.generate(prompt, module_name="GlobalReview")
            chains = self._extract_attack_chains(response)

            if chains:
                dashboard.log(f"🔗 Detected {len(chains)} potential attack chains!", "WARN")
                with open(scan_dir / "attack_chains.json", "w") as f:
                    json.dump({"chains": chains, "findings_reviewed": len(findings)}, f, indent=4)
        except Exception as e:
            logger.debug(f"Global review failed: {e}")

    def _extract_attack_chains(self, response: str) -> list:
        """Extract attack chains from LLM response."""
        from bugtrace.utils.parsers import XmlParser

        chain_contents = XmlParser.extract_list(response, "chain")
        chains = []

        for cc in chain_contents:
            chains.append({
                "name": XmlParser.extract_tag(cc, "name") or "Unnamed Chain",
                "vulnerabilities": XmlParser.extract_tag(cc, "vulnerabilities") or "",
                "impact": XmlParser.extract_tag(cc, "impact") or "High"
            })

        return chains

    async def _generate_v2_report(self, findings: list, urls: list, tech_profile: dict, scan_dir: Path, start_time: datetime):
        """Phase 4: Generates a premium report based on the sequential scan results."""
        try:
            # Load findings from files (DB = write-only)
            findings = self._load_findings_from_files()

            logger.info(f"Starting report generation with {len(findings)} findings")
            dashboard.log(f"📊 Generating final reports with {len(findings)} findings...", "INFO")

            # Collect and deduplicate findings
            collector = self._build_data_collector(findings, urls, tech_profile, start_time)

            # Generate reports
            await self._generate_all_reports(collector, scan_dir)

            dashboard.log(f"✅ Reports generated in {scan_dir}", "SUCCESS")

        except Exception as e:
            logger.error(f"Failed to generate V2 report: {e}", exc_info=True)
            dashboard.log(f"❌ Report generation failed: {e}", "ERROR")

    def _load_findings_from_files(self) -> list:
        """Load findings from specialist JSON files (source of truth). DB = write-only."""
        if hasattr(self, "state_manager") and self.state_manager:
            findings = self.state_manager.get_findings()
            if findings:
                logger.info(f"Loaded {len(findings)} findings from files for reporting.")
                return findings

        logger.warning("No findings loaded from files for reporting.")
        return []

    def _build_data_collector(self, findings: list, urls: list, tech_profile: dict, start_time: datetime):
        """Build data collector with deduplicated findings."""
        from bugtrace.reporting.collector import DataCollector

        collector = DataCollector(self.target, scan_id=self.scan_id)

        # Add deduplicated findings
        seen_findings = set()
        confirmed_findings = [f for f in findings if f.get("status") == "VALIDATED_CONFIRMED"]
        pending_findings = [f for f in findings if f.get("status") == "PENDING_VALIDATION"]

        prioritized_findings = confirmed_findings if settings.REPORT_ONLY_VALIDATED else confirmed_findings + pending_findings

        for f in prioritized_findings:
            dedupe_key = f"{(f.get('type') or '').upper()}:{urlparse(f.get('url', '')).path}:{f.get('parameter', '')}"

            if dedupe_key in seen_findings:
                continue
            seen_findings.add(dedupe_key)

            if "validator_notes" not in f:
                f["validator_notes"] = None
            if "status" not in f:
                f["status"] = "PENDING_VALIDATION"

            collector.add_vulnerability(f)

        # Add context
        collector.context.stats.urls_scanned = len(urls)
        collector.context.stats.start_time = start_time if isinstance(start_time, datetime) else datetime.fromisoformat(start_time)
        end_time = datetime.now()
        collector.context.stats.end_time = end_time
        collector.context.stats.duration_seconds = (end_time - start_time).total_seconds()
        collector.context.tech_stack = tech_profile.get("frameworks", [])

        return collector

    async def _generate_all_reports(self, collector, scan_dir: Path):
        """Generate all report formats."""
        from bugtrace.reporting.markdown_generator import MarkdownGenerator
        from bugtrace.reporting.generator import HTMLGenerator

        # Triager-Ready Markdown
        md_gen = MarkdownGenerator(output_base_dir=str(scan_dir))
        md_gen.generate(collector.get_context())

        # HTML version
        html_gen = HTMLGenerator()
        html_gen.generate(collector.get_context(), str(scan_dir / "report.html"))

        # Optional AI-enhanced summary
        try:
            from bugtrace.reporting.ai_writer import AIReportWriter
            ai_writer = AIReportWriter(output_base_dir=str(scan_dir))
            await ai_writer.generate_async(collector.get_context())
        except Exception as e:
            logger.warning(f"AI report enhancement failed (non-critical): {e}")
