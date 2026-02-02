import asyncio
import json
import hashlib
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
from bugtrace.agents.xss_agent import XSSAgent
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

# Pipeline orchestration (v2.3)
from bugtrace.core.pipeline import (
    PipelineOrchestrator, PipelineLifecycle, PipelinePhase, PipelineState
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

    def __init__(self, target: str, resume: bool = False, max_depth: int = 2, max_urls: int = 15, use_vertical_agents: bool = False, output_dir: Optional[Path] = None, scan_id: Optional[int] = None, url_list: Optional[List[str]] = None):
        self.target = target
        self.output_dir = output_dir
        self.resume = resume
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.url_list_provided = url_list  # Store provided URL list for Phase 1
        self.agents: List[BaseAgent] = []
        self._stop_event = asyncio.Event()
        self.auth_creds: Optional[str] = None

        # Scan context for event correlation (V3 pipeline)
        self.scan_context = f"scan_{id(self)}_{int(__import__('time').time())}"

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

        # Initialize ThinkingConsolidationAgent for V3 pipeline
        from bugtrace.agents.thinking_consolidation_agent import ThinkingConsolidationAgent
        self.thinking_agent = ThinkingConsolidationAgent(scan_context=self.scan_context)
        logger.info("ThinkingConsolidationAgent initialized - V3 event-driven pipeline active")

        # Specialist worker pools will be initialized async in _run_hunter_core
        self._specialist_workers_started = False

        # Pipeline orchestration (v2.3)
        self._pipeline: Optional[PipelineOrchestrator] = None
        self._lifecycle: Optional[PipelineLifecycle] = None
        logger.info("Pipeline orchestration infrastructure initialized")

    async def _init_specialist_workers(self):
        """Initialize specialist worker pools for V3 pipeline."""
        from bugtrace.agents.sqli_agent import SQLiAgent
        from bugtrace.agents.xss_agent import XSSAgent
        from bugtrace.agents.csti_agent import CSTIAgent
        from bugtrace.agents.lfi_agent import LFIAgent
        from bugtrace.agents.idor_agent import IDORAgent
        from bugtrace.agents.rce_agent import RCEAgent
        from bugtrace.agents.ssrf_agent import SSRFAgent
        from bugtrace.agents.xxe_agent import XXEAgent
        from bugtrace.agents.openredirect_agent import OpenRedirectAgent
        from bugtrace.agents.prototype_pollution_agent import PrototypePollutionAgent

        # Initialize specialist agents with minimal parameters
        # url parameter required but will be overridden by queue work items
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
        }

        # Dispatch specialists with concurrency control (dispatcher handles queue checks and specialist startup)
        max_concurrent = settings.SPECIALIST_MAX_CONCURRENT
        dispatch_result = await dispatch_specialists(specialist_map, scan_ctx, max_concurrent=max_concurrent)

        if dispatch_result["specialists_dispatched"] > 0:
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
        elif resume:
            self.scan_id = self.db.get_active_scan(self.target)
            if not self.scan_id:
                logger.warning(f"No active scan found to resume for {self.target}. Starting new.")
                self.scan_id = self.db.create_new_scan(self.target)
                self.resume = False
        else:
            self.scan_id = self.db.create_new_scan(self.target)

        logger.info(f"TeamOrchestrator initialized for Scan ID: {self.scan_id}")

        # State Manager (Database backed)
        self.state_manager = get_state_manager(self.target)
        self.state_manager.set_scan_id(self.scan_id)

        # Initialize state
        self.processed_urls = set()

        # Inject scan_id into ThinkingConsolidationAgent for DB persistence
        if hasattr(self, 'thinking_agent'):
            self.thinking_agent.scan_id = self.scan_id
            logger.info(f"Injected Scan ID {self.scan_id} into ThinkingConsolidationAgent")
        self.url_queue = []
        self.vulnerabilities_by_url: Dict[str, list] = {}

        # Load active state if resuming
        if self.resume:
            state = self.state_manager.load_state()
            if state:
                self.processed_urls = set(state.get("processed_urls", []))
                self.url_queue = state.get("url_queue", [])
                logger.info(f"Resumed scan: {len(self.processed_urls)} URLs already processed, {len(self.url_queue)} pending.")

    def _init_pipeline(self):
        """Initialize 5-phase pipeline orchestration."""
        self._pipeline = PipelineOrchestrator(
            scan_id=str(self.scan_id),
            event_bus=self.event_bus
        )
        self._lifecycle = PipelineLifecycle(
            state=self._pipeline.state,
            event_bus=self.event_bus
        )
        logger.info(f"[TeamOrchestrator] Pipeline initialized for scan {self.scan_id}")

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
        if self._pipeline:
            return self._pipeline.get_state()
        return None

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
                with Live(dashboard, refresh_per_second=4, screen=True) as live:
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

        if dashboard.stop_requested or self._stop_event.is_set():
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
        """Create and return report directory."""
        parsed = urlparse(self.target)
        domain = parsed.netloc.replace(":", "_") or "local"
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_dir = settings.REPORT_DIR / f"{domain}_{timestamp}"
        report_dir.mkdir(parents=True, exist_ok=True)
        (report_dir / "logs").mkdir(exist_ok=True)
        return report_dir

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
            logger.warning("Scan ID missing for ReportingAgent, attempting to retrieve from DB...")
            self.scan_id = self.db.get_active_scan(self.target) or 0
            
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
        """Setup scan folder with organized structure."""
        timestamp = start_time.strftime("%Y%m%d_%H%M%S")
        domain = urlparse(self.target).netloc or "unknown"
        if ":" in domain:
            domain = domain.split(":")[0]

        if self.output_dir:
            scan_dir = self.output_dir
        else:
            scan_dir = settings.REPORT_DIR / f"{domain}_{timestamp}"

        self.scan_dir = scan_dir
        scan_dir.mkdir(parents=True, exist_ok=True)

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

            try:
                # Run Nuclei ONLY on main target domain (not on every URL)
                nuclei_agent = NucleiAgent(self.target, recon_dir)
                self.tech_profile = await nuclei_agent.run()
                logger.info(f"[Recon] Tech Profile: {len(self.tech_profile.get('frameworks', []))} frameworks detected on {self.target}")
            except Exception as e:
                logger.warning(f"Nuclei detection failed: {e}")
                self.tech_profile = {"frameworks": [], "infrastructure": []}

            # Use provided URLs directly
            urls_to_scan = self.url_list_provided
            await self._scan_for_tokens(urls_to_scan)

            return self._normalize_urls(urls_to_scan)

        # ========== Normal Mode (GoSpider) ==========
        dashboard.log("Starting Phase 1: Reconnaissance (Nuclei + GoSpider)", "INFO")

        try:
            # Run Nuclei for tech detection (Phase 1: Tech-Detect + Auto-Scan)
            nuclei_agent = NucleiAgent(self.target, recon_dir)
            self.tech_profile = await nuclei_agent.run()
            logger.info(f"[Recon] Tech Profile: {len(self.tech_profile.get('frameworks', []))} frameworks, "
                       f"{len(self.tech_profile.get('infrastructure', []))} infrastructure components")

            # Run GoSpider for URL discovery
            urls_to_scan = await self._run_gospider(recon_dir)
            await self._scan_for_tokens(urls_to_scan)
        except Exception as e:
            logger.error(f"Reconnaissance crash: {e}", exc_info=True)
            urls_to_scan = [self.target]
            self.tech_profile = self.tech_profile or {"frameworks": [], "infrastructure": []}

        return self._normalize_urls(urls_to_scan)

    async def _run_gospider(self, recon_dir) -> list:
        """Run GoSpider agent for URL discovery."""
        logger.info(f"Triggering GoSpiderAgent for {self.target}")
        gospider = GoSpiderAgent(self.target, recon_dir, max_depth=self.max_depth, max_urls=self.max_urls)
        urls_to_scan = await gospider.run()
        logger.info(f"GoSpiderAgent finished. Found {len(urls_to_scan)} URLs")
        return urls_to_scan

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

    def _normalize_urls(self, urls_to_scan: list) -> list:
        """Deduplicate, normalize, and prioritize URLs."""
        unique_urls = set()
        normalized_list = []
        has_parameterized = False

        for u in urls_to_scan:
            u_norm = u.rstrip('/')
            if '?' in u_norm or '=' in u_norm:
                has_parameterized = True

            if u_norm not in unique_urls:
                unique_urls.add(u_norm)
                normalized_list.append(u)

        # Smart Filter: If we have parameterized URLs, remove PLAIN root URL (no params)
        # FIX: Only remove root if it has NO parameters (e.g., https://example.com/)
        # If target itself has params (e.g., /catalog?category=X), keep it!
        if has_parameterized:
            root_norm = self.target.rstrip('/')
            # Only filter out root if it has no query params
            if '?' not in root_norm and '=' not in root_norm:
                normalized_list = [u for u in normalized_list if u.rstrip('/') != root_norm]
            if not normalized_list:
                normalized_list = [self.target]

        urls_to_scan = normalized_list
        logger.info(f"Deduplicated URLs to scan: {len(urls_to_scan)}")

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

        self.url_queue = urls_to_scan
        self._save_checkpoint()
        return urls_to_scan

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
                if not self._validate_finding_format(f):
                    continue

                key = self._generate_finding_key(f)
                if key in seen_keys:
                    continue

                self._add_new_finding(f, key, seen_keys, all_validated_findings, dashboard)

        return process_result

    def _validate_finding_format(self, finding: dict) -> bool:
        """Validate finding payload format."""
        is_valid, error_msg = conductor._validate_payload_format(finding)
        if not is_valid:
            logger.warning(f"[TeamOrchestrator] {error_msg}")
        return is_valid

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

        return {
            "specialist_dispatches": specialist_dispatches,
            "params_map": params_map,
            "idor_params": idor_params,
            "parsed_url": parsed_url,
            "current_qs": current_qs
        }

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
            from bugtrace.agents.exploit_specialists import XXEAgent
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
            from bugtrace.agents.exploit_specialists import ProtoAgent
            p_list = list(params_map.get("PROTO_AGENT", [])) or None
            proto_agent = ProtoAgent(url, p_list, url_dir)
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

        dast = DASTySASTAgent(url, self.tech_profile, url_dir, state_manager=self.state_manager)
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
        await self._pipeline.start()

        # Setup directories
        scan_dir, recon_dir, analysis_dir, captures_dir = self._setup_scan_directory(start_time)
        dashboard.log(f"Scan directory created: {scan_dir.name}", "INFO")

        # Update ThinkingConsolidationAgent with correct scan_dir
        self.thinking_agent.scan_dir = scan_dir

        # ========== PHASE 1: DISCOVERY ==========
        # GoSpider crawls target, discovers URLs
        await self._phase_1_reconnaissance(dashboard, recon_dir)

        # Update dashboard with discovery metrics
        dashboard.set_progress_metrics(
            urls_discovered=len(self.urls_to_scan),
            urls_total=len(self.urls_to_scan),
            scan_id=self.scan_id
        )

        await self._lifecycle.signal_phase_complete(
            PipelinePhase.RECONNAISSANCE,
            {'urls_found': len(self.urls_to_scan)}
        )

        if self._check_stop_requested(dashboard):
            return

        # ========== PHASE 2: DISCOVERY (Batch DAST) ==========
        # DASTySASTAgent analyzes ALL URLs in parallel
        # ThinkingConsolidationAgent deduplicates and distributes to queues
        logger.info("=== PHASE 2: DISCOVERY (Batch DAST) ===")
        dashboard.log(f"🔬 Running batch DAST on {len(self.urls_to_scan)} URLs", "INFO")
        dashboard.set_phase("🔬 HUNTING VULNS")
        dashboard.set_status("Running", "Analysis in progress...")

        # Run batch DAST - this is the actual DISCOVERY work
        self.vulnerabilities_by_url = await self._phase_2_batch_dast(dashboard, analysis_dir)

        # Signal DISCOVERY complete AFTER batch DAST finishes
        await self._lifecycle.signal_phase_complete(
            PipelinePhase.DISCOVERY,
            {'urls_analyzed': len(self.vulnerabilities_by_url)}
        )

        if self._check_stop_requested(dashboard):
            return

        # ========== PHASE 3: STRATEGY (Batch Processing) ==========
        # ThinkingAgent reads JSON files, deduplicates, and distributes to queues
        logger.info("=== PHASE 3: STRATEGY (Deduplication & Queue Distribution) ===")
        dashboard.log("🧠 ThinkingAgent processing findings batch", "INFO")
        dashboard.set_phase("🧠 STRATEGY")
        dashboard.set_status("Running", "Deduplication in progress...")

        # Process all JSON files from scan_dir/dastysast/ (where Phase 2 saves them)
        # ThinkingAgent processes batch, fills queues, and TERMINATES
        # NOTE: Phase 2 saves to self.scan_dir/dastysast/, NOT analysis_dir/dastysast/
        analysis_json_dir = self.scan_dir / "dastysast"
        findings_count = await self._phase_3_strategy(dashboard, analysis_json_dir)

        logger.info("ThinkingConsolidationAgent finished - queues ready for specialists")

        # Signal STRATEGY complete
        await self._lifecycle.signal_phase_complete(
            PipelinePhase.STRATEGY,
            {'findings_processed': findings_count}
        )

        if self._check_stop_requested(dashboard):
            return

        # ========== PHASE 4: EXPLOITATION (Queue Consumption) ==========
        # Specialists consume from queues in true parallel
        logger.info("=== PHASE 4: EXPLOITATION (Specialist Queue Processing) ===")
        dashboard.log(f"⚡ Specialists processing findings from queues", "INFO")

        # Initialize specialist workers NOW (consume WET → create DRY → attack DRY)
        if not self._specialist_workers_started:
            await self._init_specialist_workers()
            self._specialist_workers_started = True
            logger.info("Specialist worker pools initialized and consuming queues")

        # Wait for specialists to drain queues and complete exploitation
        batch_metrics.start_queue_drain()
        queue_results = await self._wait_for_specialist_queues(dashboard, timeout=300.0)
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

        # Signal EXPLOITATION complete AFTER queue drain finishes
        await self._lifecycle.signal_phase_complete(
            PipelinePhase.EXPLOITATION,
            {'findings_exploited': self.thinking_agent.get_stats().get('distributed', 0) if self.thinking_agent else 0}
        )

        if self._check_stop_requested(dashboard):
            return

        # ========== PHASE 5: VALIDATION ==========
        all_findings_for_review = self.state_manager.get_findings()
        logger.info("=== PHASE 5: VALIDATION (Global Review) ===")
        await self._phase_3_global_review(dashboard, scan_dir)
        await self._lifecycle.signal_phase_complete(
            PipelinePhase.VALIDATION,
            {'findings_reviewed': len(all_findings_for_review)}
        )

        if self._check_stop_requested(dashboard):
            return

        # ========== PHASE 6: REPORTING ==========
        logger.info("=== PHASE 6: REPORTING ===")
        await self._phase_4_reporting(dashboard, scan_dir)
        await self._lifecycle.signal_phase_complete(
            PipelinePhase.REPORTING,
            {'report_generated': True}
        )
        await self._pipeline.stop()

        # Cleanup
        await self._shutdown_specialist_workers()

        # End metrics and log performance summary
        all_findings = self.state_manager.get_findings()
        batch_metrics.end_scan(findings_exploited=len(all_findings))
        batch_metrics.log_summary()

        duration = (datetime.now() - start_time).total_seconds()
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

    async def _wait_for_specialist_queues(self, dashboard, timeout: float = 300.0) -> Dict[str, Any]:
        """
        Wait for specialist queues to drain after batch DAST.

        Args:
            dashboard: UI dashboard for status updates
            timeout: Maximum seconds to wait for queues to drain

        Returns:
            Dict of specialist -> items_processed counts
        """
        from bugtrace.core.queue import queue_manager
        import time

        start_time = time.monotonic()
        check_interval = 2.0  # Check every 2 seconds
        last_log_time = start_time

        dashboard.log("Waiting for specialist queues to drain...", "INFO")

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
            dashboard.set_progress_metrics(queue_stats=queue_stats, scan_id=self.scan_id)

            # Log progress every 10 seconds
            if (time.monotonic() - last_log_time) >= 10.0:
                dashboard.log(f"Queue status: {total_pending} items pending", "INFO")
                last_log_time = time.monotonic()

            if total_pending == 0:
                dashboard.log("All specialist queues drained", "SUCCESS")
                break

            await asyncio.sleep(check_interval)

        elapsed = time.monotonic() - start_time

        if total_pending > 0:
            dashboard.log(f"Queue drain timeout after {elapsed:.1f}s, {total_pending} items remaining", "WARN")

        # Collect ThinkingAgent stats
        stats = self.thinking_agent.get_stats() if self.thinking_agent else {}

        return {
            "elapsed_seconds": elapsed,
            "items_distributed": stats.get("distributed", 0),
            "by_specialist": stats.get("by_specialist", {}),
            "pending_at_timeout": total_pending
        }

    async def _phase_2_batch_dast(self, dashboard, analysis_dir) -> Dict[str, list]:
        """Run DAST analysis on ALL URLs in parallel batch."""
        dashboard.log(f"Running batch DAST on {len(self.urls_to_scan)} URLs...", "INFO")

        # Start DAST metrics
        batch_metrics.start_dast()

        # Use analysis semaphore for DAST concurrency
        analysis_semaphore = get_analysis_semaphore()

        # Progress tracking
        completed_count = {"value": 0}

        async def analyze_url(url: str, url_index: int) -> tuple:
            async with analysis_semaphore:
                # Log concurrency status
                active = settings.MAX_CONCURRENT_ANALYSIS - analysis_semaphore._value
                logger.info(f"[DAST] ▶ Starting ({active}/{settings.MAX_CONCURRENT_ANALYSIS} active): {url[:60]}")

                # Create dastysast/ folder for numbered reports
                dastysast_dir = self.scan_dir / "dastysast"
                dastysast_dir.mkdir(exist_ok=True)

                dast = DASTySASTAgent(
                    url, self.tech_profile, dastysast_dir,
                    state_manager=self.state_manager,
                    scan_context=self.scan_context,
                    url_index=url_index
                )

                # FIX v3.1: Timeout INSIDE semaphore - only counts analysis time,
                # not time waiting for semaphore slot. This ensures ALL URLs get
                # analyzed even with high concurrency limits.
                # FIX v3.2: Increased timeout from 120s to configurable value (default 180s)
                # to allow probes + LLM analysis to complete
                analysis_timeout = getattr(settings, 'DAST_ANALYSIS_TIMEOUT', 180.0)
                try:
                    result = await asyncio.wait_for(dast.run(), timeout=analysis_timeout)
                    vulns = result.get("vulnerabilities", [])
                except asyncio.TimeoutError:
                    logger.warning(f"[DAST] Analysis timed out after {analysis_timeout}s: {url[:50]}...")
                    vulns = []

                logger.info(f"[DAST] ✓ Completed ({len(vulns)} findings): {url[:60]}")

                # Update progress counter and dashboard
                completed_count["value"] += 1
                dashboard.set_progress_metrics(urls_analyzed=completed_count["value"], scan_id=self.scan_id)

                return (url, vulns)

        # Run ALL URLs in parallel - semaphore controls concurrency,
        # timeout is per-analysis (not per-task including queue wait)
        # Enumerate URLs to pass index (starting at 1) for numbered reports
        tasks = [analyze_url(url, idx + 1) for idx, url in enumerate(self.urls_to_scan)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Aggregate results
        vulnerabilities_by_url = {}
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"DAST batch error: {result}")
                continue
            url, vulns = result
            vulnerabilities_by_url[url] = vulns
            self.processed_urls.add(url)

        total_vulns = sum(len(v) for v in vulnerabilities_by_url.values())
        dashboard.log(f"Batch DAST complete: {total_vulns} findings from {len(vulnerabilities_by_url)} URLs", "INFO")

        # End DAST metrics
        batch_metrics.end_dast(
            urls_analyzed=len(vulnerabilities_by_url),
            findings_count=total_vulns
        )

        return vulnerabilities_by_url

    async def _phase_3_strategy(self, dashboard, analysis_json_dir: Path) -> int:
        """
        Execute Phase 3: STRATEGY - Batch processing of DAST findings.

        Reads all JSON files from analysis_dir, passes to ThinkingAgent
        for deduplication, classification, prioritization, and queue distribution.

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
            return 0

        dashboard.log(f"Found {len(json_files)} JSON files to process", "INFO")

        # Load all findings from JSON files
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

        logger.info(f"Loaded {len(all_findings)} total findings from {len(json_files)} files")
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

    async def _phase_2_analysis(self, dashboard, analysis_dir):
        """Execute Phase 2: Batch DAST Analysis + Queue-based Specialist Execution.

        DEPRECATED: This method is no longer called from _run_sequential_pipeline.
        The logic is now inlined for proper phase signal timing.
        Kept for backward compatibility with non-batch pipelines.
        """
        dashboard.set_phase("🔬 HUNTING VULNS")

        # Phase 2A: Batch DAST Discovery (runs in parallel)
        self.vulnerabilities_by_url = await self._phase_2_batch_dast(dashboard, analysis_dir)

        # Phase 2B: Wait for ThinkingAgent to distribute to queues
        # and for specialist workers to process their items
        batch_metrics.start_queue_drain()
        queue_results = await self._wait_for_specialist_queues(dashboard, timeout=300.0)
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

    def _check_stop_requested(self, dashboard) -> bool:
        """Check if stop was requested and update scan status."""
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
        
        Creates the following structure:
        specialists/
        ├── queues/              # What each specialist received (queue input)
        │   ├── xss.jsonl
        │   ├── sqli.jsonl
        │   └── ...
        ├── warmup/              # Pre-analysis dedup summary per specialist
        │   ├── xss_warmup.json
        │   ├── sqli_warmup.json
        │   └── ...
        └── results/             # Exploitation results per specialist
            ├── xss_results.json
            ├── sqli_results.json
            └── ...
        """
        specialists_dir = scan_dir / "specialists"
        specialists_dir.mkdir(exist_ok=True)
        
        queues_dir = specialists_dir / "queues"
        warmup_dir = specialists_dir / "warmup"
        results_dir = specialists_dir / "results"
        
        queues_dir.mkdir(exist_ok=True)
        warmup_dir.mkdir(exist_ok=True)
        results_dir.mkdir(exist_ok=True)
        
        specialist_names = [
            "xss", "sqli", "csti", "lfi", "idor", "rce", 
            "ssrf", "xxe", "jwt", "openredirect", "prototype_pollution"
        ]
        
        # Collect statistics from queue manager
        from bugtrace.core.queue import queue_manager
        
        for specialist in specialist_names:
            try:
                queue = queue_manager.get_queue(specialist)
                
                # 1. Queue input (copy existing .queue file if available)
                # NOTE: v3.1 uses .queue extension with XML-like format and Base64 payloads
                source_queue_file = self.scan_dir / "queues" / f"{specialist}.queue"
                if source_queue_file.exists():
                    import shutil
                    shutil.copy(source_queue_file, queues_dir / f"{specialist}.queue")
                
                # 2. Warmup summary - what the specialist analyzed before attacking
                warmup_data = {
                    "specialist": specialist,
                    "scan_id": self.scan_id,
                    "target": self.target,
                    "queue_stats": {
                        "total_enqueued": getattr(queue, 'total_enqueued', 0),
                        "total_dequeued": getattr(queue, 'total_dequeued', 0),
                        "current_depth": queue.depth() if hasattr(queue, 'depth') else 0,
                    },
                    "work_items_received": getattr(queue, 'total_enqueued', 0),
                    "status": "COMPLETE" if queue.depth() == 0 else "TIMEOUT_PENDING"
                }
                
                warmup_file = warmup_dir / f"{specialist}_warmup.json"
                with open(warmup_file, "w", encoding="utf-8") as f:
                    json.dump(warmup_data, f, indent=2, default=str)
                
                # 3. Results - findings confirmed by this specialist
                # Get findings from state manager filtered by specialist type
                all_findings = self.state_manager.get_findings()
                specialist_findings = []
                
                # Map specialist name to finding types
                type_mapping = {
                    "xss": ["XSS", "Cross-Site Scripting", "DOM XSS", "Reflected XSS", "Stored XSS"],
                    "sqli": ["SQLI", "SQL Injection", "SQLi"],
                    "csti": ["CSTI", "Client-Side Template Injection", "SSTI", "Template Injection"],
                    "lfi": ["LFI", "Local File Inclusion", "Path Traversal"],
                    "idor": ["IDOR", "Insecure Direct Object Reference"],
                    "rce": ["RCE", "Remote Code Execution", "Command Injection"],
                    "ssrf": ["SSRF", "Server-Side Request Forgery"],
                    "xxe": ["XXE", "XML External Entity"],
                    "jwt": ["JWT", "JWT Bypass", "JWT Vulnerability"],
                    "openredirect": ["Open Redirect", "URL Redirect"],
                    "prototype_pollution": ["Prototype Pollution"],
                }
                
                valid_types = type_mapping.get(specialist, [])
                for finding in all_findings:
                    finding_type = str(finding.get("type", "")).upper()
                    if any(vt.upper() in finding_type for vt in valid_types):
                        specialist_findings.append(finding)
                
                results_data = {
                    "specialist": specialist,
                    "scan_id": self.scan_id,
                    "target": self.target,
                    "findings_count": len(specialist_findings),
                    "findings": specialist_findings,
                    "summary": {
                        "confirmed": sum(1 for f in specialist_findings if f.get("validated")),
                        "pending_validation": sum(1 for f in specialist_findings if not f.get("validated")),
                    }
                }
                
                results_file = results_dir / f"{specialist}_results.json"
                with open(results_file, "w", encoding="utf-8") as f:
                    json.dump(results_data, f, indent=2, default=str)
                    
            except Exception as e:
                logger.warning(f"[Specialist Reports] Failed to generate report for {specialist}: {e}")
        
        logger.info(f"Generated specialist reports in {specialists_dir}")

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
            # Load findings from database
            findings = self._load_findings_from_db()

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

    def _load_findings_from_db(self) -> list:
        """Load findings from database."""
        from bugtrace.core.database import get_db_manager
        db = get_db_manager()

        findings = []
        if hasattr(self, "scan_id"):
            db_findings = db.get_findings_for_scan(self.scan_id)
            if db_findings:
                logger.info(f"Loaded {len(db_findings)} findings from DB for reporting.")
                for db_f in db_findings:
                    findings.append({
                        "id": db_f.id,
                        "type": str(db_f.type.value if hasattr(db_f.type, 'value') else db_f.type),
                        "severity": db_f.severity,
                        "description": db_f.details,
                        "payload": db_f.payload_used,
                        "url": db_f.attack_url,
                        "parameter": db_f.vuln_parameter,
                        "validated": (db_f.status == "VALIDATED_CONFIRMED"),
                        "status": db_f.status,
                        "validator_notes": db_f.validator_notes,
                        "screenshot_path": db_f.proof_screenshot_path,
                        "reproduction": db_f.reproduction_command
                    })
        return findings

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
