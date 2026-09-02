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
from bugtrace.core.surface import (
    ControlModel,
    ProbeObservation,
    build_control_model,
    differs_from_control,
    drop_insecure_duplicate_origins,
    names_a_resource,
)
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
import uuid
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
# ChainDiscoveryAgent disabled: no-op (success always False, output path orphaned from scan_dir)
from bugtrace.agents.openredirect_agent import OpenRedirectAgent
from bugtrace.agents.prototype_pollution_agent import PrototypePollutionAgent
from bugtrace.agents.reattack import ReAttackAgent


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

# Pure path segment classifiers (P3-SURFACE-1)
from bugtrace.core.surface_url_policy import (
    PATH_HEX_RE,
    PATH_NUMERIC_RE,
    PATH_UUID_RE,
)

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

from bugtrace.core.team.auth_flow import TeamAuthMixin
from bugtrace.core.team.surface_flow import TeamSurfaceMixin
from bugtrace.core.team.pipeline_flow import TeamPipelineMixin
from bugtrace.core.team.phase3_flow import TeamPhase3Mixin
from bugtrace.core.team.report_flow import TeamReportMixin
from bugtrace.core.team.recon_ops_flow import TeamReconOpsMixin
from bugtrace.core.team.lifecycle_flow import TeamLifecycleMixin

class TeamOrchestrator(TeamAuthMixin, TeamSurfaceMixin, TeamPipelineMixin, TeamPhase3Mixin, TeamReportMixin, TeamReconOpsMixin, TeamLifecycleMixin):

    def __init__(self, target: str, resume: bool = False, max_depth: int = 2, max_urls: int = 15, use_vertical_agents: bool = False, output_dir: Optional[Path] = None, scan_id: Optional[int] = None, url_list: Optional[List[str]] = None, scan_depth: str = "standard", auth: Optional[Dict[str, Any]] = None, custom_headers: Optional[Dict[str, str]] = None):
        # Sanitize target: strip surrounding whitespace/newlines. A stray leading/trailing
        # space (e.g. a pasted " https://site ") otherwise reaches recon as an unparseable
        # URL → "Recon found 0 URLs to scan". Chokepoint for both API- and CLI-launched scans.
        self.target = (target or "").strip()
        self.resume = resume
        self.max_depth = max_depth
        self.max_urls = max_urls
        self._scan_depth = scan_depth
        # Strip whitespace from each provided URL too (same paste hazard); drop empties.
        self.url_list_provided = [u.strip() for u in url_list if u and u.strip()] if url_list else url_list  # Store provided URL list for Phase 1
        self.urls_to_scan: List[str] = []  # Set by _phase_1_reconnaissance
        self.agents: List[BaseAgent] = []
        self._stop_event = asyncio.Event()
        self.auth_creds: Optional[str] = None
        self.auth_config: Optional[Dict[str, Any]] = auth  # Auth config from YAML (supports TOTP)
        self._auth_required: bool = False  # Set to True after successful YAML auth - forces session usage

        # Per-scan custom HTTP headers (CLI --header / API custom_headers).
        # Merged at agent-creation time with auth-discovery headers and the global
        # DEFAULT_HEADERS_JSON so each agent receives a consistent, pre-authorised set.
        self._custom_headers: Optional[Dict[str, str]] = custom_headers

        # Captured session data from authenticated browser flow.
        # Consumed by get_effective_headers() so agents get auth cookies/headers.
        self.captured_session: Dict[str, Any] = {}

        # Scan context for event correlation (V3 pipeline).
        # It is synchronized to str(scan_id) once the DB id exists.
        self.scan_context = str(scan_id) if scan_id is not None else ""

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

        # Track last phase completed for scan resumption
        self._last_phase = None

        # Initialize specialist agents
        self._init_specialist_agents()

        # Setup vertical agent architecture
        self._init_vertical_mode(use_vertical_agents)

        # Setup persistence and resumption (use provided scan_id if available)
        self._init_database(resume, existing_scan_id=scan_id)




















































































    # Path segment classifiers — pure owner surface_url_policy (P3-SURFACE-1).
    _PATH_NUMERIC_RE = PATH_NUMERIC_RE
    _PATH_UUID_RE = PATH_UUID_RE
    _PATH_HEX_RE = PATH_HEX_RE










































    # ── Nuclei type routing (data-driven) ─────────────────────────────────

    _nuclei_routing_cache = None

























