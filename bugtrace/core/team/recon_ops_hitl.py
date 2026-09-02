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



class TeamReconHitlMixin:
    """HITL pause/resume and checkpoint helpers."""

    async def pause_pipeline(self, reason: str = "User requested") -> bool:
        """Pause through the live ScanContext control path."""
        ctx = getattr(self, "_scan_context", None)
        if ctx is None:
            return False
        ctx.request_pause()
        logger.info(f"Scan {self.scan_id} pause requested: {reason}")
        return True
    async def resume_pipeline(self) -> bool:
        """Resume through the live ScanContext control path."""
        ctx = getattr(self, "_scan_context", None)
        if ctx is None:
            return False
        ctx.request_resume()
        logger.info(f"Scan {self.scan_id} resume requested")
        return True
    def get_pipeline_state(self) -> Optional[Dict]:
        """Get current pipeline state."""
        if self._pipeline_state:
            return self._pipeline_state.to_dict()
        return None
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
        """V4 Feature: Step-by-Step Debugging Checkpoint.

        NEVER blocks when running inside uvicorn/API server.
        Guards: DEBUG flag + sys.isatty + os.isatty(0) + TERM env + 30s timeout.
        """
        if not settings.DEBUG:
            return

        import sys
        import os
        if not sys.stdin.isatty() or not os.isatty(0) or not os.environ.get("TERM"):
            logger.debug(f"[V4 DEBUG] Checkpoint '{phase_name}' skipped (no interactive TTY)")
            return

        print(f"\n✋ [V4 DEBUG] Phase '{phase_name}' Complete. System PAUSED.")
        print(f"👉 Press ENTER to continue... (auto-continues in 30s)")
        try:
            loop = asyncio.get_event_loop()
            await asyncio.wait_for(
                loop.run_in_executor(None, input),
                timeout=30.0
            )
        except asyncio.TimeoutError:
            logger.warning(f"[V4 DEBUG] Checkpoint '{phase_name}' auto-continued after 30s")
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
