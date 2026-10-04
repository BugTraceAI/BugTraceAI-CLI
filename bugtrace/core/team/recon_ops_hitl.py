"""Recon/hunter ops and remaining medium helpers.

Shell mixin; hard max 2000 LOC, prefer ~800-1500.
"""

from __future__ import annotations

import asyncio
import json
import hashlib
import re
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
