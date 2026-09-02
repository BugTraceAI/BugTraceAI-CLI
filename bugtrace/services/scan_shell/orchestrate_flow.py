"""ScanService shell mixin (orchestrate). Hard max 2000 LOC."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime

from bugtrace.utils.logger import get_logger
from bugtrace.core.config import settings
from bugtrace.core.ui import dashboard
from bugtrace.services.scan_context import ScanContext

logger = get_logger(__name__)

class ScanOrchestrateMixin:
    def _create_orchestrator(self, ctx: ScanContext, output_dir: Path):
        """Create and configure TeamOrchestrator."""
        from bugtrace.core.team import TeamOrchestrator

        orchestrator = TeamOrchestrator(
            target=ctx.options.target_url,
            resume=ctx.options.resume,
            max_depth=ctx.options.max_depth,
            max_urls=ctx.options.max_urls,
            use_vertical_agents=ctx.options.use_vertical,
            output_dir=output_dir,
            scan_id=ctx.scan_id,  # Pass existing scan_id to avoid duplicate creation
            scan_depth=ctx.options.scan_depth or settings.SCAN_DEPTH,
            url_list=ctx.options.url_list,  # Pre-defined URL list from file upload or Swagger
            auth=ctx.options.auth,  # Pass auth config for browser-based TOTP login
            custom_headers=ctx.options.custom_headers,  # Per-scan headers (API/UI scans, validated at the schema boundary)
        )

        # CRITICAL: Monkey-patch stop_event for graceful shutdown
        orchestrator._stop_event = ctx.stop_event
        # Pause support: orchestrator checks this at phase boundaries
        orchestrator._scan_context = ctx

        return orchestrator

