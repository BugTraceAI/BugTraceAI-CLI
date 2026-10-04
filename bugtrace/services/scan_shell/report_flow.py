"""ScanService shell mixin (report). Hard max 2000 LOC."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime

from bugtrace.utils.logger import get_logger
from bugtrace.core.config import settings
from bugtrace.core.ui import dashboard

logger = get_logger(__name__)

from bugtrace.core.team import TeamOrchestrator
from bugtrace.core.event_bus import event_bus, EventType
from bugtrace.core.database import get_db_manager
from bugtrace.agents.reporting import ReportingAgent
from bugtrace.core.http_manager import http_manager

from bugtrace.services.scan_shell.report_repeater import ScanReportRepeaterMixin
from bugtrace.services.scan_shell.report_delete import ScanReportDeleteMixin
from bugtrace.services.scan_shell.report_load import ScanReportLoadMixin

class ScanReportMixin(ScanReportRepeaterMixin, ScanReportDeleteMixin, ScanReportLoadMixin):
    pass

