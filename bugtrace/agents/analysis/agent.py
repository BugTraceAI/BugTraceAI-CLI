"""DASTySASTAgent shell — package owner.
"""

import asyncio
import aiohttp
import json
from typing import Dict, List, Any, Optional
from pathlib import Path
from loguru import logger

from bugtrace.core.llm_client import llm_client
from bugtrace.core.config import settings
from bugtrace.core.ui import dashboard
from bugtrace.core.http_orchestrator import orchestrator, DestinationType
from bugtrace.utils.parsers import XmlParser
from bugtrace.core.event_bus import event_bus, EventType
from bugtrace.core.verbose_events import create_emitter

from bugtrace.agents.base import BaseAgent

# xss_context values that assert the ABSENCE of a reflection point rather than describing
# one. They must not become a finding's context: doing so would relabel a candidate with a
# non-position and lose the neutral default the specialist pipeline expects.
_NO_REFLECTION_CONTEXTS = frozenset({"none", "unknown", "no_reflection", "n/a"})


from bugtrace.agents.analysis_shell.run_flow import AnalysisRunMixin
from bugtrace.agents.analysis_shell.extract_flow import AnalysisExtractMixin
from bugtrace.agents.analysis_shell.probes_flow import AnalysisProbesMixin
from bugtrace.agents.analysis_shell.llm_report_flow import AnalysisLlmReportMixin
from bugtrace.agents.analysis_shell.review_flow import AnalysisReviewMixin
from bugtrace.agents.analysis_shell.misc_flow import AnalysisMiscMixin

class DASTySASTAgent(AnalysisRunMixin, AnalysisExtractMixin, AnalysisProbesMixin, AnalysisLlmReportMixin, AnalysisReviewMixin, AnalysisMiscMixin, BaseAgent):
    """
    DAST + SAST Analysis Agent.
    Performs 5-approach analysis on a URL to identify potential vulnerabilities.
    Phase 2 (Part A) of the Sequential Pipeline.
    """
    # Class-level dedup for cookie config findings (shared across instances)
    _emitted_cookie_configs: set = set()
    # Class-level dedup for probe-confirmed cookie SQLi (shared across instances).
    # Many per-URL DASTySAST agents confirm the same cookie SQLi; emit once.
    _emitted_cookie_sqli: set = set()

    def __init__(self, url: str, tech_profile: Dict, report_dir: Path, state_manager: Any = None, scan_context: str = None, url_index: int = None, url_total: int = None):
        super().__init__("DASTySASTAgent", "Security Analysis", agent_id="analysis_agent")
        self.url = url
        self.tech_profile = tech_profile
        self.report_dir = report_dir
        self.state_manager = state_manager
        self.scan_context = scan_context or f"scan_{id(self)}"  # Default scan context
        self.url_index = url_index  # URL index for numbered reports
        self.url_total = url_total  # Total URLs in this discovery pass (for "i/N" progress)

        # Core LLM approaches (each togglable via APPROACH_* in conf)
        self.approach_mode = getattr(settings, "APPROACH_MODE", "ALL").upper()
        approach_toggles = {
            "pentester": settings.ANALYSIS_APPROACH_PENTESTER,
            "bug_bounty": settings.ANALYSIS_APPROACH_BUG_BOUNTY,
            "code_auditor": settings.ANALYSIS_APPROACH_CODE_AUDITOR,
            "red_team": settings.ANALYSIS_APPROACH_RED_TEAM,
            "researcher": settings.ANALYSIS_APPROACH_RESEARCHER,
        }
        self.approaches = [name for name, enabled in approach_toggles.items() if enabled]
        if not self.approaches:
            self.approaches = ["pentester"]  # Minimum 1 approach
        self.approaches.append("skeptical_agent")  # Always runs last as reviewer
        self.model = getattr(settings, "ANALYSIS_PENTESTER_MODEL", None) or settings.DEFAULT_MODEL
        





    # ========== Parameter-based auto-candidate injection ==========
    # File-related parameter names that suggest LFI/Path Traversal
    _LFI_PARAM_HINTS = frozenset({
        "file", "path", "doc", "document", "include", "template", "page",
        "dir", "folder", "src", "download", "read", "content", "load",
        "view", "module", "resource", "filename", "filepath", "attachment",
        "img", "image", "loc", "location",
    })
    _FILE_EXTENSIONS = frozenset({
        ".jpg", ".jpeg", ".png", ".gif", ".pdf", ".php", ".html", ".txt",
        ".xml", ".json", ".css", ".js", ".svg", ".ico", ".csv", ".log",
        ".conf", ".ini", ".yml", ".yaml", ".md", ".bak",
    })
    # Redirect-related parameter names that suggest Open Redirect
    _REDIRECT_PARAM_HINTS = frozenset({
        "redirect", "next", "return", "returnurl", "goto", "dest",
        "destination", "redir", "returnpath", "ref", "back", "backurl",
        "continue", "forward", "out", "target", "to",
    })
    # RCE-related parameter names that suggest command injection
    _RCE_PARAM_HINTS = frozenset({
        "cmd", "command", "exec", "execute", "run", "ping", "query",
        "ip", "host", "hostname", "shell", "process", "action",
    })
    # SSRF-related parameter names that suggest server-side URL fetching
    _SSRF_PARAM_HINTS = frozenset({
        "url", "uri", "src", "source", "link", "fetch", "request",
        "proxy", "callback", "webhook", "api", "endpoint", "server",
        "import", "load", "image_url", "icon_url", "avatar_url",
    })





















    # Per-approach model mapping — splits personas across providers for resilience
    _APPROACH_MODEL_MAP = {
        "pentester": "ANALYSIS_PENTESTER_MODEL",
        "bug_bounty": "ANALYSIS_BUG_BOUNTY_MODEL",
        "code_auditor": "ANALYSIS_AUDITOR_MODEL",
        "red_team": "ANALYSIS_RED_TEAM_MODEL",
        "researcher": "ANALYSIS_RESEARCHER_MODEL",
    }


























