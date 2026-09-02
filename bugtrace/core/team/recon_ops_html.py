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



class TeamReconHtmlMixin:
    """Report HTML assembly and artifact organization."""

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
    def _cleanup_unlinked_screenshots(self, linked_screenshots: set):
        """Delete unreferenced screenshots."""
        for file in settings.LOG_DIR.glob("*.png"):
            if file.name not in linked_screenshots:
                try:
                    file.unlink()
                except OSError as e:
                    logger.debug(f"Failed to delete screenshot {file}: {e}")
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
    def _embed_screenshots(self, tech_report: str, screenshots: list) -> str:
        """Embed screenshot references in markdown."""
        for screenshot in screenshots:
            if screenshot in tech_report:
                tech_report = tech_report.replace(screenshot, f"![Evidence](./{screenshot})")
        return tech_report
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
