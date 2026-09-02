"""Reporting, CDP validation, and findings shell.

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


class TeamReportMixin:
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

        # Persist specialist finding to DB so exploitation results
        # (e.g. JWT secret cracked → CRITICAL) update the original finding
        try:
            if hasattr(self, 'scan_id') and self.scan_id and hasattr(self, 'db'):
                self.db.save_scan_result(
                    self.target, [finding], scan_id=self.scan_id
                )
        except Exception as e:
            logger.error(f"Failed to persist specialist finding to DB: {e}")

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
            logger.error(f"❌ Report generation failed: {e}")

    def _create_report_directory(self) -> Path:
        """Return unified report directory (created in __init__)."""
        # v3.1: Use unified report_dir created in __init__ instead of creating new one
        # This ensures specialists and ReportingAgent write to the same directory
        (self.report_dir / "logs").mkdir(exist_ok=True)
        return self.report_dir

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

    async def _invoke_reporting_agent(self, findings: list, urls_scanned: list, metadata: dict, report_dir: Path):
        """Invoke ReportingAgent for final report."""
        logger.info(f"🤖 Deploying ReportingAgent for final assessment...")
        
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
            # Register report_dir in DB only NOW, after files are confirmed on disk.
            # This ensures has_report is never true for empty directories.
            self.db.update_scan_report_dir(self.scan_id, str(report_dir))
            logger.info(f"✅ ReportingAgent finished. Reports saved to {report_dir}")
        else:
            logger.warning("⚠️ ReportingAgent completed but returned no paths.")

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

        logger.info("🤖 Generating Technical Report (AI)...")

        tech_prompt = self._build_technical_prompt(report_data, findings_summary, meta_summary, screenshots)
        tech_report = await llm_client.generate(tech_prompt, "Report-Tech")

        if tech_report:
            tech_report = self._embed_screenshots(tech_report, screenshots)
            with open(self.scan_dir / "TECHNICAL_REPORT.md", "w") as f:
                f.write(tech_report)
            logger.info("✅ Technical Report generated")

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

    async def _generate_executive_summary(self, report_data: dict) -> str:
        """Generate executive summary report."""
        from bugtrace.core.llm_client import llm_client
        import json

        logger.info("🤖 Generating Executive Summary (AI)...")

        exec_prompt = self._build_executive_prompt(report_data)
        exec_report = await llm_client.generate(exec_prompt, "Report-Exec")

        if exec_report:
            with open(self.scan_dir / "EXECUTIVE_SUMMARY.md", "w") as f:
                f.write(exec_report)
            logger.info("✅ Executive Summary generated")

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

        logger.info("✅ HTML Report generated")

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

    async def _phase_cdp_validation(self, dashboard, scan_dir):
        """Decoupled CDP validation stage (the AgenticValidator).

        Runs the heavy, single-session CDP confirmation over the 'hard cola' — the
        XSS/CSTI/SSTI findings the specialists' fast, multi-threaded Playwright pass
        left PENDING/NEEDS_CDP. Kept DECOUPLED: reuses the proven ValidationEngine
        triage + batch (its own component, own dashboard logs, re-runnable), and only
        touches the hard residue (CDP is slow/serial, so we spend it sparingly).

        FAIL-SAFE: every error is swallowed. The scan ALWAYS continues with the findings
        exactly as the specialists left them — CDP can only upgrade a verdict, never
        break the scan.
        """
        ve = None
        try:
            findings = self.state_manager.get_findings()
            if not findings:
                return
            from bugtrace.core.validator_engine import ValidationEngine
            ve = ValidationEngine(
                scan_id=self.scan_id, output_dir=scan_dir, scan_dir=scan_dir,
                target_url=self.target,
            )
            needs_cdp = ve._triage_findings(findings).get("needs_cdp", [])
            # Only CDP-validate findings that actually carry a payload+url to inject. CDP
            # can't meaningfully test a finding with no payload — it would just time out on
            # the bare URL and WRONGLY mark it FALSE_POSITIVE. Leave those as the
            # specialists left them (a no-payload probe is noise, not a rejected vuln).
            needs_cdp = [f for f in needs_cdp if (f.get("payload") or "").strip() and (f.get("url") or "").strip()]
            if not needs_cdp:
                logger.info("[CDP] No residual findings need CDP — fast layers covered everything.")
                dashboard.log("[CDP] Nothing to validate (Playwright closed everything).", "INFO")
                return
            dashboard.log(f"[CDP] Validating {len(needs_cdp)} residual finding(s) via AgenticValidator (serial CDP)...", "INFO")
            logger.info(f"[CDP] {len(needs_cdp)} finding(s) → decoupled AgenticValidator CDP stage")
            await ve._validate_batch(needs_cdp)  # updates the finding dicts in place with CDP verdicts
            self._write_cdp_results(scan_dir, needs_cdp)
            confirmed = sum(1 for f in needs_cdp if f.get("status") == "VALIDATED_CONFIRMED")
            logger.info(f"[CDP] Done: {confirmed}/{len(needs_cdp)} confirmed by CDP")
            dashboard.log(f"[CDP] {confirmed}/{len(needs_cdp)} confirmed via CDP.", "SUCCESS")
        except Exception as e:
            logger.warning(f"[CDP] Stage failed — scan continues with specialist verdicts unchanged: {e}", exc_info=True)
            try:
                dashboard.log("[CDP] Stage error (non-fatal), scan continues.", "WARN")
            except Exception:
                pass
        finally:
            # Decoupled cleanup: drop the validator's VULNERABILITY_DETECTED subscription
            # so we don't leak a subscriber per scan on a long-lived server.
            if ve is not None:
                try:
                    from bugtrace.core.event_bus import event_bus, EventType
                    event_bus.unsubscribe(
                        EventType.VULNERABILITY_DETECTED.value,
                        ve.validator.handle_vulnerability_detected,
                    )
                except Exception:
                    pass

    def _write_cdp_results(self, scan_dir, cdp_findings):
        """Persist CDP verdicts back into specialists/results/*.json IN PLACE.

        The ReportingAgent reads only specialists/results/, so the verdict must land
        there. We update the matching entry's status in place (match by url+parameter+
        type) rather than writing a new file — a separate file would duplicate the
        PENDING and CONFIRMED versions into different report buckets.
        """
        results_dir = Path(scan_dir) / "specialists" / "results"
        if not results_dir.exists():
            return
        verdicts = {}
        for f in cdp_findings:
            key = (f.get("url", ""), f.get("parameter", ""), str(f.get("type", "")).upper())
            verdicts[key] = f
        for jf in results_dir.glob("*.json"):
            try:
                data = json.loads(jf.read_text(encoding="utf-8"))
            except Exception:
                continue
            flist = data.get("findings") if isinstance(data, dict) else None
            if not isinstance(flist, list):
                continue
            changed = False
            for fi in flist:
                if not isinstance(fi, dict):
                    continue
                key = (fi.get("url", ""), fi.get("parameter", ""), str(fi.get("type", "")).upper())
                v = verdicts.get(key)
                if v and v.get("status") and v.get("status") != fi.get("status"):
                    fi["status"] = v["status"]
                    if v.get("validated") is not None:
                        fi["validated"] = v["validated"]
                    if v.get("validator_notes"):
                        fi["validator_notes"] = v["validator_notes"]
                    if v.get("screenshot_path"):
                        fi["screenshot_path"] = v["screenshot_path"]
                    changed = True
            if changed:
                try:
                    jf.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
                    logger.info(f"[CDP] Updated verdicts in {jf.name}")
                except Exception as e:
                    logger.warning(f"[CDP] Failed to write {jf.name}: {e}")

    async def _phase_4_reporting(self, dashboard, scan_dir):
        """Execute Phase 4: Reporting."""
        logger.info("=== PHASE 4: REPORTING ===")
        dashboard.set_phase("📋 COMPILING INTEL")
        dashboard.set_status("Running", "Generating reports...")
        logger.info("📊 Phase 4: Generating Final Reports")
        logger.info("Generating final consolidated reports...")

        all_findings = self.state_manager.get_findings()
        logger.info(f"Retrieved {len(all_findings)} findings from state manager")

        self._save_raw_findings(scan_dir, all_findings)
        await self._generate_specialist_reports(scan_dir)  # v3.1: Generate specialists/ directory structure
        await self._generate_initial_report(scan_dir)

        logger.info(f"📄 Final report in {scan_dir}")

        from bugtrace.schemas.db_models import ScanStatus
        self.db.update_scan_status(self.scan_id, ScanStatus.COMPLETED)
        logger.info(f"Scan {self.scan_id} marked as COMPLETED")
        logger.info("Phase 4 complete")

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

        logger.info("🔍 Starting Global Review and Chaining Analysis...")

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
                logger.warning(f"🔗 Detected {len(chains)} potential attack chains!")
                with open(scan_dir / "attack_chains.json", "w") as f:
                    json.dump({"chains": chains, "findings_reviewed": len(findings)}, f, indent=4)
        except Exception as e:
            logger.debug(f"Global review failed: {e}")

    async def _generate_v2_report(self, findings: list, urls: list, tech_profile: dict, scan_dir: Path, start_time: datetime):
        """Phase 4: Generates a premium report based on the sequential scan results."""
        try:
            # Load findings from files (DB = write-only)
            findings = self._load_findings_from_files()

            logger.info(f"Starting report generation with {len(findings)} findings")
            logger.info(f"📊 Generating final reports with {len(findings)} findings...")

            # Collect and deduplicate findings
            collector = self._build_data_collector(findings, urls, tech_profile, start_time)

            # Generate reports
            await self._generate_all_reports(collector, scan_dir)

            logger.info(f"✅ Reports generated in {scan_dir}")

        except Exception as e:
            logger.error(f"Failed to generate V2 report: {e}", exc_info=True)
            logger.error(f"❌ Report generation failed: {e}")

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

