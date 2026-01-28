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

# Event Bus integration
from bugtrace.core.event_bus import event_bus

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
            logger.error(f"Agent {agent.name} failed: {e}")
            return {"error": str(e), "findings": []}

class TeamOrchestrator:
    
    def __init__(self, target: str, resume: bool = False, max_depth: int = 2, max_urls: int = 15, use_vertical_agents: bool = False, output_dir: Optional[Path] = None):
        self.target = target
        self.output_dir = output_dir
        self.resume = resume
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.agents: List[BaseAgent] = []
        self._stop_event = asyncio.Event()
        self.auth_creds: Optional[str] = None
        
        # Specialist Agents (Persistent instances for event-driven mode)
        self.jwt_agent = JWTAgent(event_bus=event_bus)

        # NEW: Phase 1 Competitive Advantage Agents
        self.asset_discovery_agent = AssetDiscoveryAgent(event_bus=event_bus)
        self.api_security_agent = APISecurityAgent(event_bus=event_bus)
        self.chain_discovery_agent = ChainDiscoveryAgent(event_bus=event_bus)

        # Event Bus reference
        self.event_bus = event_bus
        logger.info("Event Bus integrated into TeamOrchestrator")
        logger.info("✨ Phase 1 Agents loaded: AssetDiscovery, APISecurity, ChainDiscovery")
        
        # New: Vertical Agent Architecture (URLMasterAgent)
        self.use_vertical_agents = use_vertical_agents
        self.url_semaphore = asyncio.Semaphore(settings.MAX_CONCURRENT_URL_AGENTS)
        if use_vertical_agents:
            logger.info(f"Sequential Pipeline (V2) ENABLED (max {settings.MAX_CONCURRENT_URL_AGENTS} concurrent URLs)")
            
        # --- Persistence & Resumption Logic ---
        from bugtrace.core.database import get_db_manager
        self.db = get_db_manager()
        
        if resume:
            self.scan_id = self.db.get_active_scan(target)
            if not self.scan_id:
                logger.warning(f"No active scan found to resume for {target}. Starting new.")
                self.scan_id = self.db.create_new_scan(target)
                self.resume = False # False start
        else:
            self.scan_id = self.db.create_new_scan(target)
            
        logger.info(f"TeamOrchestrator initialized for Scan ID: {self.scan_id}")
        
        # State Manager (Now DB backed)
        self.state_manager = get_state_manager(target)
        self.state_manager.set_scan_id(self.scan_id)
        
        # Initialize State
        self.processed_urls = set()
        self.url_queue = [] 
        
        # Load active state if reusing scan
        if self.resume:
             state = self.state_manager.load_state()
             if state:
                 self.processed_urls = set(state.get("processed_urls", []))
                 self.url_queue = state.get("url_queue", [])
                 logger.info(f"Resumed scan: {len(self.processed_urls)} URLs already processed, {len(self.url_queue)} pending.")
    
    def set_auth(self, creds: str):
        self.auth_creds = creds
        
    async def start(self):
        """Starts the Multi-Agent Team."""
        
        # UI Setup
        def dashboard_sink(message):
            try:
                record = message.record
                level = record["level"].name
                text = record["message"]
                if level in ["INFO", "SUCCESS", "WARNING", "ERROR", "CRITICAL"]:
                    dashboard.log(text, level)
            except Exception as e:
                logger.debug(f"Dashboard sink error: {e}")
        
        # Signal Management with HITL (Human-In-The-Loop)
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
                # First Ctrl+C: Enter HITL mode
                self.hitl_active = True
                asyncio.create_task(self._enter_hitl_mode())

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, handle_sigint)
            except NotImplementedError:
                pass 
        
        logger.remove()
        logger.add(dashboard_sink, level="INFO")
        logger.add("logs/execution.log", rotation="10 MB", level="DEBUG")
        
        # Input Helper
        import sys, select, tty, termios
        
        def is_data():
            return select.select([sys.stdin], [], [], 0) == ([sys.stdin], [], [])

        if not dashboard.active:
            with Live(dashboard, refresh_per_second=4, screen=True) as live:
                dashboard.active = True
                await self._run_hunter_core()
                dashboard.active = False
        else:
            await self._run_hunter_core()

    async def _run_hunter_core(self):
        """Core Hunter logic separated from UI lifecycle."""
        dashboard.set_target(self.target)
        
        # --- PHASE 0: Diagnostics ---
        from bugtrace.core.diagnostics import diagnostics
        if not await diagnostics.run_all():
            dashboard.log("❌ CRITICAL SYSTEM FAILURE: Diagnostics failed. Aborting.", "CRITICAL")
            await asyncio.sleep(3) # Initial wait to read
            sys.exit(1)
        
        dashboard.set_phase("TEAM_ASSEMBLY")
        
        if not self.resume:
            self.state_manager.clear()
        
        # --- PHASE 0.5: Authentication ---
        # TASK-07: Added try/finally for browser cleanup on auth errors
        if self.auth_creds:
            dashboard.set_phase("AUTHENTICATION")
            dashboard.current_agent = "AuthAgent"
            dashboard.log(f"Initiating authenticated session for {self.auth_creds.split(':')[0]}...", "INFO")
            from bugtrace.tools.visual.browser import browser_manager
            # Attempt login at common paths or target directly
            # For Gin & Juice, login is at /login
            login_url = f"{self.target.rstrip('/')}/login"
            try:
                success = await browser_manager.login(login_url, self.auth_creds)
                if success:
                    dashboard.log("Authentication Successful. Session captured.", "SUCCESS")
                else:
                    dashboard.log("Authentication Failed. Proceeding as guest.", "WARN")
            except Exception as e:
                logger.error(f"Authentication error: {e}")
                dashboard.log(f"Authentication Error: {e}. Proceeding as guest.", "ERROR")
            finally:
                # Ensure browser resources are cleaned up even on error
                try:
                    if hasattr(browser_manager, 'cleanup_auth_session'):
                        await browser_manager.cleanup_auth_session()
                except Exception as cleanup_err:
                    logger.debug(f"Auth session cleanup warning: {cleanup_err}")
            
        # =====================================================
        # V2 SEQUENTIAL PIPELINE MODE (THE ONLY MODE)
        # =====================================================
        # We strictly enforce sequential execution to ensure stability
        # Parallel chaos is removed.
        
        dashboard.log("🔒 Enforcing Sequential Hunter Loop for stability", "INFO")
        
        if dashboard.stop_requested or self._stop_event.is_set():
            return

        # Register Global Event Handlers
        # File Upload Agent is usually on-demand or per-url, but can be global
        await self._run_sequential_pipeline(dashboard)
        
        dashboard.set_phase("COMPLETE")
        await asyncio.sleep(2)

    async def _generate_vertical_report(self, findings: list, urls_scanned: list, metadata: dict = None):
        """
        Generate consolidated report for vertical mode.
        Uses the new ReportingAgent for high-quality artifacts.
        """
        from pathlib import Path
        from datetime import datetime
        from urllib.parse import urlparse
        import shutil
        
        try:
            # Create report directory based on target
            parsed = urlparse(self.target)
            domain = parsed.netloc.replace(":", "_") or "local"
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_dir = settings.REPORT_DIR / f"{domain}_{timestamp}"
            report_dir.mkdir(parents=True, exist_ok=True)
            
            # Create subdirectories for organization
            (report_dir / "logs").mkdir(exist_ok=True)
            
            # 1. Use ReportingAgent for the "Beautiful" part
            dashboard.log(f"🤖 Deploying ReportingAgent for final assessment...", "INFO")
            reporting_agent = ReportingAgent(self.target)
            
            # Organize Artifacts by URL (Per-URL Folder Structure)
            url_folders = {}
            for u in urls_scanned:
                # Sanitize URL for folder name
                safe_name = u.replace("://", "_").replace("/", "_").replace("?", "_").replace("&", "_").replace("=", "_")
                # Limit length
                safe_name = safe_name[:100]
                folder = report_dir / safe_name
                folder.mkdir(exist_ok=True)
                url_folders[u] = folder
                
            # Move screenshots to their respective URL folders
            linked_screenshots = set()
            for f in findings:
                f_url = f.get("url", "unknown")
                # find matching folder (closest match or default to root/logs)
                target_folder = report_dir / "logs" # Default
                
                # Match finding URL to scanned URLs
                # Simple exact match or derived
                safe_name = f_url.replace("://", "_").replace("/", "_").replace("?", "_").replace("&", "_").replace("=", "_")[:100]
                possible_folder = report_dir / safe_name
                
                if possible_folder.exists():
                    target_folder = possible_folder
                
                # Handle Screenshot
                if f.get("screenshot"):
                    original_name = Path(f["screenshot"]).name
                    source_path = settings.LOG_DIR / original_name
                    
                    # Try legacy location too
                    if not source_path.exists():
                         source_path = Path("reports") / original_name
                         
                    if source_path.exists():
                        dest_path = target_folder / original_name
                        shutil.move(str(source_path), str(dest_path))
                        # Update finding to point to relative path for HTML
                        f["screenshot"] = f"{target_folder.name}/{original_name}"
                        linked_screenshots.add(original_name)
                    else:
                        # Keep original path if not found (might be absolute custom path)
                        pass
                
                # Generate Mini-Report for this URL (JSON)
                # This matches "URL1-Exploit_Report" concept
                with open(target_folder / "finding_details.json", "a") as fd:
                     import json
                     fd.write(json.dumps(f, default=str) + "\n")

            # Cleanup unlinked screenshots in LOG_DIR
            for file in settings.LOG_DIR.glob("*.png"):
                if file.name not in linked_screenshots:
                    try:
                        file.unlink() # Delete unreferenced to save space
                    except OSError as e:
                        logger.debug(f"Failed to delete screenshot {file}: {e}")

            # 2. Invoke AI Report Generation
            await reporting_agent.generate_final_report(findings, urls_scanned, metadata, report_dir)
            
            # 3. Cleanup redundant folders if they were used
            for folder in ["evidence", "screenshots", "test_results"]:
                p = Path(folder)
                if p.exists() and p.is_dir():
                    # Move orphan files if any
                    for file in p.glob("*"):
                        if file.is_file():
                             shutil.move(str(file), str(report_dir / "logs" / file.name))
                    try:
                        p.rmdir() # Only if empty now
                    except OSError as e:
                        logger.debug(f"Failed to remove directory {p}: {e}")

            print(f"\n{'='*60}")
            print(f"[✓] SCAN COMPLETE - V1.6.1 Phoenix")
            print(f"[✓] Target: {self.target}")
            print(f"[✓] Findings: {len(findings)}")
            print(f"[✓] Detailed Report: {report_dir / 'REPORT.html'}")
            print(f"{'='*60}\n")
            
        except asyncio.TimeoutError as e:
            logger.critical(f"[ReportingAgent] ⏳ CRASH DETECTED: Report generation exceeded timeout. Killing tool. Error: {e}")
            # Optionally, return a default or partial report structure
            return {}
        except Exception as e:
            logger.error(f"Failed to generate vertical report: {e}")
            import traceback
            logger.debug(traceback.format_exc())
            dashboard.log(f"❌ Report generation failed: {e}", "ERROR")

    async def _generate_ai_reports(self, report_dir, report_data: dict, screenshots: list):
        """
        Generate professional AI-written reports: Technical + Executive.
        """
        from bugtrace.core.llm_client import llm_client
        import json
        
        findings_summary = json.dumps(report_data["findings"], indent=2, default=str)[:8000]
        meta_summary = json.dumps(report_data.get("metadata", {}), indent=2, default=str)[:4000]
        
        # 1. Technical Report (Pentester Level)
        dashboard.log("🤖 Generating Technical Report (AI)...", "INFO")
        
        system_prompt = conductor.get_full_system_prompt("ai_writer")
        if system_prompt:
             tech_prompt = system_prompt.split("## Technical Assessment Report Prompt (Full)")[-1].split("## ")[0].strip()
        else:
            tech_prompt = f"""You are a Senior Penetration Tester writing a Professional Technical Assessment Report.
            
            TARGET: {report_data["scan_info"]["target"]}
            SCAN DATE: {report_data["scan_info"]["scan_date"]}
            URLS ANALYZED: {report_data["scan_info"]["urls_scanned"]}
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
        
        tech_prompt = tech_prompt.format(
            target=report_data["scan_info"]["target"],
            scan_date=report_data["scan_info"]["scan_date"],
            urls_scanned=report_data["scan_info"]["urls_scanned"],
            findings_summary=findings_summary,
            meta_summary=meta_summary,
            screenshots=screenshots
        )
        
        tech_report = await llm_client.generate(tech_prompt, "Report-Tech")
        
        if tech_report:
            # Embed screenshots as references in markdown
            for screenshot in screenshots:
                if screenshot in tech_report:
                    tech_report = tech_report.replace(screenshot, f"![Evidence](./{screenshot})")
            
            with open(report_dir / "TECHNICAL_REPORT.md", "w") as f:
                f.write(tech_report)
            dashboard.log("✅ Technical Report generated", "SUCCESS")
        
        # 2. Executive Summary (C-Level)
        dashboard.log("🤖 Generating Executive Summary (AI)...", "INFO")
        
        if system_prompt:
             exec_prompt = system_prompt.split("## CISO Executive Summary Prompt (Full)")[-1].split("## ")[0].strip()
        else:
            exec_prompt = f"""You are a CISO writing an Executive Summary for board-level stakeholders.
            
            TARGET: {report_data["scan_info"]["target"]}
            TOTAL VULNERABILITIES: {report_data["summary"]["total_findings"]}
            BY TYPE: {json.dumps(report_data["summary"]["by_type"])}
            BY SEVERITY: {json.dumps(report_data["summary"]["by_severity"])}
            ATTACK SURFACE (INPUTS): {len(report_data.get("metadata", {}).get("inputs_found", []))}
            TECH STACK: {json.dumps(report_data.get("metadata", {}).get("tech_stack", {}))}
            
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
        
        exec_prompt = exec_prompt.format(
            target=report_data["scan_info"]["target"],
            total_findings=report_data["summary"]["total_findings"],
            by_type=json.dumps(report_data["summary"]["by_type"]),
            by_severity=json.dumps(report_data["summary"]["by_severity"]),
            inputs_count=len(report_data.get("metadata", {}).get("inputs_found", [])),
            tech_stack=json.dumps(report_data.get("metadata", {}).get("tech_stack", {}))
        )
        
        exec_report = await llm_client.generate(exec_prompt, "Report-Exec")
        
        if exec_report:
            with open(report_dir / "EXECUTIVE_SUMMARY.md", "w") as f:
                f.write(exec_report)
            dashboard.log("✅ Executive Summary generated", "SUCCESS")
        
        # 3. Generate HTML version (optional but nice)
        if tech_report:
            await self._generate_html_report(report_dir, tech_report, exec_report, screenshots, report_data.get("findings", []))
    
    async def _generate_html_report(self, report_dir, tech_md: str, exec_md: str, screenshots: list, findings: list = None):
        """Generate a beautiful HTML report from the markdown."""
        try:
            import markdown
            import re
        except ImportError:
            # If markdown not installed, skip HTML generation
            return
        
        findings = findings or []
        
        # Calculate Severity Counts
        sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in findings:
            s = f.get("severity", "Info").capitalize()
            if s in sev_counts:
                sev_counts[s] += 1
            else:
                sev_counts["Info"] += 1

        html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; background: #0d1117; color: #c9d1d9; padding-right: 240px; }}
        h1 {{ color: #58a6ff; border-bottom: 2px solid #30363d; padding-bottom: 10px; }}
        h2 {{ color: #79c0ff; margin-top: 30px; }}
        h3 {{ color: #a5d6ff; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #30363d; padding: 12px; text-align: left; }}
        th {{ background: #21262d; color: #58a6ff; }}
        tr:nth-child(even) {{ background: #161b22; }}
        code {{ background: #21262d; padding: 2px 6px; border-radius: 4px; color: #f97583; }}
        pre {{ background: #161b22; padding: 15px; border-radius: 6px; overflow-x: auto; }}
        .critical {{ color: #f85149; font-weight: bold; }}
        .high {{ color: #db6d28; font-weight: bold; }}
        .medium {{ color: #d29922; }}
        .low {{ color: #3fb950; }}
        img {{ max-width: 100%; border: 1px solid #30363d; border-radius: 6px; margin: 10px 0; }}
        .nav {{ background: #21262d; padding: 15px; border-radius: 6px; margin-bottom: 30px; }}
        .nav a {{ color: #58a6ff; text-decoration: none; margin-right: 20px; }}
        .nav a:hover {{ text-decoration: underline; }}
        .header {{ background: linear-gradient(135deg, #238636, #1f6feb); padding: 30px; border-radius: 10px; margin-bottom: 30px; }}
        .header h1 {{ border: none; color: white; margin: 0; }}
        
        /* Floating Sidebar */
        .sidebar {{
            position: fixed;
            top: 20px;
            right: 20px;
            width: 200px;
            background: #161b22;
            padding: 15px;
            border: 1px solid #30363d;
            border-radius: 6px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.5);
            max-height: 90vh;
            overflow-y: auto;
        }}
        .sidebar h3 {{ margin-top: 0; font-size: 16px; color: #c9d1d9; border-bottom: 1px solid #30363d; padding-bottom: 8px; }}
        .sidebar a {{ display: block; color: #58a6ff; text-decoration: none; margin: 8px 0; font-size: 14px; transition: color 0.2s; }}
        .sidebar a:hover {{ color: #79c0ff; text-decoration: none; padding-left: 5px; }}
        .count-badge {{ background: #30363d; color: #c9d1d9; padding: 2px 8px; border-radius: 10px; font-size: 12px; float: right; }}
        .crit-badge {{ background: rgba(248, 81, 73, 0.2); color: #f85149; }}
        .high-badge {{ background: rgba(219, 109, 40, 0.2); color: #db6d28; }}
        .med-badge {{ background: rgba(210, 153, 34, 0.2); color: #d29922; }}
        .low-badge {{ background: rgba(63, 185, 80, 0.2); color: #3fb950; }}
        
        @media (max-width: 1000px) {{
            body {{ padding-right: 20px; }}
            .sidebar {{ position: static; width: auto; margin-bottom: 20px; }}
        }}
        .watermark {
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%) rotate(-45deg);
            font-size: 15vw;
            color: rgba(255, 255, 255, 0.02);
            white-space: nowrap;
            pointer-events: none;
            z-index: 0;
            user-select: none;
        }
    </style>
</head>
<body>
    <div class="watermark">CONFIDENTIAL</div>
    <div class="sidebar">
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
    </div>

    <div class="header">
        <h1>🔒 BugtraceAI Security Assessment</h1>
    </div>
    
    <section id="executive">
        <h1>Executive Summary</h1>
        {exec_content}
    </section>
    
    <section id="technical">
        <h1>Technical Assessment</h1>
        {tech_content}
    </section>
    
    <section id="evidence">
        <h1>Evidence Screenshots</h1>
        {evidence_section}
    </section>
    
    <footer style="margin-top: 50px; padding-top: 20px; border-top: 1px solid #30363d; color: #6e7681; font-size: 0.9em;">
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
    </footer>
</body>
</html>"""
        
        # Convert markdown to HTML
        tech_html = markdown.markdown(tech_md or "", extensions=['tables', 'fenced_code'])
        exec_html = markdown.markdown(exec_md or "", extensions=['tables', 'fenced_code'])
        
        # Inject IDs into Technical HTML for anchoring
        # We look for <h3>Title - Severity</h3> patterns and inject id="severity-[level]" into the FIRST occurrence
        for sev in ["Critical", "High", "Medium", "Low"]:
            # Valid patterns: <h3>XSS - Critical</h3> or <h3>... (Critical)</h3>
            # The prompt says: ### [Vulnerability Type] - [Severity]
            # So looking for " - Critical" or similar inside h3 tag
            pattern = re.compile(rf'(<h3.*?>.*?[\s\-(]+{sev}.*?</h3>)', re.IGNORECASE)
            
            # Use a function to only replace the FIRST occurrence with the ID
            def replace_first(match):
                return match.group(0).replace('<h3', f'<h3 id="severity-{sev.lower()}"', 1)
            
            # re.sub with count=1
            tech_html = pattern.sub(replace_first, tech_html, count=1)
        
        # Build evidence section
        evidence_items = []
        for screenshot in screenshots:
            evidence_items.append(f'<div><h3>{screenshot}</h3><img src="{screenshot}" alt="{screenshot}"></div>')
        evidence_section = "\n".join(evidence_items) if evidence_items else "<p>No screenshots captured.</p>"
        
        html_content = html_template.format(
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

    async def _enter_hitl_mode(self):
        """
        Enter Human-In-The-Loop mode.
        Pauses scan and shows interactive menu.
        """
        import sys
        import termios
        import tty
        
        # Restore terminal to normal mode for input
        try:
            old_settings = termios.tcgetattr(sys.stdin)
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
        except (termios.error, AttributeError) as e:
            logger.debug(f"Terminal settings restoration failed: {e}")
        
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
        
        try:
            choice = input("Your choice: ").strip().lower()
        except EOFError:
            choice = 'c'
        
        if choice == 'c':
            print("▶️  Resuming scan...")
            self.hitl_active = False
            self.sigint_count = 0
            
        elif choice == 'f':
            self._show_findings()
            await self._enter_hitl_mode()  # Show menu again
            
        elif choice == 's':
            print("💾 Saving progress...")
            await self._save_hitl_progress()
            print("✅ Progress saved. Exiting...")
            self._stop_event.set()
            
        elif choice == 'q':
            print("👋 Quitting...")
            sys.exit(0)
            
        else:
            print(f"❓ Unknown option: {choice}")
            await self._enter_hitl_mode()
    
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
        
        # Create partial report
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
        if settings.DEBUG: # Only in debug mode (set in bugtraceaicli.conf)
            print(f"\n✋ [V4 DEBUG] Phase '{phase_name}' Complete. System PAUSED.")
            print(f"👉 Press ENTER to continue to next phase... (or Ctrl+C to abort)")
            try:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, input)
            except Exception:
                pass
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

    async def _run_sequential_pipeline(self, dashboard):
        """Implements the V2 Sequential Pipeline Flow."""
        logger.info("Entering V2 Sequential Pipeline")
        start_time = datetime.now()
        
        # 0. Setup Scan Folder with organized structure
        timestamp = start_time.strftime("%Y%m%d_%H%M%S")
        from urllib.parse import urlparse
        domain = urlparse(self.target).netloc or "unknown"
        if ":" in domain:
            domain = domain.split(":")[0]
            
        if self.output_dir:
            scan_dir = self.output_dir
        else:
            scan_dir = settings.REPORT_DIR / f"{domain}_{timestamp}"
        
        self.scan_dir = scan_dir
        scan_dir.mkdir(parents=True, exist_ok=True)
        
        # Create organized subdirectories
        recon_dir = scan_dir / "recon"
        analysis_dir = scan_dir / "analysis"
        captures_dir = scan_dir / "captures"
        recon_dir.mkdir(exist_ok=True)
        analysis_dir.mkdir(exist_ok=True)
        captures_dir.mkdir(exist_ok=True)
        
        dashboard.log(f"📂 Scan directory created: {scan_dir.name}", "INFO")
        
        # 1. PHASE 1: RECONNAISSANCE
        dashboard.set_phase("PHASE_1_RECON")
        
        # Target Health Check (Sentinel Guard)
        async with httpx.AsyncClient() as client:
            try:
                resp = await client.get(self.target, timeout=10.0)
                if resp.status_code >= 500:
                    dashboard.log(f"Target {self.target} is unstable (HTTP {resp.status_code}). Aborting scan.", "ERROR")
                    return
            except Exception as e:
                dashboard.log(f"Target {self.target} is unreachable. Skipping engagement. Error: {e}", "ERROR")
                return

        urls_to_scan = []
        self.tech_profile = {"frameworks": [], "server": "unknown"}
        
        if self.resume and self.url_queue:
            dashboard.log(f"⏩ Skipping Recon: Resuming with {len(self.url_queue)} URLs found in DB.", "INFO")
            urls_to_scan = self.url_queue
            # Try to load tech profile from state
            loaded_state = self.state_manager.load_state()
            self.tech_profile = loaded_state.get("tech_profile", self.tech_profile)
        else:
            dashboard.log("Starting Phase 1: Reconnaissance (Nuclei + GoSpider)", "INFO")
            
            # GoSpider: URL discovery
            try:
                logger.info(f"Triggering GoSpiderAgent for {self.target}")
                gospider = GoSpiderAgent(self.target, recon_dir, max_depth=self.max_depth, max_urls=self.max_urls)  # Output to recon/
                urls_to_scan = await gospider.run()
                logger.info(f"GoSpiderAgent finished. Found {len(urls_to_scan)} URLs")
                
                # --- TOKEN SCANNING (V4 Skill) ---
                dashboard.log("🔍 Scanning discovery artifacts for authentication tokens...", "INFO")
                combined_recon_data = " ".join(urls_to_scan) + " " + json.dumps(self.tech_profile)
                found_jwts = find_jwts(combined_recon_data)
                if found_jwts:
                    dashboard.log(f"🔑 Found {len(found_jwts)} potential JWT(s) in recon data!", "WARN")
                    for token in found_jwts:
                        # Signal the JWTAgent
                        self.event_bus.publish("auth_token_found", {
                            "token": token,
                            "url": self.target,
                            "location": "recon_discovery"
                        })
            except Exception as e:
                logger.error(f"GoSpiderAgent crash: {e}")
                urls_to_scan = [self.target]
            
            # Update State
            # Deduplicate and Normalize URLs
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
            
            # Smart Filter: If we have parameterized URLs, remove Root URL to prevent redundant scraping
            if has_parameterized:
                # Remove root if present
                root_norm = self.target.rstrip('/')
                normalized_list = [u for u in normalized_list if u.rstrip('/') != root_norm]
                if not normalized_list: # If filtering removed everything (rare)
                    normalized_list = [self.target]
            
            urls_to_scan = normalized_list
            logger.info(f"Deduplicated URLs to scan: {len(urls_to_scan)}")
            for u in urls_to_scan:
                logger.info(f">> To Scan: {u}")

            self.url_queue = urls_to_scan
            self._save_checkpoint()

        # Stop check after recon (GoSpider can take minutes)
        if dashboard.stop_requested or self._stop_event.is_set():
            dashboard.log("🛑 Stop requested after reconnaissance. Exiting.", "WARN")
            from bugtrace.schemas.db_models import ScanStatus
            self.db.update_scan_status(self.scan_id, ScanStatus.STOPPED)
            return

        # 2. PHASE 2: URL-BY-URL ANALYSIS
        dashboard.set_phase("PHASE_2_ANALYSIS")
        # variables moved inside loop
        
        for i, url in enumerate(urls_to_scan):
            if url in self.processed_urls:
                dashboard.log(f"⏩ Skipping already processed URL: {url[:60]}", "INFO")
                continue

            dashboard.log(f"🚀 Processing URL {i+1}/{len(urls_to_scan)}: {url[:60]}", "INFO")
            dashboard.update_task("Orchestrator", status=f"Processing {url[:40]}")
            
            if dashboard.stop_requested or self._stop_event.is_set():
                dashboard.log("🛑 Stop requested. Finishing current URL and exiting...", "WARN")
                break

            # Reset findings for this URL
            all_validated_findings = []
            seen_keys = set()

            # Create URL Folder in analysis/ subdirectory (ensure uniqueness for URLs with different parameters)
            import hashlib
            # Create readable base name (truncated)
            safe_base = url.replace("://", "_").replace("/", "_").replace("?", "_").replace("&", "_").replace("=", "_")[:40]
            # Add hash of full URL to ensure uniqueness
            url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
            safe_url_name = f"{safe_base}_{url_hash}"
            url_dir = analysis_dir / f"url_{safe_url_name}"  # Place in analysis/ subdirectory
            url_dir.mkdir(exist_ok=True)

            # A. DAST+SAST ANALYSIS
            if dashboard.stop_requested or self._stop_event.is_set(): break
            dast = DASTySASTAgent(url, self.tech_profile, url_dir, state_manager=self.state_manager)
            analysis_result = await dast.run()
            if dashboard.stop_requested or self._stop_event.is_set(): break
            
            vulnerabilities = analysis_result.get("vulnerabilities", [])
            
            # B. ORCHESTRATOR DECISION & SPECIALISTS
            if vulnerabilities:
                dashboard.log(f"🧠 Orchestrator deciding on {len(vulnerabilities)} potential vulnerabilities...", "INFO")
                
                # Helper to process results (De-duplication & State Update)
                def process_result(res):
                    if res and res.get("findings"):
                        for f in res["findings"]:
                            # --- PRE-FLIGHT VALIDATION (V3.5 Reactor) ---
                            # Reject conversational payloads before they pollute the DB
                            is_valid, error_msg = conductor._validate_payload_format(f)
                            if not is_valid:
                                logger.warning(f"[TeamOrchestrator] {error_msg}")
                                continue

                            # DEDUPE FIX: Use PATH only (not full URL with query params)
                            # This groups SQLi in productId=18 and productId=11 as the SAME finding
                            finding_url = f.get('url', '')
                            finding_path = urlparse(finding_url).path if finding_url else ''
                            key = f"{f['type']}:{finding_path}:{f.get('parameter', 'none')}"
                            logger.info(f"[TeamOrchestrator] Processing finding Key: {key}")
                            if key not in seen_keys:
                                logger.info(f"[TeamOrchestrator] New Key! Adding finding.")
                                seen_keys.add(key)
                                all_validated_findings.append(f)
                                # UI marking
                                dashboard.add_finding(f['type'], f"{f['url']} [{f.get('parameter')}]", f.get('severity', 'HIGH'))
                                
                                self.state_manager.add_finding(
                                    url=f['url'], type=f['type'], description=f.get('description', f"Discovery finding"),
                                    severity=f.get('severity', 'HIGH'), parameter=f.get('parameter'), payload=f.get('payload'),
                                    evidence=f.get('evidence'), screenshot_path=f.get('screenshot') or f.get('screenshot_path'),
                                    validated=f.get('validated', False), # Respect Specialist Agent decision
                                    status=f.get('status', 'PENDING_VALIDATION'),
                                    # 2026-01-24 FIX: Include reproduction command from specialist agents (e.g., SQLMap)
                                    reproduction=f.get('reproduction') or f.get('reproduction_command')
                                )

                # Group findings for optimization
                specialist_dispatches = set()
                params_map = {} # type -> set of params
                idor_params = [] # List[Dict] for IDORAgent
                
                # Pre-parse URL for IDOR original values
                parsed_url = urlparse(url)
                current_qs = parse_qs(parsed_url.query)
                
                for vuln in vulnerabilities:
                    specialist_type = await self._decide_specialist(vuln)
                    dashboard.log(f"🤖 Dispatcher chose: {specialist_type} for {vuln.get('parameter')}", "INFO")
                    specialist_dispatches.add(specialist_type)
                    
                    param = vuln.get("parameter")
                    if param and str(param).lower() not in ["none", "unknown", "null"]:
                        if specialist_type == "IDOR_AGENT":
                            original_val = current_qs.get(param, ["1"])[0] # Default to 1 if not found
                            idor_params.append({"parameter": param, "original_value": original_val})
                        else:
                            if specialist_type not in params_map: params_map[specialist_type] = set()
                            params_map[specialist_type].add(param)

                    # Handle non-agent types immediately
                    if specialist_type == "HEADER_INJECTION":
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

                # Execute Batched Agents IN PARALLEL
                agent_tasks = []

                if "XSS_AGENT" in specialist_dispatches:
                    p_list = list(params_map.get("XSS_AGENT", [])) or None
                    xss_agent = XSSAgent(url, params=p_list, report_dir=url_dir)
                    agent_tasks.append(run_agent_with_semaphore(self.url_semaphore, xss_agent, process_result))

                # 2026-01-23 FIX: ALWAYS run SQLMapAgent when URL has query params
                # SQLMap is a definitive validator - don't gate it behind LLM analysis
                # If skeptical review rejected SQLi, we still test with SQLMap
                url_has_params = bool(parsed_url.query)
                if "SQL_AGENT" in specialist_dispatches or url_has_params:
                    # Use params from skeptical review if available, else extract from URL
                    p_list = list(params_map.get("SQL_AGENT", []))
                    if not p_list and url_has_params:
                        # Extract all param names from URL query string
                        p_list = list(current_qs.keys())
                        dashboard.log(f"🔧 [SQLMapAgent] Auto-dispatching for URL params: {p_list}", "INFO")
                    sql_agent = SQLMapAgent(url, p_list or None, url_dir)
                    agent_tasks.append(run_agent_with_semaphore(self.url_semaphore, sql_agent, process_result))

                if "CSTI_AGENT" in specialist_dispatches:
                    p_list = list(params_map.get("CSTI_AGENT", [])) or None
                    csti_agent = CSTIAgent(url, params=[{"parameter": p} for p in p_list] if p_list else None, report_dir=url_dir)
                    agent_tasks.append(run_agent_with_semaphore(self.url_semaphore, csti_agent, process_result))

                if "XXE_AGENT" in specialist_dispatches:
                    from bugtrace.agents.exploit_specialists import XXEAgent
                    p_list = list(params_map.get("XXE_AGENT", [])) or None
                    xxe_agent = XXEAgent(url, p_list, url_dir)
                    agent_tasks.append(run_agent_with_semaphore(self.url_semaphore, xxe_agent, process_result))

                if "SSRF_AGENT" in specialist_dispatches:
                    from bugtrace.agents.ssrf_agent import SSRFAgent
                    p_list = list(params_map.get("SSRF_AGENT", [])) or None
                    ssrf_agent = SSRFAgent(url, p_list, url_dir)
                    agent_tasks.append(run_agent_with_semaphore(self.url_semaphore, ssrf_agent, process_result))

                if "LFI_AGENT" in specialist_dispatches:
                    from bugtrace.agents.lfi_agent import LFIAgent
                    p_list = list(params_map.get("LFI_AGENT", [])) or None
                    lfi_agent = LFIAgent(url, p_list, url_dir)
                    agent_tasks.append(run_agent_with_semaphore(self.url_semaphore, lfi_agent, process_result))

                if "RCE_AGENT" in specialist_dispatches:
                    from bugtrace.agents.rce_agent import RCEAgent
                    p_list = list(params_map.get("RCE_AGENT", [])) or None
                    rce_agent = RCEAgent(url, p_list, url_dir)
                    agent_tasks.append(run_agent_with_semaphore(self.url_semaphore, rce_agent, process_result))

                if "PROTO_AGENT" in specialist_dispatches:
                    from bugtrace.agents.exploit_specialists import ProtoAgent
                    p_list = list(params_map.get("PROTO_AGENT", [])) or None
                    proto_agent = ProtoAgent(url, p_list, url_dir)
                    agent_tasks.append(run_agent_with_semaphore(self.url_semaphore, proto_agent, process_result))

                if "FILE_UPLOAD_AGENT" in specialist_dispatches:
                    from bugtrace.agents.fileupload_agent import FileUploadAgent
                    upload_agent = FileUploadAgent(url)
                    agent_tasks.append(run_agent_with_semaphore(self.url_semaphore, upload_agent, process_result))
                
                if "JWT_AGENT" in specialist_dispatches:
                    agent_tasks.append(run_agent_with_semaphore(self.url_semaphore, self.jwt_agent, process_result))

                if "IDOR_AGENT" in specialist_dispatches:
                    from bugtrace.agents.idor_agent import IDORAgent
                    idor_agent = IDORAgent(url, params=idor_params, report_dir=url_dir)
                    agent_tasks.append(run_agent_with_semaphore(self.url_semaphore, idor_agent, process_result))

                # Execute all agents in parallel (respecting semaphore limit)
                # Uses cancellation-aware pattern: polls stop flag every 0.5s
                # and cancels remaining tasks if 'q' is pressed
                if agent_tasks:
                    logger.info(f"[TeamOrchestrator] Executing {len(agent_tasks)} agents in parallel (max {settings.MAX_CONCURRENT_URL_AGENTS} concurrent)")
                    pending = {asyncio.ensure_future(t) for t in agent_tasks}
                    while pending:
                        done, pending = await asyncio.wait(pending, timeout=0.5, return_when=asyncio.FIRST_COMPLETED)
                        if dashboard.stop_requested or self._stop_event.is_set():
                            dashboard.log("🛑 Stop requested. Cancelling running agents...", "WARN")
                            for task in pending:
                                task.cancel()
                            # Wait for cancellations to complete
                            if pending:
                                await asyncio.wait(pending, timeout=5)
                            break

            # C. NO-SWARM MODE
            # We no longer unleash the swarm unconditionally. 
            # Only specialists decided by DASTySAST in step B are executed.
            dashboard.log(f"🎯 Intelligent dispatch complete for {url[:50]}", "SUCCESS")

            # Incremental save to DB (V3 Style)
            if all_validated_findings:
                try:
                    from bugtrace.core.database import get_db_manager
                    db = get_db_manager()
                    db.save_scan_result(self.target, all_validated_findings, scan_id=self.scan_id)
                except Exception as e:
                    logger.error(f"Failed to save findings to DB: {e}")
            
            # Step 5: Save URL Checkpoint
            self._save_checkpoint(url)
        
        # V4 Checkpoint
        await self._checkpoint("Analysis & Exploitation (DAST + Specialists)")

        # Stop check before Phase 3
        if dashboard.stop_requested or self._stop_event.is_set():
            dashboard.log("🛑 Stop requested. Skipping review and reporting.", "WARN")
            from bugtrace.schemas.db_models import ScanStatus
            self.db.update_scan_status(self.scan_id, ScanStatus.STOPPED)
            return

        # 3. PHASE 3: GLOBAL REVIEW
        logger.info("=== PHASE 3: GLOBAL REVIEW ===")
        dashboard.set_phase("PHASE_3_REVIEW")
        dashboard.log("🔍 Phase 3: Global Review and Chaining Analysis", "INFO")
        # Use all findings from state_manager for global review (not just validated ones)
        all_findings_for_review = self.state_manager.get_findings()
        await self._global_review(all_findings_for_review, scan_dir, dashboard)
        logger.info("Phase 3 complete")
        
        
        # V4 Checkpoint
        await self._checkpoint("Global Review")

        # Stop check before Phase 4
        if dashboard.stop_requested or self._stop_event.is_set():
            dashboard.log("🛑 Stop requested. Skipping report generation.", "WARN")
            from bugtrace.schemas.db_models import ScanStatus
            self.db.update_scan_status(self.scan_id, ScanStatus.STOPPED)
            return

        # 4. PHASE 4: REPORTING
        logger.info("=== PHASE 4: REPORTING ===")
        dashboard.set_phase("PHASE_4_REPORTING")
        dashboard.log("📊 Phase 4: Generating Final Reports", "INFO")
        dashboard.log("Generating final consolidated reports...", "INFO")
        
        # Aggregate ALL findings from StateManager (Database source of truth)
        all_findings = self.state_manager.get_findings()
        logger.info(f"Retrieved {len(all_findings)} findings from state manager")
        raw_findings_path = scan_dir / "raw_findings.json"
        with open(raw_findings_path, "w") as f:
            json.dump({
                "meta": {"scan_id": self.scan_id, "target": self.target, "phase": "hunter"},
                "findings": all_findings
            }, f, indent=2, default=str)
        logger.info(f"Saved {len(all_findings)} raw findings to {raw_findings_path}")

        # V5: Also trigger an initial report generation so the user has an HTML immediately
        try:
            from bugtrace.agents.reporting import ReportingAgent
            reporter = ReportingAgent(self.scan_id, self.target, scan_dir)
            await reporter.generate_all_deliverables()
            logger.info("Generated initial Hunter report")
        except Exception as e:
            logger.error(f"Failed to generate initial report: {e}")

        logger.info("Phase 4 complete")
        
        dashboard.log(f"📄 Final report in {scan_dir}", "INFO")
        
        # Mark scan as completed
        from bugtrace.schemas.db_models import ScanStatus
        self.db.update_scan_status(self.scan_id, ScanStatus.COMPLETED)
        logger.info(f"Scan {self.scan_id} marked as COMPLETED")
        
        logger.info("=== V2 SEQUENTIAL PIPELINE COMPLETE ===")

    async def _decide_specialist(self, vuln: dict) -> str:
        """
        Uses LLM to classify vulnerability and select best specialist agent.
        Uses industry-standard dispatcher patterns.
        """
        from bugtrace.core.llm_client import llm_client
        
        # Fast path for obvious ones to save tokens
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
        
        prompt = f"""
        Act as a Security Dispatcher.
        Analyze this potential vulnerability finding and assign the correct Specialist Agent.
        
        FINDING: {vuln}
        
        AVAILABLE AGENTS:
        - XSS_AGENT (Cross-Site Scripting, HTML injection)
        - SQL_AGENT (SQL Injection, Database errors)
        - CSTI_AGENT (Client-Side Template Injection, SSTI, {{7*7}} indicators)
        - XXE_AGENT (XML External Entity, XML parsing)
        - PROTO_AGENT (Prototype Pollution, JS Object injection)
        - JWT_AGENT (JSON Web Token vulnerabilities, alg: none, weak secrets)
        - HEADER_INJECTION (CRLF, Response Splitting)
        - FILE_UPLOAD_AGENT (Unrestricted file upload, RCE via shell)
        - IDOR_AGENT (Insecure Direct Object Reference, Parameter Tampering)
        - IGNORE (If low confidence or not relevant)
        
        Return ONLY the Agent Name using XML format:
        <thought>Reasoning for selection</thought>
        <agent>AGENT_NAME</agent>
        """
        
        try:
            # Use a faster model for dispatching if possible
            decision = await llm_client.generate(prompt, module_name="Dispatcher", max_tokens=100)
            
            from bugtrace.utils.parsers import XmlParser
            chosen_agent = XmlParser.extract_tag(decision, "agent")
            
            if chosen_agent:
                chosen_agent = chosen_agent.strip().replace("`", "").upper()
                valid_agents = ["XSS_AGENT", "SQL_AGENT", "XXE_AGENT", "SSRF_AGENT", "LFI_AGENT", "RCE_AGENT", "PROTO_AGENT", "HEADER_INJECTION", "IDOR_AGENT", "JWT_AGENT", "FILE_UPLOAD_AGENT", "IGNORE"]
                
                # Fuzzy match in case of minor typos or extra chars
                for valid in valid_agents:
                    if valid in chosen_agent:
                        return valid
            
            # Simple keyword fallback for JWTAgent
            v_type_lower = v_type.lower()
            if "jwt" in v_type_lower or "auth token" in v_type_lower:
                return "JWT_AGENT"

            # Fallback if no valid tag found but text contains the agent name clearly (heuristic backup)
            if decision:
                 valid_agents = ["XSS_AGENT", "SQL_AGENT", "XXE_AGENT", "PROTO_AGENT", "HEADER_INJECTION", "IDOR_AGENT", "IGNORE"]
                 for agent in valid_agents:
                     if agent in decision and "NOT" not in decision: # Basic negative constraint
                         return agent

            return "IGNORE"
            
        except Exception as e:
            logger.error(f"Dispatcher LLM failed: {e}")
            # Fallback to naive keyword matching
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
            from bugtrace.utils.parsers import XmlParser
            
            chain_contents = XmlParser.extract_list(response, "chain")
            chains = []
            
            for cc in chain_contents:
                chains.append({
                    "name": XmlParser.extract_tag(cc, "name") or "Unnamed Chain",
                    "vulnerabilities": XmlParser.extract_tag(cc, "vulnerabilities") or "",
                    "impact": XmlParser.extract_tag(cc, "impact") or "High"
                })
            
            if chains:
                dashboard.log(f"🔗 Detected {len(chains)} potential attack chains!", "WARN")
                with open(scan_dir / "attack_chains.json", "w") as f:
                    json.dump({"chains": chains, "findings_reviewed": len(findings)}, f, indent=4)
        except Exception as e:
            logger.debug(f"Global review failed: {e}")

    async def _generate_v2_report(self, findings: list, urls: list, tech_profile: dict, scan_dir: Path, start_time: datetime):
        """Phase 4: Generates a premium report based on the sequential scan results. Pulls high-fidelity audits from DB."""
        try:
            from bugtrace.core.database import get_db_manager
            db = get_db_manager()
            
            # Pull findings from DB for this scan (Source of Truth)
            if hasattr(self, "scan_id"):
                db_findings = db.get_findings_for_scan(self.scan_id)
                if db_findings:
                    logger.info(f"Loaded {len(db_findings)} findings from DB for reporting.")
                    # Convert DB models to list of dicts for collector compatibility
                    findings = []
                    for db_f in db_findings:
                        f = {
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
                            # 2026-01-24 FIX: Include reproduction command for SQLi/reports
                            "reproduction": db_f.reproduction_command
                        }
                        findings.append(f)
            
            logger.info(f"Starting report generation with {len(findings)} findings")
            dashboard.log(f"📊 Generating final reports with {len(findings)} findings...", "INFO")
            
            from bugtrace.reporting.collector import DataCollector
            from bugtrace.reporting.ai_writer import AIReportWriter
            
            collector = DataCollector(self.target, scan_id=self.scan_id)
            
            # Add Findings with Deduplication and Audit Filtering
            seen_findings = set()
            
            # V3 Filter: Only show Confirmed findings in high-impact sections
            confirmed_findings = [f for f in findings if f.get("status") == "VALIDATED_CONFIRMED"]
            pending_findings = [f for f in findings if f.get("status") == "PENDING_VALIDATION"]
            
            if settings.REPORT_ONLY_VALIDATED:
                prioritized_findings = confirmed_findings
            else:
                prioritized_findings = confirmed_findings + pending_findings
            
            for f in prioritized_findings:
                # Deduplication Logic - Use PATH only (not full URL with query params)
                # This groups SQLi in productId=18 and productId=11 as the SAME finding
                vType = (f.get("type") or "").upper()
                url = f.get("url", "")
                path = urlparse(url).path if url else ""
                param = f.get("parameter", "")
                dedupe_key = f"{vType}:{path}:{param}"
                
                if dedupe_key in seen_findings:
                    continue
                seen_findings.add(dedupe_key)
                
                # Ensure validator metadata is passed through
                if "validator_notes" not in f:
                    f["validator_notes"] = None
                if "status" not in f:
                    f["status"] = "PENDING_VALIDATION"
                
                collector.add_vulnerability(f)
            
            # Add Context
            collector.context.stats.urls_scanned = len(urls)
            collector.context.stats.start_time = start_time if isinstance(start_time, datetime) else datetime.fromisoformat(start_time)
            end_time = datetime.now()
            collector.context.stats.end_time = end_time
            collector.context.stats.duration_seconds = (end_time - start_time).total_seconds()
            collector.context.tech_stack = tech_profile.get("frameworks", [])
            
            # Generate Reports - Use MarkdownGenerator for Triager-Ready format
            from bugtrace.reporting.markdown_generator import MarkdownGenerator
            from bugtrace.reporting.generator import HTMLGenerator

            # 1. Triager-Ready Markdown (Primary deliverable)
            md_gen = MarkdownGenerator(output_base_dir=str(scan_dir))
            md_gen.generate(collector.get_context())

            # 2. HTML version for visual review
            html_gen = HTMLGenerator()
            html_gen.generate(collector.get_context(), str(scan_dir / "report.html"))

            # 3. Optional: AI-enhanced summary (supplementary, not primary)
            try:
                from bugtrace.reporting.ai_writer import AIReportWriter
                ai_writer = AIReportWriter(output_base_dir=str(scan_dir))
                await ai_writer.generate_async(collector.get_context())
            except Exception as e:
                logger.warning(f"AI report enhancement failed (non-critical): {e}")
            
            dashboard.log(f"✅ Reports generated in {scan_dir}", "SUCCESS")
            
        except Exception as e:
            logger.error(f"Failed to generate V2 report: {e}", exc_info=True)
            dashboard.log(f"❌ Report generation failed: {e}", "ERROR")

