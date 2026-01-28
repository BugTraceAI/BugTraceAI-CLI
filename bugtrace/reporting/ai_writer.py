from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional
import json

from bugtrace.core.config import settings
from bugtrace.core.llm_client import llm_client
from bugtrace.core.conductor import conductor
from bugtrace.core.ui import dashboard
from bugtrace.reporting.models import ReportContext, Finding, FindingType, Severity
from bugtrace.reporting.markdown_generator import MarkdownGenerator
from bugtrace.utils.logger import get_logger

logger = get_logger("reporting.ai_writer")

class AIReportWriter(MarkdownGenerator):
    """
    Enhanced Report Generator that uses LLM to write professional assessments.
    Inherits basic file/directory handling from MarkdownGenerator.
    """
    
    async def generate_async(self, context: ReportContext) -> str:
        """
        Async version of generate() to allow LLM calls.
        """
        # Use the scan directory directly (no subdirectory)
        report_dir = Path(self.output_base_dir)
        report_dir.mkdir(parents=True, exist_ok=True)
        
        captures_dir = report_dir / "captures"
        captures_dir.mkdir(parents=True, exist_ok=True)

        # 2. Prepare Data for AI
        recon_summary = self._summarize_context_for_ai(context)
        
        # 3. Generate AI Content (Parallelize if possible, but we enforce sequential for costs)
        tech_content = await self._generate_technical_assessment(context, recon_summary)
        exec_content = await self._generate_executive_summary(context, recon_summary)

        # 4. Write Files directly to scan folder
        tech_path = report_dir / "technical_report.md"
        with open(tech_path, "w", encoding="utf-8") as f:
            f.write(tech_content)
            
        exec_path = report_dir / "executive_summary.md"
        with open(exec_path, "w", encoding="utf-8") as f:
            f.write(exec_content)

        # 5. Save Evidence (Images & JSON)
        # We need to handle image copying manually since we bypassed parent's _write_technical_report
        self._copy_evidence_images(context, report_dir)
        
        json_path = report_dir / "engagement_data.json"
        self._save_engagement_json(context, json_path)

        return str(report_dir)

    def _summarize_context_for_ai(self, context: ReportContext) -> str:
        """Compresses the finding data into a token-optimized string."""
        summary = {
            "target": context.target_url,
            "stats": context.stats.model_dump(),
            "inputs_found": [],
            "urls_crawled_count": 0,
            "vulnerabilities": []
        }
        
        # Extract meaningful Recon Data (Inputs)
        for f in context.findings:
            if f.type == FindingType.OBSERVATION:
                 meta = f.metadata
                 if meta.get('type') == 'Input':
                     summary["inputs_found"].append(f"{meta.get('name')} ({meta.get('element_type')})")
                 elif meta.get('type') == 'URL':
                     summary["urls_crawled_count"] += 1
            elif f.type == FindingType.VULNERABILITY:
                summary["vulnerabilities"].append(f"{f.title} ({f.severity.value})")

        return json.dumps(summary, indent=2)

    async def _generate_technical_assessment(self, context: ReportContext, summary: str) -> str:
        dashboard.update_task("Reporting", status="Generating Technical Report (AI)...")
        
        system_prompt = conductor.get_full_system_prompt("ai_writer")
        if system_prompt:
            prompt = system_prompt.split("## Technical Assessment Prompt")[-1].split("## ")[0].strip()
        else:
            prompt = f"""
            You are a Lead Penetration Tester writing a Technical Assessment Report.
            
            TARGET: {context.target_url}
            DATA: {summary}
            
            TASK:
            Write a professional Technical Report in Markdown.
            
            Structure:
            1. Engagement Summary (Date, Scope).
            2. Attack Surface Analysis:
               - Analyze the 'inputs_found'. Explain what attacks they might be susceptible to (e.g., 'The presence of 'product_id' suggests potential IDOR or SQLi vectors...').
               - Review 'vulnerabilities'. If list is empty, explain what was tested and that no *verified* exploits were successful found in the automated timeframe, but highlight the surface risks.
            3. Detailed Findings (if any) or Observations.
            4. Recommendations (General hardening based on the surface found).
            
            Tone: Technical, precise, objective. Use 'We identified...'
            Do NOT hallucinate specific vulnerabilities that are not in the DATA. Talk about RISKS based on the SURFACE.
            """
        
        prompt = prompt.format(
            target_url=context.target_url,
            summary=summary
        )
        
        return await llm_client.generate(prompt, "Report-Tech") or "AI Generation Failed."

    async def _generate_executive_summary(self, context: ReportContext, summary: str) -> str:
        dashboard.update_task("Reporting", status="Generating Executive Summary (AI)...")
        
        system_prompt = conductor.get_full_system_prompt("ai_writer")
        if system_prompt:
            prompt = system_prompt.split("## Executive Summary Prompt")[-1].split("## ")[0].strip()
        else:
            prompt = f"""
            You are a CISO writing an Executive Summary for a client.
            
            TARGET: {context.target_url}
            DATA: {summary}
            
            TASK:
            Write a high-level Executive Summary in Markdown.
            
            Structure:
            1. Executive Overview: High-level status.
            2. Risk Profile: Base this on the surface area (e.g., e-commerce site with inputs vs static site).
            3. Key Recommendations: Strategic advice (e.g., "Implement WAF", "Regular Audits").
            
            Tone: Professional, business-focused. Avoid jargon where possible.
            """
        
        prompt = prompt.format(
            target_url=context.target_url,
            summary=summary
        )
        
        return await llm_client.generate(prompt, "Report-Exec") or "AI Generation Failed."

    def _copy_evidence_images(self, context: ReportContext, report_dir: Path):
        import shutil
        import os
        for f in context.findings:
             img_path = f.metadata.get("screenshot_path")
             if img_path and os.path.exists(img_path):
                img_name = os.path.basename(img_path)
                dest_path = report_dir / "captures" / img_name
                try:
                    shutil.copy(img_path, dest_path)
                except (OSError, IOError, PermissionError) as e:
                    # Non-critical: Screenshot copy failed, report will still generate
                    logger.warning(f"Failed to copy screenshot {img_name}: {e}")
