"""
ReportingAgent: Thin orchestrator class.

Generates all 4 deliverables for a scan.

Deliverables:
1. raw_findings.json - Pre-AgenticValidator findings (for manual review)
2. validated_findings.json - Only VALIDATED_CONFIRMED findings
3. final_report.md - Triager-ready markdown with all findings
4. engagement_data.json - Structured JSON for HTML viewer
5. report.html - Static HTML that loads engagement_data.json
"""

import asyncio
import json
import re
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from bugtrace.agents.base import BaseAgent
from bugtrace.core.config import settings
from bugtrace.core.database import get_db_manager
from bugtrace.core.ui import dashboard
from bugtrace.core.llm_client import llm_client
from bugtrace.core.event_bus import EventType, event_bus
from bugtrace.core.validation_status import ValidationStatus
from bugtrace.utils.logger import get_logger

from bugtrace.agents.reporting_mod.types import (
    INFORMATIONAL_TYPES,
    TYPE_SPECIFIC_CONTEXTS,
)
from bugtrace.agents.reporting_mod.finding_processor import (
    categorize_findings,
    deduplicate_exact,
    deduplicate_findings,
    consolidate_informational,
    merge_event_findings,
    event_finding_to_db_format,
    nuclei_parse_findings,
    nuclei_extract_tech_stack,
    group_findings_by_type,
    db_build_finding_dict,
    db_enrich_sqli_metadata,
    count_by_severity,
)
from bugtrace.agents.reporting_mod.formatters import (
    get_type_specific_context,
)
from bugtrace.agents.reporting_mod.report_builder import (
    build_engagement_data,
    compute_enrichment_status,
)
from bugtrace.agents.reporting_mod.cvss import (
    calculate_cvss_batch,
    calculate_cvss,
    cvss_update_finding,
)
from bugtrace.agents.reporting_mod.screenshot_handler import copy_screenshots
from bugtrace.agents.reporting_mod.file_writer import (
    write_json,
    write_validated_json,
    write_engagement_json,
    write_engagement_js,
    write_markdown_report,
)

logger = get_logger("agents.reporting")


class ReportingAgent(BaseAgent):
    """
    Final Agent responsible for generating all report deliverables.
    """

    def __init__(self, scan_id: int, target_url: str, output_dir: Path, tech_profile: Dict = None):
        super().__init__("ReportingAgent", "Reporting Specialist", agent_id="reporting_agent")
        self.scan_id = scan_id
        self.target_url = target_url
        self.output_dir = Path(output_dir)
        self.tech_profile = tech_profile or {}
        self.db = get_db_manager()

        # Event-driven finding accumulation
        self._validated_findings: List[Dict] = []
        self._event_bus = event_bus
        self._subscribed = False

        # Enrichment tracking
        self._enrichment_failures = 0
        self._enrichment_total = 0

    # ── Event Bus Lifecycle ──────────────────────────────────────────────

    def subscribe_to_events(self) -> None:
        """Subscribe to validation events from the pipeline."""
        if self._subscribed:
            logger.warning(f"[{self.name}] Already subscribed to events")
            return

        self._event_bus.subscribe(
            EventType.VULNERABILITY_DETECTED.value,
            self._handle_vulnerability_detected
        )
        self._event_bus.subscribe(
            EventType.FINDING_VALIDATED.value,
            self._handle_finding_validated
        )

        self._subscribed = True
        logger.info(f"[{self.name}] Subscribed to vulnerability_detected and finding_validated events")

    def unsubscribe_from_events(self) -> None:
        """Unsubscribe from validation events."""
        if not self._subscribed:
            logger.debug(f"[{self.name}] Not subscribed, nothing to unsubscribe")
            return

        self._event_bus.unsubscribe(
            EventType.VULNERABILITY_DETECTED.value,
            self._handle_vulnerability_detected
        )
        self._event_bus.unsubscribe(
            EventType.FINDING_VALIDATED.value,
            self._handle_finding_validated
        )

        self._subscribed = False
        logger.info(f"[{self.name}] Unsubscribed from validation events")

    async def _handle_vulnerability_detected(self, data: Dict[str, Any]) -> None:
        """Handle vulnerability_detected events from specialist agents."""
        try:
            status = data.get("status", "")
            if status != ValidationStatus.VALIDATED_CONFIRMED.value:
                return

            finding = data.get("finding", {}).copy()
            specialist = data.get("specialist", "unknown")

            finding["scan_context"] = data.get("scan_context", "")
            finding["specialist"] = specialist
            finding["validation_requires_cdp"] = data.get("validation_requires_cdp", False)
            finding["status"] = status
            finding["event_source"] = "vulnerability_detected"

            self._validated_findings.append(finding)
            logger.info(f"[{self.name}] Collected VALIDATED_CONFIRMED finding from {specialist}")
        except Exception as e:
            logger.error(f"[{self.name}] Failed to handle vulnerability_detected: {e}")

    async def _handle_finding_validated(self, data: Dict[str, Any]) -> None:
        """Handle finding_validated events from AgenticValidator."""
        try:
            finding = data.get("finding", {}).copy()
            validation_result = data.get("validation_result", {})
            specialist = finding.get("specialist", data.get("specialist", "unknown"))

            finding["status"] = "VALIDATED"
            finding["cdp_validated"] = True
            finding["cdp_reasoning"] = validation_result.get("reasoning", "")
            finding["cdp_confidence"] = validation_result.get("confidence", 0.0)
            finding["scan_context"] = data.get("scan_context", "")
            finding["event_source"] = "finding_validated"

            self._validated_findings.append(finding)
            logger.info(f"[{self.name}] Collected CDP-VALIDATED finding from {specialist}")
        except Exception as e:
            logger.error(f"[{self.name}] Failed to handle finding_validated: {e}")

    def get_validated_findings(self) -> List[Dict]:
        """Get a copy of all accumulated validated findings."""
        return self._validated_findings.copy()

    def clear_validated_findings(self) -> None:
        """Clear all accumulated validated findings."""
        self._validated_findings.clear()
        logger.debug(f"[{self.name}] Cleared validated findings")

    # ── Main Orchestration ───────────────────────────────────────────────

    async def run_loop(self):
        """Not used - call generate_all_deliverables() directly."""
        pass

    async def generate_all_deliverables(self) -> Dict[str, Path]:
        """Main entry point. Generates all 4 deliverables."""
        dashboard.update_task("reporting", name="Reporting Agent", status="Generating deliverables...")
        logger.info(f"[{self.name}] Starting report generation for scan {self.scan_id}")

        # Phase 1: Setup and data collection
        self._setup_output_directories()
        all_findings, tech_stack = await self._collect_all_findings()

        # Phase 2: Categorize and enrich findings
        categorized = categorize_findings(all_findings)
        await self._enrich_findings_batch(categorized["validated"] + categorized["manual_review"])

        # Phase 2.5: Consolidate informational findings
        categorized["validated"] = consolidate_informational(categorized["validated"])
        categorized["manual_review"] = consolidate_informational(categorized["manual_review"])

        # Phase 3: Calculate statistics
        stats = self._calculate_scan_stats(all_findings)

        # Phase 4: Generate all report deliverables
        paths = self._generate_json_reports(all_findings, categorized)
        paths.update(self._generate_markdown_reports(categorized))
        paths.update(self._generate_data_files(all_findings, categorized, stats, tech_stack))
        paths.update(self._generate_html_report(paths))

        # Phase 5: Organize artifacts
        copy_screenshots(all_findings, self.output_dir / "captures")

        # Persist enrichment status to database
        self.db.update_scan_enrichment_status(
            self.scan_id,
            compute_enrichment_status(self._enrichment_total, self._enrichment_failures)
        )

        dashboard.log(f"[{self.name}] Generated {len(paths)} deliverables in {self.output_dir}", "SUCCESS")
        return paths

    # ── Setup ────────────────────────────────────────────────────────────

    def _setup_output_directories(self):
        """Create necessary output directories."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / "captures").mkdir(exist_ok=True)

    # ── Data Collection ──────────────────────────────────────────────────

    async def _collect_all_findings(self) -> tuple[List[Dict], Dict]:
        """Collect all findings from specialist result files."""
        all_findings = self._load_specialist_results()
        logger.info(f"[{self.name}] Loaded {len(all_findings)} findings from specialists/results/")

        if not all_findings:
            logger.warning(f"[{self.name}] No specialist results found, falling back to DB")
            all_findings = self._get_findings_from_db()
            logger.info(f"[{self.name}] Retrieved {len(all_findings)} findings from DB (fallback)")

        nuclei_findings, tech_stack = self._load_nuclei_findings()
        if nuclei_findings:
            all_findings.extend(nuclei_findings)
            logger.info(f"[{self.name}] Added {len(nuclei_findings)} Nuclei findings")

        return all_findings, tech_stack

    def _load_specialist_results(self) -> List[Dict]:
        """Load findings from specialist report files."""
        from bugtrace.core.payload_format import decode_finding_payloads

        all_findings = []
        specialists_dir = self.output_dir / "specialists"

        if not specialists_dir.exists():
            logger.debug(f"[{self.name}] specialists/ directory not found")
            return []

        # Priority 1: specialist *_report.json
        for report_file in specialists_dir.glob("*_report.json"):
            findings = self._load_findings_from_report_file(report_file, decode_finding_payloads)
            all_findings.extend(findings)

        # Priority 2: results/*_results.json
        results_dir = specialists_dir / "results"
        if results_dir.exists():
            for result_file in results_dir.glob("*_results.json"):
                findings = self._load_findings_from_results_file(result_file, decode_finding_payloads)
                all_findings.extend(findings)

        # Priority 3: wet/*.json (fallback)
        wet_dir = specialists_dir / "wet"
        if wet_dir.exists() and not all_findings:
            for wet_file in wet_dir.glob("*.json"):
                findings = self._load_findings_from_wet_file(wet_file, decode_finding_payloads)
                all_findings.extend(findings)
            logger.info(f"[{self.name}] Loaded {len(all_findings)} findings from wet/ (fallback)")

        all_findings = deduplicate_exact(all_findings)
        logger.info(f"[{self.name}] Loaded {len(all_findings)} total findings from specialist files")
        return all_findings

    # I/O
    def _load_findings_from_report_file(self, report_file: Path, decode_fn) -> List[Dict]:
        """Load findings from specialist *_report.json file."""
        findings = []
        try:
            with open(report_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            report_findings = data.get("validated_findings", []) or data.get("findings", []) or data.get("results", [])
            specialist = data.get("specialist", report_file.stem.replace("_report", ""))

            for finding in report_findings:
                finding = decode_fn(finding)
                finding["source"] = f"specialist_report:{specialist}"
                if not finding.get("status"):
                    finding["status"] = "VALIDATED_CONFIRMED"
                findings.append(finding)

            if findings:
                logger.debug(f"[{self.name}] Loaded {len(findings)} from {report_file.name}")

        except Exception as e:
            logger.warning(f"[{self.name}] Failed to load {report_file}: {e}")

        return findings

    # I/O
    def _load_findings_from_results_file(self, result_file: Path, decode_fn) -> List[Dict]:
        """Load findings from results/*_results.json file."""
        findings = []
        try:
            with open(result_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            result_findings = data.get("findings", [])
            specialist = data.get("specialist", result_file.stem.replace("_results", ""))

            for finding in result_findings:
                finding = decode_fn(finding)
                finding["source"] = f"specialist:{specialist}"
                if not finding.get("status"):
                    finding["status"] = "VALIDATED_CONFIRMED"
                findings.append(finding)

            if findings:
                logger.debug(f"[{self.name}] Loaded {len(findings)} from {result_file.name}")

        except Exception as e:
            logger.warning(f"[{self.name}] Failed to load {result_file}: {e}")

        return findings

    # I/O
    def _load_findings_from_wet_file(self, wet_file: Path, decode_fn) -> List[Dict]:
        """Load findings from wet/*.json file (JSON Lines format)."""
        findings = []
        try:
            with open(wet_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        finding = entry.get("finding", entry)
                        finding = decode_fn(finding)
                        specialist = entry.get("specialist", wet_file.stem)
                        finding["source"] = f"wet:{specialist}"
                        if not finding.get("status"):
                            finding["status"] = "VALIDATED_CONFIRMED"
                        findings.append(finding)
                    except json.JSONDecodeError:
                        continue

        except Exception as e:
            logger.warning(f"[{self.name}] Failed to load {wet_file}: {e}")

        return findings

    def _get_findings_from_db(self) -> List[Dict]:
        """DEPRECATED: DB is write-only from CLI. Returns empty list."""
        logger.warning(f"[{self.name}] _get_findings_from_db() called but DB is write-only. Returning empty.")
        return []

    # I/O
    def _load_nuclei_findings(self) -> tuple[List[Dict], Dict]:
        """Load Nuclei findings from tech_profile.json."""
        possible_paths = [
            self.output_dir / "recon" / "tech_profile.json",
            self.output_dir / "tech_profile.json",
        ]
        tech_profile_path = None
        for path in possible_paths:
            if path.exists():
                tech_profile_path = path
                break

        if not tech_profile_path:
            logger.debug(f"[{self.name}] No tech_profile.json found")
            return [], {}

        tech_profile = self._nuclei_load_file(tech_profile_path)
        if not tech_profile:
            return [], {}

        nuc_findings = nuclei_parse_findings(tech_profile)
        tech_stack = nuclei_extract_tech_stack(tech_profile)

        logger.info(f"[{self.name}] Loaded {len(nuc_findings)} Nuclei findings, tech stack: {tech_stack}")
        return nuc_findings, tech_stack

    # I/O
    def _nuclei_load_file(self, path: Path) -> Optional[Dict]:
        """Load and parse tech_profile.json file."""
        try:
            with open(path, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"[{self.name}] Failed to load tech_profile.json: {e}")
            return None

    # ── Stats Calculation ────────────────────────────────────────────────

    def _calculate_scan_stats(self, all_findings: List[Dict]) -> Dict:
        """Calculate scan statistics (duration, URLs scanned, token usage)."""
        stats = {"urls_scanned": 0, "duration": "Unknown"}
        try:
            stats.update(self._calculate_scan_duration())
            stats["urls_scanned"] = self._count_urls_scanned(all_findings)
        except Exception as e:
            logger.warning(f"[{self.name}] Failed to calc stats: {e}")

        try:
            from bugtrace.core.llm_client import llm_client
            token_summary = llm_client.token_tracker.get_summary()
            stats["total_tokens"] = token_summary.get("total", 0)
            stats["input_tokens"] = token_summary.get("total_input", 0)
            stats["output_tokens"] = token_summary.get("total_output", 0)
            stats["estimated_cost"] = token_summary.get("estimated_cost", 0.0)
            stats["tokens_by_model"] = token_summary.get("by_model", {})
        except Exception as e:
            logger.debug(f"[{self.name}] Failed to get token stats: {e}")

        return stats

    # I/O
    def _calculate_scan_duration(self) -> Dict:
        """Calculate scan duration from scan directory timestamp."""
        try:
            if self.output_dir and self.output_dir.exists():
                import os
                dir_stat = os.stat(self.output_dir)
                start_time = datetime.fromtimestamp(dir_stat.st_ctime)
                duration = datetime.now() - start_time
                hours, remainder = divmod(int(duration.total_seconds()), 3600)
                minutes, seconds = divmod(remainder, 60)
                return {
                    "duration": f"{hours}h {minutes}m {seconds}s",
                    "duration_seconds": int(duration.total_seconds())
                }
        except Exception as e:
            logger.debug(f"[{self.name}] Failed to calculate duration: {e}")
        return {}

    # I/O
    def _count_urls_scanned(self, all_findings: List[Dict]) -> int:
        """Count URLs scanned from file, memory, or findings."""
        urls_file = self.output_dir / "recon" / "urls.txt"

        if urls_file.exists():
            with open(urls_file, "r") as f:
                return len([line.strip() for line in f if line.strip()])

        from bugtrace.core.conductor import conductor
        urls = conductor.get_shared_context("discovered_urls") or []
        if urls:
            return len(urls)

        unique_urls = set(f.get("url") for f in all_findings if f.get("url"))
        return len(unique_urls)

    # ── Report Generation Dispatch ───────────────────────────────────────

    def _generate_json_reports(self, all_findings: List[Dict], categorized: Dict) -> Dict[str, Path]:
        """Generate JSON report files."""
        validated_deduped = deduplicate_findings(categorized["validated"])
        manual_review_deduped = deduplicate_findings(categorized["manual_review"])

        return {
            "raw_findings": write_json(
                categorized["raw"],
                "raw_findings.json",
                "All findings before/after AgenticValidator",
                self.output_dir,
                self.scan_id,
                self.target_url,
            ),
            "validated_findings": write_validated_json(
                validated_deduped,
                manual_review_deduped,
                self.output_dir,
                self.scan_id,
                self.target_url,
            )
        }

    def _generate_markdown_reports(self, categorized: Dict) -> Dict[str, Path]:
        """Generate Markdown report files."""
        return {
            "final_report": write_markdown_report(
                validated=categorized["validated"],
                manual_review=categorized["manual_review"],
                pending=categorized["pending"],
                output_dir=self.output_dir,
                scan_id=self.scan_id,
                target_url=self.target_url,
                tech_profile=self.tech_profile,
            )
        }

    def _generate_data_files(
        self,
        all_findings: List[Dict],
        categorized: Dict,
        stats: Dict,
        tech_stack: Dict
    ) -> Dict[str, Path]:
        """Generate engagement data files (JS and JSON)."""
        eng_data = build_engagement_data(
            all_findings=all_findings,
            validated=categorized["validated"],
            false_positives=categorized["false_positives"],
            manual_review=categorized["manual_review"],
            stats=stats,
            tech_stack=tech_stack,
            scan_id=self.scan_id,
            target_url=self.target_url,
            tech_profile=self.tech_profile,
            enrichment_total=self._enrichment_total,
            enrichment_failures=self._enrichment_failures,
        )

        write_engagement_json(eng_data, self.output_dir)

        return {
            "engagement_data": write_engagement_js(eng_data, self.output_dir)
        }

    def _generate_html_report(self, paths: Dict[str, Path]) -> Dict[str, Path]:
        """Generate HTML report using HTMLGenerator."""
        from bugtrace.reporting.generator import HTMLGenerator

        generator = HTMLGenerator()
        return {
            "report_html": Path(generator.generate(
                paths.get("engagement_data"),
                self.output_dir / "report.html"
            ))
        }

    # ── Enrichment (CVSS + PoC) ──────────────────────────────────────────

    async def _enrich_findings_batch(self, findings: List[Dict]):
        """
        Enrich a batch of findings with CVSS scores and professional PoC using LLM.
        """
        if not findings:
            return

        self._enrichment_total = len(findings)

        # Pre-check: Is LLM available?
        health = llm_client.get_health_status() or {}
        if health.get("state") == "CRITICAL":
            logger.warning(f"[{self.name}] LLM circuit breaker OPEN. Skipping enrichment for {len(findings)} findings.")
            dashboard.log(
                f"[Reporting] LLM unavailable (circuit breaker OPEN). "
                f"{len(findings)} findings will not be enriched with CVSS/PoC details. "
                f"Use re-enrich to retry when LLM recovers.",
                "WARN"
            )
            for f in findings:
                f["enriched"] = False
            self._enrichment_failures = len(findings)
            await self._event_bus.emit(EventType.ENRICHMENT_DEGRADED, {
                "scan_id": self.scan_id,
                "total": len(findings),
                "enriched": 0,
                "failed": len(findings),
                "enrichment_status": "none",
                "message": f"LLM unavailable — {len(findings)} findings lack CVSS and exploitation details.",
            })
            return

        # CVSS and PoC enrichment run IN PARALLEL
        groups = group_findings_by_type(findings)
        logger.info(
            f"[{self.name}] Starting parallel enrichment: CVSS + PoC for {len(findings)} findings "
            f"in {len(groups)} type groups: {list(groups.keys())}"
        )

        cvss_task = calculate_cvss_batch(findings)
        poc_tasks = [
            self._poc_enrich_group_with_fallback(vtype, group)
            for vtype, group in groups.items()
        ]
        await asyncio.gather(cvss_task, *poc_tasks)

        # Post-check: detect findings that failed CVSS enrichment
        for f in findings:
            if f.get("enriched") is None and f.get("cvss_score") is None:
                f["enriched"] = False
                self._enrichment_failures += 1
            elif f.get("enriched") is None:
                f["enriched"] = True

        # Emit degraded event if any failures
        if self._enrichment_failures > 0:
            enrichment_status = compute_enrichment_status(self._enrichment_total, self._enrichment_failures)
            enriched_count = self._enrichment_total - self._enrichment_failures
            logger.warning(
                f"[{self.name}] Enrichment degraded: {enriched_count}/{self._enrichment_total} findings enriched"
            )
            dashboard.log(
                f"[Reporting] {self._enrichment_failures}/{self._enrichment_total} findings could not be enriched. "
                f"Use re-enrich to retry when LLM recovers.",
                "WARN"
            )
            await self._event_bus.emit(EventType.ENRICHMENT_DEGRADED, {
                "scan_id": self.scan_id,
                "total": self._enrichment_total,
                "enriched": enriched_count,
                "failed": self._enrichment_failures,
                "enrichment_status": enrichment_status,
                "message": f"{self._enrichment_failures}/{self._enrichment_total} findings lack enrichment.",
            })

    # ── PoC Enrichment ───────────────────────────────────────────────────

    # I/O
    async def _enrich_poc_with_llm(self, finding: Dict):
        """Use LLM to generate professional exploitation explanation."""
        try:
            context = self._poc_prepare_context(finding)
            prompt = self._poc_build_prompt(context)
            response = await self._poc_execute_llm(prompt)

            if response and ("LLM unavailable" in response or "fail open" in response or '"payloads"' in response):
                finding["enriched"] = False
                self._enrichment_failures += 1
                return

            if response:
                self._poc_parse_response(finding, response)
                finding["enriched"] = True
            else:
                finding["enriched"] = False
                self._enrichment_failures += 1

        except Exception as e:
            logger.debug(f"[{self.name}] Exploitation enrichment skipped for {finding.get('id')}: {e}")
            finding["enriched"] = False
            self._enrichment_failures += 1

    # PURE
    def _poc_prepare_context(self, finding: Dict) -> Dict:
        """Prepare context for PoC enrichment prompt."""
        vuln_type = finding.get("type", "Unknown")
        validator_notes = finding.get("validator_notes", "")
        extra_evidence = f"- Validation Evidence: {validator_notes}" if validator_notes else ""

        return {
            "vuln_type": vuln_type,
            "url": finding.get("url", ""),
            "param": finding.get("parameter", ""),
            "payload": finding.get("payload", ""),
            "description": finding.get("description", ""),
            "extra_evidence": extra_evidence,
            "type_context": get_type_specific_context(vuln_type)
        }

    # PURE
    def _poc_build_prompt(self, context: Dict) -> str:
        """Build PoC enrichment prompt."""
        return f"""You are a senior bug bounty hunter writing a FINAL report for a HackerOne/Bugcrowd triager or a non-technical stakeholder.
The goal is to provide a COMPLETE, STEP-BY-STEP guide that anyone can follow to reproduce the issue blindly.

**Confirmed Vulnerability:**
- Type: {context['vuln_type']}
- URL: {context['url']}
- Vulnerable Parameter: {context['param']}
- Payload Used: {context['payload']}
- Detection Notes: {context['description']}
{context['extra_evidence']}

{context['type_context']}

**Your Task: Write a comprehensive exploitation report covering:**

1. **Summary** (1-2 sentences): Explain the vulnerability and its core impact in plain English.

2. **Attack Scenario**: A realistic, detailed story of how this would be exploited in the wild.

3. **Maximum Impact**: The worst-case consequences (e.g., data theft types, system compromise level).

4. **Proof of Exploitation**: A specific one-liner or description of what the provided payload proves.

5. **Step-by-Step Reproduction (CRITICAL)**:
   - Must be extremely detailed and idiot-proof.
   - Do NOT just say "Scan with tool".
   - Start from "1. Open the browser...".
   - Include specific inputs, buttons to click, or curl commands to run.
   - Mention EXACTLY what to look for (e.g., "Look for an alert box saying '1'").
   - If it involves a complex HTTP request, describe how to construct it.

**Format your response as plain text with these exact headers:**
## Summary
[your summary]

## Attack Scenario
[your scenario]

## Maximum Impact
[your impact]

## Proof of Exploitation
[your proof]

## Reproduction Steps
[1. Step one...
2. Step two...
3. ...]

Be PRECISE. Imagine the reader has no context about the scan tool."""

    # I/O
    async def _poc_execute_llm(self, prompt: str) -> Optional[str]:
        """Execute LLM call for PoC enrichment."""
        return await llm_client.generate(
            prompt,
            module_name="Reporting-Exploitation",
            model_override=settings.REPORTING_MODEL,
            temperature=0.4
        )

    # PURE
    def _poc_parse_response(self, finding: Dict, response: str):
        """Parse PoC enrichment response and update finding."""
        content = response.strip()
        finding["exploitation_details"] = content

        steps_match = re.search(r"## Reproduction Steps\s*(.*?)(?:$|##)", content, re.DOTALL)
        if steps_match:
            raw_steps = steps_match.group(1).strip()
            steps_list = [line.strip() for line in raw_steps.split('\n') if line.strip()]
            if steps_list:
                finding["llm_reproduction_steps"] = steps_list

    # ── Batch PoC Enrichment ─────────────────────────────────────────────

    # PURE
    def _poc_batch_build_prompt(self, vuln_type: str, findings_in_group: List[Dict]) -> str:
        """Build a single prompt for batch PoC enrichment of a type group."""
        type_context = get_type_specific_context(vuln_type)

        finding_blocks = []
        for i, f in enumerate(findings_in_group):
            payload_str = str(f.get("payload", ""))[:200]
            desc_str = str(f.get("description", ""))[:300]
            validator_notes = f.get("validator_notes", "")
            evidence = f"  Validation Evidence: {validator_notes}" if validator_notes else ""
            finding_blocks.append(
                f"[Finding {i}]\n"
                f"  URL: {f.get('url', '')}\n"
                f"  Parameter: {f.get('parameter', '')}\n"
                f"  Payload: {payload_str}\n"
                f"  Description: {desc_str}\n"
                f"{evidence}"
            )

        findings_text = "\n\n".join(finding_blocks)

        return f"""You are a senior bug bounty hunter writing exploitation reports for a batch of {len(findings_in_group)} confirmed {vuln_type} vulnerabilities.

{type_context}

**Confirmed Findings:**

{findings_text}

**Your Task:** For EACH finding above, write a complete exploitation report.

Return a JSON array where each element has:
- "finding_id": (integer, matching the [Finding N] number above)
- "summary": (1-2 sentences explaining the vulnerability)
- "attack_scenario": (realistic exploitation story)
- "maximum_impact": (worst-case consequences)
- "proof_of_exploitation": (what the payload proves)
- "reproduction_steps": (array of strings, step-by-step, start from "Open the browser...")

**CRITICAL:** Return ONLY a valid JSON array. No markdown fences, no explanation outside the JSON.
Example format:
[
  {{"finding_id": 0, "summary": "...", "attack_scenario": "...", "maximum_impact": "...", "proof_of_exploitation": "...", "reproduction_steps": ["1. Open...", "2. Navigate..."]}},
  {{"finding_id": 1, "summary": "...", ...}}
]"""

    # I/O
    async def _poc_batch_execute_llm(self, prompt: str, n_findings: int) -> Optional[str]:
        """Execute LLM call for batch PoC enrichment with scaled token budget."""
        scaled_tokens = max(
            settings.REPORTING_POC_MIN_TOKENS,
            min(n_findings * settings.REPORTING_POC_TOKENS_PER_FINDING, settings.REPORTING_POC_MAX_TOKENS)
        )
        return await llm_client.generate(
            prompt,
            module_name="Reporting-Exploitation-Batch",
            model_override=settings.REPORTING_MODEL,
            temperature=0.4,
            max_tokens=scaled_tokens
        )

    # PURE
    def _poc_batch_parse_response(self, response: str, findings_in_group: List[Dict]) -> tuple:
        """Parse batch JSON response and populate findings.
        Returns (enriched_count, list_of_failed_finding_ids).
        """
        enriched_count = 0
        failed_ids = []

        cleaned = response.strip()
        fence_match = re.search(r'```\w*\s*\n?(.*?)```', cleaned, re.DOTALL)
        if fence_match:
            cleaned = fence_match.group(1).strip()
        elif cleaned.startswith("```"):
            cleaned = re.sub(r'^```\w*\s*\n?', '', cleaned).strip()

        parsed = None
        try:
            p = json.loads(cleaned)
            if isinstance(p, list):
                parsed = p
            elif isinstance(p, dict):
                for key in p:
                    if isinstance(p[key], list):
                        parsed = p[key]
                        break
        except (json.JSONDecodeError, ValueError):
            pass

        if not parsed:
            match = re.search(r'\[.*\]', cleaned, re.DOTALL)
            if match:
                try:
                    parsed = json.loads(match.group(0))
                except json.JSONDecodeError:
                    pass

        if not parsed:
            return 0, list(range(len(findings_in_group)))

        parsed_map = {}
        for item in parsed:
            if isinstance(item, dict) and "finding_id" in item:
                parsed_map[item["finding_id"]] = item

        for i, f in enumerate(findings_in_group):
            item = parsed_map.get(i)
            if not item:
                failed_ids.append(i)
                continue

            sections = []
            summary = item.get("summary")
            if summary:
                sections.append(f"## Summary\n{summary}")
            attack_scenario = item.get("attack_scenario")
            if attack_scenario:
                sections.append(f"## Attack Scenario\n{attack_scenario}")
            max_impact = item.get("maximum_impact")
            if max_impact:
                sections.append(f"## Maximum Impact\n{max_impact}")
            proof = item.get("proof_of_exploitation")
            if proof:
                sections.append(f"## Proof of Exploitation\n{proof}")
            repro_steps = item.get("reproduction_steps", [])
            if repro_steps:
                steps_text = "\n".join(repro_steps) if isinstance(repro_steps, list) else str(repro_steps)
                sections.append(f"## Reproduction Steps\n{steps_text}")

            if sections:
                f["exploitation_details"] = "\n\n".join(sections)
                enriched_count += 1
            else:
                failed_ids.append(i)
                continue

            if item.get("reproduction_steps") and isinstance(item["reproduction_steps"], list):
                f["llm_reproduction_steps"] = item["reproduction_steps"]

        return enriched_count, failed_ids

    # I/O
    def _poc_write_wet_file(self, vuln_type: str, response: str, status: str,
                            n_findings: int, error_msg: Optional[str] = None) -> None:
        """Write raw LLM response to poc_enrichment/wet/ for traceability."""
        try:
            wet_dir = self.output_dir / "poc_enrichment" / "wet"
            wet_dir.mkdir(parents=True, exist_ok=True)

            safe_type = vuln_type.lower().replace(" ", "_")
            wet_path = wet_dir / f"{safe_type}_wet.json"

            wet_data = {
                "vuln_type": vuln_type,
                "timestamp": datetime.now().isoformat(),
                "model": settings.REPORTING_MODEL,
                "findings_count": n_findings,
                "max_tokens": max(
                    settings.REPORTING_POC_MIN_TOKENS,
                    min(n_findings * settings.REPORTING_POC_TOKENS_PER_FINDING, settings.REPORTING_POC_MAX_TOKENS)
                ),
                "status": status,
                "error_message": error_msg,
                "raw_response": response or ""
            }

            if wet_path.exists():
                try:
                    existing = json.loads(wet_path.read_text(encoding="utf-8"))
                    if isinstance(existing, list):
                        existing.append(wet_data)
                        wet_data = existing
                    else:
                        wet_data = [existing, wet_data]
                except (json.JSONDecodeError, OSError):
                    wet_data = [wet_data]
            else:
                wet_data = [wet_data]

            wet_path.write_text(json.dumps(wet_data, indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception as e:
            logger.warning(f"[{self.name}] Failed to write WET file for {vuln_type}: {e}")

    # I/O
    def _poc_write_dry_file(self, vuln_type: str, findings_in_group: List[Dict],
                            enriched_ids: List[int], failed_ids: List[int],
                            parse_method: str = "batch_json") -> None:
        """Write parsed PoC summary to poc_enrichment/dry/ for traceability."""
        try:
            dry_dir = self.output_dir / "poc_enrichment" / "dry"
            dry_dir.mkdir(parents=True, exist_ok=True)

            safe_type = vuln_type.lower().replace(" ", "_")
            dry_path = dry_dir / f"{safe_type}_dry.json"

            findings_summary = []
            for i, f in enumerate(findings_in_group):
                status = "enriched" if i in enriched_ids else "failed"
                source = "batch" if i in enriched_ids else "pending_fallback"
                findings_summary.append({
                    "finding_id": i,
                    "url": f.get("url", ""),
                    "parameter": f.get("parameter", ""),
                    "status": status,
                    "enrichment_source": source,
                    "has_exploitation_details": bool(f.get("exploitation_details")),
                    "has_reproduction_steps": bool(f.get("llm_reproduction_steps")),
                    "reproduction_steps_count": len(f.get("llm_reproduction_steps", []))
                })

            failed_summary = []
            for fid in failed_ids:
                if fid < len(findings_in_group):
                    ff = findings_in_group[fid]
                    failed_summary.append({
                        "finding_id": fid,
                        "url": ff.get("url", ""),
                        "parameter": ff.get("parameter", ""),
                        "reason": "missing_from_response",
                        "fallback_action": "individual_enrichment"
                    })

            dry_data = {
                "vuln_type": vuln_type,
                "timestamp": datetime.now().isoformat(),
                "wet_count": len(findings_in_group),
                "dry_count": len(enriched_ids),
                "failed_count": len(failed_ids),
                "parse_method": parse_method,
                "findings": findings_summary,
                "failed_findings": failed_summary
            }

            if dry_path.exists():
                try:
                    existing = json.loads(dry_path.read_text(encoding="utf-8"))
                    if isinstance(existing, list):
                        existing.append(dry_data)
                        dry_data = existing
                    else:
                        dry_data = [existing, dry_data]
                except (json.JSONDecodeError, OSError):
                    dry_data = [dry_data]
            else:
                dry_data = [dry_data]

            dry_path.write_text(json.dumps(dry_data, indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception as e:
            logger.warning(f"[{self.name}] Failed to write DRY file for {vuln_type}: {e}")

    # I/O
    async def _poc_enrich_group_with_fallback(self, vuln_type: str, findings_in_group: List[Dict]) -> None:
        """
        Orchestrator: enrich a type group with batch LLM call + individual fallback.

        Flow:
        1. Single finding -> direct individual enrichment (no JSON overhead)
        2. Multiple findings -> batch call -> parse -> fallback for failures
        3. >BATCH_SIZE findings -> chunk into sub-batches
        """
        (self.output_dir / "poc_enrichment" / "wet").mkdir(parents=True, exist_ok=True)
        (self.output_dir / "poc_enrichment" / "dry").mkdir(parents=True, exist_ok=True)

        n = len(findings_in_group)

        # Single finding: bypass batch overhead
        if n == 1:
            f = findings_in_group[0]
            await self._enrich_poc_with_llm(f)
            enriched = [0] if f.get("exploitation_details") else []
            failed = [] if f.get("exploitation_details") else [0]
            self._poc_write_wet_file(vuln_type, f.get("exploitation_details", ""), "success" if enriched else "fallback_individual", 1)
            self._poc_write_dry_file(vuln_type, findings_in_group, enriched, failed, parse_method="individual")
            logger.info(f"[{self.name}] Batch PoC: {vuln_type} group (1 finding) enriched individually")
            return

        # Chunk large groups into sub-batches
        batch_size = settings.REPORTING_POC_BATCH_SIZE
        chunks = [findings_in_group[i:i + batch_size] for i in range(0, n, batch_size)]

        all_enriched_ids = []
        all_failed_ids = []
        offset = 0

        for chunk in chunks:
            try:
                prompt = self._poc_batch_build_prompt(vuln_type, chunk)
                response = await self._poc_batch_execute_llm(prompt, len(chunk))

                if response and "LLM unavailable" not in response and '"payloads"' not in response:
                    self._poc_write_wet_file(vuln_type, response, "success", len(chunk))
                    enriched_count, failed_local = self._poc_batch_parse_response(response, chunk)
                    enriched_local = [i for i in range(len(chunk)) if i not in failed_local]
                    all_enriched_ids.extend([i + offset for i in enriched_local])
                    all_failed_ids.extend([i + offset for i in failed_local])

                    logger.info(
                        f"[{self.name}] Batch PoC: {vuln_type} group ({len(chunk)} findings) "
                        f"enriched {enriched_count} in 1 call, {len(failed_local)} need fallback"
                    )

                    if failed_local:
                        for fid in failed_local:
                            await self._enrich_poc_with_llm(chunk[fid])
                            if chunk[fid].get("exploitation_details"):
                                global_id = fid + offset
                                try:
                                    all_failed_ids.remove(global_id)
                                except ValueError:
                                    pass
                                all_enriched_ids.append(global_id)
                else:
                    self._poc_write_wet_file(vuln_type, response or "", "error", len(chunk),
                                            error_msg="LLM unavailable or circuit breaker open")
                    all_failed_ids.extend(range(offset, offset + len(chunk)))

                    logger.warning(f"[{self.name}] Batch PoC: {vuln_type} batch failed, falling back to individual")
                    for idx_in_chunk, f in enumerate(chunk):
                        await self._enrich_poc_with_llm(f)
                        idx = offset + idx_in_chunk
                        if f.get("exploitation_details"):
                            try:
                                all_failed_ids.remove(idx)
                            except ValueError:
                                pass
                            all_enriched_ids.append(idx)

            except Exception as e:
                logger.warning(f"[{self.name}] Batch PoC error for {vuln_type}: {e}")
                self._poc_write_wet_file(vuln_type, "", "error", len(chunk), error_msg=str(e))
                all_failed_ids.extend(range(offset, offset + len(chunk)))

                for idx_in_chunk, f in enumerate(chunk):
                    try:
                        await self._enrich_poc_with_llm(f)
                        idx = offset + idx_in_chunk
                        if f.get("exploitation_details"):
                            try:
                                all_failed_ids.remove(idx)
                            except ValueError:
                                pass
                            all_enriched_ids.append(idx)
                    except Exception:
                        pass

            offset += len(chunk)

        self._poc_write_dry_file(vuln_type, findings_in_group, all_enriched_ids, all_failed_ids)
        logger.info(
            f"[{self.name}] Batch PoC: {vuln_type} complete — "
            f"{len(all_enriched_ids)}/{n} enriched, {len(all_failed_ids)}/{n} failed"
        )
