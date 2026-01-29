"""
ReportingAgent: Generates all 4 deliverables for a scan.

Deliverables:
1. raw_findings.json - Pre-AgenticValidator findings (for manual review)
2. validated_findings.json - Only VALIDATED_CONFIRMED findings
3. final_report.md - Triager-ready markdown with all findings
4. engagement_data.json - Structured JSON for HTML viewer
5. report.html - Static HTML that loads engagement_data.json
"""

import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

from bugtrace.agents.base import BaseAgent
from bugtrace.core.config import settings
from bugtrace.core.database import get_db_manager
from bugtrace.core.ui import dashboard
from bugtrace.utils.logger import get_logger
from bugtrace.core.llm_client import llm_client
from bugtrace.core.event_bus import EventType, event_bus
from bugtrace.core.validation_status import ValidationStatus
from bugtrace.schemas.db_models import ScanTable
from bugtrace.reporting.standards import (
    get_cwe_for_vuln,
    get_remediation_for_vuln,
    normalize_severity,
    format_cve,
)
import asyncio
import re

logger = get_logger("agents.reporting")


class ReportingAgent(BaseAgent):
    """
    Final Agent responsible for generating all report deliverables.
    """

    def __init__(self, scan_id: int, target_url: str, output_dir: Path):
        super().__init__("ReportingAgent", "Reporting Specialist", agent_id="reporting_agent")
        self.scan_id = scan_id
        self.target_url = target_url
        self.output_dir = Path(output_dir)
        self.db = get_db_manager()

        # Event-driven finding accumulation
        self._validated_findings: List[Dict] = []
        self._event_bus = event_bus
        self._subscribed = False

    def subscribe_to_events(self) -> None:
        """
        Subscribe to validation events from the pipeline.

        Subscribes to:
        - VULNERABILITY_DETECTED: Specialist self-validated findings (VALIDATED_CONFIRMED)
        - FINDING_VALIDATED: AgenticValidator CDP-validated findings

        Call this during scan startup to enable event-driven report generation.
        """
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
        """
        Unsubscribe from validation events.

        Call this during scan cleanup to prevent memory leaks.
        """
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
        """
        Handle vulnerability_detected events from specialist agents.

        Only processes findings with VALIDATED_CONFIRMED status (specialist self-validated).
        These are high-confidence findings that don't require CDP validation.

        Args:
            data: Event payload containing:
                - status: ValidationStatus string
                - finding: Finding dictionary
                - specialist: Specialist agent name
                - scan_context: Scan context identifier
                - validation_requires_cdp: Whether CDP validation was needed
        """
        status = data.get("status", "")

        # Only collect VALIDATED_CONFIRMED findings (skip PENDING_VALIDATION)
        if status != ValidationStatus.VALIDATED_CONFIRMED.value:
            return

        finding = data.get("finding", {}).copy()
        specialist = data.get("specialist", "unknown")

        # Enrich finding with event metadata
        finding["scan_context"] = data.get("scan_context", "")
        finding["specialist"] = specialist
        finding["validation_requires_cdp"] = data.get("validation_requires_cdp", False)
        finding["status"] = status
        finding["event_source"] = "vulnerability_detected"

        self._validated_findings.append(finding)
        logger.info(f"[{self.name}] Collected VALIDATED_CONFIRMED finding from {specialist}")

    async def _handle_finding_validated(self, data: Dict[str, Any]) -> None:
        """
        Handle finding_validated events from AgenticValidator.

        These are findings that required CDP validation and were confirmed.

        Args:
            data: Event payload containing:
                - finding: Original finding dictionary
                - validation_result: CDP validation result with reasoning/confidence
                - scan_context: Scan context identifier
        """
        finding = data.get("finding", {}).copy()
        validation_result = data.get("validation_result", {})
        specialist = finding.get("specialist", data.get("specialist", "unknown"))

        # Mark as CDP-validated
        finding["status"] = "VALIDATED"
        finding["cdp_validated"] = True
        finding["cdp_reasoning"] = validation_result.get("reasoning", "")
        finding["cdp_confidence"] = validation_result.get("confidence", 0.0)
        finding["scan_context"] = data.get("scan_context", "")
        finding["event_source"] = "finding_validated"

        self._validated_findings.append(finding)
        logger.info(f"[{self.name}] Collected CDP-VALIDATED finding from {specialist}")

    def get_validated_findings(self) -> List[Dict]:
        """
        Get a copy of all accumulated validated findings.

        Returns:
            List of validated finding dictionaries (copy to prevent mutation)
        """
        return self._validated_findings.copy()

    def clear_validated_findings(self) -> None:
        """
        Clear all accumulated validated findings.

        Useful for testing or multi-scan scenarios where the same
        ReportingAgent instance is reused.
        """
        self._validated_findings.clear()
        logger.debug(f"[{self.name}] Cleared validated findings")

    async def run_loop(self):
        """Not used - call generate_all_deliverables() directly."""
        pass

    async def generate_all_deliverables(self) -> Dict[str, Path]:
        """
        Main entry point. Generates all 4 deliverables.

        Returns dict with paths to each deliverable.
        """
        dashboard.update_task("reporting", name="Reporting Agent", status="Generating deliverables...")
        logger.info(f"[{self.name}] Starting report generation for scan {self.scan_id}")

        # Phase 1: Setup and data collection
        self._setup_output_directories()
        all_findings, tech_stack = await self._collect_all_findings()

        # Phase 2: Categorize and enrich findings
        categorized = self._categorize_findings(all_findings)
        await self._enrich_findings_batch(categorized["validated"] + categorized["manual_review"])

        # Phase 3: Calculate statistics
        stats = self._calculate_scan_stats(all_findings)

        # Phase 4: Generate all report deliverables
        paths = self._generate_json_reports(all_findings, categorized)
        paths.update(self._generate_markdown_reports(categorized))
        paths.update(self._generate_data_files(all_findings, categorized, stats, tech_stack))
        paths.update(self._generate_html_report(paths))

        # Phase 5: Organize artifacts
        self._copy_screenshots(all_findings, self.output_dir / "captures")

        dashboard.log(f"[{self.name}] Generated {len(paths)} deliverables in {self.output_dir}", "SUCCESS")
        return paths

    def _setup_output_directories(self):
        """Create necessary output directories."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / "captures").mkdir(exist_ok=True)

    async def _collect_all_findings(self) -> tuple[List[Dict], Dict]:
        """Collect all findings from DB, Nuclei, and event bus."""
        all_findings = self._get_findings_from_db()
        logger.info(f"[{self.name}] Retrieved {len(all_findings)} findings from DB")

        nuclei_findings, tech_stack = self._load_nuclei_findings()
        if nuclei_findings:
            all_findings.extend(nuclei_findings)
            logger.info(f"[{self.name}] Added {len(nuclei_findings)} Nuclei findings")

        # Merge event-sourced findings
        all_findings = self._merge_event_findings(all_findings)

        return all_findings, tech_stack

    def _merge_event_findings(self, db_findings: List[Dict]) -> List[Dict]:
        """
        Merge event-sourced validated findings with database findings.

        Deduplicates based on (url, parameter, payload) to prevent duplicates.
        Event findings are marked with source='event_bus'.

        Args:
            db_findings: Findings from database and Nuclei

        Returns:
            Merged list with event findings appended (no duplicates)
        """
        event_findings = self.get_validated_findings()
        if not event_findings:
            return db_findings

        # Build deduplication key function
        def dedup_key(f: Dict) -> tuple:
            return (f.get("url"), f.get("parameter"), f.get("payload"))

        # Create seen keys set from DB findings
        seen_keys = set(dedup_key(f) for f in db_findings)

        # Mark DB findings with source
        for f in db_findings:
            if "source" not in f:
                f["source"] = "database"

        # Merge non-duplicate event findings
        merged = list(db_findings)
        added_count = 0

        for event_finding in event_findings:
            key = dedup_key(event_finding)
            if key not in seen_keys:
                # Convert to DB-compatible format
                formatted = self._event_finding_to_db_format(event_finding)
                merged.append(formatted)
                seen_keys.add(key)
                added_count += 1

        logger.info(f"[{self.name}] Merged {added_count} event findings with {len(db_findings)} DB findings")
        return merged

    def _event_finding_to_db_format(self, event_finding: Dict) -> Dict:
        """
        Convert event finding structure to DB-compatible structure.

        Args:
            event_finding: Finding from event bus accumulator

        Returns:
            Dictionary with DB-compatible field names
        """
        evidence = event_finding.get("evidence", {})

        return {
            "id": None,  # Event findings don't have DB IDs
            "type": event_finding.get("type") or event_finding.get("vuln_type", "Unknown"),
            "severity": event_finding.get("severity", "HIGH"),
            "url": event_finding.get("url", ""),
            "parameter": event_finding.get("parameter", ""),
            "payload": event_finding.get("payload", ""),
            "description": event_finding.get("description") or evidence.get("description", ""),
            "status": event_finding.get("status", "VALIDATED_CONFIRMED"),
            "validator_notes": event_finding.get("cdp_reasoning") or event_finding.get("reasoning", ""),
            "screenshot_path": event_finding.get("screenshot_path"),
            "validation_method": event_finding.get("validation_method", "event_bus"),
            "source": "event_bus",
            # Preserve event-specific metadata
            "specialist": event_finding.get("specialist"),
            "scan_context": event_finding.get("scan_context"),
            "cdp_validated": event_finding.get("cdp_validated", False),
            "cdp_confidence": event_finding.get("cdp_confidence"),
        }

    def _categorize_findings(self, all_findings: List[Dict]) -> Dict[str, List[Dict]]:
        """
        Categorize findings by validation status.

        Handles both:
        - VALIDATED_CONFIRMED: Specialist self-validated (no CDP needed)
        - VALIDATED: CDP-validated findings from AgenticValidator
        """
        # Define validated status values (both specialist and CDP confirmed)
        validated_statuses = {
            "VALIDATED_CONFIRMED",  # Specialist self-validated
            "VALIDATED",  # CDP validated (from finding_validated events)
            ValidationStatus.VALIDATED_CONFIRMED.value,
            ValidationStatus.FINDING_VALIDATED.value if hasattr(ValidationStatus, 'FINDING_VALIDATED') else "FINDING_VALIDATED",
        }

        return {
            "raw": [f for f in all_findings],
            "validated": [f for f in all_findings if f.get("status") in validated_statuses],
            "manual_review": [f for f in all_findings if f.get("status") == "MANUAL_REVIEW_RECOMMENDED"],
            "false_positives": [f for f in all_findings if f.get("status") == "VALIDATED_FALSE_POSITIVE"],
            "pending": [f for f in all_findings if f.get("status") == "PENDING_VALIDATION"]
        }

    def _calculate_scan_stats(self, all_findings: List[Dict]) -> Dict:
        """Calculate scan statistics (duration, URLs scanned)."""
        stats = {"urls_scanned": 0, "duration": "Unknown"}
        try:
            # Calculate duration
            stats.update(self._calculate_scan_duration())
            # Count URLs scanned
            stats["urls_scanned"] = self._count_urls_scanned(all_findings)
        except Exception as e:
            logger.warning(f"[{self.name}] Failed to calc stats: {e}")
        return stats

    def _calculate_scan_duration(self) -> Dict:
        """Calculate scan duration from database."""
        with self.db.get_session() as session:
            scan = session.get(ScanTable, self.scan_id)
            if scan and scan.timestamp:
                duration = datetime.utcnow() - scan.timestamp
                hours, remainder = divmod(int(duration.total_seconds()), 3600)
                minutes, seconds = divmod(remainder, 60)
                return {
                    "duration": f"{hours}h {minutes}m {seconds}s",
                    "duration_seconds": int(duration.total_seconds())
                }
        return {}

    def _count_urls_scanned(self, all_findings: List[Dict]) -> int:
        """Count URLs scanned from file, memory, or findings."""
        # Priority: File on disk (persistent) > Shared Context (memory) > Findings
        urls_file = self.output_dir / "recon" / "urls.txt"

        if urls_file.exists():
            with open(urls_file, "r") as f:
                return len([line.strip() for line in f if line.strip()])

        from bugtrace.core.conductor import conductor
        urls = conductor.get_shared_context("discovered_urls") or []
        if urls:
            return len(urls)

        # Fallback to counting unique finding URLs
        unique_urls = set(f.get("url") for f in all_findings if f.get("url"))
        return len(unique_urls)

    def _generate_json_reports(self, all_findings: List[Dict], categorized: Dict) -> Dict[str, Path]:
        """Generate JSON report files."""
        return {
            "raw_findings": self._write_json(
                categorized["raw"],
                "raw_findings.json",
                "All findings before/after AgenticValidator"
            ),
            "validated_findings": self._write_json(
                categorized["validated"],
                "validated_findings.json",
                "Only VALIDATED_CONFIRMED findings"
            )
        }

    def _generate_markdown_reports(self, categorized: Dict) -> Dict[str, Path]:
        """Generate Markdown report files."""
        return {
            "final_report": self._write_markdown_report(
                validated=categorized["validated"],
                manual_review=categorized["manual_review"],
                pending=categorized["pending"]
            ),
            "raw_findings_md": self._write_raw_markdown(findings=categorized["raw"]),
            "validated_findings_md": self._write_validated_markdown(
                validated=categorized["validated"],
                manual_review=categorized["manual_review"]
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
        # Generate both JS and JSON engagement data files
        self._write_engagement_json(
            all_findings=all_findings,
            validated=categorized["validated"],
            false_positives=categorized["false_positives"],
            manual_review=categorized["manual_review"],
            stats=stats,
            tech_stack=tech_stack
        )

        return {
            "engagement_data": self._write_engagement_js(
                all_findings=all_findings,
                validated=categorized["validated"],
                false_positives=categorized["false_positives"],
                manual_review=categorized["manual_review"],
                stats=stats,
                tech_stack=tech_stack
            )
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

    def _get_findings_from_db(self) -> List[Dict]:
        """Pull findings from database for this scan_id."""
        db_findings = self.db.get_findings_for_scan(self.scan_id)

        findings = []
        for f in db_findings:
            finding = self._db_build_finding_dict(f)
            self._db_enrich_sqli_metadata(finding, f)
            findings.append(finding)

        return findings

    def _db_build_finding_dict(self, f) -> Dict:
        """Build finding dictionary from database record."""
        return {
            "id": f.id,
            "type": str(f.type.value if hasattr(f.type, 'value') else f.type),
            "severity": f.severity,
            "url": f.attack_url,
            "parameter": f.vuln_parameter,
            "payload": f.payload_used,
            "description": f.details,
            "status": f.status,
            "validator_notes": f.validator_notes,
            "screenshot_path": f.proof_screenshot_path,
            "reproduction": getattr(f, 'reproduction_command', None),
            "created_at": None
        }

    def _db_enrich_sqli_metadata(self, finding: Dict, f) -> None:
        """Parse and enrich SQLMap metadata from details JSON."""
        import json

        # Only process SQLi findings with details
        if finding["type"] not in ["SQLI", "SQLi"]:
            return
        if not f.details:
            return

        try:
            details_json = json.loads(f.details)
            # Extract SQLMap-specific fields
            finding["db_type"] = details_json.get("db_type")
            finding["tamper_used"] = details_json.get("tamper_used")
            finding["confidence"] = details_json.get("confidence")
            finding["evidence"] = details_json.get("evidence")
            finding["description"] = details_json.get("description", f.details)
            # Extract reproduction command if present in details
            if details_json.get("reproduction_command"):
                finding["reproduction"] = details_json.get("reproduction_command")
        except (json.JSONDecodeError, TypeError):
            # Not JSON, use as-is
            pass

    def _load_nuclei_findings(self) -> tuple[List[Dict], Dict]:
        """
        Load Nuclei findings from tech_profile.json.
        Returns tuple: (list of findings, tech_stack dict)
        """
        tech_profile_path = self.output_dir / "tech_profile.json"
        if not tech_profile_path.exists():
            logger.debug(f"[{self.name}] No tech_profile.json found")
            return [], {}

        tech_profile = self._nuclei_load_file(tech_profile_path)
        if not tech_profile:
            return [], {}

        nuclei_findings = self._nuclei_parse_findings(tech_profile)
        tech_stack = self._nuclei_extract_tech_stack(tech_profile)

        logger.info(f"[{self.name}] Loaded {len(nuclei_findings)} Nuclei findings, tech stack: {tech_stack}")
        return nuclei_findings, tech_stack

    def _nuclei_load_file(self, path: Path) -> Optional[Dict]:
        """Load and parse tech_profile.json file."""
        try:
            with open(path, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"[{self.name}] Failed to load tech_profile.json: {e}")
            return None

    def _nuclei_parse_findings(self, tech_profile: Dict) -> List[Dict]:
        """Parse Nuclei findings from tech profile."""
        nuclei_findings = []
        for finding in tech_profile.get("raw_findings", []):
            info = finding.get("info", {})
            severity = self._nuclei_map_severity(info.get("severity"))
            status = "VALIDATED_CONFIRMED" if severity in ["CRITICAL", "HIGH"] else "PENDING_VALIDATION"

            nuclei_findings.append({
                "id": None,
                "type": f"NUCLEI:{info.get('name', 'Unknown')}",
                "severity": severity,
                "url": finding.get("matched_at", ""),
                "parameter": info.get("name", ""),  # Template name as "parameter"
                "payload": finding.get("template_id", ""),  # Template ID
                "description": info.get("description", f"Detected by Nuclei template: {finding.get('template_id', 'unknown')}"),
                "status": status,
                "validator_notes": f"Nuclei detection (template: {finding.get('template_id', 'unknown')})",
                "screenshot_path": None,
                "reproduction": None,
                "source": "nuclei",
                "nuclei_template": finding.get("template_id"),
                "nuclei_tags": info.get("tags", [])
            })
        return nuclei_findings

    def _nuclei_map_severity(self, nuclei_sev: Optional[str]) -> str:
        """Map Nuclei severity to our severity scale."""
        nuclei_sev = (nuclei_sev or "info").upper()
        severity_map = {
            "CRITICAL": "CRITICAL",
            "HIGH": "HIGH",
            "MEDIUM": "MEDIUM",
            "LOW": "LOW",
            "INFO": "INFO"
        }
        return severity_map.get(nuclei_sev, "INFO")

    def _nuclei_extract_tech_stack(self, tech_profile: Dict) -> Dict:
        """Extract tech stack info from tech profile."""
        return {
            "frameworks": tech_profile.get("frameworks", []),
            "languages": tech_profile.get("languages", []),
            "servers": tech_profile.get("servers", [])
        }

    def _write_json(self, findings: List[Dict], filename: str, description: str) -> Path:
        """Write findings to a JSON file."""
        path = self.output_dir / filename

        output = {
            "meta": {
                "scan_id": self.scan_id,
                "target": self.target_url,
                "generated_at": datetime.now().isoformat(),
                "description": description,
                "count": len(findings)
            },
            "findings": findings
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, default=str)

        logger.info(f"[{self.name}] Wrote {filename} ({len(findings)} findings)")
        return path

    def _deduplicate_findings(self, findings: List[Dict]) -> List[Dict]:
        """
        Deduplicate findings by (type, parameter).
        
        For example, if we have 4 SQLi findings on productId=6,10,12,13,
        we'll return 1 representative finding with a note about affected URLs.
        
        Returns: List of deduplicated findings with 'affected_urls' metadata.
        """
        from collections import defaultdict
        
        # Group by (type, parameter)
        groups = defaultdict(list)
        for f in findings:
            key = (f.get("type", "Unknown"), f.get("parameter", ""))
            groups[key].append(f)
        
        deduplicated = []
        for (vuln_type, param), group in groups.items():
            if len(group) == 1:
                # No duplicates - keep as-is
                deduplicated.append(group[0])
            else:
                # Multiple findings - pick the first as representative
                representative = group[0].copy()
                
                # Collect all affected URLs
                affected_urls = [f.get("url", "") for f in group]
                representative["affected_urls"] = affected_urls
                representative["affected_count"] = len(affected_urls)
                
                # Update description to mention multiple URLs
                original_desc = representative.get("description", "")
                dedup_note = f"\n\n**Note:** This vulnerability affects {len(affected_urls)} URLs with the same parameter `{param}`."
                representative["description"] = original_desc + dedup_note
                
                deduplicated.append(representative)
                
                logger.info(f"[{self.name}] Deduplicated {len(group)} {vuln_type} findings on parameter '{param}'")
        
        return deduplicated


    def _build_triager_findings(
        self,
        validated: List[Dict],
        manual_review: List[Dict],
        i_param: int = 1
    ) -> Tuple[List[Dict], List[Dict]]:
        """Build triager-ready findings from validated and manual review lists."""
        triager_findings = []

        # Process validated findings
        for i, f in enumerate(validated, i_param):
            finding_entry = self._build_finding_entry(f, f"F-{i:03d}", "VALIDATED_CONFIRMED", "CERTAIN")
            triager_findings.append(finding_entry)

        # Process manual review findings
        for i, f in enumerate(manual_review, len(validated) + i_param):
            finding_entry = self._build_finding_entry(f, f"M-{i:03d}", "MANUAL_REVIEW_RECOMMENDED", "POTENTIAL")
            triager_findings.append(finding_entry)

        # Separate Nuclei findings
        nuclei_infra = [f for f in triager_findings if f.get("type", "").startswith("NUCLEI:")]
        vuln_findings = [f for f in triager_findings if not f.get("type", "").startswith("NUCLEI:")]

        return vuln_findings, nuclei_infra

    def _build_finding_entry(self, f: Dict, finding_id: str, status: str, confidence: str) -> Dict:
        """Build a single finding entry with all required fields."""
        # Determine source (event_bus or database)
        source = f.get("source", "database")
        validation_source = "event_bus" if source == "event_bus" else "database"

        entry = {
            "id": finding_id,
            "type": f.get("type", "Unknown"),
            "severity": f.get("severity", "MEDIUM" if status == "VALIDATED_CONFIRMED" else "HIGH"),
            "confidence": confidence,
            "status": status,
            "url": f.get("url", ""),
            "parameter": f.get("parameter", ""),
            "payload": f.get("payload", ""),
            "validation": self._build_validation_section(f, status),
            "reproduction": self._build_reproduction_section(f),
            "description": f.get("description", ""),
            "impact": self._get_impact_for_type(f.get("type", "")),
            "remediation": self._get_remediation_for_type(f.get("type", "")),
            "cvss_score": f.get("cvss_score"),
            "cvss_vector": f.get("cvss_vector"),
            "cvss_rationale": f.get("cvss_rationale"),
            "cve": f.get("cve"),
            "markdown_block": self._generate_finding_markdown(f, int(finding_id.split("-")[1])),
            # Source tracking for report viewers
            "source": source,
            "validation_source": validation_source,
        }

        # Add SQLi-specific fields
        if f.get("db_type"):
            entry["db_type"] = f.get("db_type")
        if f.get("tamper_used"):
            entry["tamper_used"] = f.get("tamper_used")

        # Add exploitation details if present
        if f.get("exploitation_details"):
            entry["exploitation_details"] = f.get("exploitation_details")

        # Add screenshot path if available
        if f.get("screenshot_path"):
            entry["screenshot_path"] = f"captures/{Path(f.get('screenshot_path', '')).name}"

        # Add CDP validation metadata if present (from event_bus findings)
        if f.get("cdp_validated"):
            entry["cdp_validated"] = f.get("cdp_validated")
        if f.get("cdp_confidence"):
            entry["cdp_confidence"] = f.get("cdp_confidence")
        if f.get("specialist"):
            entry["specialist"] = f.get("specialist")

        # Add validation method label for report display
        entry["validation_method_label"] = self._extract_validation_method(f)

        return entry

    def _build_validation_section(self, f: Dict, status: str) -> Dict:
        """Build validation section for a finding."""
        if status == "MANUAL_REVIEW_RECOMMENDED":
            return {
                "method": "Manual Review Required",
                "screenshot": f"captures/{Path(f.get('screenshot_path', '')).name}" if f.get("screenshot_path") else None,
                "notes": f.get("validator_notes", "") or "Automated validation inconclusive. Manual verification required."
            }
        return {
            "method": self._get_validation_method(f),
            "screenshot": f"captures/{Path(f.get('screenshot_path', '')).name}" if f.get("screenshot_path") else None,
            "notes": self._get_validation_notes(f)
        }

    def _build_reproduction_section(self, f: Dict) -> Dict:
        """Build reproduction section for a finding."""
        return {
            "steps": self._generate_reproduction_steps(f),
            "poc": self._generate_curl(f)
        }

    def _sort_findings_by_cvss(self, findings: List[Dict]) -> List[Dict]:
        """Sort findings by CVSS score descending."""
        severity_weights = {"CRITICAL": 10.0, "HIGH": 8.0, "MEDIUM": 5.0, "LOW": 2.0, "INFO": 0.0}

        def get_score(x):
            s = x.get("cvss_score")
            if s is not None and isinstance(s, (int, float)):
                return float(s)
            sev = (x.get("severity") or "MEDIUM").upper()
            return severity_weights.get(sev, 5.0)

        return sorted(findings, key=get_score, reverse=True)

    def _write_engagement_json(
        self,
        all_findings: List[Dict],
        validated: List[Dict],
        false_positives: List[Dict],
        manual_review: List[Dict],
        stats: Dict = None,
        tech_stack: Dict = None
    ) -> Path:
        """Write the structured engagement_data.json for HTML viewer."""
        path = self.output_dir / "engagement_data.json"
        output = self._build_engagement_data(
            all_findings, validated, false_positives, manual_review, stats, tech_stack
        )

        with open(path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, default=str)

        logger.info(f"[{self.name}] Wrote engagement_data.json ({len(output['findings'])} vuln findings, {len(output['infrastructure']['nuclei_findings'])} nuclei findings)")
        return path

    def _write_engagement_js(
        self,
        all_findings: List[Dict],
        validated: List[Dict],
        false_positives: List[Dict],
        manual_review: List[Dict],
        stats: Dict = None,
        tech_stack: Dict = None
    ) -> Path:
        """Write the structured engagement_data.js for HTML viewer (JSONP style)."""
        path = self.output_dir / "engagement_data.js"
        output = self._build_engagement_data(
            all_findings, validated, false_positives, manual_review, stats, tech_stack
        )

        # Write as JS assignment
        js_content = f"window.BUGTRACE_REPORT_DATA = {json.dumps(output, indent=2, default=str)};"

        with open(path, "w", encoding="utf-8") as f:
            f.write(js_content)

        logger.info(f"[{self.name}] Wrote engagement_data.js ({len(output['findings'])} vuln findings, {len(output['infrastructure']['nuclei_findings'])} nuclei findings)")
        return path

    def _build_engagement_data(
        self,
        all_findings: List[Dict],
        validated: List[Dict],
        false_positives: List[Dict],
        manual_review: List[Dict],
        stats: Dict = None,
        tech_stack: Dict = None
    ) -> Dict:
        """Build engagement data structure (shared between JSON and JS outputs)."""
        stats = stats or {"urls_scanned": 0, "duration": "0s"}
        tech_stack = tech_stack or {}

        # Deduplicate and process findings
        validated = self._deduplicate_findings(validated)
        manual_review = self._deduplicate_findings(manual_review)
        by_severity = self._count_by_severity(validated)

        # Build and sort findings
        vuln_findings, nuclei_infra = self._build_triager_findings(validated, manual_review)
        vuln_findings = self._sort_findings_by_cvss(vuln_findings)
        nuclei_infra = self._sort_findings_by_cvss(nuclei_infra)

        return {
            "meta": self._engagement_build_meta(),
            "stats": self._engagement_build_stats(stats),
            "summary": self._engagement_build_summary(all_findings, validated, false_positives, manual_review, by_severity),
            "findings": vuln_findings,
            "infrastructure": {
                "tech_stack": tech_stack,
                "nuclei_findings": nuclei_infra
            }
        }

    def _engagement_build_meta(self) -> Dict:
        """Build engagement metadata section."""
        return {
            "scan_id": self.scan_id,
            "target": self.target_url,
            "scan_date": datetime.now().isoformat(),
            "tool_version": settings.VERSION,
            "validation_engine": "AgenticValidator + CDP + Vision AI",
            "report_signature": "BUGTRACE_AI_REPORT_V5"
        }

    def _engagement_build_stats(self, stats: Dict) -> Dict:
        """Build engagement statistics section."""
        return {
            "urls_scanned": stats.get("urls_scanned", 0),
            "duration": stats.get("duration", "N/A"),
            "duration_seconds": stats.get("duration_seconds", 0),
            "validation_coverage": "100%"
        }

    def _engagement_build_summary(
        self,
        all_findings: List[Dict],
        validated: List[Dict],
        false_positives: List[Dict],
        manual_review: List[Dict],
        by_severity: Dict
    ) -> Dict:
        """Build engagement summary section with source tracking."""
        # Count findings by source
        event_sourced = sum(1 for f in all_findings if f.get("source") == "event_bus")
        db_sourced = sum(1 for f in all_findings if f.get("source") in ("database", None))
        nuclei_sourced = sum(1 for f in all_findings if f.get("source") == "nuclei")

        return {
            "total_findings": len(all_findings),
            "validated": len(validated),
            "false_positives": len(false_positives),
            "manual_review": len(manual_review),
            "by_severity": by_severity,
            # Source breakdown for report insights
            "event_sourced": event_sourced,
            "db_sourced": db_sourced,
            "nuclei_sourced": nuclei_sourced,
        }

    def _count_by_severity(self, validated: List[Dict]) -> Dict[str, int]:
        """Count findings by severity level."""
        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in validated:
            sev = (f.get("severity") or "medium").lower()
            if sev in by_severity:
                by_severity[sev] += 1
        return by_severity

    def _write_markdown_report(
        self,
        validated: List[Dict],
        manual_review: List[Dict],
        pending: List[Dict]
    ) -> Path:
        """Write the triager-ready markdown report."""
        path = self.output_dir / "final_report.md"

        lines = []
        self._md_build_header(lines, validated, manual_review, pending)
        self._md_build_validated_findings(lines, validated)
        self._md_build_manual_review(lines, manual_review)

        # Write file
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        logger.info(f"[{self.name}] Wrote final_report.md")
        return path

    def _md_build_header(self, lines: List[str], validated: List[Dict], manual_review: List[Dict], pending: List[Dict]):
        """Build markdown report header and summary with standardized structure."""
        # Calculate stats for header
        stats = self._calculate_scan_stats(validated + manual_review + pending)
        by_severity = self._count_by_severity(validated)

        # Header: Security Assessment Report
        lines.append("# Security Assessment Report\n")

        # Scan Metadata table
        lines.append("## Scan Metadata\n")
        lines.append("| Field | Value |")
        lines.append("|-------|-------|")
        lines.append(f"| **Target** | {self.target_url} |")
        lines.append(f"| **Scan ID** | {self.scan_id} |")
        lines.append(f"| **Date** | {datetime.now().strftime('%d %b %Y %H:%M')} |")
        lines.append(f"| **Tool Version** | BugTraceAI v{settings.VERSION} |")
        lines.append(f"| **Duration** | {stats.get('duration', 'N/A')} |")
        lines.append(f"| **URLs Scanned** | {stats.get('urls_scanned', 0)} |")
        lines.append("")

        # Executive Summary
        lines.append("## Executive Summary\n")

        # Findings by Severity table
        lines.append("### Findings by Severity\n")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        lines.append(f"| Critical | {by_severity.get('critical', 0)} |")
        lines.append(f"| High | {by_severity.get('high', 0)} |")
        lines.append(f"| Medium | {by_severity.get('medium', 0)} |")
        lines.append(f"| Low | {by_severity.get('low', 0)} |")
        lines.append(f"| Info | {by_severity.get('info', 0)} |")
        total_count = sum(by_severity.values())
        lines.append(f"| **Total** | **{total_count}** |")
        lines.append("")

        # Validation Summary table
        lines.append("### Validation Summary\n")
        lines.append("| Category | Count |")
        lines.append("|----------|-------|")
        lines.append(f"| Confirmed | {len(validated)} |")
        lines.append(f"| Manual Review | {len(manual_review)} |")

        # Count false positives and pending from all findings if available
        # For now, we'll use the pending list passed in
        false_positive_count = 0  # Not tracked in this method's params
        lines.append(f"| False Positives | {false_positive_count} |")
        lines.append(f"| Pending | {len(pending)} |")
        lines.append("")

    def _md_build_validated_findings(self, lines: List[str], validated: List[Dict]):
        """Build validated findings section of markdown report."""
        lines.append("---\n")
        lines.append("## Confirmed Vulnerabilities (Triager Ready)\n")

        if not validated:
            lines.append("*No confirmed vulnerabilities found.*\n")
            return

        # Sort by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        validated_sorted = sorted(validated, key=lambda x: severity_order.get((x.get("severity") or "MEDIUM").upper(), 5))

        for i, f in enumerate(validated_sorted, 1):
            self._md_build_finding_entry(lines, f, i)

    def _generate_standardized_finding(self, finding: Dict, index: int) -> str:
        """
        Generate a standardized finding entry using the finding template.

        Args:
            finding: Finding dictionary with all data
            index: Finding number (1-based)

        Returns:
            Formatted markdown string for the finding
        """
        # Load template
        template_path = Path(__file__).parent.parent / "reporting" / "templates" / "finding_template.md"
        try:
            with open(template_path, "r") as f:
                template = f.read()
        except FileNotFoundError:
            logger.warning(f"[{self.name}] Template not found, falling back to inline format")
            return self._md_build_finding_entry_inline(finding, index)

        # Extract finding data
        vuln_type = finding.get("type", "Unknown")
        severity = finding.get("severity", "MEDIUM")
        url = finding.get("url", "")
        parameter = finding.get("parameter", "")
        payload = finding.get("payload", "")
        description = finding.get("description", "")

        # Get CWE reference
        cwe_id = get_cwe_for_vuln(vuln_type) or "N/A"
        cwe_num = cwe_id.replace("CWE-", "") if cwe_id != "N/A" else "0"

        # Format CVE reference
        cve_raw = finding.get("cve")
        if cve_raw:
            try:
                cve_reference = f"[{format_cve(cve_raw)}](https://nvd.nist.gov/vuln/detail/{format_cve(cve_raw)})"
            except ValueError:
                cve_reference = "N/A"
        else:
            cve_reference = "N/A"

        # Get remediation (prefer from finding, fallback to standards)
        remediation = finding.get("remediation") or get_remediation_for_vuln(vuln_type)

        # Get impact
        impact = self._get_impact_for_type(vuln_type)

        # Format CVSS score
        cvss_score = finding.get("cvss_score")
        cvss_score_str = f"{cvss_score:.1f}" if cvss_score else "N/A"

        # Severity badge (emoji-based)
        severity_badges = {
            "CRITICAL": "🔴 CRITICAL",
            "HIGH": "🟠 HIGH",
            "MEDIUM": "🟡 MEDIUM",
            "LOW": "🔵 LOW",
            "INFO": "⚪ INFO"
        }
        severity_badge = severity_badges.get(severity, severity)

        # Status badge
        status_badge = "✅ CONFIRMED"

        # Build HTTP request (if available)
        http_request = self._generate_curl(finding)

        # Build HTTP response excerpt (first 500 chars of validator_notes or description)
        validator_notes = finding.get("validator_notes", "")
        http_response_excerpt = validator_notes[:500] if validator_notes else description[:500]

        # Screenshot section
        screenshot_section = ""
        if finding.get("screenshot_path"):
            img_name = Path(finding.get("screenshot_path")).name
            screenshot_section = f"**Screenshot:**\n\n![Evidence](captures/{img_name})"

        # Reproduction steps
        reproduction_steps_list = self._generate_reproduction_steps(finding)
        reproduction_steps = "\n".join(reproduction_steps_list)

        # Validation method label
        validation_method = self._extract_validation_method(finding)

        # Fill template
        filled = template.format(
            index=index,
            title=vuln_type,
            severity_badge=severity_badge,
            cwe_id=cwe_id,
            cwe_num=cwe_num,
            cve_reference=cve_reference,
            status_badge=status_badge,
            cvss_score=cvss_score_str,
            validation_method=validation_method,
            url=url,
            parameter=parameter,
            payload=payload,
            description=description,
            impact=impact,
            remediation=remediation,
            http_request=http_request,
            http_response_excerpt=http_response_excerpt,
            screenshot_section=screenshot_section,
            reproduction_steps=reproduction_steps
        )

        return filled

    def _md_build_finding_entry_inline(self, finding: Dict, index: int) -> str:
        """
        Fallback method to build finding entry inline (used when template not found).
        Returns markdown string instead of appending to lines list.
        """
        lines = []
        lines.append(f"### {index}. {finding.get('type', 'Unknown Vulnerability')}\n")
        lines.append(f"| Field | Value |")
        lines.append(f"|-------|-------|")
        lines.append(f"| **Severity** | {finding.get('severity', 'MEDIUM')} |")
        lines.append(f"| **Status** | ✅ CONFIRMED |")
        lines.append(f"| **Validation Method** | {self._extract_validation_method(finding)} |")
        lines.append(f"| **URL** | `{finding.get('url', '')}` |")
        lines.append(f"| **Parameter** | `{finding.get('parameter', '')}` |")
        if finding.get("db_type"):
            lines.append(f"| **DB Type** | {finding.get('db_type')} |")
        if finding.get("tamper_used"):
            lines.append(f"| **Tamper Script** | {finding.get('tamper_used')} |")
        lines.append("")

        # Steps to Reproduce (type-specific)
        lines.append("#### Steps to Reproduce\n")
        for step in self._generate_reproduction_steps(finding):
            lines.append(step)
        lines.append("")

        # PoC (Only for SQLi where we have SQLMap command)
        if "SQL" in finding.get("type", "").upper() and not self._generate_curl(finding).startswith("#"):
            lines.append("#### Proof of Concept\n")
            lines.append("```bash")
            lines.append(self._generate_curl(finding))
            lines.append("```\n")

        # Validator Notes
        if finding.get("validator_notes"):
            lines.append("#### Validation Notes\n")
            lines.append(f"> {finding.get('validator_notes')}\n")

        # Screenshot
        if finding.get("screenshot_path"):
            img_name = Path(finding.get("screenshot_path")).name
            lines.append(f"#### Screenshot\n")
            lines.append(f"![Evidence](captures/{img_name})\n")

        lines.append("---\n")
        return "\n".join(lines)

    def _md_build_finding_entry(self, lines: List[str], f: Dict, index: int):
        """Build a single finding entry in markdown report using standardized template."""
        # Use new standardized generation
        finding_md = self._generate_standardized_finding(f, index)
        lines.append(finding_md)

    def _md_build_manual_review(self, lines: List[str], manual_review: List[Dict]):
        """Build manual review section of markdown report."""
        if not manual_review:
            return

        lines.append("## Needs Manual Review\n")
        lines.append("> These findings have high AI confidence but could not be confirmed via browser automation.\n")

        for i, f in enumerate(manual_review, 1):
            lines.append(f"### MR-{i}. {f.get('type', 'Unknown')}\n")
            lines.append(f"- **URL:** `{f.get('url', '')}`")
            lines.append(f"- **Parameter:** `{f.get('parameter', '')}`")
            lines.append(f"- **Payload:** `{f.get('payload', '')}`")
            if f.get("validator_notes"):
                lines.append(f"- **AI Notes:** {f.get('validator_notes')}")
            lines.append("")

    def _copy_html_template(self) -> Path:
        """Copy the static HTML template that loads engagement_data.json."""
        # The HTML template location
        template_src = Path(__file__).parent.parent / "reporting" / "templates" / "report_dynamic.html"
        dest = self.output_dir / "report.html"

        if template_src.exists():
            shutil.copy(template_src, dest)
        else:
            # Create a minimal HTML if template doesn't exist
            self._create_minimal_html(dest)

        logger.info(f"[{self.name}] Copied report.html")
        return dest

    def _create_minimal_html(self, path: Path):
        """Create minimal HTML that loads JSON dynamically."""
        html = self._build_html_template()
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

    def _build_html_template(self) -> str:
        """
        Build HTML template string for dynamic report viewer.
        Note: HTML template strings >50 lines are acceptable per 08-03 decision.
        """
        return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BugTraceAI Report</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body { font-family: system-ui, sans-serif; background: #f8fafc; }
        .severity-critical { background: #991b1b; color: white; }
        .severity-high { background: #dc2626; color: white; }
        .severity-medium { background: #d97706; color: white; }
        .severity-low { background: #2563eb; color: white; }
        .severity-info { background: #059669; color: white; }
        pre { background: #1e293b; color: #e2e8f0; padding: 1rem; border-radius: 0.5rem; overflow-x: auto; }
    </style>
</head>
<body class="p-8">
    <div id="app" class="max-w-6xl mx-auto">
        <div class="text-center py-8">
            <p class="text-gray-500">Loading report...</p>
        </div>
    </div>

    <script>
        async function loadReport() {
            try {
                const response = await fetch('./engagement_data.json');
                const data = await response.json();
                renderReport(data);
            } catch (e) {
                document.getElementById('app').innerHTML =
                    '<p class="text-red-500">Error loading report: ' + e.message + '</p>';
            }
        }

        function renderReport(data) {
            const app = document.getElementById('app');

            let html = `
                <header class="mb-8">
                    <h1 class="text-3xl font-bold text-gray-900">Security Assessment Report</h1>
                    <p class="text-gray-600 mt-2">Target: ${data.meta.target}</p>
                    <p class="text-gray-500 text-sm">Scan ID: ${data.meta.scan_id} | Date: ${data.meta.scan_date}</p>
                </header>

                <section class="grid grid-cols-4 gap-4 mb-8">
                    <div class="bg-white p-4 rounded-lg shadow">
                        <p class="text-3xl font-bold text-green-600">${data.summary.validated}</p>
                        <p class="text-gray-600">Confirmed</p>
                    </div>
                    <div class="bg-white p-4 rounded-lg shadow">
                        <p class="text-3xl font-bold text-yellow-600">${data.summary.manual_review}</p>
                        <p class="text-gray-600">Manual Review</p>
                    </div>
                    <div class="bg-white p-4 rounded-lg shadow">
                        <p class="text-3xl font-bold text-red-600">${data.summary.false_positives}</p>
                        <p class="text-gray-600">False Positives</p>
                    </div>
                    <div class="bg-white p-4 rounded-lg shadow">
                        <p class="text-3xl font-bold text-gray-600">${data.summary.total_findings}</p>
                        <p class="text-gray-600">Total</p>
                    </div>
                </section>

                <section>
                    <h2 class="text-2xl font-bold mb-4">Confirmed Vulnerabilities</h2>
            `;

            if (data.findings.length === 0) {
                html += '<p class="text-gray-500">No confirmed vulnerabilities found.</p>';
            } else {
                data.findings.forEach((f, i) => {
                    const sevClass = 'severity-' + f.severity.toLowerCase();
                    html += `
                        <div class="bg-white rounded-lg shadow mb-4 overflow-hidden">
                            <div class="flex items-center justify-between p-4 border-b">
                                <h3 class="text-xl font-bold">${f.id}. ${f.type}</h3>
                                <span class="px-3 py-1 rounded text-sm font-bold ${sevClass}">${f.severity}</span>
                            </div>
                            <div class="p-4">
                                <p class="mb-2"><strong>URL:</strong> <code class="bg-gray-100 px-2 py-1 rounded">${f.url}</code></p>
                                <p class="mb-2"><strong>Parameter:</strong> <code class="bg-gray-100 px-2 py-1 rounded">${f.parameter}</code></p>
                                <p class="mb-4"><strong>Payload:</strong> <code class="bg-gray-100 px-2 py-1 rounded">${f.payload}</code></p>
                                ${f.db_type ? `<p class="mb-2"><strong>DB Type:</strong> <span class="bg-blue-100 text-blue-800 px-2 py-1 rounded">${f.db_type}</span></p>` : ''}
                                ${f.tamper_used ? `<p class="mb-2"><strong>Tamper Script:</strong> <code class="bg-gray-100 px-2 py-1 rounded">${f.tamper_used}</code></p>` : ''}

                                <h4 class="font-bold mt-4 mb-2">Steps to Reproduce</h4>
                                <ol class="list-decimal list-inside mb-4">
                                    ${f.reproduction.steps.map(s => '<li>' + s + '</li>').join('')}
                                </ol>

                                ${(f.reproduction.poc && !f.reproduction.poc.trim().startsWith('#')) ?
                                `<h4 class="font-bold mt-4 mb-2">Proof of Concept</h4>
                                <pre class="whitespace-pre-wrap">${f.reproduction.poc}</pre>` : ''}

                                ${f.exploitation_details ? '<div class="mt-4 p-4 bg-red-50 border-l-4 border-red-500 rounded"><h4 class="font-bold text-red-700 mb-2">🎯 Exploitation Details</h4><pre class="whitespace-pre-wrap text-sm text-gray-800">' + f.exploitation_details + '</pre></div>' : ''}

                                ${f.validation.notes ? '<p class="mt-4 text-gray-600"><strong>Validator Notes:</strong> ' + f.validation.notes + '</p>' : ''}
                                ${f.validation.screenshot ? '<img src="' + f.validation.screenshot + '" class="mt-4 rounded border" />' : ''}
                            </div>
                        </div>
                    `;
                });
            }

            html += '</section>';
            app.innerHTML = html;
        }

        loadReport();
    </script>
</body>
</html>'''

    def _copy_screenshots(self, findings: List[Dict], captures_dir: Path):
        """Copy all screenshots to the captures folder."""
        for f in findings:
            self._copy_single_screenshot(f, captures_dir)

    def _copy_single_screenshot(self, finding: Dict, captures_dir: Path):
        """Copy a single screenshot to captures directory."""
        src = finding.get("screenshot_path")
        if not src:
            return
        if not Path(src).exists():
            return

        try:
            shutil.copy(src, captures_dir / Path(src).name)
        except Exception as e:
            logger.debug(f"Could not copy screenshot {src}: {e}")

    def _generate_curl(self, finding: Dict) -> str:
        """
        Generate reproduction command for the finding.
        2026-01-24 FIX: Generate useful curl commands for ALL vuln types.
        """
        # Priority 1: Use specialist-provided reproduction command
        if finding.get("reproduction"):
            return finding.get("reproduction")

        # Priority 2: Generate command based on vuln type
        vuln_type = (finding.get("type") or "").upper()
        url = finding.get("url", "")
        param = finding.get("parameter", "")
        payload = finding.get("payload", "")

        if vuln_type in ["SQLI", "SQL"]:
            return self._curl_build_sqli(url, param)

        if vuln_type in ["CSTI", "SSTI"]:
            return self._curl_build_csti(url, param, payload)

        if vuln_type == "XSS":
            return self._curl_build_xss(url, param, payload)

        if vuln_type == "SSRF":
            return f"# SSRF: Use Burp Collaborator or webhook.site to test OOB callbacks\ncurl '{url}'"

        if vuln_type == "LFI":
            return self._curl_build_lfi(url, param)

        if vuln_type == "IDOR":
            return f"# IDOR: Test with different user IDs/values\ncurl '{url}'"

        return self._curl_build_fallback(url, param, payload)

    def _curl_build_sqli(self, url: str, param: str) -> str:
        """Build SQLi reproduction command."""
        if param:
            return f"sqlmap -u \"{url}\" -p {param} --batch --dbs"
        return f"sqlmap -u \"{url}\" --batch --dbs"

    def _curl_build_csti(self, url: str, param: str, payload: str) -> str:
        """Build CSTI/SSTI reproduction command."""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        default_payload = "{{7*7}}"
        test_payload = payload if payload else default_payload

        # Check if it's a header injection
        if param and param.startswith("HEADER:"):
            header_name = param.replace("HEADER:", "")
            return f"curl -H '{header_name}: {test_payload}' '{url}' | grep 49"
        elif param and param.startswith("POST:"):
            param_name = param.replace("POST:", "")
            return f"curl -X POST '{url}' -d '{param_name}={test_payload}' | grep 49"
        elif param and payload:
            # URL param injection
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            qs[param] = [payload]
            new_query = urlencode(qs, doseq=True)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', new_query, ''))
            return f"curl '{test_url}' | grep 49"
        return f"# CSTI on {url} - inject {{{{7*7}}}} in parameter {param}"

    def _curl_build_xss(self, url: str, param: str, payload: str) -> str:
        """Build XSS reproduction command."""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        if param and payload:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            qs[param] = [payload]
            new_query = urlencode(qs, doseq=True)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', new_query, ''))
            return f"# Open in browser to trigger XSS:\n{test_url}"
        elif payload:
            return f"# XSS Payload: {payload}\n# Inject in parameter: {param or 'unknown'}"
        return f"# XSS on {url} - test with <script>alert(1)</script> in {param or 'input fields'}"

    def _curl_build_lfi(self, url: str, param: str) -> str:
        """Build LFI reproduction command."""
        if param:
            return f"curl '{url}' --data-urlencode '{param}=../../../etc/passwd'"
        return f"# LFI on {url} - test with ../../etc/passwd"

    def _curl_build_fallback(self, url: str, param: str, payload: str) -> str:
        """Build fallback reproduction command."""
        if url and param:
            return f"# Vulnerable endpoint: {url}\n# Parameter: {param}\n# Payload: {payload or 'N/A'}"
        elif url:
            return f"# Vulnerable endpoint: {url}"
        else:
            return "# No reproduction command available"

    def _extract_validation_method(self, finding: Dict) -> str:
        """
        Extract and normalize validation method from findings.

        Maps various validation method indicators to standardized labels:
        - OOB (Interactsh): Out-of-band validation via Interactsh callbacks
        - HTTP Response Analysis: Server response analysis without browser
        - Playwright Browser: Full browser automation validation
        - CDP + Vision AI: Chrome DevTools Protocol with visual AI
        - SQLMap Automated: SQLMap tool validation
        - Template Engine: CSTI/SSTI template injection validation
        - Fuzzer Validation: Go fuzzer or similar tool validation

        Args:
            finding: Finding dictionary with validation data

        Returns:
            Standardized validation method label
        """
        # Extract raw method from multiple possible locations
        raw_method = finding.get("validation_method")
        if not raw_method:
            evidence = finding.get("evidence")
            if isinstance(evidence, dict):
                raw_method = evidence.get("validation_method")
        if not raw_method:
            raw_method = ""
        raw_method = str(raw_method).lower()

        # OOB-based validation (Interactsh callbacks)
        if "interactsh" in raw_method or "oob" in raw_method:
            return "OOB (Interactsh)"

        # HTTP response analysis (no browser needed)
        if "http" in raw_method or raw_method == "http_response_analysis":
            return "HTTP Response Analysis"

        # Playwright browser validation
        if "playwright" in raw_method or "browser" in raw_method:
            return "Playwright Browser"

        # CDP validation (Chrome DevTools Protocol)
        if finding.get("cdp_validated") or "cdp" in raw_method or "vision" in raw_method:
            return "CDP + Vision AI"

        # SQLMap validation
        if "sqlmap" in raw_method:
            return "SQLMap Automated"

        # Template-specific (CSTI)
        template_engines = ["jinja", "twig", "freemarker", "velocity", "mako", "smarty"]
        if raw_method and any(engine in raw_method for engine in template_engines):
            return f"Template Engine ({raw_method.title()})"

        # Fuzzer-based
        if "fuzzer" in raw_method:
            return "Fuzzer Validation"

        # Fallback based on vuln type
        vuln_type = (finding.get("type") or "").upper()
        if vuln_type in ["SQLI", "SQL"]:
            return "SQLMap/Error Detection"
        if vuln_type == "XSS":
            return "HTTP/Playwright"

        return raw_method.title() if raw_method else "Automated Check"

    def _get_validation_method(self, finding: Dict) -> str:
        """
        Get validation method based on finding.
        Delegates to _extract_validation_method for consistent extraction.
        """
        return self._extract_validation_method(finding)
    
    def _get_validation_notes(self, finding: Dict) -> str:
        """Generate detailed validation notes based on finding type."""
        vuln_type = finding.get("type", "").upper()
        
        if vuln_type in ["SQLI", "SQLi"]:
            # Build SQLMap validation details
            notes = []
            notes.append("**SQLMap Validation Results:**")
            
            if finding.get("db_type"):
                notes.append(f"- Database Type: {finding.get('db_type')}")
            
            if finding.get("payload"):
                notes.append(f"- Injection Technique: {finding.get('payload')}")
            
            if finding.get("tamper_used"):
                notes.append(f"- WAF Bypass: {finding.get('tamper_used')}")  
            
            if finding.get("confidence"):
                notes.append(f"- Confidence: {finding.get('confidence')*100:.0f}%")
            
            if finding.get("evidence"):
                notes.append(f"\n**Evidence:**\n```\n{finding.get('evidence')[:200]}...\n```")
            
            return "\n".join(notes)
        else:
            # Default notes
            return finding.get("validator_notes", "Confirmed by specialist agent (CDP not required)")

    def _generate_reproduction_steps(self, finding: Dict) -> List[str]:
        """
        Generate detailed, triager-ready reproduction steps based on vulnerability type.
        These steps tell the triager EXACTLY what to do and what to observe.
        """
        vuln_type = (finding.get("type") or "").upper()

        if vuln_type == "XXE":
            return self._build_xxe_steps(finding)

        if vuln_type in ["SQLI", "SQL_INJECTION"]:
            return self._build_sqli_steps(finding)

        if vuln_type in ["XSS", "STORED_XSS", "REFLECTED_XSS"]:
            return self._build_xss_steps(finding)

        if vuln_type == "SSRF":
            return self._build_ssrf_steps(finding)

        if vuln_type in ["CSRF", "SECURITY_MISCONFIGURATION"]:
            return self._build_csrf_steps(finding)

        if vuln_type == "OPEN_REDIRECT":
            return self._build_open_redirect_steps(finding)

        return self._build_generic_steps(finding)

    def _build_xxe_steps(self, finding: Dict) -> List[str]:
        """Build reproduction steps for XXE vulnerabilities."""
        from urllib.parse import urlparse
        url = finding.get("url", "")
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        post_endpoint = f"{base_url}/catalog/product/stock"

        return [
            f"1. Navigate to the product page: {url}",
            "2. Open browser DevTools (F12) → Network tab",
            "3. Click the 'Check stock' button to observe the normal XML request",
            f"4. Intercept the POST request to: {post_endpoint}",
            "5. Replace the XML body with the malicious payload containing the XXE entity",
            "6. Forward the request and observe the out-of-band callback on your server",
            "7. **Expected Result:** Your OOB server receives a DNS/HTTP callback from the target server"
        ]

    def _build_sqli_steps(self, finding: Dict) -> List[str]:
        """Build reproduction steps for SQLi vulnerabilities."""
        url = finding.get("url", "")
        param = finding.get("parameter", "")
        payload = finding.get("payload", "")

        is_time_based = any(kw in payload.lower() for kw in ["sleep", "benchmark", "pg_sleep", "waitfor", "delay"])
        is_error_based = any(kw in payload.lower() for kw in ["cast", "convert", "extractvalue", "updatexml"])

        if is_time_based:
            return [
                f"1. Navigate to: {url}",
                f"2. Locate the `{param}` parameter in the URL/form",
                f"3. Inject the time-based payload: `{payload}`",
                "4. Submit the request and start a timer",
                "5. **Expected Result:** Response takes 5+ seconds (indicating SQL SLEEP executed)",
                "6. Compare with normal request time (should be <1 second)",
                "7. Difference in response time confirms blind SQL injection"
            ]
        elif is_error_based:
            return [
                f"1. Navigate to: {url}",
                f"2. Locate the `{param}` parameter",
                f"3. Inject the error-based payload: `{payload}`",
                "4. Submit the request",
                "5. **Expected Result:** Response contains database data in error message",
                "6. Look for extracted values (usernames, passwords, etc.) in the error output"
            ]
        else:
            return [
                f"1. Navigate to: {url}",
                f"2. Locate the `{param}` parameter",
                f"3. Inject the payload: `{payload}`",
                "4. Submit the request",
                "5. **Expected Result:** SQL error message or altered response indicating injection",
                f"6. For further exploitation, use SQLMap: `sqlmap -u \"{url}\" -p {param} --batch`"
            ]

    def _build_xss_steps(self, finding: Dict) -> List[str]:
        """Build reproduction steps for XSS vulnerabilities."""
        return [
            f"1. Copy the full exploit URL with payload",
            f"2. Open a new browser window/incognito session",
            f"3. Paste the URL and navigate to it",
            "4. **Expected Result:** JavaScript alert box appears OR payload executes in DOM",
            f"5. Open DevTools Console (F12) to verify payload execution",
            "6. For stored XSS: Navigate to where the payload is stored and verify execution",
            "7. Screenshot the alert/execution as proof"
        ]

    def _build_ssrf_steps(self, finding: Dict) -> List[str]:
        """Build reproduction steps for SSRF vulnerabilities."""
        url = finding.get("url", "")
        param = finding.get("parameter", "")

        return [
            f"1. Set up an out-of-band callback server (Burp Collaborator, interactsh, or webhook.site)",
            f"2. Navigate to: {url}",
            f"3. Locate the `{param}` parameter",
            f"4. Inject your callback URL as the payload",
            "5. Submit the request",
            "6. **Expected Result:** Your callback server receives a request from the target server",
            "7. For internal network access, try: http://169.254.169.254/latest/meta-data/ (AWS metadata)"
        ]

    def _build_csrf_steps(self, finding: Dict) -> List[str]:
        """Build reproduction steps for CSRF vulnerabilities."""
        return [
            "1. Save the HTML PoC form to a local file (csrf_poc.html)",
            "2. Log into the target application in your browser",
            "3. Open the csrf_poc.html file in the same browser (file:// or hosted)",
            "4. The form will auto-submit after 1 second",
            "5. **Expected Result:** Action is performed without user consent (e.g., item added to cart)",
            "6. Check the target application to verify the unauthorized action occurred"
        ]

    def _build_open_redirect_steps(self, finding: Dict) -> List[str]:
        """Build reproduction steps for Open Redirect vulnerabilities."""
        return [
            f"1. Copy the exploit URL with the redirect parameter",
            "2. Open a new browser window",
            "3. Paste and navigate to the URL",
            "4. **Expected Result:** Browser redirects to the external attacker domain",
            "5. Check the address bar to confirm redirection occurred",
            "6. This can be used for phishing: redirect users to fake login pages"
        ]

    def _build_generic_steps(self, finding: Dict) -> List[str]:
        """Build generic reproduction steps for unknown vulnerability types."""
        url = finding.get("url", "")
        param = finding.get("parameter", "")
        payload = finding.get("payload", "")

        return [
            f"1. Navigate to: {url}",
            f"2. Locate the vulnerable parameter: `{param}`",
            f"3. Inject the payload: `{payload}`",
            "4. Submit the request",
            "5. Observe the application response for vulnerability indicators",
            "6. Document any security-relevant behavior"
        ]

    def _get_impact_for_type(self, vuln_type: str) -> str:
        """Get standard impact description for vulnerability type."""
        impacts = {
            "XSS": "Cross-Site Scripting can lead to session hijacking, credential theft, defacement, and malware distribution.",
            "SQLI": "SQL Injection can lead to unauthorized data access, data manipulation, and complete database compromise.",
            "SQLi": "SQL Injection can lead to unauthorized data access, data manipulation, and complete database compromise.",
            "LFI": "Local File Inclusion can expose sensitive files and potentially lead to remote code execution.",
            "RCE": "Remote Code Execution allows attackers to run arbitrary commands on the server.",
            "SSRF": "Server-Side Request Forgery can expose internal services and sensitive data.",
            "IDOR": "Insecure Direct Object Reference can lead to unauthorized access to other users' data.",
        }
        return impacts.get(vuln_type.upper(), "This vulnerability may compromise the security of the application.")


    async def _enrich_findings_batch(self, findings: List[Dict]):
        """
        Enrich a batch of findings with CVSS scores and professional PoC using LLM.
        """
        if not findings:
            return

        logger.info(f"[{self.name}] Enriching {len(findings)} findings with CVSS/Severity analysis...")

        # Phase 1: CVSS Scoring
        cvss_tasks = [self._calculate_cvss(f) for f in findings]
        await asyncio.gather(*cvss_tasks)

        # Phase 2: Professional PoC Enrichment (for final report quality)
        logger.info(f"[{self.name}] Generating professional PoC for {len(findings)} findings...")
        poc_tasks = [self._enrich_poc_with_llm(f) for f in findings]
        await asyncio.gather(*poc_tasks)

    async def _enrich_poc_with_llm(self, finding: Dict):
        """
        Use LLM to generate professional, triager-ready exploitation explanation AND detailed reproduction steps.
        This adds detailed context that makes reports stand out on bug bounty platforms.
        """
        try:
            context = self._poc_prepare_context(finding)
            prompt = self._poc_build_prompt(context)
            response = await self._poc_execute_llm(prompt)

            if response:
                self._poc_parse_response(finding, response)

        except Exception as e:
            logger.debug(f"[{self.name}] Exploitation enrichment skipped for {finding.get('id')}: {e}")

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
            "type_context": self._get_type_specific_context(vuln_type)
        }

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

    async def _poc_execute_llm(self, prompt: str) -> Optional[str]:
        """Execute LLM call for PoC enrichment."""
        return await llm_client.generate(
            prompt,
            module_name="Reporting-Exploitation",
            model_override="deepseek/deepseek-chat",
            temperature=0.4  # Slightly higher for more descriptive steps
        )

    def _poc_parse_response(self, finding: Dict, response: str):
        """Parse PoC enrichment response and update finding."""
        content = response.strip()
        finding["exploitation_details"] = content

        # Extract Reproduction Steps for structured usage
        steps_match = re.search(r"## Reproduction Steps\s*(.*?)(?:$|##)", content, re.DOTALL)
        if steps_match:
            raw_steps = steps_match.group(1).strip()
            # Split by lines starting with numbers or bullet points
            steps_list = [line.strip() for line in raw_steps.split('\n') if line.strip()]
            if steps_list:
                finding["llm_reproduction_steps"] = steps_list

    def _get_type_specific_context(self, vuln_type: str) -> str:
        """Get type-specific context for LLM prompt."""
        contexts = {
            "SQLI": """**SQLi-Specific Context:**
- This is a SQL Injection vulnerability
- Consider: Data exfiltration, authentication bypass, privilege escalation
- Think about what tables might exist (users, orders, payments, admin)
- Mention specific SQLMap flags or techniques if relevant""",

            "XSS": """**XSS-Specific Context:**
- This is a Cross-Site Scripting vulnerability
- Consider: Session hijacking, credential theft, keylogging, defacement
- Think about the impact if this executes in an admin's browser
- Mention if it's reflected, stored, or DOM-based""",

            "XXE": """**XXE-Specific Context:**
- This is an XML External Entity vulnerability
- Consider: File disclosure (/etc/passwd, application configs), SSRF, DoS
- Think about what sensitive files might be accessible
- Mention the ability to exfiltrate data via out-of-band channels""",

            "SSRF": """**SSRF-Specific Context:**
- This is a Server-Side Request Forgery vulnerability
- Consider: Internal network access, cloud metadata (169.254.169.254), port scanning
- Think about internal services (databases, admin panels, APIs)
- Mention AWS/GCP/Azure metadata endpoints if cloud-hosted""",

            "CSTI": """**CSTI-Specific Context:**
- This is a Client-Side Template Injection vulnerability
- Consider: XSS via template expressions, data exfiltration
- Think about the frontend framework (Angular, Vue, React)
- Mention the ability to execute arbitrary JavaScript""",

            "IDOR": """**IDOR-Specific Context:**
- This is an Insecure Direct Object Reference vulnerability
- Consider: Access to other users' data, horizontal privilege escalation
- Think about what resources can be accessed (profiles, orders, files)
- Mention the predictability of object IDs"""
        }
        return contexts.get(vuln_type.upper(), "**Context:** This is a confirmed security vulnerability. Explain the real-world impact.")

    async def _calculate_cvss(self, f: Dict):
        """
        Query LLM to calculate CVSS v3.1 score and severity.
        Updates the finding dictionary in-place.
        """
        try:
            prompt = self._cvss_build_prompt(f)
            response = await self._cvss_execute_llm(prompt)

            if response:
                data = self._cvss_parse_response(response)
                if data:
                    self._cvss_update_finding(f, data)

        except Exception as e:
            logger.warning(f"[{self.name}] Failed to enrich finding {f.get('id')}: {e}")

    def _cvss_build_prompt(self, f: Dict) -> str:
        """Build CVSS calculation prompt for LLM."""
        return f"""
            You are a Senior Penetration Testing Expert analyzing a confirmed security vulnerability.

            **Vulnerability Details:**
            - Type: {f.get('type')}
            - Description: {f.get('description')}
            - URL: {f.get('url')}
            - Parameter: {f.get('parameter')}
            - Payload: {f.get('payload')}

            **Your Task:**
            1. Calculate the CVSS v3.1 Vector String (e.g., CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
            2. Calculate the Base Score (0.0-10.0) based on the vector
            3. Assign Severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)
            4. Write a DETAILED technical rationale explaining:
               - Why this vulnerability is exploitable
               - The complete exploitation path (step-by-step)
               - Real-world impact scenarios
               - Why each CVSS metric was chosen
            5. If this matches a known CVE, provide it

            **CRITICAL: SEVERITY CALIBRATION GUIDELINES**
            Be REALISTIC with scoring - not everything is CRITICAL. Use these guidelines:

            - **CRITICAL (9.0-10.0)**: Remote Code Execution, SQL Injection with full DB access, Authentication Bypass
            - **HIGH (7.0-8.9)**: Stored XSS, SSRF with internal network access, XXE with file read, CSTI/SSTI
            - **MEDIUM (4.0-6.9)**: Reflected XSS, CSRF, Information Disclosure, Open Redirect, XXE (DoS only)
            - **LOW (0.1-3.9)**: Security Misconfigurations, Minor info leaks

            **Scoring Examples:**
            - SQLi (UNION-based, data exfiltration): CRITICAL 9.8
            - Stored XSS (session hijacking): HIGH 8.0-8.5
            - Reflected XSS (requires user interaction): MEDIUM 6.0-7.0
            - XXE (file read): HIGH 7.5-8.0
            - SSRF (internal network): HIGH 7.0-8.0
            - Open Redirect: MEDIUM 4.0-6.0

            **Important:**
            - Be TECHNICAL and DETAILED - this is for professional pentesters
            - Explain the FULL exploitation chain, not just "attacker can execute code"
            - Include specific attack vectors and post-exploitation scenarios
            - Don't hold back on technical details - this is authorized security testing

            Output STRICT JSON ONLY (no markdown):
            {{
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "score": 9.8,
                "severity": "CRITICAL",
                "rationale": "Detailed 3-4 sentence technical explanation of exploitation path and impact...",
                "cve": "CVE-XXXX-XXXX" or null
            }}
            """

    async def _cvss_execute_llm(self, prompt: str) -> Optional[str]:
        """Execute LLM call for CVSS calculation."""
        # Use DeepSeek for detailed, uncensored security analysis
        # Gemini is too conservative and avoids explaining exploitation paths
        return await llm_client.generate(
            prompt,
            module_name="Reporting-CVSS",
            model_override="deepseek/deepseek-chat",  # DeepSeek Chat (uncensored)
            temperature=0.3  # Higher temp for more creative/detailed explanations
        )

    def _cvss_parse_response(self, response: str) -> Optional[Dict]:
        """Parse LLM response and extract CVSS data."""
        # Extract JSON from potential markdown blocks
        json_match = re.search(r'\{.*\}', response, re.DOTALL)
        if json_match:
            return json.loads(json_match.group(0))
        return None

    def _cvss_update_finding(self, f: Dict, data: Dict):
        """Update finding with CVSS data."""
        # Update finding
        f['severity'] = data.get('severity', f.get('severity')).upper()
        f['cvss_score'] = data.get('score')
        f['cvss_vector'] = data.get('vector')
        f['cve'] = data.get('cve')
        f['cvss_rationale'] = data.get('rationale')

        # Append rationale to description or notes
        rationale = data.get('rationale', '')
        cve = data.get('cve')

        enrichment_text = f"\n\n**CVSS Analysis**:\n- **Severity**: {f['severity']} ({f['cvss_score']})\n- **Vector**: `{f['cvss_vector']}`\n- **Rationale**: {rationale}"
        if cve:
            enrichment_text += f"\n- **Potential CVE**: [{cve}](https://nvd.nist.gov/vuln/detail/{cve})"

        # Append to validator_notes instead of overwriting description to keep original clean
        if f.get('validator_notes'):
            f['validator_notes'] += enrichment_text
        else:
            f['validator_notes'] = enrichment_text.strip()

    def _get_remediation_for_type(self, vuln_type: str) -> str:
        """
        Get standard remediation for vulnerability type.
        Delegates to centralized standards module for consistency.
        """
        return get_remediation_for_vuln(vuln_type)

    def _get_cwe_for_type(self, vuln_type: str) -> str:
        """
        Get CWE reference for vulnerability type.
        Delegates to centralized standards module.
        """
        return get_cwe_for_vuln(vuln_type) or "N/A"

    def _write_raw_markdown(self, findings: List[Dict]) -> Path:
        """Write raw findings to a markdown file (Pre-Audit)."""
        path = self.output_dir / "raw_findings.md"
        
        lines = []
        lines.append(f"# Raw Findings (Pre-Audit): {self.target_url}\n")
        lines.append(f"**Scan ID:** {self.scan_id}")
        lines.append(f"**Date:** {datetime.now().strftime('%d %b %Y %H:%M')}")
        lines.append(f"**Total Findings:** {len(findings)}\n")
        lines.append("---\n")

        for i, f in enumerate(findings, 1):
            lines.append(f"### {i}. {f.get('type')} on {f.get('parameter', 'unknown')}\n")
            lines.append(f"- **URL:** `{f.get('url')}`")
            lines.append(f"- **Payload:** `{f.get('payload')}`")
            lines.append(f"- **Description:** {f.get('description')}\n")
            lines.append("---\n")

        with open(path, "w", encoding="utf-8") as file:
            file.write("\n".join(lines))
        
        logger.info(f"[{self.name}] Wrote raw_findings.md")
        return path

    def _write_validated_markdown(self, validated: List[Dict], manual_review: List[Dict]) -> Path:
        """Write validated findings to a markdown file (Post-Audit)."""
        path = self.output_dir / "validated_findings.md"
        
        lines = []
        lines.append(f"# Validated Findings (Post-Audit): {self.target_url}\n")
        lines.append(f"**Scan ID:** {self.scan_id}")
        lines.append(f"**Date:** {datetime.now().strftime('%d %b %Y %H:%M')}")
        lines.append(f"**Confirmed:** {len(validated)} | **Manual Review:** {len(manual_review)}\n")
        lines.append("---\n")

        # Confirmed Section
        if validated:
            lines.append("## ✅ Confirmed Vulnerabilities\n")
            for i, f in enumerate(validated, 1):
                lines.append(f"### C-{i}. {f.get('type')}\n")
                lines.append(f"**Severity:** {f.get('severity')}\n")
                lines.append(f"**URL:** `{f.get('url')}`\n")
                lines.append(f"**Parameter:** `{f.get('parameter')}`\n")
                lines.append(f"**PoC:**\n```bash\n{self._generate_curl(f)}\n```\n")
                if f.get("validator_notes"):
                    lines.append(f"**Validation Notes:**\n> {f.get('validator_notes')}\n")
                lines.append("---\n")
        
        # Manual Review Section
        if manual_review:
            lines.append("## ⚠️ Needs Manual Review\n")
            for i, f in enumerate(manual_review, 1):
                lines.append(f"### M-{i}. {f.get('type')}\n")
                lines.append(f"**URL:** `{f.get('url')}`\n")
                lines.append(f"**Parameter:** `{f.get('parameter')}`\n")
                lines.append(f"**Payload:** `{f.get('payload')}`\n")
                lines.append(f"**Why Review:** {f.get('validator_notes')}\n")
                lines.append("---\n")

        with open(path, "w", encoding="utf-8") as file:
            file.write("\n".join(lines))
        
        logger.info(f"[{self.name}] Wrote validated_findings.md")
        return path

    def _generate_finding_markdown(self, f: Dict, index: int) -> str:
        """Generate the markdown block for a single finding (for copy-paste)."""
        md = []
        md.append(f"### {index}. {f.get('type')}")
        md.append(f"**Severity:** {f.get('severity')}")
        md.append(f"**URL:** `{f.get('url')}`")
        md.append(f"**Parameter:** `{f.get('parameter')}`")
        if f.get("db_type"):
            md.append(f"**DB Type:** {f.get('db_type')}")
        if f.get("tamper_used"):
            md.append(f"**Tamper Script:** {f.get('tamper_used')}")
        md.append("")
        md.append("#### Steps to Reproduce")
        for step in self._generate_reproduction_steps(f):
            md.append(step)
        md.append("")
        if "SQL" in f.get("type", "").upper() and not self._generate_curl(f).startswith("#"):
            md.append("#### Proof of Concept")
            md.append("```bash")
            md.append(self._generate_curl(f))
            md.append("```")
        return "\\n".join(md)
