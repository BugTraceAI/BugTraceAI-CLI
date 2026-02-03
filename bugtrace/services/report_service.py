"""
Report Service - Multi-format report generation and retrieval.

Wraps existing report generators (HTMLGenerator, MarkdownGenerator) to provide
API-friendly access for CLI, API, and MCP interfaces.

Solves:
- SVC-03: ReportService for multi-format report generation

Author: BugtraceAI Team
Date: 2026-01-27
Version: 2.0.0
"""

import json
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime

from bugtrace.core.database import get_db_manager
from bugtrace.reporting.generator import HTMLGenerator
from bugtrace.reporting.markdown_generator import MarkdownGenerator
from bugtrace.reporting.collector import DataCollector
from bugtrace.reporting.models import ReportContext, Finding, Severity, FindingType
from bugtrace.core.config import settings
from bugtrace.utils.logger import get_logger
from bugtrace.schemas.db_models import FindingTable

logger = get_logger("services.report_service")


class ReportService:
    """
    Multi-format report generation and retrieval service.

    Supports:
    - HTML reports (static viewer with engagement_data.js)
    - Markdown reports (technical + executive summary)
    - JSON reports (raw engagement data)

    Key methods:
    - generate_report(scan_id, format): Generate report for a scan
    - get_report(scan_id, format): Get existing report or generate if missing
    - get_report_path(scan_id, format): Find existing report file path
    """

    def __init__(self):
        """Initialize ReportService with database connection."""
        self.db = get_db_manager()
        self.html_generator = HTMLGenerator()
        self.markdown_generator = MarkdownGenerator(output_base_dir=str(settings.REPORT_DIR))

        logger.info("ReportService initialized")

    def generate_report(self, scan_id: int, format: str = "html") -> str:
        """
        Generate a report for a scan in the specified format.

        Args:
            scan_id: Scan ID to generate report for
            format: Report format (html, markdown, json)

        Returns:
            str: Path to generated report file or directory

        Raises:
            ValueError: If scan not found or format invalid
        """
        format = format.lower()

        if format not in ["html", "markdown", "json"]:
            raise ValueError(f"Invalid report format: {format}. Must be html, markdown, or json")

        # Get scan info
        with self.db.get_session() as session:
            from sqlmodel import select
            from bugtrace.schemas.db_models import ScanTable, TargetTable

            statement = select(ScanTable).where(ScanTable.id == scan_id)
            scan = session.exec(statement).first()

            if not scan:
                raise ValueError(f"Scan {scan_id} not found")

            target = session.get(TargetTable, scan.target_id)
            target_url = target.url if target else "unknown"

        # Build ReportContext using DataCollector
        context = self._build_report_context(scan_id, target_url)

        # Generate report based on format
        if format == "html":
            return self._generate_html_report(context, scan_id)
        elif format == "markdown":
            return self._generate_markdown_report(context, scan_id)
        elif format == "json":
            return self._generate_json_report(context, scan_id)

    def _build_report_context(self, scan_id: int, target_url: str) -> ReportContext:
        """
        Build ReportContext from database findings.

        Args:
            scan_id: Scan ID
            target_url: Target URL

        Returns:
            ReportContext populated with findings
        """
        # Initialize DataCollector
        collector = DataCollector(target_url=target_url, scan_id=scan_id)

        # Get findings from database
        findings = self.db.get_findings_for_scan(scan_id)

        # Convert FindingTable to dict format expected by DataCollector
        for finding_table in findings:
            finding_dict = self._finding_table_to_dict(finding_table)
            collector.add_vulnerability(finding_dict)

        # Get the built context
        context = collector.context

        # Update stats
        context.stats.vulns_found = len([
            f for f in context.findings
            if f.severity != Severity.INFO
        ])
        context.stats.validated_findings = len([f for f in context.findings if f.validated])

        logger.info(f"Built report context for scan {scan_id}: {len(context.findings)} findings")

        return context

    def _finding_table_to_dict(self, finding: FindingTable) -> Dict[str, Any]:
        """
        Convert FindingTable to dictionary format expected by DataCollector.

        Args:
            finding: FindingTable instance

        Returns:
            Dictionary with finding data
        """
        return {
            "type": finding.type.value if hasattr(finding.type, 'value') else str(finding.type),
            "severity": finding.severity,
            "description": finding.details or "No description available",
            "payload": finding.payload_used,
            "url": finding.attack_url,
            "parameter": finding.vuln_parameter,
            "validated": finding.visual_validated,
            "confidence_score": finding.confidence_score,
            "screenshot_path": finding.proof_screenshot_path,
            "reproduction_command": finding.reproduction_command,
            "status": finding.status.value,
        }

    def _generate_html_report(self, context: ReportContext, scan_id: int) -> str:
        """
        Generate HTML report.

        Args:
            context: ReportContext
            scan_id: Scan ID for file naming

        Returns:
            Path to generated HTML file

        Raises:
            RuntimeError: If engagement_data.js cannot be generated (JSON serialization or I/O error)
        """
        # Create scan-specific report directory
        report_dir = settings.REPORT_DIR / f"scan_{scan_id}"
        report_dir.mkdir(parents=True, exist_ok=True)

        output_path = report_dir / "report.html"

        # First, write engagement_data.js with validation
        data_js_path = report_dir / "engagement_data.js"

        try:
            json_content = context.model_dump_json(indent=4)
        except Exception as e:
            logger.error(f"Failed to serialize ReportContext to JSON for scan {scan_id}: {e}")
            raise RuntimeError(f"engagement_data.js generation failed: JSON serialization error: {e}")

        # Validate JSON content before writing
        if not json_content or len(json_content) < 50:
            logger.error(f"Invalid JSON content generated for scan {scan_id} (length={len(json_content) if json_content else 0})")
            raise RuntimeError("engagement_data.js generation failed: invalid JSON content")

        with open(data_js_path, 'w', encoding='utf-8') as f:
            f.write(f"window.BUGTRACE_REPORT_DATA = {json_content};")

        # Validate file was written correctly
        if not data_js_path.exists() or data_js_path.stat().st_size < 100:
            logger.error(f"engagement_data.js not written correctly for scan {scan_id}")
            raise RuntimeError("engagement_data.js generation failed: file not written correctly")

        # Generate HTML (copies report_viewer.html template)
        self.html_generator.generate(context, str(output_path))

        logger.info(f"Generated HTML report for scan {scan_id}: {output_path}")
        return str(output_path)

    def _generate_markdown_report(self, context: ReportContext, scan_id: int) -> str:
        """
        Generate Markdown report.

        Args:
            context: ReportContext
            scan_id: Scan ID for file naming

        Returns:
            Path to generated report directory
        """
        # MarkdownGenerator creates its own directory structure
        report_dir = self.markdown_generator.generate(context)

        logger.info(f"Generated Markdown report for scan {scan_id}: {report_dir}")
        return report_dir

    def _generate_json_report(self, context: ReportContext, scan_id: int) -> str:
        """
        Generate JSON report.

        Args:
            context: ReportContext
            scan_id: Scan ID for file naming

        Returns:
            Path to generated JSON file
        """
        # Create scan-specific report directory
        report_dir = settings.REPORT_DIR / f"scan_{scan_id}"
        report_dir.mkdir(parents=True, exist_ok=True)

        output_path = report_dir / "engagement_data.json"

        # Write JSON
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(context.model_dump_json(indent=4))

        logger.info(f"Generated JSON report for scan {scan_id}: {output_path}")
        return str(output_path)

    def get_report(self, scan_id: int, format: str = "html") -> Optional[bytes]:
        """
        Get report bytes for a scan (generate if doesn't exist).

        Args:
            scan_id: Scan ID
            format: Report format (html, markdown, json)

        Returns:
            Report file bytes, or None if format is markdown (directory)

        Note:
            For markdown format, returns None since it's a directory.
            Use get_report_path() to get the directory path.
        """
        format = format.lower()

        # Check if report exists
        report_path = self.get_report_path(scan_id, format)

        if not report_path:
            # Generate report
            logger.info(f"Report not found for scan {scan_id} ({format}), generating...")
            report_path = self.generate_report(scan_id, format)

        # Return bytes for single files (html, json)
        if format in ["html", "json"]:
            path_obj = Path(report_path)
            if path_obj.is_file():
                return path_obj.read_bytes()
            else:
                # For HTML, look for report.html in directory
                html_file = path_obj / "report.html"
                if html_file.exists():
                    return html_file.read_bytes()
                logger.error(f"Report file not found: {report_path}")
                return None

        # For markdown (directory), return None
        return None

    def get_report_path(self, scan_id: int, format: str = "html") -> Optional[str]:
        """
        Find existing report file path for a scan.

        Args:
            scan_id: Scan ID
            format: Report format (html, markdown, json)

        Returns:
            Path to report file or directory, or None if not found
        """
        format = format.lower()
        report_dir = settings.REPORT_DIR / f"scan_{scan_id}"

        if not report_dir.exists():
            return None

        return self._find_report_by_format(scan_id, format, report_dir)

    def _find_report_by_format(
        self, scan_id: int, format: str, report_dir: Path
    ) -> Optional[str]:
        """Find report file by format type."""
        if format == "html":
            return self._find_html_report(report_dir)
        if format == "json":
            return self._find_json_report(report_dir)
        if format == "markdown":
            return self._find_markdown_report(scan_id)
        return None

    def _find_html_report(self, report_dir: Path) -> Optional[str]:
        """Find HTML report file."""
        html_file = report_dir / "report.html"
        if html_file.exists():
            return str(html_file)
        return None

    def _find_json_report(self, report_dir: Path) -> Optional[str]:
        """Find JSON report file."""
        json_file = report_dir / "engagement_data.json"
        if json_file.exists():
            return str(json_file)
        return None

    def _find_markdown_report(self, scan_id: int) -> Optional[str]:
        """Find markdown report directory."""
        for md_dir in settings.REPORT_DIR.glob(f"report_*_{scan_id}_*"):
            if (md_dir / "technical_report.md").exists():
                return str(md_dir)
        return None

    def list_reports(self, scan_id: int) -> Dict[str, Any]:
        """
        List available reports for a scan.

        Args:
            scan_id: Scan ID

        Returns:
            Dictionary with available report formats and paths
        """
        available = {}

        for format in ["html", "json", "markdown"]:
            path = self.get_report_path(scan_id, format)
            if path:
                available[format] = path

        return {
            "scan_id": scan_id,
            "available_formats": list(available.keys()),
            "paths": available,
        }
