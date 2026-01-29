"""
Summary generation for scan findings.

Provides aggregated views of findings by severity, type, and validation status.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from datetime import datetime
import json
from rich.table import Table
from rich.console import Console


@dataclass
class ScanSummary:
    """Summary of scan results with aggregated metrics."""
    scan_id: int
    target_url: str
    scan_date: datetime
    status: str

    # Severity counts
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    total: int = 0

    # By agent/type breakdown
    by_type: Dict[str, int] = field(default_factory=dict)

    # Validation summary
    validated: int = 0
    manual_review: int = 0
    false_positive: int = 0
    pending: int = 0


def generate_scan_summary(scan_id: Optional[int] = None, target_url: Optional[str] = None) -> ScanSummary:
    """
    Generate aggregated summary for a scan.

    Args:
        scan_id: Specific scan ID (takes priority)
        target_url: Target URL (uses latest scan for this target)

    Returns:
        ScanSummary with aggregated findings data

    Raises:
        ValueError: If no scans found or scan doesn't exist
    """
    from bugtrace.core.database import get_db_manager
    from bugtrace.schemas.db_models import FindingStatus

    db = get_db_manager()

    # Resolve scan_id
    if scan_id is None:
        if target_url:
            scan_id = db.get_latest_scan_id(target_url)
        else:
            scan_id = db.get_most_recent_scan_id()

    if scan_id is None:
        raise ValueError("No scans found. Run a scan first.")

    # Get scan info
    scan_info = db.get_scan_info(scan_id)
    if scan_info is None:
        raise ValueError(f"Scan {scan_id} not found.")

    # Get findings
    findings = db.get_findings_for_scan(scan_id)

    summary = ScanSummary(
        scan_id=scan_id,
        target_url=scan_info.target_url,
        scan_date=scan_info.timestamp,
        status=scan_info.status.value,
    )

    # Count by severity
    for f in findings:
        sev = (f.severity or "INFO").upper()
        if sev == "CRITICAL":
            summary.critical += 1
        elif sev == "HIGH":
            summary.high += 1
        elif sev == "MEDIUM":
            summary.medium += 1
        elif sev == "LOW":
            summary.low += 1
        else:
            summary.info += 1

        # Count by type
        vuln_type = f.type.value if hasattr(f.type, 'value') else str(f.type)
        summary.by_type[vuln_type] = summary.by_type.get(vuln_type, 0) + 1

        # Count by validation status
        if f.status == FindingStatus.VALIDATED_CONFIRMED:
            summary.validated += 1
        elif f.status == FindingStatus.MANUAL_REVIEW_RECOMMENDED:
            summary.manual_review += 1
        elif f.status == FindingStatus.VALIDATED_FALSE_POSITIVE:
            summary.false_positive += 1
        else:
            summary.pending += 1

    summary.total = len(findings)
    return summary


def format_summary_table(summary: ScanSummary) -> str:
    """
    Format summary as rich tables for CLI display.

    Args:
        summary: ScanSummary to format

    Returns:
        Formatted string output with tables
    """
    console = Console()

    # Header
    output = []
    output.append(f"\n[bold cyan]Scan Summary - ID: {summary.scan_id}[/bold cyan]")
    output.append(f"[bold]Target:[/bold] {summary.target_url}")
    output.append(f"[bold]Date:[/bold] {summary.scan_date.strftime('%Y-%m-%d %H:%M:%S')}")
    output.append(f"[bold]Status:[/bold] {summary.status}")
    output.append(f"[bold]Total Findings:[/bold] {summary.total}\n")

    # Severity breakdown table
    severity_table = Table(title="Findings by Severity", show_header=True, header_style="bold magenta")
    severity_table.add_column("Severity", style="cyan", width=12)
    severity_table.add_column("Count", justify="right", style="yellow")
    severity_table.add_column("Percentage", justify="right", style="green")

    severities = [
        ("Critical", summary.critical, "red"),
        ("High", summary.high, "orange1"),
        ("Medium", summary.medium, "yellow"),
        ("Low", summary.low, "blue"),
        ("Info", summary.info, "dim"),
    ]

    for sev_name, count, color in severities:
        pct = (count / summary.total * 100) if summary.total > 0 else 0
        severity_table.add_row(
            f"[{color}]{sev_name}[/{color}]",
            f"[{color}]{count}[/{color}]",
            f"[{color}]{pct:.1f}%[/{color}]"
        )

    # Type breakdown table
    type_table = Table(title="Findings by Type", show_header=True, header_style="bold magenta")
    type_table.add_column("Vulnerability Type", style="cyan")
    type_table.add_column("Count", justify="right", style="yellow")

    for vuln_type, count in sorted(summary.by_type.items(), key=lambda x: x[1], reverse=True):
        type_table.add_row(vuln_type, str(count))

    # Validation status table
    validation_table = Table(title="Validation Status", show_header=True, header_style="bold magenta")
    validation_table.add_column("Status", style="cyan")
    validation_table.add_column("Count", justify="right", style="yellow")

    validation_table.add_row("[green]Validated[/green]", f"[green]{summary.validated}[/green]")
    validation_table.add_row("[yellow]Manual Review[/yellow]", f"[yellow]{summary.manual_review}[/yellow]")
    validation_table.add_row("[red]False Positive[/red]", f"[red]{summary.false_positive}[/red]")
    validation_table.add_row("[dim]Pending[/dim]", f"[dim]{summary.pending}[/dim]")

    # Render tables to string
    from io import StringIO
    string_console = Console(file=StringIO(), force_terminal=True, width=100)

    string_console.print("\n".join(output))
    string_console.print(severity_table)
    string_console.print("")
    string_console.print(type_table)
    string_console.print("")
    string_console.print(validation_table)

    return string_console.file.getvalue()


def format_summary_json(summary: ScanSummary) -> str:
    """
    Format summary as JSON for programmatic use.

    Args:
        summary: ScanSummary to format

    Returns:
        JSON string
    """
    data = {
        "scan_id": summary.scan_id,
        "target_url": summary.target_url,
        "scan_date": summary.scan_date.isoformat(),
        "status": summary.status,
        "total_findings": summary.total,
        "severity": {
            "critical": summary.critical,
            "high": summary.high,
            "medium": summary.medium,
            "low": summary.low,
            "info": summary.info
        },
        "by_type": summary.by_type,
        "validation": {
            "validated": summary.validated,
            "manual_review": summary.manual_review,
            "false_positive": summary.false_positive,
            "pending": summary.pending
        }
    }
    return json.dumps(data, indent=2)
