"""
Summary generation for scan findings.

Provides aggregated views of findings by severity, type, and validation status.

v3: FILE-BASED - reads from specialist JSON files (DB = write-only from CLI).
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from datetime import datetime
from pathlib import Path
import json
from rich.table import Table
from rich.console import Console

from bugtrace.core.config import settings


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


def _find_latest_scan_dir(target_url: Optional[str] = None) -> Optional[Path]:
    """Find the latest scan directory for a target (or overall latest)."""
    report_dir = Path(settings.REPORT_DIR)
    if not report_dir.exists():
        return None

    if target_url:
        from urllib.parse import urlparse
        domain = urlparse(target_url).netloc.split(":")[0]
        scan_dirs = sorted(report_dir.glob(f"{domain}_*"), reverse=True)
    else:
        scan_dirs = sorted(report_dir.iterdir(), reverse=True)
        scan_dirs = [d for d in scan_dirs if d.is_dir()]

    return scan_dirs[0] if scan_dirs else None


def _load_findings_from_scan_dir(scan_dir: Path) -> List[Dict]:
    """Load findings from specialist JSON files in a scan directory."""
    specialists_dir = scan_dir / "specialists"
    if not specialists_dir.exists():
        return []

    findings = []
    seen_keys = set()

    for subdir in ["results", "dry", "wet"]:
        subdir_path = specialists_dir / subdir
        if not subdir_path.exists():
            continue

        for json_file in sorted(subdir_path.glob("*.json")):
            try:
                content = json_file.read_text(encoding="utf-8").strip()
                if not content:
                    continue

                data = json.loads(content)

                # Handle wrapper format: {"findings": [...]}
                if isinstance(data, dict) and "findings" in data:
                    raw_findings = data["findings"]
                elif isinstance(data, list):
                    raw_findings = data
                else:
                    continue

                for f in raw_findings:
                    if not isinstance(f, dict):
                        continue

                    dedup_key = (
                        f.get("url", ""),
                        f.get("parameter", ""),
                        f.get("type", ""),
                        f.get("payload", ""),
                    )
                    if dedup_key in seen_keys:
                        continue
                    seen_keys.add(dedup_key)

                    findings.append(f)
            except (json.JSONDecodeError, Exception):
                continue

    return findings


def generate_scan_summary(scan_id: Optional[int] = None, target_url: Optional[str] = None) -> ScanSummary:
    """
    Generate aggregated summary for a scan.

    v3: Reads from files (DB = write-only from CLI).

    Args:
        scan_id: Ignored (kept for API compatibility)
        target_url: Target URL (finds latest scan directory)

    Returns:
        ScanSummary with aggregated findings data

    Raises:
        ValueError: If no scans found
    """
    scan_dir = _find_latest_scan_dir(target_url)

    if scan_dir is None:
        raise ValueError("No scans found. Run a scan first.")

    # Extract info from directory name (format: domain_YYYYMMDD_HHMMSS)
    dir_name = scan_dir.name
    parts = dir_name.rsplit("_", 2)
    if len(parts) >= 3:
        domain = parts[0]
        try:
            scan_date = datetime.strptime(f"{parts[1]}_{parts[2]}", "%Y%m%d_%H%M%S")
        except ValueError:
            scan_date = datetime.fromtimestamp(scan_dir.stat().st_ctime)
    else:
        domain = dir_name
        scan_date = datetime.fromtimestamp(scan_dir.stat().st_ctime)

    resolved_target = target_url or domain

    # Load findings from files
    findings = _load_findings_from_scan_dir(scan_dir)

    summary = ScanSummary(
        scan_id=scan_id or 0,
        target_url=resolved_target,
        scan_date=scan_date,
        status="completed",
    )

    # Count by severity and type
    for f in findings:
        sev = (f.get("severity") or "INFO").upper()
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

        vuln_type = str(f.get("type", "Unknown")).upper()
        summary.by_type[vuln_type] = summary.by_type.get(vuln_type, 0) + 1

        status = f.get("status", "")
        if status == "VALIDATED_CONFIRMED":
            summary.validated += 1
        elif status == "MANUAL_REVIEW_RECOMMENDED":
            summary.manual_review += 1
        elif status == "VALIDATED_FALSE_POSITIVE":
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
