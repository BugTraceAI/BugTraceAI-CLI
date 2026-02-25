"""
SQLi Agent Reporting (I/O)

I/O functions for saving SQLi specialist reports to filesystem.

These functions write files to the report directory.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from loguru import logger

from bugtrace.core.config import settings


def generate_specialist_report(
    findings: List[Dict],
    dry_findings: List[Dict],
    scan_context: str,
    report_dir: Optional[Path] = None,
    wet_count: Optional[int] = None,
) -> str:
    """
    # I/O
    Generate specialist report after exploitation.

    Steps:
    1. Summarize findings (validated vs pending)
    2. Technical analysis per finding
    3. Save to: reports/scan_{id}/specialists/results/sqli_results.json

    Args:
        findings: List of validated finding dicts
        dry_findings: List of DRY finding dicts (for metrics)
        scan_context: Scan context path string
        report_dir: Optional explicit report directory
        wet_count: Optional WET count for metrics

    Returns:
        Path to generated report
    """
    # Resolve report directory
    scan_dir = report_dir
    if not scan_dir:
        scan_id = scan_context.split("/")[-1]
        scan_dir = settings.BASE_DIR / "reports" / scan_id
    results_dir = scan_dir / "specialists" / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    # Build report
    report = {
        "agent": "SQLiAgent",
        "scan_id": scan_context.split("/")[-1],
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "phase_a": {
            "wet_count": wet_count if wet_count is not None else len(dry_findings),
            "dry_count": len(dry_findings),
            "duplicates_removed": max(0, (wet_count if wet_count is not None else len(dry_findings)) - len(dry_findings)),
            "analysis_duration_s": 0,
        },
        "phase_b": {
            "attacks_executed": len(dry_findings),
            "validated_confirmed": len([f for f in findings if f.get("status") == "VALIDATED_CONFIRMED"]),
            "validated_likely": 0,
            "pending_validation": len([f for f in findings if f.get("status") == "PENDING_VALIDATION"]),
            "exploitation_duration_s": 0,
        },
        "findings": findings
    }

    # Save report
    report_path = results_dir / "sqli_results.json"
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)

    logger.info(f"Specialist report saved: {report_path}")

    return str(report_path)


__all__ = [
    "generate_specialist_report",
]
