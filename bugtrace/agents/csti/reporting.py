"""
CSTI Reporting

I/O functions for saving CSTI specialist reports.
"""

import json
from typing import Dict, List
from pathlib import Path

from bugtrace.utils.logger import get_logger

logger = get_logger("agents.csti.reporting")


async def generate_specialist_report(
    validated_findings: List[Dict],
    dry_findings: List[Dict],
    scan_context: str,
    agent_name: str,
    report_dir: Path = None,
) -> None:  # I/O
    """
    Generate specialist report for CSTI findings.

    Report structure:
    - phase_a: WET -> DRY deduplication stats
    - phase_b: Exploitation results
    - findings: All validated CSTI findings

    Args:
        validated_findings: List of validated finding dicts
        dry_findings: List of DRY findings from Phase A
        scan_context: Scan identifier
        agent_name: Agent name for report metadata
        report_dir: Optional report directory (falls back to scan_context)
    """
    import aiofiles
    from bugtrace.core.config import settings

    # Resolve report directory
    scan_dir = report_dir
    if not scan_dir:
        scan_id = scan_context.split("/")[-1] if "/" in scan_context else scan_context
        scan_dir = settings.BASE_DIR / "reports" / scan_id

    # Write to specialists/results/ for unified wet->dry->results flow
    results_dir = scan_dir / "specialists" / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    report = {
        "agent": agent_name,
        "vulnerability_type": "CSTI",
        "scan_context": scan_context,
        "phase_a": {
            "wet_count": len(dry_findings) + (len(validated_findings) - len(dry_findings)),
            "dry_count": len(dry_findings),
            "deduplication_method": "LLM + fingerprint fallback",
        },
        "phase_b": {
            "exploited_count": len(dry_findings),
            "validated_count": len(validated_findings),
        },
        "findings": validated_findings,
        "summary": {
            "total_validated": len(validated_findings),
            "template_engines_found": list(
                set(f.get("template_engine", "unknown") for f in validated_findings)
            ),
        },
    }

    report_path = results_dir / "csti_results.json"

    async with aiofiles.open(report_path, "w") as f:
        await f.write(json.dumps(report, indent=2))

    logger.info(f"[{agent_name}] Specialist report saved: {report_path}")
