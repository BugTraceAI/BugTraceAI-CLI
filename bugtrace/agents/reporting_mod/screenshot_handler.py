"""
Screenshot copying and image processing.

All functions are I/O (filesystem operations).
"""

import shutil
from pathlib import Path
from typing import Dict, List

from bugtrace.utils.logger import get_logger

logger = get_logger("agents.reporting.screenshot_handler")


# I/O
def copy_screenshots(findings: List[Dict], captures_dir: Path) -> None:
    """Copy all screenshots to the captures folder."""
    for f in findings:
        copy_single_screenshot(f, captures_dir)


# I/O
def copy_single_screenshot(finding: Dict, captures_dir: Path) -> None:
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
