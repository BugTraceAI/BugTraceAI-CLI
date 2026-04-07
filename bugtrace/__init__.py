"""
BugTraceAI CLI - AI-Driven Professional Penetration Testing Framework
"""

from importlib.metadata import PackageNotFoundError, version as installed_version
from pathlib import Path


def _read_version() -> str:
	version_file = Path(__file__).resolve().parents[1] / "VERSION"
	if version_file.exists():
		return version_file.read_text(encoding="utf-8").strip()

	try:
		return installed_version("bugtraceai-cli")
	except PackageNotFoundError:
		return "0.0.0"


__version__ = _read_version()
__author__ = "BugTraceAI Team"
__license__ = "AGPL-3.0"
