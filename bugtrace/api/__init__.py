"""
API Package - FastAPI application for BugtraceAI.

Exposes ScanService and ReportService via REST endpoints.
"""

from bugtrace.api.main import app

__all__ = ["app"]
