"""
Service Layer - Foundation for concurrent scan management.

This package provides the service layer abstractions that enable safe concurrent
scans by isolating state and managing per-scan resources.

Author: BugtraceAI Team
Date: 2026-01-27
Version: 2.0.0
"""

from bugtrace.services.scan_context import ScanContext, ScanOptions
from bugtrace.services.event_bus import ServiceEventBus, service_event_bus

__all__ = [
    "ScanContext",
    "ScanOptions",
    "ServiceEventBus",
    "service_event_bus",
]
