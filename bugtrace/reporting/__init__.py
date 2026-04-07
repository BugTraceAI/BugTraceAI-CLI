"""
Reporting module for BugtraceAI-CLI.
"""

from bugtrace.reporting.standards import (
    get_cwe_for_vuln,
    get_remediation_for_vuln,
    get_default_severity,
    normalize_severity,
    format_cve,
    CWE_MAPPINGS,
    REMEDIATION_TEMPLATES,
    DEFAULT_SEVERITY,
)

__all__ = [
    "get_cwe_for_vuln",
    "get_remediation_for_vuln",
    "get_default_severity",
    "normalize_severity",
    "format_cve",
    "CWE_MAPPINGS",
    "REMEDIATION_TEMPLATES",
    "DEFAULT_SEVERITY",
]
