"""
IDOR Agent Types

Dataclasses and type definitions for IDOR vulnerability detection.
Extracted from idor_agent.py for modularity.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


@dataclass
class IDORFinding:
    """Represents a confirmed or potential IDOR vulnerability.

    Attributes:
        type: Always "IDOR"
        url: The target URL
        parameter: The injectable parameter name
        payload: The tested ID value
        description: Detailed vulnerability description
        severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW)
        validated: Whether the vulnerability was confirmed
        evidence: Differential analysis evidence
        status: Validation status
        reproduction: Reproduction steps (curl commands)
        cwe_id: CWE identifier
        cve_id: CVE identifier or "N/A"
        remediation: Remediation guidance
        http_request: HTTP request evidence
        http_response: HTTP response evidence
        original_value: Original parameter value
        exploitation: Deep exploitation data (if performed)
    """
    type: str = "IDOR"
    url: str = ""
    parameter: str = ""
    payload: str = ""
    description: str = ""
    severity: str = ""
    validated: bool = False
    evidence: Dict[str, Any] = field(default_factory=dict)
    status: str = "PENDING_VALIDATION"
    reproduction: str = ""
    cwe_id: str = ""
    cve_id: str = "N/A"
    remediation: str = ""
    http_request: str = ""
    http_response: str = ""
    original_value: str = ""
    exploitation: Optional[Dict] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""  # PURE
        result = {
            "type": self.type,
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "description": self.description,
            "severity": self.severity,
            "validated": self.validated,
            "evidence": self.evidence,
            "status": self.status,
            "reproduction": self.reproduction,
            "cwe_id": self.cwe_id,
            "cve_id": self.cve_id,
            "remediation": self.remediation,
            "http_request": self.http_request,
            "http_response": self.http_response,
        }
        if self.exploitation:
            result["exploitation"] = self.exploitation
        return result


# Sensitive data markers for differential analysis
SENSITIVE_MARKERS = [
    'password', 'token', 'secret', 'api_key', 'ssn', 'credit_card',
    'address', 'shipping', 'billing', 'phone', 'payment',
    'tracking', 'salary', 'balance',
]  # PURE constant

# User-specific data patterns for regex matching
USER_PATTERNS = [
    r'"user_id":\s*"?(\d+)"?',
    r'"email":\s*"([^"]+@[^"]+)"',
    r'"username":\s*"([^"]+)"',
    r'/users/(\d+)',
]  # PURE constant

# Privilege keywords for vertical escalation detection
PRIVILEGE_KEYWORDS_MAP = {
    "admin_panel": ["admin panel", "dashboard", "control panel"],
    "user_management": ["delete user", "edit user", "manage users"],
    "system_config": ["system settings", "configuration", "server config"],
}  # PURE constant

# Special/privileged account markers
SPECIAL_MARKERS = ["admin", "administrator", "root", "system", "superuser"]  # PURE constant

# Path-based param indicators
PATH_INDICATORS = {"URL Path", "url_path", "path", "path_id"}  # PURE constant


__all__ = [
    "IDORFinding",
    "SENSITIVE_MARKERS",
    "USER_PATTERNS",
    "PRIVILEGE_KEYWORDS_MAP",
    "SPECIAL_MARKERS",
    "PATH_INDICATORS",
]
