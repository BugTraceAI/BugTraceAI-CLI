"""
JWT Agent Types

Dataclasses and type definitions for JWT vulnerability detection.
Extracted from jwt_agent.py for modularity.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


@dataclass
class JWTFinding:
    """Represents a confirmed or potential JWT vulnerability.

    Attributes:
        type: Vulnerability subtype (e.g., "JWT None Algorithm", "Weak JWT Secret")
        url: The target URL where the token was found/tested
        parameter: The parameter or location (e.g., "alg", "header", "kid")
        payload: The attack payload or cracked secret
        severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW)
        cwe_id: CWE identifier
        cve_id: CVE identifier or "N/A"
        remediation: Remediation guidance
        validated: Whether the vulnerability was confirmed
        status: Validation status (VALIDATED_CONFIRMED, PENDING_VALIDATION)
        description: Detailed vulnerability description
        reproduction: Reproduction steps
        http_request: HTTP request evidence
        http_response: HTTP response evidence
        evidence: Additional evidence data
    """
    type: str
    url: str
    parameter: str
    payload: str
    severity: str
    cwe_id: str = ""
    cve_id: str = "N/A"
    remediation: str = ""
    validated: bool = False
    status: str = "PENDING_VALIDATION"
    description: str = ""
    reproduction: str = ""
    http_request: str = ""
    http_response: str = ""
    evidence: Any = field(default_factory=dict)
    _post_exploit: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""  # PURE
        result = {
            "type": self.type,
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "severity": self.severity,
            "cwe_id": self.cwe_id,
            "cve_id": self.cve_id,
            "remediation": self.remediation,
            "validated": self.validated,
            "status": self.status,
            "description": self.description,
            "reproduction": self.reproduction,
            "http_request": self.http_request,
            "http_response": self.http_response,
            "evidence": self.evidence,
        }
        if self._post_exploit:
            result["_post_exploit"] = True
        return result


# Algorithm categories for attack routing
ALG_NONE_VARIANTS = ['none', 'None', 'NONE', 'nOnE']  # PURE constant

# Success/failure keywords for token verification
SUCCESS_KEYWORDS = [
    "welcome", "admin", "logged in", "flag", "success",
    "bt7331", "role: admin", "MASTER_PASS", "ROOT_KEY",
]  # PURE constant

FAIL_KEYWORDS = [
    "invalid", "unauthorized", "expired", "forbidden",
    "anonymous", "invalid token", "blocked",
]  # PURE constant

# Privilege keywords for body comparison
PRIVILEGE_KEYWORDS = [
    "admin", "superuser", "permissions", "role", "privilege",
    "all_users", "is_admin", "is_staff", "elevated", "root",
]  # PURE constant

# Auth-required path patterns for protected endpoint discovery
AUTH_PATTERNS = [
    "/admin", "/dashboard", "/profile", "/account", "/me",
    "/user", "/settings", "/orders", "/cart",
]  # PURE constant

# Common admin/protected paths for post-exploitation
ADMIN_PATHS = [
    "/api/admin/stats", "/api/admin/users", "/api/admin/products",
    "/api/admin/orders", "/api/admin/settings", "/api/admin/config",
    "/api/admin/email-preview", "/api/admin/email-templates",
    "/api/admin/import", "/api/admin/export", "/api/admin/logs",
    "/api/admin/debug", "/api/admin/vulnerable-debug-stats",
    "/api/user/profile", "/api/user/preferences", "/api/user/settings",
    "/api/health", "/api/status", "/api/debug", "/api/internal",
    "/admin", "/dashboard", "/api/dashboard",
]  # PURE constant

# Common admin usernames for token forging
ADMIN_NAMES = ['admin', 'administrator', 'root']  # PURE constant

# RCE detection parameters
RCE_PARAMS = ["cmd", "exec", "command", "shell", "run", "ping", "query", "process"]  # PURE constant

# RCE indicators in response
RCE_INDICATORS = [
    r"uid=\d+",
    r"gid=\d+",
    r"root:",
    r"bin/\w+sh",
    r"total \d+",
    r"drwx",
]  # PURE constant

# SSTI payloads
SSTI_PAYLOAD = "{{7*7}}"  # PURE constant
SSTI_ALT_PAYLOADS = ["${7*7}", "<%= 7*7 %>", "#{7*7}"]  # PURE constant
SSTI_EXPECTED_RESULT = "49"  # PURE constant
SSTI_BODY_FIELDS = ["body", "content", "template", "message", "text", "html", "subject"]  # PURE constant

# Noise words for app name extraction
HTML_NOISE_WORDS = {
    "welcome", "message", "status", "running", "version", "error",
    "true", "false", "null", "undefined", "module", "export",
    "function", "return", "script", "style", "charset",
}  # PURE constant

RECON_NOISE_WORDS = {
    "welcome", "message", "status", "running", "version", "error",
    "true", "false", "null", "undefined", "localhost", "http", "https",
}  # PURE constant


__all__ = [
    "JWTFinding",
    "ALG_NONE_VARIANTS",
    "SUCCESS_KEYWORDS",
    "FAIL_KEYWORDS",
    "PRIVILEGE_KEYWORDS",
    "AUTH_PATTERNS",
    "ADMIN_PATHS",
    "ADMIN_NAMES",
    "RCE_PARAMS",
    "RCE_INDICATORS",
    "SSTI_PAYLOAD",
    "SSTI_ALT_PAYLOADS",
    "SSTI_EXPECTED_RESULT",
    "SSTI_BODY_FIELDS",
    "HTML_NOISE_WORDS",
    "RECON_NOISE_WORDS",
]
