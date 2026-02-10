"""
XSS Agent Types

Dataclasses and enums for XSS detection.
Extracted from xss_agent.py for modularity.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any


@dataclass
class InjectionContext:
    """Represents the context where user input is reflected."""
    type: str  # e.g., "html_text", "script_block", "html_attribute"
    code_snippet: str  # The surrounding code showing the injection point


class ValidationMethod(Enum):
    """Methods for validating XSS execution."""
    INTERACTSH = "interactsh"  # OOB callback - definitive proof
    VISION = "vision"          # Screenshot analysis for visual markers
    CDP = "cdp"                # DOM marker check via Chrome DevTools Protocol


@dataclass
class XSSFinding:
    """Represents a confirmed or potential XSS vulnerability.

    Attributes:
        url: The vulnerable URL
        parameter: The injectable parameter name
        payload: The XSS payload that triggered the vulnerability
        context: The injection context (e.g., "script_block")
        validation_method: How the XSS was validated
        evidence: Supporting evidence (screenshots, callbacks, etc.)
        confidence: Confidence score (0.0-1.0)
        type: Vulnerability type (always "XSS")
        status: Validation status (PENDING_VALIDATION, VALIDATED_CONFIRMED, etc.)
        validated: Authority flag for confirmed findings
    """
    url: str
    parameter: str
    payload: str
    context: str
    validation_method: str
    evidence: Dict[str, Any]
    confidence: float
    type: str = "XSS"
    status: str = "PENDING_VALIDATION"
    validated: bool = False
    screenshot_path: Optional[str] = None
    reflection_context: Optional[str] = None
    surviving_chars: Optional[str] = None
    successful_payloads: Optional[List[str]] = None

    # Enhanced reporting fields
    xss_type: str = "reflected"  # reflected, stored, dom
    injection_context_type: str = "unknown"
    vulnerable_code_snippet: str = ""
    server_escaping: Dict[str, bool] = field(default_factory=dict)
    escape_bypass_technique: str = "none"
    bypass_explanation: str = ""
    exploit_url: str = ""
    exploit_url_encoded: str = ""
    verification_methods: List[Dict] = field(default_factory=list)
    verification_warnings: List[str] = field(default_factory=list)
    reproduction_steps: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "context": self.context,
            "validation_method": self.validation_method,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "type": self.type,
            "status": self.status,
            "validated": self.validated,
            "screenshot_path": self.screenshot_path,
            "reflection_context": self.reflection_context,
            "surviving_chars": self.surviving_chars,
            "successful_payloads": self.successful_payloads,
            "xss_type": self.xss_type,
            "injection_context_type": self.injection_context_type,
            "vulnerable_code_snippet": self.vulnerable_code_snippet,
            "server_escaping": self.server_escaping,
            "escape_bypass_technique": self.escape_bypass_technique,
            "bypass_explanation": self.bypass_explanation,
            "exploit_url": self.exploit_url,
            "exploit_url_encoded": self.exploit_url_encoded,
            "verification_methods": self.verification_methods,
            "verification_warnings": self.verification_warnings,
            "reproduction_steps": self.reproduction_steps,
        }


@dataclass
class ReflectionResult:
    """Result of probing for reflection points."""
    url: str
    parameter: str
    reflected: bool
    context: str  # Where the probe was found
    surviving_chars: str  # Which special chars survived encoding
    raw_response: Optional[str] = None
    response_length: int = 0


@dataclass
class PayloadTestResult:
    """Result of testing a single payload."""
    payload: str
    url: str
    parameter: str
    success: bool
    method: str  # "interactsh", "vision", "http_reflection"
    evidence: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


__all__ = [
    "InjectionContext",
    "ValidationMethod",
    "XSSFinding",
    "ReflectionResult",
    "PayloadTestResult",
]
