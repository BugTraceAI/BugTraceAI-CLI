"""
CSTI Agent Types

Dataclasses and constants for CSTI/SSTI detection.
Extracted from csti_agent.py for modularity.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any


@dataclass
class CSTIFinding:
    """
    Represents a confirmed CSTI/SSTI finding with strict verification data.
    """
    url: str                # The verified URL where exploitation works
    parameter: str
    type: str = "CSTI"
    severity: str = "HIGH"

    # Classification
    template_engine: str = "unknown"  # "angular", "jinja2", etc.
    engine_type: str = "unknown"      # "client-side" or "server-side"

    # Payload & Exploit
    payload: str = ""
    payload_syntax: str = ""          # "expression", "erb_tag", etc.

    # Verification
    verified_url: str = ""            # Same as url, but explicit
    original_url: str = ""            # Where scan started
    arithmetic_proof: bool = False
    baseline_check_passed: bool = False

    # Metadata
    description: str = ""
    reproduction_steps: List[str] = field(default_factory=list)
    reproduction_command: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)

    # Alternative confirmed payloads (up to 5)
    successful_payloads: List[str] = field(default_factory=list)

    # Validation status
    validated: bool = True
    status: str = "VALIDATED_CONFIRMED"

    def to_dict(self) -> Dict[str, Any]:  # PURE
        """Convert CSTIFinding to dictionary for JSON serialization."""
        result = {
            "type": self.type,
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "severity": self.severity,
            "template_engine": self.template_engine,
            "injection_type": f"{self.engine_type} Template Injection",

            "validated": self.validated,
            "status": self.status,
            "description": self.description,
            "reproduction": self.reproduction_command,
            "reproduction_steps": self.reproduction_steps,

            "evidence": self.evidence,

            # Additional metadata for deep dive report
            "csti_metadata": {
                "engine": self.template_engine,
                "type": self.engine_type,
                "syntax": self.payload_syntax,
                "arithmetic_proof": self.arithmetic_proof,
                "verified_url": self.verified_url,
            },
        }

        if self.successful_payloads:
            result["successful_payloads"] = self.successful_payloads

        return result
