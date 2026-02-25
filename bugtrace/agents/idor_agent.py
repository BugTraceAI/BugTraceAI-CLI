"""
IDOR Agent - Backward Compatibility Wrapper

This module re-exports IDORAgent from the refactored
bugtrace.agents.idor package for backward compatibility.

All logic has been moved to the idor/ subpackage:
    - idor/types.py: IDORFinding dataclass, vulnerability constants
    - idor/patterns.py: PURE: ID format detection, context inference, test ID generation
    - idor/payloads.py: PURE: URL injection, path ID extraction
    - idor/validation.py: PURE: differential analysis, finding validation, impact analysis
    - idor/discovery.py: I/O: parameter discovery from URLs, paths, HTML forms
    - idor/exploitation.py: I/O: access control testing, escalation, auth token handling
    - idor/dedup.py: PURE: IDOR fingerprint dedup
    - idor/agent.py: Thin orchestrator class

Usage (new):
    from bugtrace.agents.idor import IDORAgent

Usage (legacy, still works):
    from bugtrace.agents.idor_agent import IDORAgent
"""

# Re-export everything from the new package for backward compatibility
from bugtrace.agents.idor import IDORAgent  # noqa: F401

__all__ = ["IDORAgent"]
