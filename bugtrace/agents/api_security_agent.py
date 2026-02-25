"""
API Security Agent - Backward compatibility shim.

All logic has been moved to the bugtrace.agents.api_security subpackage.
This file re-exports APISecurityAgent for backward compatibility.
"""

from bugtrace.agents.api_security.agent import APISecurityAgent

__all__ = ["APISecurityAgent"]
