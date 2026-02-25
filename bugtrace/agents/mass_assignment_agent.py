"""
Mass Assignment Agent - Backward compatibility shim.

All logic has been moved to the bugtrace.agents.mass_assignment subpackage.
This file re-exports MassAssignmentAgent for backward compatibility.
"""

from bugtrace.agents.mass_assignment.agent import MassAssignmentAgent
from bugtrace.agents.mass_assignment.core import PRIVILEGE_FIELDS

__all__ = ["MassAssignmentAgent", "PRIVILEGE_FIELDS"]
