"""
Mass Assignment Agent Module

Detects mass assignment / overposting vulnerabilities by injecting
privilege-escalation fields into POST/PUT/PATCH requests.

Modules:
    - core: PURE functions for privilege field detection, grouping, field acceptance,
            fingerprint generation, and finding construction
    - testing: I/O functions for HTTP testing, baseline retrieval, endpoint discovery,
               and follow-up validation
    - agent: Thin orchestrator (MassAssignmentAgent class)

Usage:
    from bugtrace.agents.mass_assignment import MassAssignmentAgent

For backward compatibility:
    from bugtrace.agents.mass_assignment_agent import MassAssignmentAgent
"""

from bugtrace.agents.mass_assignment.core import (
    PRIVILEGE_FIELDS,
    group_privilege_fields,
    check_field_acceptance,
    build_finding,
    generate_fingerprint,
)

from bugtrace.agents.mass_assignment.testing import (
    get_baseline,
    test_method_with_fields,
    check_followup_get,
    test_endpoint_mass_assignment,
    discover_writable_endpoints,
)

from bugtrace.agents.mass_assignment.agent import MassAssignmentAgent

__all__ = [
    # Main class
    "MassAssignmentAgent",
    # Core (PURE)
    "PRIVILEGE_FIELDS",
    "group_privilege_fields",
    "check_field_acceptance",
    "build_finding",
    "generate_fingerprint",
    # Testing (I/O)
    "get_baseline",
    "test_method_with_fields",
    "check_followup_get",
    "test_endpoint_mass_assignment",
    "discover_writable_endpoints",
]
