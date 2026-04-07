"""
Auth Discovery Agent - Backward compatibility shim.

All logic has been moved to the bugtrace.agents.auth_discovery subpackage.
This file re-exports AuthDiscoveryAgent for backward compatibility.
"""

from bugtrace.agents.auth_discovery.agent import AuthDiscoveryAgent

__all__ = ["AuthDiscoveryAgent"]
