"""
JWT Agent - Backward Compatibility Wrapper

This module re-exports JWTAgent and run_jwt_analysis from the refactored
bugtrace.agents.jwt package for backward compatibility.

All logic has been moved to the jwt/ subpackage:
    - jwt/types.py: JWTFinding dataclass, vulnerability constants
    - jwt/analysis.py: PURE: JWT parsing, claim analysis, algorithm detection
    - jwt/attacks.py: PURE: payload generation for alg:none, key confusion, weak secrets
    - jwt/validation.py: PURE: token validation, finding validation logic
    - jwt/discovery.py: I/O: JWT token discovery in URLs, cookies, localStorage
    - jwt/exploitation.py: I/O: attack execution, token forging, secret cracking
    - jwt/dedup.py: PURE: JWT fingerprint dedup
    - jwt/agent.py: Thin orchestrator class

Usage (new):
    from bugtrace.agents.jwt import JWTAgent, run_jwt_analysis

Usage (legacy, still works):
    from bugtrace.agents.jwt_agent import JWTAgent
    from bugtrace.agents.jwt_agent import run_jwt_analysis
"""

# Re-export everything from the new package for backward compatibility
from bugtrace.agents.jwt import JWTAgent, run_jwt_analysis  # noqa: F401

__all__ = ["JWTAgent", "run_jwt_analysis"]
