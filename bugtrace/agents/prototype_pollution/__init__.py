"""
Prototype Pollution Agent Module

Detects Prototype Pollution vulnerabilities (CWE-1321) in Node.js APIs
and frontend JavaScript with vulnerable merge/extend operations.

Modules:
    - core: PURE functions for payload analysis, response verification, fingerprinting
    - testing: I/O functions for HTTP/Playwright testing, client-side pollution detection
    - agent: Thin orchestrator (BaseAgent subclass with run_loop)

Note: Payload data lives in bugtrace.agents.prototype_pollution_payloads (unchanged).
      core.py references that module for payload constants.

Usage:
    from bugtrace.agents.prototype_pollution import PrototypePollutionAgent

For backward compatibility, PrototypePollutionAgent can also be imported from:
    from bugtrace.agents.prototype_pollution_agent import PrototypePollutionAgent
"""

from bugtrace.agents.prototype_pollution.agent import PrototypePollutionAgent

__all__ = ["PrototypePollutionAgent"]
