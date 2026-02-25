"""
XXE Agent Module

Detects XML External Entity (XXE) vulnerabilities in endpoints
consuming XML.

Modules:
    - core: PURE functions for payload generation, DTD patterns, validation, fingerprinting
    - testing: I/O functions for XML submission, OOB XXE testing, response analysis
    - agent: Thin orchestrator (BaseAgent subclass with run_loop)

Usage:
    from bugtrace.agents.xxe import XXEAgent

For backward compatibility, XXEAgent can also be imported from:
    from bugtrace.agents.xxe_agent import XXEAgent
"""

from bugtrace.agents.xxe.agent import XXEAgent

__all__ = ["XXEAgent"]
