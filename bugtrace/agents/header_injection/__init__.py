"""
Header Injection Agent Module

Detects HTTP Response Header Injection (CRLF injection) vulnerabilities.

Modules:
    - core: PURE functions for payload generation, URL building, response analysis
    - testing: I/O functions for HTTP testing and header injection verification
    - agent: Thin orchestrator (BaseAgent subclass with run_loop)

Usage:
    from bugtrace.agents.header_injection import HeaderInjectionAgent

For backward compatibility, HeaderInjectionAgent can also be imported from:
    from bugtrace.agents.header_injection_agent import HeaderInjectionAgent
"""

from bugtrace.agents.header_injection.agent import HeaderInjectionAgent

__all__ = ["HeaderInjectionAgent"]
