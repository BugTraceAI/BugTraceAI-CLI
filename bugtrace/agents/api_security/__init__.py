"""
API Security Agent Module

Comprehensive API security testing covering GraphQL, REST, and WebSocket.

Modules:
    - core: PURE functions for response analysis, URL classification,
            vulnerability finding construction, and introspection parsing
    - testing: I/O functions for GraphQL testing, REST endpoint testing,
               auth bypass, IDOR, verb tampering, and WebSocket testing
    - agent: Thin orchestrator (APISecurityAgent class)

Usage:
    from bugtrace.agents.api_security import APISecurityAgent

For backward compatibility:
    from bugtrace.agents.api_security_agent import APISecurityAgent
"""

from bugtrace.agents.api_security.core import (
    WEBSOCKETS_AVAILABLE,
    is_api_url,
    parse_introspection_response,
    check_injection_response,
    check_bypass_response,
    check_idor_response,
    check_verb_tampering,
    create_introspection_vuln,
    create_injection_vuln,
    create_idor_finding,
)

from bugtrace.agents.api_security.testing import (
    test_graphql_introspection,
    test_graphql_injection,
    test_graphql_dos,
    test_graphql_endpoint,
    test_auth_bypass,
    test_idor,
    test_http_verb_tampering,
    test_rest_endpoint,
    test_websocket,
    discover_graphql_endpoint,
)

from bugtrace.agents.api_security.agent import APISecurityAgent

__all__ = [
    # Main class
    "APISecurityAgent",
    # Core (PURE)
    "WEBSOCKETS_AVAILABLE",
    "is_api_url",
    "parse_introspection_response",
    "check_injection_response",
    "check_bypass_response",
    "check_idor_response",
    "check_verb_tampering",
    "create_introspection_vuln",
    "create_injection_vuln",
    "create_idor_finding",
    # Testing (I/O)
    "test_graphql_introspection",
    "test_graphql_injection",
    "test_graphql_dos",
    "test_graphql_endpoint",
    "test_auth_bypass",
    "test_idor",
    "test_http_verb_tampering",
    "test_rest_endpoint",
    "test_websocket",
    "discover_graphql_endpoint",
]
