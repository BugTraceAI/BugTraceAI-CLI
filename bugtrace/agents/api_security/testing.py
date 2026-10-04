"""
API Security Agent — I/O testing facade.

Implementation split:
  - testing_graphql.py: GraphQL introspection/injection/DoS/authz
  - testing_rest.py: auth bypass, IDOR, verb tampering, REST, WebSocket
"""

from bugtrace.agents.api_security.testing_graphql import (
    test_graphql_introspection,
    test_graphql_injection,
    test_graphql_dos,
    test_graphql_endpoint,
    test_graphql_unauth_read_exposure,
    test_graphql_unauth_write_authz,
)
from bugtrace.agents.api_security.testing_rest import (
    test_auth_bypass,
    test_idor,
    test_http_verb_tampering,
    test_rest_endpoint,
    test_websocket,
    discover_graphql_endpoint,
)

__all__ = [
    "test_graphql_introspection",
    "test_graphql_injection",
    "test_graphql_dos",
    "test_graphql_endpoint",
    "test_graphql_unauth_read_exposure",
    "test_graphql_unauth_write_authz",
    "test_auth_bypass",
    "test_idor",
    "test_http_verb_tampering",
    "test_rest_endpoint",
    "test_websocket",
    "discover_graphql_endpoint",
]
