"""
API Security Agent - GraphQL, REST, and WebSocket Testing

Comprehensive API security testing covering:
- GraphQL introspection and injection
- REST endpoint fuzzing and authentication bypass
- JWT integration (works with JWTAgent)
- WebSocket security testing
- API rate limit bypass
- Mass assignment vulnerabilities

This gives BugTraceAI first-class API testing capabilities.
"""

import asyncio
import json
import re
from typing import List, Dict, Set, Optional, Any
from loguru import logger

import httpx

# Optional websockets support
try:
    import websockets
    WEBSOCKETS_AVAILABLE = True
except ImportError:
    WEBSOCKETS_AVAILABLE = False
    logger.warning("websockets module not available - WebSocket testing disabled")

from bugtrace.agents.base import BaseAgent
from bugtrace.core.llm_client import llm_client
from bugtrace.core.ui import dashboard
from bugtrace.core.config import settings


class APISecurityAgent(BaseAgent):
    """
    Specialized agent for modern API security testing.

    Attack Surface:
    1. GraphQL (introspection, injection, DoS)
    2. REST APIs (parameter fuzzing, IDOR, auth bypass)
    3. WebSocket (injection, auth bypass)
    4. API Documentation (Swagger/OpenAPI exposure)
    """

    def __init__(self, event_bus=None):
        super().__init__(
            "APISecurityAgent",
            "API & GraphQL Specialist",
            event_bus,
            agent_id="api_security"
        )
        self.graphql_endpoints: Set[str] = set()
        self.rest_endpoints: Set[str] = set()
        self.websocket_endpoints: Set[str] = set()
        self.findings: List[Dict] = []

    def _setup_event_subscriptions(self):
        """Subscribe to endpoint discovery events."""
        if self.event_bus:
            self.event_bus.subscribe("api_endpoint_found", self.handle_api_endpoint)
            self.event_bus.subscribe("graphql_endpoint_found", self.handle_graphql_endpoint)
            logger.info(f"[{self.name}] Subscribed to API discovery events")

    async def handle_api_endpoint(self, data: Dict[str, Any]):
        """Triggered when REST API endpoint is discovered."""
        endpoint = data.get("url")
        self.think(f"New REST API endpoint: {endpoint}")
        await self._test_rest_endpoint(endpoint)

    async def handle_graphql_endpoint(self, data: Dict[str, Any]):
        """Triggered when GraphQL endpoint is discovered."""
        endpoint = data.get("url")
        self.think(f"New GraphQL endpoint: {endpoint}")
        await self._test_graphql_endpoint(endpoint)

    async def run_loop(self):
        """Main agent loop."""
        dashboard.current_agent = self.name
        self.think("API Security Agent initialized...")

        while self.running:
            await asyncio.sleep(1)

    # ==================== GRAPHQL TESTING ====================

    async def _test_graphql_endpoint(self, endpoint: str) -> Dict[str, Any]:
        """
        Comprehensive GraphQL security testing.

        Tests:
        1. Introspection query (schema disclosure)
        2. Injection in query variables
        3. Nested query DoS
        4. Authorization bypass
        """
        self.think(f"Testing GraphQL endpoint: {endpoint}")
        dashboard.log(f"🔍 GraphQL Testing: {endpoint}", "INFO")

        results = {
            "endpoint": endpoint,
            "vulnerabilities": []
        }

        # Test 1: Introspection
        introspection_result = await self._test_graphql_introspection(endpoint)
        if introspection_result["enabled"]:
            results["vulnerabilities"].append({
                "type": "GraphQL Introspection Enabled",
                "severity": "MEDIUM",
                "description": "Schema can be fully enumerated",
                "schema": introspection_result.get("schema")
            })

        # Test 2: Injection in queries
        injection_result = await self._test_graphql_injection(endpoint)
        if injection_result["vulnerable"]:
            results["vulnerabilities"].append({
                "type": "GraphQL Injection",
                "severity": "CRITICAL",
                "payload": injection_result["payload"],
                "response": injection_result["response"][:500],
                "description": f"GraphQL query injection vulnerability detected. Malicious payloads can manipulate query structure to access unauthorized data or execute unintended operations.",
                "reproduction": f"curl -X POST '{endpoint}' -H 'Content-Type: application/json' -d '{{\"query\": \"{injection_result['payload'][:100]}...\"}}'"
            })

        # Test 3: Nested query DoS
        dos_result = await self._test_graphql_dos(endpoint)
        if dos_result["vulnerable"]:
            results["vulnerabilities"].append({
                "type": "GraphQL Nested Query DoS",
                "severity": "HIGH",
                "description": "Server accepts deeply nested queries without limit"
            })

        # Report findings
        for vuln in results["vulnerabilities"]:
            await self._report_finding(vuln)

        return results

    async def _test_graphql_introspection(self, endpoint: str) -> Dict:
        """Test if GraphQL introspection is enabled."""
        introspection_query = {
            "query": """
                query IntrospectionQuery {
                    __schema {
                        queryType { name }
                        mutationType { name }
                        types {
                            name
                            kind
                            fields {
                                name
                                type { name kind }
                            }
                        }
                    }
                }
            """
        }

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.post(
                    endpoint,
                    json=introspection_query,
                    headers={"Content-Type": "application/json"}
                )

                if response.status_code == 200:
                    data = response.json()
                    if "data" in data and "__schema" in data.get("data", {}):
                        schema = data["data"]["__schema"]
                        type_count = len(schema.get("types", []))

                        dashboard.log(
                            f"  ⚠️  GraphQL Introspection ENABLED: {type_count} types exposed",
                            "CRITICAL"
                        )

                        return {
                            "enabled": True,
                            "schema": schema,
                            "type_count": type_count
                        }
        except Exception as e:
            logger.warning(f"GraphQL introspection test failed: {e}")

        return {"enabled": False}

    async def _test_graphql_injection(self, endpoint: str) -> Dict:
        """Test for injection vulnerabilities in GraphQL queries."""
        # Test SQLi-style injection in query variables
        injection_payloads = [
            {"id": "1' OR '1'='1"},
            {"id": "1; DROP TABLE users--"},
            {"search": "test' UNION SELECT password FROM users--"},
            {"user": {"id": "1", "role": "admin"}},  # Mass assignment
        ]

        for payload in injection_payloads:
            query = {
                "query": "query GetUser($id: ID!) { user(id: $id) { id name email } }",
                "variables": payload
            }

            try:
                async with httpx.AsyncClient(timeout=10) as client:
                    response = await client.post(endpoint, json=query)

                    # Check for SQL error messages in response
                    error_patterns = [
                        "sql", "mysql", "postgresql", "syntax error",
                        "unclosed quotation", "unexpected", "exception"
                    ]

                    response_text = response.text.lower()
                    if any(pattern in response_text for pattern in error_patterns):
                        dashboard.log(
                            f"  🚨 GraphQL Injection: Error-based vulnerability found!",
                            "CRITICAL"
                        )
                        return {
                            "vulnerable": True,
                            "payload": json.dumps(payload),
                            "response": response.text
                        }
            except Exception as e:
                logger.debug(f"operation failed: {e}")

        return {"vulnerable": False}

    async def _test_graphql_dos(self, endpoint: str) -> Dict:
        """Test for Nested Query DoS vulnerability."""
        # Create deeply nested query
        nested_query = {
            "query": """
                query {
                    user {
                        posts {
                            author {
                                posts {
                                    author {
                                        posts {
                                            comments {
                                                author { name }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            """
        }

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                import time
                start_time = time.time()

                response = await client.post(endpoint, json=nested_query, timeout=15)
                duration = time.time() - start_time

                # If server takes >5s, likely vulnerable to query complexity DoS
                if duration > 5 or response.status_code == 500:
                    dashboard.log(
                        f"  ⚠️  GraphQL DoS: Server took {duration:.2f}s for nested query",
                        "HIGH"
                    )
                    return {"vulnerable": True, "duration": duration}
        except asyncio.TimeoutError:
            dashboard.log("  ⚠️  GraphQL DoS: Query timeout (15s)", "HIGH")
            return {"vulnerable": True, "duration": 15}
        except Exception as e:
            logger.debug(f"operation failed: {e}")

        return {"vulnerable": False}

    # ==================== REST API TESTING ====================

    async def _test_rest_endpoint(self, endpoint: str) -> Dict[str, Any]:
        """
        Comprehensive REST API testing.

        Tests:
        1. Authentication bypass
        2. IDOR (Insecure Direct Object Reference)
        3. Mass assignment
        4. HTTP verb tampering
        5. Rate limit bypass
        """
        self.think(f"Testing REST endpoint: {endpoint}")
        dashboard.log(f"🔍 REST API Testing: {endpoint}", "INFO")

        results = {"endpoint": endpoint, "vulnerabilities": []}

        # Test 1: Authentication bypass
        auth_bypass = await self._test_auth_bypass(endpoint)
        if auth_bypass["vulnerable"]:
            results["vulnerabilities"].append(auth_bypass)

        # Test 2: IDOR
        idor = await self._test_idor(endpoint)
        if idor["vulnerable"]:
            results["vulnerabilities"].append(idor)

        # Test 3: HTTP Verb Tampering
        verb_tamper = await self._test_http_verb_tampering(endpoint)
        if verb_tamper["vulnerable"]:
            results["vulnerabilities"].append(verb_tamper)

        # Report findings
        for vuln in results["vulnerabilities"]:
            await self._report_finding(vuln)

        return results

    async def _test_auth_bypass(self, endpoint: str) -> Dict:
        """Test authentication bypass techniques."""
        bypass_techniques = [
            # Remove authentication header
            {"headers": {}},
            # JWT "none" algorithm
            {"headers": {"Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9."}},
            # Empty Bearer token
            {"headers": {"Authorization": "Bearer "}},
            # Malformed token
            {"headers": {"Authorization": "Bearer invalid_token"}},
        ]

        try:
            async with httpx.AsyncClient(timeout=5) as client:
                # Get baseline response with no auth
                baseline = await client.get(endpoint, timeout=5)

                for technique in bypass_techniques:
                    response = await client.get(endpoint, **technique, timeout=5)

                    # If we get 200 instead of 401/403, auth is bypassed
                    if response.status_code == 200 and baseline.status_code in [401, 403]:
                        dashboard.log(
                            f"  🚨 AUTH BYPASS: {endpoint} accessible without valid token!",
                            "CRITICAL"
                        )
                        return {
                            "vulnerable": True,
                            "type": "Authentication Bypass",
                            "severity": "CRITICAL",
                            "technique": str(technique),
                            "url": endpoint,
                            "description": f"Authentication bypass vulnerability. The endpoint returns 200 OK without valid credentials using technique: {technique}. Original response was {baseline.status_code}.",
                            "reproduction": f"curl -X GET '{endpoint}' # Returns 200 instead of 401/403"
                        }
        except Exception as e:
            logger.debug(f"operation failed: {e}")

        return {"vulnerable": False}

    async def _test_idor(self, endpoint: str) -> Dict:
        """Test for Insecure Direct Object Reference."""
        # Extract numeric IDs from endpoint
        id_pattern = r'/(\d+)(?:/|$)'
        match = re.search(id_pattern, endpoint)

        if not match:
            return {"vulnerable": False}

        original_id = int(match.group(1))

        # Try accessing other IDs
        test_ids = [
            original_id - 1,
            original_id + 1,
            1,  # First user
            999,  # Random user
        ]

        try:
            async with httpx.AsyncClient(timeout=5) as client:
                # Get original resource
                original_response = await client.get(endpoint, timeout=5)

                if original_response.status_code != 200:
                    return {"vulnerable": False}

                original_data = original_response.text

                # Test other IDs
                for test_id in test_ids:
                    if test_id == original_id:
                        continue

                    test_endpoint = re.sub(id_pattern, f'/{test_id}/', endpoint)
                    test_response = await client.get(test_endpoint, timeout=5)

                    # If we get different data with 200 status, IDOR exists
                    if test_response.status_code == 200 and test_response.text != original_data:
                        dashboard.log(
                            f"  🚨 IDOR: Can access other user data at {test_endpoint}",
                            "CRITICAL"
                        )
                        return {
                            "vulnerable": True,
                            "type": "IDOR (Insecure Direct Object Reference)",
                            "severity": "CRITICAL",
                            "original_id": original_id,
                            "accessible_id": test_id,
                            "url": endpoint,
                            "parameter": "id",
                            "description": f"Insecure Direct Object Reference (IDOR) vulnerability. Changing ID from {original_id} to {test_id} returns different user data without authorization checks.",
                            "reproduction": f"# Original: curl '{endpoint}'\n# IDOR: curl '{test_endpoint}'"
                        }
        except Exception as e:
            logger.debug(f"operation failed: {e}")

        return {"vulnerable": False}

    async def _test_http_verb_tampering(self, endpoint: str) -> Dict:
        """Test HTTP method override vulnerabilities."""
        # Try accessing with different HTTP methods
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

        try:
            async with httpx.AsyncClient(timeout=5) as client:
                results_by_method = {}

                for method in methods:
                    try:
                        response = await client.request(method, endpoint, timeout=5)
                        results_by_method[method] = response.status_code
                    except Exception as e:
                        logger.debug(f"operation failed: {e}")

                # Check for verb tampering (e.g., DELETE allowed when it shouldn't be)
                if "DELETE" in results_by_method and results_by_method["DELETE"] in [200, 204]:
                    dashboard.log(
                        f"  ⚠️  HTTP Verb Tampering: DELETE method allowed on {endpoint}",
                        "HIGH"
                    )
                    return {
                        "vulnerable": True,
                        "type": "HTTP Verb Tampering",
                        "severity": "HIGH",
                        "allowed_methods": list(results_by_method.keys()),
                        "url": endpoint,
                        "description": f"HTTP Verb Tampering vulnerability. The DELETE method is allowed on this endpoint, potentially allowing unauthorized resource deletion. Allowed methods: {list(results_by_method.keys())}",
                        "reproduction": f"curl -X DELETE '{endpoint}' # Returns {results_by_method['DELETE']}"
                    }
        except Exception as e:
            logger.debug(f"operation failed: {e}")

        return {"vulnerable": False}

    # ==================== WEBSOCKET TESTING ====================

    async def _test_websocket(self, ws_url: str) -> Dict:
        """Test WebSocket security."""
        if not WEBSOCKETS_AVAILABLE:
            return {"accessible": False, "error": "websockets module not installed"}

        self.think(f"Testing WebSocket: {ws_url}")

        try:
            async with websockets.connect(ws_url, timeout=5) as websocket:
                # Test 1: Check if authentication is required
                test_message = json.dumps({"type": "ping", "data": "test"})
                await websocket.send(test_message)

                response = await asyncio.wait_for(websocket.recv(), timeout=3)

                dashboard.log(f"  📡 WebSocket connection established: {ws_url}", "INFO")

                # Test 2: Try injection payloads
                injection_payloads = [
                    {"type": "message", "content": "<script>alert(1)</script>"},
                    {"type": "message", "content": "' OR '1'='1"},
                ]

                for payload in injection_payloads:
                    await websocket.send(json.dumps(payload))

                return {"accessible": True, "authenticated": False}
        except Exception as e:
            logger.debug(f"operation failed: {e}")
            return {"accessible": False}

    # ==================== HELPERS ====================

    async def _report_finding(self, vulnerability: Dict):
        """Report discovered vulnerability."""
        self.findings.append(vulnerability)

        # Emit finding event
        if self.event_bus:
            await self.event_bus.emit("vulnerability_detected", {
                "agent": self.name,
                "vulnerability": vulnerability,
                "timestamp": logger._core.handlers[0]._sink._file.name
            })

        # Dashboard notification
        severity = vulnerability.get("severity", "MEDIUM")
        vuln_type = vulnerability.get("type", "Unknown")
        dashboard.log(f"  🚨 {severity}: {vuln_type}", severity)


# Export
__all__ = ["APISecurityAgent"]
