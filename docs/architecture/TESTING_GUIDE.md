# BugTraceAI Testing Guide for Agent Development

**Last Updated:** 2026-01-29
**For:** BugTraceAI v2.2+
**Audience:** Agent developers, contributors, QA engineers

---

## 1. Overview

### Testing Philosophy

BugTraceAI uses a **layered testing strategy** to ensure security agents are both effective and reliable:

1. **Mock Servers** - Simulate vulnerable endpoints without real targets
2. **Unit Tests** - Test individual agent phases (Hunter, Auditor) in isolation
3. **Integration Tests** - Verify agents work within the full pipeline
4. **False Positive Validation** - Ensure safe patterns are NOT flagged

This approach ensures:
- **Speed:** Unit tests run in milliseconds
- **Safety:** No testing against live production systems
- **Reliability:** Comprehensive coverage prevents regressions
- **Quality:** False positive rate remains near zero

### Test Pyramid

```
         ╱╲
        ╱  ╲         Validation Tests (slow, few)
       ╱────╲        - False positive checks
      ╱      ╲       - End-to-end scenarios
     ╱────────╲
    ╱          ╲     Integration Tests (medium, more)
   ╱────────────╲    - Pipeline dispatch
  ╱              ╲   - Agent execution
 ╱────────────────╲
╱__________________╲ Unit Tests (fast, many)
                     - Hunter phase
                     - Auditor phase
                     - Payload libraries
```

### Running Tests

```bash
# All tests
pytest tests/

# Specific agent
pytest tests/test_openredirect_agent.py -v

# Integration only
pytest tests/test_integration_new_agents.py -v

# False positive validation
pytest tests/test_false_positive_validation.py -v

# With coverage
pytest --cov=bugtrace tests/

# Parallel execution
pytest -n auto tests/
```

---

## 2. Mock Server Architecture

### Purpose

Mock servers simulate **vulnerable endpoints** without requiring live targets. This allows:
- Testing attack vectors safely
- Reproducing specific vulnerability patterns
- Validating false positive filtering
- Running tests in CI/CD pipelines

### Location and Framework

- **Directory:** `tests/mocks/`
- **Framework:** `aiohttp.web` (lightweight async HTTP server)
- **Pattern:** Vulnerable endpoints + safe endpoints (for false positive testing)

### Example: Open Redirect Mock Server

**File:** `tests/mocks/mock_openredirect_server.py`

```python
from aiohttp import web
from urllib.parse import urlparse

SAFE_DOMAINS = ["example.com", "trusted.com", "localhost"]

async def vulnerable_redirect(request: web.Request) -> web.Response:
    """
    Vulnerable: Accepts any URL without validation.
    TEST CASE: Basic open redirect via query parameter.
    """
    url = request.query.get("url", "/")
    return web.HTTPFound(location=url)

async def safe_redirect(request: web.Request) -> web.Response:
    """
    Safe: Validates redirect URL against whitelist.
    TEST CASE: Should NOT be flagged as vulnerable.
    """
    url = request.query.get("url", "/")

    try:
        parsed = urlparse(url)
        host = parsed.netloc.lower()

        # Allow relative URLs
        if not host:
            return web.HTTPFound(location=url)

        # Check whitelist
        if any(host == domain or host.endswith(f".{domain}") for domain in SAFE_DOMAINS):
            return web.HTTPFound(location=url)

        # Reject external domains
        return web.Response(text="Invalid redirect URL", status=400)
    except Exception:
        return web.Response(text="Invalid URL format", status=400)

def create_app() -> web.Application:
    """Create the aiohttp application."""
    app = web.Application()
    app.router.add_get("/redirect", vulnerable_redirect)
    app.router.add_get("/redirect-safe", safe_redirect)
    return app
```

### Creating a New Mock Server

**Step-by-step process:**

1. **Create file:** `tests/mocks/mock_{vuln_type}_server.py`

2. **Import framework:**
   ```python
   from aiohttp import web
   import asyncio
   ```

3. **Define vulnerable endpoints:**
   ```python
   async def vulnerable_endpoint(request: web.Request) -> web.Response:
       """Endpoint with actual vulnerability"""
       user_input = request.query.get("param", "")
       # Implement vulnerable behavior
       return web.Response(text=f"Result: {user_input}")
   ```

4. **Define safe endpoints:**
   ```python
   async def safe_endpoint(request: web.Request) -> web.Response:
       """Properly validated/sanitized version"""
       user_input = request.query.get("param", "")
       # Implement proper validation/sanitization
       if not is_safe(user_input):
           return web.Response(text="Invalid input", status=400)
       return web.Response(text=f"Safe result")
   ```

5. **Create app factory:**
   ```python
   def create_app() -> web.Application:
       app = web.Application()
       app.router.add_get("/vuln", vulnerable_endpoint)
       app.router.add_get("/safe", safe_endpoint)
       return app
   ```

6. **Add standalone runner (optional):**
   ```python
   async def start_server(host: str = "127.0.0.1", port: int = 5080):
       app = create_app()
       runner = web.AppRunner(app)
       await runner.setup()
       site = web.TCPSite(runner, host, port)
       await site.start()
       print(f"Mock server running on http://{host}:{port}")
       return runner

   if __name__ == "__main__":
       asyncio.run(start_server())
   ```

**Key principles:**
- Document each endpoint's vulnerability/safety in docstrings
- Use realistic patterns from real-world vulnerabilities
- Include edge cases (encoding, bypass techniques)
- Keep server stateless for reproducible tests

---

## 3. Unit Test Structure

### Test File Organization

**Naming:** `tests/test_{agent_name}.py`

**Class structure:**
```python
class TestHunterPhase:
    """Tests for Hunter phase - vector discovery."""

    def test_discover_param_vectors_existing(self):
        """Hunter identifies redirect params in existing URL."""
        pass

    def test_discover_param_vectors_heuristic(self):
        """Hunter uses heuristics for redirect-like params."""
        pass

class TestAuditorPhase:
    """Tests for Auditor phase - payload testing and validation."""

    def test_is_external_redirect_protocol_relative(self):
        """Auditor correctly identifies protocol-relative redirects."""
        pass

    def test_validation_logic(self):
        """Auditor validates findings correctly."""
        pass

class TestPayloadLibrary:
    """Tests for payload library module."""

    def test_payload_count(self):
        """Payload library has sufficient payloads."""
        pass

    def test_payload_substitution(self):
        """Payloads substitute placeholders correctly."""
        pass

class TestIntegration:
    """Integration tests requiring mock server."""

    @pytest.mark.asyncio
    async def test_run_loop_returns_dict(self):
        """Agent run_loop returns proper structure."""
        pass
```

### Async Testing with pytest-asyncio

For agents using `async/await`, mark tests with `@pytest.mark.asyncio`:

```python
import pytest

@pytest.mark.asyncio
async def test_hunter_phase_calls_discovery_methods(self):
    """Hunter phase calls all discovery methods."""
    agent = OpenRedirectAgent("http://test.com?redirect=test")

    with patch.object(agent, '_discover_param_vectors', return_value=[]) as mock_params:
        with patch.object(agent, '_discover_path_vectors', return_value=[]) as mock_paths:
            with patch.object(agent, '_discover_content_vectors',
                            new_callable=AsyncMock, return_value=[]) as mock_content:
                await agent._hunter_phase()

    mock_params.assert_called_once()
    mock_paths.assert_called_once()
    mock_content.assert_called_once()
```

### Fixtures for Mock Servers

Use `aiohttp` test utilities to spin up mock servers:

```python
from aiohttp.test_utils import TestClient, TestServer

@pytest.mark.asyncio
async def test_with_mock_server(self):
    """Test agent against mock server."""
    from tests.mocks.mock_openredirect_server import create_app

    app = create_app()
    async with TestClient(TestServer(app)) as client:
        base_url = str(client.server.make_url("/redirect"))
        test_url = f"{base_url}?url=http://evil.com"

        agent = OpenRedirectAgent(test_url)
        result = await agent.run_loop()

        assert result["vulnerable"] is True
        assert result["findings_count"] > 0
```

### Example Unit Test from OpenRedirect Agent

**File:** `tests/test_openredirect_agent.py`

```python
class TestHunterPhase:
    def test_discover_param_vectors_existing(self):
        """Hunter identifies redirect params in existing URL."""
        agent = OpenRedirectAgent("http://test.com/page?redirect=http://other.com&q=search")
        vectors = agent._discover_param_vectors()

        # Should find 'redirect' param
        redirect_vectors = [v for v in vectors if v.get("param") == "redirect"]
        assert len(redirect_vectors) >= 1, "Should detect 'redirect' parameter"
        assert redirect_vectors[0]["confidence"] == "HIGH"

class TestAuditorPhase:
    def test_is_external_redirect_protocol_relative(self):
        """Auditor correctly identifies protocol-relative redirects."""
        agent = OpenRedirectAgent("http://test.com")

        assert agent._is_external_redirect("//evil.com", "//evil.com") is True

    def test_is_external_redirect_internal(self):
        """Auditor correctly identifies internal redirects as safe."""
        agent = OpenRedirectAgent("http://test.com")

        # Same host = internal = safe
        assert agent._is_external_redirect("http://test.com/page", "test") is False
        # Relative = internal = safe
        assert agent._is_external_redirect("/dashboard", "/dashboard") is False
```

---

## 4. Integration Tests

### Purpose

Integration tests verify that:
1. **Pipeline Dispatch:** TeamOrchestrator routes vulnerabilities to correct agents
2. **Agent Execution:** Agents instantiate and run without errors in the pipeline
3. **Full Pipeline:** All agents work together without conflicts

### Test Classes

**File:** `tests/test_integration_new_agents.py`

```python
class TestPipelineDispatch:
    """Tests that TeamOrchestrator dispatch logic correctly routes to new agents."""

    def test_fast_path_open_redirect_variations(self):
        """Fast-path classification routes OPEN_REDIRECT types to OPENREDIRECT_AGENT."""
        orchestrator = TeamOrchestrator("http://test.com", max_urls=1)

        test_cases = [
            {"type": "OPEN_REDIRECT", "parameter": "url"},
            {"type": "REDIRECT", "parameter": "next"},
            {"type": "URL_REDIRECT", "parameter": "returnUrl"},
        ]

        for vuln in test_cases:
            result = orchestrator._try_fast_path_classification(vuln)
            assert result == "OPENREDIRECT_AGENT", f"Failed for {vuln['type']}"

class TestAgentExecution:
    """Tests that agents instantiate correctly within the pipeline."""

    def test_openredirect_agent_instantiation(self):
        """OpenRedirectAgent can be instantiated with target URL."""
        with TemporaryDirectory() as tmpdir:
            url_dir = Path(tmpdir)

            agent = OpenRedirectAgent(
                "http://test.com/redirect?url=http://evil.com",
                params=["url"],
                report_dir=url_dir
            )

            assert agent is not None
            assert hasattr(agent, 'run_loop')
            assert callable(agent.run_loop)
```

### Mocking Strategy

For integration tests, **mock HTTP responses** rather than full scans:

```python
@pytest.mark.asyncio
async def test_full_scan_generates_findings(self):
    """Full scan with mocked vulnerabilities generates tasks for all agent types."""
    with TemporaryDirectory() as tmpdir:
        scan_dir = Path(tmpdir)

        with patch('bugtrace.core.team.get_state_manager'):
            orchestrator = TeamOrchestrator("http://test.com", max_urls=1, output_dir=scan_dir)

            # Mock dispatch info with multiple agent types
            dispatch_info = {
                "specialist_dispatches": {
                    "XSS_AGENT",
                    "OPENREDIRECT_AGENT",
                    "PROTOTYPE_POLLUTION_AGENT"
                },
                "params_map": {
                    "XSS_AGENT": {"q"},
                    "OPENREDIRECT_AGENT": {"url"},
                    "PROTOTYPE_POLLUTION_AGENT": {"data"}
                }
            }

            # Build tasks
            tasks = await orchestrator._build_other_tasks(...)

            assert len(tasks) >= 2, "OpenRedirect and PrototypePollution tasks should be created"
```

---

## 5. False Positive Validation

### Purpose

False positive validation ensures agents **distinguish between vulnerable and safe patterns**. Without this, agents generate alert fatigue and lose trust.

### Safe Endpoint Patterns

**For Open Redirect:**
- Whitelist-validated redirects (only allows trusted domains)
- Internal redirects (same domain or relative paths)
- Static redirects (ignores user input)

**For Prototype Pollution:**
- Immutable objects (`Object.create(null)`)
- Frozen objects (`Object.freeze()`)
- Filtered merge operations (blocks `__proto__` and `constructor`)

### Test Structure

**File:** `tests/test_false_positive_validation.py`

```python
class TestOpenRedirectFalsePositives:
    """Tests that safe redirect patterns are NOT flagged as vulnerabilities."""

    @pytest.mark.asyncio
    async def test_whitelist_validated_redirect_not_vulnerable(self):
        """
        Safe endpoint: /redirect-safe validates against whitelist.
        Should NOT be flagged as vulnerable.
        """
        app = create_openredirect_app()
        async with TestClient(TestServer(app)) as client:
            base_url = str(client.server.make_url("/redirect-safe"))
            test_url = f"{base_url}?url=http://trusted.com"

            agent = OpenRedirectAgent(test_url)
            result = await agent.run_loop()

            # Assert: Should NOT detect vulnerability on whitelisted redirect
            assert result["vulnerable"] is False, "Whitelist-validated redirect should NOT be flagged"
            assert result["findings_count"] == 0, "Should have zero findings for safe redirect"

    @pytest.mark.asyncio
    async def test_internal_redirect_not_vulnerable(self):
        """
        Safe endpoint: /internal always redirects to /dashboard (internal path).
        Should NOT be flagged as vulnerable.
        """
        app = create_openredirect_app()
        async with TestClient(TestServer(app)) as client:
            base_url = str(client.server.make_url("/internal"))

            agent = OpenRedirectAgent(base_url)
            result = await agent.run_loop()

            # Assert: Internal redirect should NOT be flagged
            assert result["vulnerable"] is False, "Internal redirect should NOT be flagged"
            assert result["findings_count"] == 0
```

### Combined Validation Test

Test all safe endpoints together to verify **zero false positive rate**:

```python
@pytest.mark.asyncio
async def test_safe_endpoints_zero_findings(self):
    """
    Run both agents against ALL safe endpoints.
    Should produce zero HIGH/CRITICAL findings.
    """
    or_app = create_openredirect_app()
    async with TestClient(TestServer(or_app)) as client:
        safe_endpoints = [
            "/redirect-safe?url=http://trusted.com",
            "/internal",
        ]

        total_findings = 0
        for endpoint in safe_endpoints:
            url = str(client.server.make_url(endpoint))
            agent = OpenRedirectAgent(url)
            result = await agent.run_loop()
            total_findings += result.get("findings_count", 0)

        assert total_findings == 0, \
            f"Safe endpoints should have ZERO findings, got {total_findings}"
```

---

## 6. Running Tests

### Full Test Suite

```bash
# Run all tests
cd BugTraceAI-CLI
pytest tests/

# Output:
# tests/test_openredirect_agent.py::TestHunterPhase::test_discover_param_vectors_existing PASSED
# tests/test_openredirect_agent.py::TestAuditorPhase::test_is_external_redirect_protocol_relative PASSED
# ...
# ==================== 45 passed in 2.34s ====================
```

### Specific Agent Tests

```bash
# OpenRedirect agent unit tests
pytest tests/test_openredirect_agent.py -v

# PrototypePollution agent unit tests
pytest tests/test_prototype_pollution_agent.py -v

# Show detailed output
pytest tests/test_openredirect_agent.py -v -s
```

### Integration Tests Only

```bash
# Run integration tests
pytest tests/test_integration_new_agents.py -v

# Output:
# tests/test_integration_new_agents.py::TestPipelineDispatch::test_fast_path_open_redirect_variations PASSED
# tests/test_integration_new_agents.py::TestAgentExecution::test_openredirect_agent_instantiation PASSED
# ...
```

### False Positive Validation

```bash
# Run false positive tests
pytest tests/test_false_positive_validation.py -v

# Should show all safe endpoint tests passing:
# tests/test_false_positive_validation.py::TestOpenRedirectFalsePositives::test_whitelist_validated_redirect_not_vulnerable PASSED
# tests/test_false_positive_validation.py::TestOpenRedirectFalsePositives::test_internal_redirect_not_vulnerable PASSED
# ...
```

### With Coverage

```bash
# Generate coverage report
pytest --cov=bugtrace tests/

# HTML coverage report
pytest --cov=bugtrace --cov-report=html tests/
# View: open htmlcov/index.html
```

### Parallel Execution

```bash
# Install pytest-xdist
pip install pytest-xdist

# Run tests in parallel
pytest -n auto tests/

# Speeds up test suite significantly for large test counts
```

### Filtering by Markers

```bash
# Run only async tests
pytest -m asyncio tests/

# Skip slow tests
pytest -m "not slow" tests/

# Run specific test class
pytest tests/test_openredirect_agent.py::TestHunterPhase -v
```

---

## 7. Checklist: Testing a New Agent

When developing a new security agent, follow this checklist:

### Mock Server
- [ ] Mock server created in `tests/mocks/mock_{agent}_server.py`
- [ ] Vulnerable endpoints implemented (at least 3 variations)
- [ ] Safe endpoints for false positive testing (at least 2)
- [ ] Mock server can run standalone: `python -m tests.mocks.mock_{agent}_server`
- [ ] Endpoints documented with docstrings explaining vulnerability/safety

### Unit Tests - Hunter Phase
- [ ] Test file created: `tests/test_{agent}_agent.py`
- [ ] `TestHunterPhase` class with vector discovery tests
- [ ] Test parameter-based vector discovery
- [ ] Test heuristic-based vector discovery
- [ ] Test content-based vector discovery (if applicable)
- [ ] All Hunter tests passing: `pytest tests/test_{agent}_agent.py::TestHunterPhase -v`

### Unit Tests - Auditor Phase
- [ ] `TestAuditorPhase` class with validation tests
- [ ] Test payload generation and substitution
- [ ] Test validation logic (what makes a finding "confirmed")
- [ ] Test severity assignment logic
- [ ] All Auditor tests passing: `pytest tests/test_{agent}_agent.py::TestAuditorPhase -v`

### Unit Tests - Payload Library
- [ ] `TestPayloadLibrary` class (if agent has separate payload module)
- [ ] Test payload count (sufficient coverage)
- [ ] Test payload tiers (basic, advanced, encoding, etc.)
- [ ] Test placeholder substitution
- [ ] Payload tests passing

### Integration Tests
- [ ] Add agent to `tests/test_integration_new_agents.py`
- [ ] Test fast-path classification in `TestPipelineDispatch`
- [ ] Test agent instantiation in `TestAgentExecution`
- [ ] Test findings structure in `TestFullPipeline`
- [ ] Integration tests passing: `pytest tests/test_integration_new_agents.py -v`

### False Positive Validation
- [ ] Add agent to `tests/test_false_positive_validation.py`
- [ ] Test class created: `Test{Agent}FalsePositives`
- [ ] Test all safe endpoint patterns (at least 3 tests)
- [ ] Test combined safe endpoints (zero findings assertion)
- [ ] False positive tests passing: `pytest tests/test_false_positive_validation.py -v`

### Final Verification
- [ ] All tests passing: `pytest tests/test_{agent}_agent.py -v`
- [ ] No false positives on safe endpoints
- [ ] Coverage > 80% for agent module: `pytest --cov=bugtrace.agents.{agent}_agent tests/test_{agent}_agent.py`
- [ ] Integration tests verify agent works in full pipeline
- [ ] CI/CD pipeline green (if applicable)

---

## 8. Best Practices

### Test Naming

- Use descriptive test names that explain **what** is being tested
- Good: `test_hunter_identifies_redirect_params_in_existing_url`
- Bad: `test_hunter_1`

### Assertions

- Use descriptive assertion messages
- Good: `assert result["vulnerable"] is True, "Vulnerable endpoint should be flagged"`
- Bad: `assert result["vulnerable"]`

### Test Independence

- Each test should be **independent** and **idempotent**
- Don't rely on test execution order
- Clean up any state/files created during tests

### Async Testing

- Always mark async tests with `@pytest.mark.asyncio`
- Use `AsyncMock` for async methods, `MagicMock` for sync methods
- Use `await` when calling async functions in tests

### Fixtures vs Helpers

- Use fixtures for reusable setup (mock servers, test clients)
- Use helper functions for complex test data generation
- Keep fixtures lightweight and focused

### Coverage Goals

- **Unit tests:** 80%+ coverage per agent module
- **Integration tests:** Cover all pipeline entry points
- **False positive tests:** Cover all safe patterns for agent vulnerability type

---

## Summary

BugTraceAI's testing strategy ensures agents are:
- **Accurate:** Unit tests verify correct vector discovery and validation
- **Reliable:** Integration tests ensure agents work within full pipeline
- **Precise:** False positive tests prevent alert fatigue

**Key files to reference:**
- `tests/mocks/mock_openredirect_server.py` - Mock server example
- `tests/test_openredirect_agent.py` - Unit test example
- `tests/test_integration_new_agents.py` - Integration test example
- `tests/test_false_positive_validation.py` - False positive validation example

**Next steps:**
1. Review existing test files for patterns
2. Create mock server for your agent
3. Write unit tests for Hunter and Auditor phases
4. Add integration tests to verify pipeline integration
5. Add false positive validation tests
6. Run full test suite and verify all passing

For questions or issues, refer to existing agent tests as examples or consult the development team.
