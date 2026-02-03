# Testing Patterns

**Analysis Date:** 2026-02-03

## Test Framework

**Runner:**
- pytest (detected via `import pytest` in test files)
- Config: `./tests/conftest.py` (pytest configuration file present)

**Assertion Library:**
- pytest's built-in assertions (simple `assert` statements)
- `pytest.approx()` for floating-point comparisons
  - Example: `assert cost == pytest.approx(0.05, rel=0.01)`

**Run Commands:**
```bash
# Run all tests
pytest tests/

# Run specific test file
pytest tests/test_llm_client.py

# Run specific test class
pytest tests/test_llm_client.py::TestSanitizeText

# Run specific test function
pytest tests/test_llm_client.py::TestSanitizeText::test_sanitize_api_key

# Verbose output with print statements
pytest tests/ -v -s

# Coverage (if pytest-cov installed)
pytest tests/ --cov=bugtrace
```

## Test File Organization

**Location:**
- Tests co-located in `./tests/` directory (separate from source)
- Source code: `./bugtrace/`
- Test helpers and mocks: `./tests/mocks/`

**Naming:**
- Test files: `test_*.py` or `*_test.py`
  - Examples: `test_llm_client.py`, `test_jwt_agent.py`, `test_bugtrace_sanity.py`
- Mock files: `mock_*.py`
  - Examples: `mock_openredirect_server.py`, `mock_prototype_pollution_server.py`

**Structure:**
```
./tests/
├── conftest.py                              # pytest configuration & session fixtures
├── test_llm_client.py                       # Tests for LLMClient class
├── test_jwt_agent.py                        # Tests for JWT agent
├── test_bugtrace_sanity.py                  # Sanity check imports
├── test_integration_new_agents.py           # Integration tests
├── test_waf_system.py                       # WAF system tests
├── mocks/
│   ├── mock_openredirect_server.py          # Mock server for testing
│   └── mock_prototype_pollution_server.py   # Mock server for testing
└── [other test files...]
```

## Test Structure

**Suite Organization:**
```python
# From test_llm_client.py - Class-based organization
class TestSanitizeText:
    """Tests for sanitize_text function."""

    def test_sanitize_api_key(self):
        """Should redact API keys."""
        text = 'api_key="sk-proj-..."'
        result = sanitize_text(text)
        assert "[REDACTED]" in result
        assert "sk-proj-..." not in result


class TestTokenUsageTracker:
    """Tests for TokenUsageTracker class."""

    def test_record_usage_basic(self):
        """Should record token usage correctly."""
        tracker = TokenUsageTracker()
        tracker.record_usage("model-a", "agent-1", 100, 50)

        assert tracker.total_input_tokens == 100
        assert tracker.total_output_tokens == 50
```

**Patterns:**
- Class-based test organization: Group related tests into classes
  - Naming: `Test{ComponentName}` or `Test{FunctionName}`
- Test method naming: `test_{scenario}_{expected_outcome}` or `test_{what_is_tested}`
  - Examples: `test_sanitize_api_key`, `test_record_usage_basic`, `test_cache_key_generation`
- Docstrings: One-line summary in triple quotes describing what is tested
  - Examples: `"""Should redact API keys."""`, `"""Should accumulate token usage across calls."""`

**Setup/Teardown:**
- No explicit setup/teardown in most tests
- Fixtures provide test data (see Fixtures section)
- Inline initialization common for simple tests

## Mocking

**Framework:** `unittest.mock`
- `AsyncMock`: For async functions
- `MagicMock`: For regular objects
- `patch`: For replacing functions/classes
- `patch.object`: For replacing class methods

**Patterns from test_llm_client.py:**
```python
from unittest.mock import AsyncMock, patch, MagicMock

# Pattern 1: Mocking class initialization
@pytest.fixture
def client(self):
    """Create LLMClient with mocked API key."""
    with patch.object(LLMClient, '__init__', lambda self, api_key=None: None):
        client = LLMClient.__new__(LLMClient)
        client.api_key = "test-key"
        client.models = ["test-model"]
        client.cache = {}
        client.cache_ttl = 3600
        client.model_metrics = {}
        client.token_tracker = TokenUsageTracker()
        return client

# Pattern 2: Mocking async context managers
client.semaphore = MagicMock()
client.semaphore.__aenter__ = AsyncMock()
client.semaphore.__aexit__ = AsyncMock()

# Pattern 3: Using patch decorator/context manager
with patch.object(LLMClient, '__init__', ...):
    # Test code here
    pass
```

**What to Mock:**
- External API calls (OpenAI, OpenRouter, etc.)
- Database connections
- File I/O operations
- Time-dependent code (use `freezegun` if present)
- Third-party services (Interactsh, CDP, etc.)

**What NOT to Mock:**
- Utility functions like `sanitize_text()`, `validate_json()`
- Business logic specific to the application
- Class methods being directly tested
- Data structures and validation logic

## Fixtures and Factories

**Test Data:**
```python
# From test_llm_client.py - Fixture pattern
@pytest.fixture
def client(self):
    """Create LLMClient with mocked dependencies."""
    with patch.object(LLMClient, '__init__', lambda self, api_key=None: None):
        client = LLMClient.__new__(LLMClient)
        client.api_key = "test-key"
        client.models = ["test-model"]
        client.cache = {}
        client.cache_ttl = 3600
        client.model_metrics = {}
        client.token_tracker = TokenUsageTracker()
        return client

# From conftest.py - Session-scoped event loop
@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()
```

**Location:**
- Test class fixtures: Methods decorated with `@pytest.fixture` within test class
- Session-level fixtures: In `./tests/conftest.py` with `scope="session"`
- Mock servers: `./tests/mocks/mock_*.py` with factory functions
  - Example: `def create_app()` in `mock_openredirect_server.py`

**Pattern - Mock Server Factory:**
```python
# From test_integration_new_agents.py
from tests.mocks.mock_openredirect_server import create_app as create_openredirect_app
from tests.mocks.mock_prototype_pollution_server import create_app as create_pp_app

# Usage in test setup:
openredirect_app = create_openredirect_app()
```

## Coverage

**Requirements:** No coverage requirements detected
- No `.coveragerc` or pytest coverage configuration found
- Coverage not enforced in CI

**View Coverage:**
```bash
# If pytest-cov is installed
pytest tests/ --cov=bugtrace --cov-report=html
```

## Test Types

**Unit Tests:**
- Scope: Individual functions and classes
- Approach: Isolated from dependencies via mocking
- Examples from `test_llm_client.py`:
  - `TestSanitizeText` - 8 tests for sanitization utility
  - `TestTokenUsageTracker` - 7 tests for token tracking
  - `TestModelMetrics` - 5 tests for metrics calculation
  - `TestCaching` - 3 tests for cache behavior
- No database access in unit tests

**Integration Tests:**
- Scope: Multiple components working together
- Approach: Use mock servers and orchestrated test flows
- Examples:
  - `test_integration_new_agents.py` - Tests agents against mock vulnerability servers
  - `test_jwt_agent.py` - Async test of JWT analysis pipeline
- Mock servers: FastAPI apps in `./tests/mocks/`

**E2E Tests:**
- Framework: Not detected in current test suite
- Note: May be present in archived test scripts (`./archive/scripts/test_*.py`)

## Common Patterns

**Async Testing:**
```python
# From test_jwt_agent.py
import asyncio
import pytest

async def test_jwt_agent():
    """Test JWT agent analysis."""
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"user": "guest", "admin": False}
    token = jwt.encode(payload, "secret", algorithm="HS256")

    print(f"Testing JWTAgent with token: {token}")

    await run_jwt_analysis(token, "https://juice-shop.herokuapp.com/")
    print("Test complete. Check logs for agent 'thinking' and findings.")

if __name__ == "__main__":
    asyncio.run(test_jwt_agent())
```

**Error Testing:**
```python
# From test_llm_client.py - Testing error cases
def test_sanitize_empty_string(self):
    """Should handle empty strings."""
    assert sanitize_text("") == ""
    assert sanitize_text(None) is None

def test_validate_invalid_json(self, client):
    """Should return None for invalid JSON."""
    response = "This is not JSON at all"
    result = client.validate_json_response(response)
    assert result is None
```

**Parametrized Tests:**
Not detected in current tests (no `@pytest.mark.parametrize`), but pattern could be used for:
- Multiple input variations (e.g., different encoding types)
- Different vulnerability types
- Various WAF bypass strategies

**Floating Point Assertions:**
```python
def test_estimate_cost_known_model(self):
    """Should estimate cost for known models."""
    tracker = TokenUsageTracker()
    tracker.record_usage("google/gemini-2.5-flash-preview", "test", 1_000_000, 0)
    cost = tracker.estimate_cost()
    assert cost == pytest.approx(0.05, rel=0.01)  # 1% relative tolerance
```

## Test Data Constants

**Model pricing constants:**
- Used in `TestTokenUsageTracker` for cost estimation tests
- Example: `google/gemini-2.5-flash-preview` at `$0.05` per 1M input tokens

**Vulnerability schema:**
- `VULNERABILITY_SCHEMA` imported from `llm_client`
- Used in `test_validate_with_schema_valid()` for schema validation testing

**Sample payloads:**
- JWT tokens: Standard HS256 tokens in `test_jwt_agent.py`
- Sanitization samples: API keys, bearer tokens, passwords, URLs in `test_llm_client.py`

## Test Execution Notes

**conftest.py setup:**
```python
import pytest
import asyncio
from typing import Generator

# Session-scoped event loop for async tests
@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()
```

**Running tests:**
- Direct execution: `python tests/test_file.py` works for many test files
- Pytest: `pytest tests/` preferred for full test discovery
- Async handling: Automatic via pytest-asyncio (if installed)

---

*Testing analysis: 2026-02-03*
