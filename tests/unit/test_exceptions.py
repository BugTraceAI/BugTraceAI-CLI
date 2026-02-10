"""
Tests for BugTraceAI Exception Hierarchy

Tests the exception classes defined in bugtrace/core/exceptions.py
"""

import pytest
from bugtrace.core.exceptions import (
    # Base
    BugTraceException,
    # Network
    NetworkError,
    TimeoutError,
    ConnectionError,
    SSLError,
    DNSError,
    # LLM
    LLMError,
    LLMTimeoutError,
    LLMRateLimitError,
    LLMAuthenticationError,
    LLMParseError,
    LLMRefusalError,
    LLMContextLengthError,
    LLMServiceUnavailableError,
    # Tools
    ToolError,
    DockerError,
    DockerNotFoundError,
    DockerImageNotFoundError,
    DockerTimeoutError,
    SubprocessError,
    FuzzerError,
    FuzzerNotInstalledError,
    FuzzerTimeoutError,
    NucleiError,
    SQLMapError,
    # Validation
    ValidationError,
    PayloadValidationError,
    ReflectionError,
    FalsePositiveError,
    ScreenshotValidationError,
    # Data
    DataError,
    JSONParseError,
    EncodingError,
    HTMLParseError,
    URLParseError,
    # Config
    ConfigError,
    MissingConfigError,
    InvalidConfigError,
    # Resource
    ResourceError,
    ResourceExhaustedError,
    ResourceLockedError,
    BrowserError,
    InteractshError,
    # Discovery
    DiscoveryError,
    NoParametersFoundError,
    NoURLsFoundError,
    TargetUnreachableError,
    # Pipeline
    PipelineError,
    PhaseError,
    PhaseTimeoutError,
    QueueError,
    # Helpers
    is_transient,
    wrap_exception,
)


class TestExceptionHierarchy:
    """Test that exception inheritance is correct."""

    def test_all_exceptions_inherit_from_base(self):
        """All custom exceptions should inherit from BugTraceException."""
        exceptions = [
            NetworkError, TimeoutError, ConnectionError, SSLError, DNSError,
            LLMError, LLMTimeoutError, LLMRateLimitError, LLMParseError,
            ToolError, DockerError, DockerTimeoutError, FuzzerError,
            ValidationError, PayloadValidationError, FalsePositiveError,
            DataError, JSONParseError, EncodingError,
            ConfigError, MissingConfigError,
            ResourceError, BrowserError,
            DiscoveryError, NoParametersFoundError,
            PipelineError, PhaseError, QueueError,
        ]
        for exc_class in exceptions:
            assert issubclass(exc_class, BugTraceException), \
                f"{exc_class.__name__} should inherit from BugTraceException"

    def test_network_errors_inherit_from_network_error(self):
        """Network exceptions should inherit from NetworkError."""
        network_exceptions = [TimeoutError, ConnectionError, SSLError, DNSError]
        for exc_class in network_exceptions:
            assert issubclass(exc_class, NetworkError), \
                f"{exc_class.__name__} should inherit from NetworkError"

    def test_llm_errors_inherit_from_llm_error(self):
        """LLM exceptions should inherit from LLMError."""
        llm_exceptions = [
            LLMTimeoutError, LLMRateLimitError, LLMAuthenticationError,
            LLMParseError, LLMRefusalError, LLMContextLengthError,
            LLMServiceUnavailableError
        ]
        for exc_class in llm_exceptions:
            assert issubclass(exc_class, LLMError), \
                f"{exc_class.__name__} should inherit from LLMError"

    def test_tool_errors_inherit_from_tool_error(self):
        """Tool exceptions should inherit from ToolError."""
        tool_exceptions = [
            DockerError, DockerNotFoundError, DockerImageNotFoundError,
            DockerTimeoutError, SubprocessError, FuzzerError,
            FuzzerNotInstalledError, FuzzerTimeoutError, NucleiError, SQLMapError
        ]
        for exc_class in tool_exceptions:
            assert issubclass(exc_class, ToolError), \
                f"{exc_class.__name__} should inherit from ToolError"

    def test_docker_errors_inherit_from_docker_error(self):
        """Docker exceptions should inherit from DockerError."""
        docker_exceptions = [DockerNotFoundError, DockerImageNotFoundError, DockerTimeoutError]
        for exc_class in docker_exceptions:
            assert issubclass(exc_class, DockerError), \
                f"{exc_class.__name__} should inherit from DockerError"


class TestExceptionAttributes:
    """Test exception attributes and behavior."""

    def test_base_exception_attributes(self):
        """BugTraceException should have standard attributes."""
        exc = BugTraceException("Test error", context={"key": "value"})
        assert exc.message == "Test error"
        assert exc.context == {"key": "value"}
        assert exc.cause is None
        assert exc.retry_eligible is False

    def test_exception_with_cause(self):
        """Exceptions should track the original cause."""
        original = ValueError("Original error")
        exc = BugTraceException("Wrapped error", cause=original)
        assert exc.cause is original

    def test_exception_str_includes_context(self):
        """String representation should include context."""
        exc = BugTraceException("Test", context={"url": "http://test.com"})
        exc_str = str(exc)
        assert "Test" in exc_str
        assert "url" in exc_str

    def test_exception_str_includes_error_code(self):
        """String representation should include error code."""
        exc = LLMTimeoutError("Timed out", model="gpt-4")
        exc_str = str(exc)
        assert "LLM_TIMEOUT" in exc_str

    def test_timeout_error_attributes(self):
        """TimeoutError should have timeout-specific attributes."""
        exc = TimeoutError(
            "Request timed out",
            timeout_seconds=30.0,
            url="http://test.com"
        )
        assert exc.context["timeout_seconds"] == 30.0
        assert exc.context["url"] == "http://test.com"

    def test_llm_rate_limit_attributes(self):
        """LLMRateLimitError should have retry_after."""
        exc = LLMRateLimitError("Rate limited", retry_after=60.0, model="gpt-4")
        assert exc.context["retry_after_seconds"] == 60.0
        assert exc.context["model"] == "gpt-4"

    def test_json_parse_error_truncates_data(self):
        """JSONParseError should truncate long raw_data."""
        long_data = "x" * 500
        exc = JSONParseError("Parse failed", raw_data=long_data)
        assert len(exc.context["raw_data"]) == 200  # Truncated

    def test_false_positive_attributes(self):
        """FalsePositiveError should have reason and confidence."""
        exc = FalsePositiveError(
            "Marked as FP",
            reason="WAF blocking",
            confidence=0.95
        )
        assert exc.context["fp_reason"] == "WAF blocking"
        assert exc.context["fp_confidence"] == 0.95


class TestRetryEligibility:
    """Test retry eligibility flags."""

    def test_transient_exceptions_are_retry_eligible(self):
        """Transient exceptions should be retry eligible."""
        transient = [
            NetworkError("test"),
            TimeoutError("test"),
            ConnectionError("test"),
            LLMTimeoutError("test"),
            LLMRateLimitError("test"),
            LLMServiceUnavailableError("test"),
            DockerImageNotFoundError("test"),
            DockerTimeoutError("test"),
            FuzzerTimeoutError("test"),
            ResourceError("test"),
            PhaseTimeoutError("test"),
        ]
        for exc in transient:
            assert exc.retry_eligible is True, \
                f"{type(exc).__name__} should be retry eligible"

    def test_permanent_exceptions_not_retry_eligible(self):
        """Permanent exceptions should NOT be retry eligible."""
        permanent = [
            LLMAuthenticationError("test"),
            LLMParseError("test"),
            LLMRefusalError("test"),
            DockerNotFoundError("test"),
            FuzzerNotInstalledError("test"),
            ValidationError("test"),
            PayloadValidationError("test"),
            FalsePositiveError("test"),
            DataError("test"),
            JSONParseError("test"),
            ConfigError("test"),
            MissingConfigError("test"),
            DiscoveryError("test"),
            NoParametersFoundError("test"),
        ]
        for exc in permanent:
            assert exc.retry_eligible is False, \
                f"{type(exc).__name__} should NOT be retry eligible"


class TestIsTransient:
    """Test the is_transient helper function."""

    def test_is_transient_with_bugtrace_exceptions(self):
        """is_transient should check retry_eligible for BugTraceExceptions."""
        assert is_transient(LLMTimeoutError("test")) is True
        assert is_transient(LLMParseError("test")) is False

    def test_is_transient_with_asyncio_timeout(self):
        """is_transient should recognize asyncio.TimeoutError."""
        import asyncio
        assert is_transient(asyncio.TimeoutError()) is True

    def test_is_transient_with_os_error(self):
        """is_transient should recognize OSError as transient."""
        assert is_transient(OSError("Connection refused")) is True

    def test_is_transient_with_value_error(self):
        """is_transient should NOT consider ValueError transient."""
        assert is_transient(ValueError("bad value")) is False


class TestWrapException:
    """Test the wrap_exception helper function."""

    def test_wrap_exception_creates_typed_exception(self):
        """wrap_exception should create the specified exception type."""
        original = ValueError("Original error")
        wrapped = wrap_exception(original, LLMParseError)

        assert isinstance(wrapped, LLMParseError)
        assert wrapped.cause is original
        assert "Original error" in wrapped.message

    def test_wrap_exception_with_custom_message(self):
        """wrap_exception should use custom message if provided."""
        original = ValueError("Original")
        wrapped = wrap_exception(original, NetworkError, "Custom message")

        assert wrapped.message == "Custom message"


class TestErrorCodes:
    """Test that error codes are set correctly."""

    def test_network_error_codes(self):
        """Network errors should have NET_* error codes."""
        assert NetworkError("test").error_code == "NET"
        assert TimeoutError("test").error_code == "NET_TIMEOUT"
        assert ConnectionError("test").error_code == "NET_CONN"
        assert SSLError("test").error_code == "NET_SSL"
        assert DNSError("test").error_code == "NET_DNS"

    def test_llm_error_codes(self):
        """LLM errors should have LLM_* error codes."""
        assert LLMError("test").error_code == "LLM"
        assert LLMTimeoutError("test").error_code == "LLM_TIMEOUT"
        assert LLMRateLimitError("test").error_code == "LLM_RATE_LIMIT"
        assert LLMAuthenticationError("test").error_code == "LLM_AUTH"
        assert LLMParseError("test").error_code == "LLM_PARSE"

    def test_tool_error_codes(self):
        """Tool errors should have TOOL_* error codes."""
        assert ToolError("test").error_code == "TOOL"
        assert DockerError("test").error_code == "TOOL_DOCKER"
        assert DockerTimeoutError("test").error_code == "TOOL_DOCKER_TIMEOUT"
        assert FuzzerError("test").error_code == "TOOL_FUZZER"
        assert NucleiError("test").error_code == "TOOL_NUCLEI"

    def test_validation_error_codes(self):
        """Validation errors should have VAL_* error codes."""
        assert ValidationError("test").error_code == "VAL"
        assert PayloadValidationError("test").error_code == "VAL_PAYLOAD"
        assert FalsePositiveError("test").error_code == "VAL_FP"

    def test_data_error_codes(self):
        """Data errors should have DATA_* error codes."""
        assert DataError("test").error_code == "DATA"
        assert JSONParseError("test").error_code == "DATA_JSON"
        assert EncodingError("test").error_code == "DATA_ENCODING"

    def test_config_error_codes(self):
        """Config errors should have CFG_* error codes."""
        assert ConfigError("test").error_code == "CFG"
        assert MissingConfigError("test").error_code == "CFG_MISSING"

    def test_pipeline_error_codes(self):
        """Pipeline errors should have PIPE_* error codes."""
        assert PipelineError("test").error_code == "PIPE"
        assert PhaseError("test").error_code == "PIPE_PHASE"
        assert QueueError("test").error_code == "PIPE_QUEUE"
