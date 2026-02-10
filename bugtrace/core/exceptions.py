"""
BugTraceAI Exception Hierarchy

This module defines a structured exception hierarchy for better error handling,
debugging, and selective retry logic throughout the codebase.

Exception Categories:
- NetworkError: Transient network issues (should retry)
- LLMError: LLM API issues (mixed - some retry, some not)
- ToolError: External tool execution issues (mixed)
- ValidationError: Data validation failures (permanent - no retry)
- DataError: Data parsing/encoding issues (permanent)
- ConfigError: Configuration issues (permanent)
- ResourceError: Resource availability issues (transient)

Usage:
    from bugtrace.core.exceptions import LLMTimeoutError, NetworkError

    try:
        result = await llm_client.generate(prompt)
    except LLMTimeoutError as e:
        # Transient - retry with backoff
        logger.warning(f"LLM timeout, retrying: {e}")
    except LLMParseError as e:
        # Permanent - don't retry
        logger.error(f"Invalid LLM response: {e}")
"""

from typing import Optional, Dict, Any


class BugTraceException(Exception):
    """Base exception for all BugTraceAI errors.

    Attributes:
        message: Human-readable error description
        retry_eligible: Whether this error type is transient and worth retrying
        error_code: Optional error code for logging/metrics
        context: Additional context about the error
    """

    retry_eligible: bool = False
    error_code: Optional[str] = None

    def __init__(
        self,
        message: str,
        *,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None
    ):
        super().__init__(message)
        self.message = message
        self.context = context or {}
        self.cause = cause

    def __str__(self) -> str:
        base = self.message
        if self.error_code:
            base = f"[{self.error_code}] {base}"
        if self.context:
            base = f"{base} | context={self.context}"
        return base


# =============================================================================
# NETWORK ERRORS (Transient - should retry)
# =============================================================================

class NetworkError(BugTraceException):
    """Base class for network-related errors. Generally transient."""
    retry_eligible = True
    error_code = "NET"


class TimeoutError(NetworkError):
    """Request timed out. Transient - retry with longer timeout."""
    error_code = "NET_TIMEOUT"

    def __init__(
        self,
        message: str,
        *,
        timeout_seconds: Optional[float] = None,
        url: Optional[str] = None,
        **kwargs
    ):
        context = kwargs.pop("context", {})
        if timeout_seconds:
            context["timeout_seconds"] = timeout_seconds
        if url:
            context["url"] = url
        super().__init__(message, context=context, **kwargs)


class ConnectionError(NetworkError):
    """Failed to establish connection. Transient - retry after delay."""
    error_code = "NET_CONN"

    def __init__(
        self,
        message: str,
        *,
        host: Optional[str] = None,
        port: Optional[int] = None,
        **kwargs
    ):
        context = kwargs.pop("context", {})
        if host:
            context["host"] = host
        if port:
            context["port"] = port
        super().__init__(message, context=context, **kwargs)


class SSLError(NetworkError):
    """SSL/TLS handshake or certificate error."""
    error_code = "NET_SSL"


class DNSError(NetworkError):
    """DNS resolution failed."""
    error_code = "NET_DNS"


# =============================================================================
# LLM ERRORS (Mixed - some transient, some permanent)
# =============================================================================

class LLMError(BugTraceException):
    """Base class for LLM API errors."""
    error_code = "LLM"

    def __init__(
        self,
        message: str,
        *,
        model: Optional[str] = None,
        provider: Optional[str] = None,
        **kwargs
    ):
        context = kwargs.pop("context", {})
        if model:
            context["model"] = model
        if provider:
            context["provider"] = provider
        super().__init__(message, context=context, **kwargs)


class LLMTimeoutError(LLMError):
    """LLM request timed out. Transient - retry."""
    retry_eligible = True
    error_code = "LLM_TIMEOUT"


class LLMRateLimitError(LLMError):
    """Hit LLM rate limit. Transient - retry with longer backoff."""
    retry_eligible = True
    error_code = "LLM_RATE_LIMIT"

    def __init__(
        self,
        message: str,
        *,
        retry_after: Optional[float] = None,
        **kwargs
    ):
        context = kwargs.pop("context", {})
        if retry_after:
            context["retry_after_seconds"] = retry_after
        super().__init__(message, context=context, **kwargs)


class LLMAuthenticationError(LLMError):
    """LLM API authentication failed. Permanent - check API key."""
    retry_eligible = False
    error_code = "LLM_AUTH"


class LLMParseError(LLMError):
    """Failed to parse LLM response. Permanent - bad response format."""
    retry_eligible = False
    error_code = "LLM_PARSE"

    def __init__(
        self,
        message: str,
        *,
        raw_response: Optional[str] = None,
        expected_format: Optional[str] = None,
        **kwargs
    ):
        context = kwargs.pop("context", {})
        if raw_response:
            # Truncate for logging
            context["raw_response"] = raw_response[:500] if len(raw_response) > 500 else raw_response
        if expected_format:
            context["expected_format"] = expected_format
        super().__init__(message, context=context, **kwargs)


class LLMRefusalError(LLMError):
    """LLM refused to process request (content policy). Permanent."""
    retry_eligible = False
    error_code = "LLM_REFUSED"


class LLMContextLengthError(LLMError):
    """Prompt exceeded context length. Permanent - reduce prompt size."""
    retry_eligible = False
    error_code = "LLM_CTX_LEN"


class LLMServiceUnavailableError(LLMError):
    """LLM service temporarily unavailable. Transient - retry."""
    retry_eligible = True
    error_code = "LLM_UNAVAIL"


# =============================================================================
# TOOL ERRORS (Mixed - depends on tool and failure mode)
# =============================================================================

class ToolError(BugTraceException):
    """Base class for external tool execution errors."""
    error_code = "TOOL"

    def __init__(
        self,
        message: str,
        *,
        tool_name: Optional[str] = None,
        exit_code: Optional[int] = None,
        stderr: Optional[str] = None,
        **kwargs
    ):
        context = kwargs.pop("context", {})
        if tool_name:
            context["tool"] = tool_name
        if exit_code is not None:
            context["exit_code"] = exit_code
        if stderr:
            context["stderr"] = stderr[:500] if len(stderr) > 500 else stderr
        super().__init__(message, context=context, **kwargs)


class DockerError(ToolError):
    """Docker execution error."""
    error_code = "TOOL_DOCKER"


class DockerNotFoundError(DockerError):
    """Docker not installed or not running. Permanent."""
    retry_eligible = False
    error_code = "TOOL_DOCKER_NOT_FOUND"


class DockerImageNotFoundError(DockerError):
    """Docker image not pulled. Transient - can auto-pull."""
    retry_eligible = True
    error_code = "TOOL_DOCKER_IMG"


class DockerTimeoutError(DockerError):
    """Docker container timed out. Transient - retry with longer timeout."""
    retry_eligible = True
    error_code = "TOOL_DOCKER_TIMEOUT"


class SubprocessError(ToolError):
    """Subprocess execution error."""
    error_code = "TOOL_SUBPROCESS"


class FuzzerError(ToolError):
    """Fuzzer tool error (Go XSS fuzzer, etc.)."""
    error_code = "TOOL_FUZZER"


class FuzzerNotInstalledError(FuzzerError):
    """Fuzzer binary not found. Permanent - needs installation."""
    retry_eligible = False
    error_code = "TOOL_FUZZER_NOT_FOUND"


class FuzzerTimeoutError(FuzzerError):
    """Fuzzer timed out. Transient."""
    retry_eligible = True
    error_code = "TOOL_FUZZER_TIMEOUT"


class NucleiError(ToolError):
    """Nuclei scanner error."""
    error_code = "TOOL_NUCLEI"


class SQLMapError(ToolError):
    """SQLMap tool error."""
    error_code = "TOOL_SQLMAP"


# =============================================================================
# VALIDATION ERRORS (Permanent - no retry)
# =============================================================================

class ValidationError(BugTraceException):
    """Base class for validation failures. Permanent - don't retry."""
    retry_eligible = False
    error_code = "VAL"


class PayloadValidationError(ValidationError):
    """Payload didn't execute as expected."""
    error_code = "VAL_PAYLOAD"

    def __init__(
        self,
        message: str,
        *,
        payload: Optional[str] = None,
        expected: Optional[str] = None,
        actual: Optional[str] = None,
        **kwargs
    ):
        context = kwargs.pop("context", {})
        if payload:
            context["payload"] = payload[:200] if len(payload) > 200 else payload
        if expected:
            context["expected"] = expected
        if actual:
            context["actual"] = actual
        super().__init__(message, context=context, **kwargs)


class ReflectionError(ValidationError):
    """Reflection analysis failed or unexpected."""
    error_code = "VAL_REFLECTION"


class FalsePositiveError(ValidationError):
    """Finding was determined to be a false positive."""
    error_code = "VAL_FP"

    def __init__(
        self,
        message: str,
        *,
        reason: Optional[str] = None,
        confidence: Optional[float] = None,
        **kwargs
    ):
        context = kwargs.pop("context", {})
        if reason:
            context["fp_reason"] = reason
        if confidence is not None:
            context["fp_confidence"] = confidence
        super().__init__(message, context=context, **kwargs)


class ScreenshotValidationError(ValidationError):
    """Screenshot/visual validation failed."""
    error_code = "VAL_SCREENSHOT"


# =============================================================================
# DATA ERRORS (Permanent - no retry)
# =============================================================================

class DataError(BugTraceException):
    """Base class for data parsing/encoding errors. Permanent."""
    retry_eligible = False
    error_code = "DATA"


class JSONParseError(DataError):
    """JSON parsing failed."""
    error_code = "DATA_JSON"

    def __init__(
        self,
        message: str,
        *,
        raw_data: Optional[str] = None,
        position: Optional[int] = None,
        **kwargs
    ):
        context = kwargs.pop("context", {})
        if raw_data:
            context["raw_data"] = raw_data[:200] if len(raw_data) > 200 else raw_data
        if position is not None:
            context["position"] = position
        super().__init__(message, context=context, **kwargs)


class EncodingError(DataError):
    """Text encoding/decoding error."""
    error_code = "DATA_ENCODING"


class HTMLParseError(DataError):
    """HTML parsing error."""
    error_code = "DATA_HTML"


class URLParseError(DataError):
    """URL parsing error."""
    error_code = "DATA_URL"


# =============================================================================
# CONFIG ERRORS (Permanent - fix config and restart)
# =============================================================================

class ConfigError(BugTraceException):
    """Base class for configuration errors. Permanent."""
    retry_eligible = False
    error_code = "CFG"


class MissingConfigError(ConfigError):
    """Required configuration key missing."""
    error_code = "CFG_MISSING"

    def __init__(
        self,
        message: str,
        *,
        key: Optional[str] = None,
        **kwargs
    ):
        context = kwargs.pop("context", {})
        if key:
            context["missing_key"] = key
        super().__init__(message, context=context, **kwargs)


class InvalidConfigError(ConfigError):
    """Configuration value is invalid."""
    error_code = "CFG_INVALID"


# =============================================================================
# RESOURCE ERRORS (Transient - resources may become available)
# =============================================================================

class ResourceError(BugTraceException):
    """Base class for resource availability errors. Generally transient."""
    retry_eligible = True
    error_code = "RES"


class ResourceExhaustedError(ResourceError):
    """Resource pool exhausted (connections, workers, etc.)."""
    error_code = "RES_EXHAUSTED"


class ResourceLockedError(ResourceError):
    """Resource is locked by another process."""
    error_code = "RES_LOCKED"


class BrowserError(ResourceError):
    """Browser/Playwright resource error."""
    error_code = "RES_BROWSER"


class InteractshError(ResourceError):
    """Interactsh service error."""
    error_code = "RES_INTERACTSH"


# =============================================================================
# DISCOVERY ERRORS (Permanent in most cases)
# =============================================================================

class DiscoveryError(BugTraceException):
    """Base class for discovery phase errors."""
    retry_eligible = False
    error_code = "DISC"


class NoParametersFoundError(DiscoveryError):
    """No injectable parameters found on target."""
    error_code = "DISC_NO_PARAMS"


class NoURLsFoundError(DiscoveryError):
    """No URLs discovered during crawling."""
    error_code = "DISC_NO_URLS"


class TargetUnreachableError(DiscoveryError):
    """Target is unreachable or returned error."""
    error_code = "DISC_UNREACHABLE"


# =============================================================================
# PIPELINE ERRORS
# =============================================================================

class PipelineError(BugTraceException):
    """Base class for pipeline orchestration errors."""
    error_code = "PIPE"


class PhaseError(PipelineError):
    """Error during pipeline phase execution."""
    error_code = "PIPE_PHASE"

    def __init__(
        self,
        message: str,
        *,
        phase: Optional[str] = None,
        **kwargs
    ):
        context = kwargs.pop("context", {})
        if phase:
            context["phase"] = phase
        super().__init__(message, context=context, **kwargs)


class PhaseTimeoutError(PhaseError):
    """Pipeline phase timed out."""
    retry_eligible = True
    error_code = "PIPE_PHASE_TIMEOUT"


class QueueError(PipelineError):
    """Work queue error."""
    error_code = "PIPE_QUEUE"


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def is_transient(exc: Exception) -> bool:
    """Check if an exception is transient (worth retrying).

    Args:
        exc: The exception to check

    Returns:
        True if the exception is transient and retry might succeed
    """
    if isinstance(exc, BugTraceException):
        return exc.retry_eligible

    # Handle standard library exceptions
    import asyncio
    import aiohttp

    transient_types = (
        asyncio.TimeoutError,
        aiohttp.ClientError if hasattr(aiohttp, 'ClientError') else type(None),
        OSError,  # Includes ConnectionError, etc.
    )

    return isinstance(exc, transient_types)


def wrap_exception(
    exc: Exception,
    wrapper_class: type,
    message: Optional[str] = None
) -> BugTraceException:
    """Wrap a standard exception in a BugTraceException.

    Args:
        exc: The original exception
        wrapper_class: The BugTraceException subclass to wrap with
        message: Optional custom message (defaults to str(exc))

    Returns:
        A BugTraceException wrapping the original
    """
    return wrapper_class(
        message or str(exc),
        cause=exc
    )


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Base
    "BugTraceException",

    # Network
    "NetworkError",
    "TimeoutError",
    "ConnectionError",
    "SSLError",
    "DNSError",

    # LLM
    "LLMError",
    "LLMTimeoutError",
    "LLMRateLimitError",
    "LLMAuthenticationError",
    "LLMParseError",
    "LLMRefusalError",
    "LLMContextLengthError",
    "LLMServiceUnavailableError",

    # Tools
    "ToolError",
    "DockerError",
    "DockerNotFoundError",
    "DockerImageNotFoundError",
    "DockerTimeoutError",
    "SubprocessError",
    "FuzzerError",
    "FuzzerNotInstalledError",
    "FuzzerTimeoutError",
    "NucleiError",
    "SQLMapError",

    # Validation
    "ValidationError",
    "PayloadValidationError",
    "ReflectionError",
    "FalsePositiveError",
    "ScreenshotValidationError",

    # Data
    "DataError",
    "JSONParseError",
    "EncodingError",
    "HTMLParseError",
    "URLParseError",

    # Config
    "ConfigError",
    "MissingConfigError",
    "InvalidConfigError",

    # Resource
    "ResourceError",
    "ResourceExhaustedError",
    "ResourceLockedError",
    "BrowserError",
    "InteractshError",

    # Discovery
    "DiscoveryError",
    "NoParametersFoundError",
    "NoURLsFoundError",
    "TargetUnreachableError",

    # Pipeline
    "PipelineError",
    "PhaseError",
    "PhaseTimeoutError",
    "QueueError",

    # Helpers
    "is_transient",
    "wrap_exception",
]
