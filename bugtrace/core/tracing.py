"""
OpenTelemetry Tracing Module for BugtraceAI-CLI v1.6

Provides decorators for tracing LLM calls and skill executions.
"""
import time
import functools
from typing import Callable, Any
from contextlib import contextmanager

from bugtrace.utils.logger import get_logger

logger = get_logger("core.tracing")

# Try to import OpenTelemetry, graceful fallback if not installed
try:
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import ConsoleSpanExporter, SimpleSpanProcessor
    from opentelemetry.sdk.resources import Resource
    
    # Initialize tracer
    resource = Resource.create({"service.name": "bugtraceai-cli"})
    provider = TracerProvider(resource=resource)
    
    # Console exporter for debugging
    console_exporter = ConsoleSpanExporter()
    provider.add_span_processor(SimpleSpanProcessor(console_exporter))
    
    trace.set_tracer_provider(provider)
    tracer = trace.get_tracer("bugtraceai")
    
    OTEL_AVAILABLE = True
    logger.info("OpenTelemetry tracing initialized")
    
except ImportError:
    OTEL_AVAILABLE = False
    tracer = None
    logger.warning("OpenTelemetry not installed. Tracing disabled. Install with: pip install opentelemetry-sdk")


class TracingStats:
    """Simple stats tracker when OTEL is not available."""
    
    def __init__(self):
        self.llm_calls = 0
        self.llm_total_time = 0.0
        self.skill_calls = 0
        self.skill_total_time = 0.0
        self.errors = 0
    
    def record_llm(self, duration: float, success: bool):
        self.llm_calls += 1
        self.llm_total_time += duration
        if not success:
            self.errors += 1
    
    def record_skill(self, duration: float, success: bool):
        self.skill_calls += 1
        self.skill_total_time += duration
        if not success:
            self.errors += 1
    
    def get_stats(self) -> dict:
        return {
            "llm_calls": self.llm_calls,
            "llm_avg_time": self.llm_total_time / max(1, self.llm_calls),
            "skill_calls": self.skill_calls,
            "skill_avg_time": self.skill_total_time / max(1, self.skill_calls),
            "errors": self.errors
        }


# Global stats instance
stats = TracingStats()


def trace_llm(model: str = "unknown"):
    """
    Decorator to trace LLM calls.
    
    Usage:
        @trace_llm(model="gemini-2.5-flash")
        async def call_llm(prompt):
            ...
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs) -> Any:
            start = time.time()
            success = True
            
            try:
                if OTEL_AVAILABLE and tracer:
                    with tracer.start_as_current_span(f"llm.{func.__name__}") as span:
                        span.set_attribute("llm.model", model)
                        span.set_attribute("llm.function", func.__name__)
                        result = await func(*args, **kwargs)
                        span.set_attribute("llm.success", True)
                        return result
                else:
                    return await func(*args, **kwargs)
            except Exception as e:
                success = False
                if OTEL_AVAILABLE and tracer:
                    span.set_attribute("llm.success", False)
                    span.set_attribute("llm.error", str(e))
                raise
            finally:
                duration = time.time() - start
                stats.record_llm(duration, success)
                logger.debug(f"LLM call {func.__name__} took {duration:.2f}s")
        
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs) -> Any:
            start = time.time()
            success = True
            
            try:
                if OTEL_AVAILABLE and tracer:
                    with tracer.start_as_current_span(f"llm.{func.__name__}") as span:
                        span.set_attribute("llm.model", model)
                        result = func(*args, **kwargs)
                        return result
                else:
                    return func(*args, **kwargs)
            except Exception as e:
                success = False
                raise
            finally:
                duration = time.time() - start
                stats.record_llm(duration, success)
        
        # Return appropriate wrapper based on function type
        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper
    
    return decorator


def trace_skill(skill_name: str = None):
    """
    Decorator to trace skill executions.
    
    Usage:
        @trace_skill("exploit_sqli")
        async def execute(url, params):
            ...
    """
    def decorator(func: Callable) -> Callable:
        name = skill_name or func.__name__
        
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs) -> Any:
            start = time.time()
            success = True
            
            try:
                if OTEL_AVAILABLE and tracer:
                    with tracer.start_as_current_span(f"skill.{name}") as span:
                        span.set_attribute("skill.name", name)
                        
                        # Try to get URL from args
                        if args and isinstance(args[0], str):
                            span.set_attribute("skill.url", args[0][:100])
                        
                        result = await func(*args, **kwargs)
                        
                        # Record findings count if available
                        if isinstance(result, dict) and "findings" in result:
                            span.set_attribute("skill.findings", len(result["findings"]))
                        
                        return result
                else:
                    return await func(*args, **kwargs)
            except Exception as e:
                success = False
                raise
            finally:
                duration = time.time() - start
                stats.record_skill(duration, success)
                logger.debug(f"Skill {name} took {duration:.2f}s")
        
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs) -> Any:
            start = time.time()
            success = True
            
            try:
                if OTEL_AVAILABLE and tracer:
                    with tracer.start_as_current_span(f"skill.{name}") as span:
                        span.set_attribute("skill.name", name)
                        return func(*args, **kwargs)
                else:
                    return func(*args, **kwargs)
            except Exception as e:
                success = False
                raise
            finally:
                duration = time.time() - start
                stats.record_skill(duration, success)
        
        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper
    
    return decorator


@contextmanager
def trace_span(name: str, attributes: dict = None):
    """
    Context manager for custom spans.
    
    Usage:
        with trace_span("my_operation", {"key": "value"}):
            do_something()
    """
    start = time.time()
    
    if OTEL_AVAILABLE and tracer:
        with tracer.start_as_current_span(name) as span:
            if attributes:
                for k, v in attributes.items():
                    span.set_attribute(k, v)
            yield span
    else:
        yield None
    
    duration = time.time() - start
    logger.debug(f"Span {name} took {duration:.2f}s")


def get_tracing_stats() -> dict:
    """Get current tracing statistics."""
    return {
        "otel_available": OTEL_AVAILABLE,
        **stats.get_stats()
    }
