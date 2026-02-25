"""
Result types for functional error handling.

Instead of raising exceptions, return Result values that carry either
success data (Ok) or error information (Err). This makes error paths
explicit in the type system and enables composition via map/flat_map.

Usage:
    result = safe_call(some_function, arg1, arg2)
    if result.is_ok:
        value = result.unwrap()
    else:
        error = result.error

    # Or use map/flat_map for chaining:
    final = (
        safe_call(parse_url, raw_url)
        .map(extract_params)
        .flat_map(validate_params)
    )
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TypeVar, Generic, Callable, Any, List, Union

T = TypeVar("T")
E = TypeVar("E")
U = TypeVar("U")


@dataclass(frozen=True)
class Ok(Generic[T]):
    """Represents a successful result carrying a value."""

    value: T

    @property
    def is_ok(self) -> bool:
        return True

    @property
    def is_err(self) -> bool:
        return False

    def unwrap(self) -> T:
        """Return the contained value."""
        return self.value

    def unwrap_or(self, default: T) -> T:
        """Return the contained value (default is ignored)."""
        return self.value

    def map(self, fn: Callable[[T], U]) -> Result:
        """Apply fn to the contained value, wrapping the result in Ok."""
        return Ok(fn(self.value))

    def flat_map(self, fn: Callable[[T], Result]) -> Result:
        """Apply fn to the contained value; fn must return a Result."""
        return fn(self.value)


@dataclass(frozen=True)
class Err(Generic[E]):
    """Represents a failed result carrying an error."""

    error: E

    @property
    def is_ok(self) -> bool:
        return False

    @property
    def is_err(self) -> bool:
        return True

    def unwrap(self) -> Any:
        """Raise ValueError — there is no success value to unwrap."""
        raise ValueError(f"Called unwrap on Err: {self.error}")

    def unwrap_or(self, default: Any) -> Any:
        """Return the default since this is an error."""
        return default

    def map(self, fn: Callable) -> Result:
        """No-op on Err — propagate the error unchanged."""
        return self

    def flat_map(self, fn: Callable) -> Result:
        """No-op on Err — propagate the error unchanged."""
        return self


Result = Union[Ok, Err]


def collect_results(results: List[Result]) -> Result:
    """
    Collect a list of Results into a single Result.

    If ALL results are Ok, returns Ok(list_of_values).
    If ANY result is Err, returns Err(list_of_errors) with all errors collected.

    Args:
        results: A list of Ok or Err values.

    Returns:
        Ok(values) if all succeeded, Err(errors) if any failed.
    """
    values = []
    errors = []

    for r in results:
        if r.is_ok:
            values.append(r.unwrap())
        else:
            errors.append(r.error)

    if errors:
        return Err(errors)
    return Ok(values)


def safe_call(fn: Callable, *args: Any, **kwargs: Any) -> Result:
    """
    Call fn(*args, **kwargs) and wrap the outcome in a Result.

    Returns Ok(return_value) on success, Err(exception) on any exception.

    Args:
        fn: The function to call.
        *args: Positional arguments forwarded to fn.
        **kwargs: Keyword arguments forwarded to fn.

    Returns:
        Ok with the return value, or Err with the caught exception.
    """
    try:
        return Ok(fn(*args, **kwargs))
    except Exception as e:
        return Err(e)
