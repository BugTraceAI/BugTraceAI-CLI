"""HTTP effect port contracts (Phase 2 foundation).

Protocols only — no httpx/requests/aiohttp imports. Transport adapters will
implement these later; pure code depends on the port, never the client.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Optional, Protocol, runtime_checkable


@dataclass(frozen=True)
class HttpRequestDesc:
    """Immutable description of an outbound HTTP request (effect descriptor)."""

    method: str
    url: str
    headers: Mapping[str, str] = field(default_factory=dict)
    params: Mapping[str, Any] = field(default_factory=dict)
    body: bytes | str | None = None
    timeout_s: float | None = None
    allow_redirects: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "method", (self.method or "GET").upper())
        object.__setattr__(self, "url", str(self.url))
        object.__setattr__(self, "headers", dict(self.headers or {}))
        object.__setattr__(self, "params", dict(self.params or {}))


@dataclass(frozen=True)
class HttpResponseDesc:
    """Immutable snapshot of an HTTP response for pure analysis."""

    status_code: int
    url: str
    headers: Mapping[str, str] = field(default_factory=dict)
    body: str | bytes = ""
    elapsed_s: float | None = None
    request: HttpRequestDesc | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "headers", dict(self.headers or {}))

    @property
    def text(self) -> str:
        if isinstance(self.body, bytes):
            return self.body.decode("utf-8", errors="replace")
        return str(self.body)


@runtime_checkable
class HttpClientPort(Protocol):
    """Narrow outbound HTTP port. Implementations own connection pools/timeouts."""

    async def request(self, desc: HttpRequestDesc) -> HttpResponseDesc:
        """Execute one request described by ``desc`` and return a response snapshot."""
        ...

    async def aclose(self) -> None:
        """Release resources (connections). Safe to call multiple times."""
        ...


def request_desc(
    method: str,
    url: str,
    *,
    headers: Optional[Mapping[str, str]] = None,
    params: Optional[Mapping[str, Any]] = None,
    body: bytes | str | None = None,
    timeout_s: float | None = None,
    allow_redirects: bool = True,
) -> HttpRequestDesc:
    """Factory for request descriptors (pure)."""
    return HttpRequestDesc(
        method=method,
        url=url,
        headers=headers or {},
        params=params or {},
        body=body,
        timeout_s=timeout_s,
        allow_redirects=allow_redirects,
    )
