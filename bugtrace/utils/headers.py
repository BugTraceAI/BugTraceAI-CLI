"""Custom HTTP headers — validation, merging, redaction, and persistence-safe handling.

Public API:
    - RESERVED_HEADER_NAMES:  tuple of header names that cannot be set by users.
    - PROFILE_PROTECTED_HEADER_NAMES:  tuple of names that the auth layer may set
      (Authorization, Cookie); user values still win per the precedence rules.
    - validate_header_name(name):  raise InvalidHeaderError on forbidden names/CRLF.
    - validate_header_value(name, value):  raise InvalidHeaderError on empty/CRLF.
    - parse_header_kv(raw):  parse a "Name: value" string into a 2-tuple.
    - merge_headers(*layers):  case-insensitive merge with right-side precedence.
    - resolve_env_placeholders(headers, env):  expand ${VAR} placeholders.
    - REDACTED:  sentinel value used in place of a secret when serialising.
    - redact_headers(headers):  drop a header entirely from a dict (preferred).
    - redact_text(text):  scan a text blob (raw request/response, log line) and
      replace the value of every sensitive header (Authorization, Cookie, plus
      anything the caller lists) with REDACTED. Header names are never redacted
      — only their values, so the contract is preserved for re-issuance.

Why a separate module:
    BugTraceAI has three header injection points (HTTP orchestrator, GoSpider,
    Nuclei, Playwright/AgenticValidator) and four persistence points
    (findings DB, report JSON, report HTML, log lines). Centralising the
    validation, merge order, and redaction rules here keeps those seven sites
    in lockstep and gives a single home for the tests.

Precedence (low -> high) — applied by merge_headers:
    1. DEFAULT_HEADERS from bugtraceaicli.conf [SCAN] (global, non-sensitive only)
    2. Auto-discovered auth from scan_context.get_auth_headers() (Authorization, Cookie)
    3. Per-scan custom_headers (CLI / API / UI)

    Authorization and Cookie may appear at any layer; the per-scan value always
    wins so a tester can override auto-discovered auth per request.

Security:
    - No header value is ever logged, reported, or persisted.
    - redact_text() scans raw request/response strings and replaces values
      inline. The redactor is intentionally name-aware (Authorization, Cookie,
      Proxy-Authorization, and any caller-listed name) — generic "value=..."
      rewriting would over-redact.
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple

# Sentinel returned by redact_text() in place of a secret value. Chosen so a
# downstream parser that expects a string (e.g. JSON) does not crash, but a
# human reading the log line immediately sees the value was redacted.
REDACTED = "***REDACTED***"

# Header names a user must NEVER be able to set. The HTTP client (aiohttp,
# httpx, requests) sets these automatically; allowing user override would
# either crash the request or let the user break the connection layer.
RESERVED_HEADER_NAMES: Tuple[str, ...] = (
    "Host",
    "Content-Length",
    "Transfer-Encoding",
    "Connection",
    "Upgrade",
)

# Header names the auth-discovery layer is allowed to populate. Users can
# still override them per scan (precedence rule: per-scan > auto-auth).
PROFILE_PROTECTED_HEADER_NAMES: Tuple[str, ...] = (
    "Authorization",
    "Cookie",
)

# Names whose values are treated as secrets for the redaction pass. The list
# is intentionally narrow — if we redact by *prefix* (e.g. "X-Api-*") we
# risk breaking legitimate header inspection. Better to be explicit.
_SENSITIVE_HEADER_NAMES: Tuple[str, ...] = (
    "Authorization",
    "Proxy-Authorization",
    "Cookie",
    "Set-Cookie",
)

# Header values must not contain CR or LF (header injection / request smuggling).
_INVALID_VALUE_CHARS = re.compile(r"[\r\n]")
# RFC 7230 token characters for header names: tchar = "!" / "#" / "$" /
# "%" / "&" / "'" / "*" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"
# / DIGIT / ALPHA. Allow ":" for the legacy "Name: value" parsing path.
_INVALID_NAME_CHARS = re.compile(r"[^\t\x20-\x7e\x80-\xff]")  # controls + non-ASCII


class InvalidHeaderError(ValueError):
    """Raised when a custom header is malformed or forbidden."""


def _normalize(name: str) -> str:
    """Case-insensitive canonical name. RFC 7230 says header names are
    case-insensitive, so we use the lower-cased form as the merge key."""
    return name.strip().lower()


def validate_header_name(name: Any) -> str:
    """Validate a single header name. Return the canonical form on success.

    Raises:
        InvalidHeaderError: empty, contains control/CR/LF, or in RESERVED_HEADER_NAMES.
    """
    if not isinstance(name, str):
        raise InvalidHeaderError(f"header name must be a string, got {type(name).__name__}")
    stripped = name.strip()
    if not stripped:
        raise InvalidHeaderError("header name is empty")
    if "\r" in stripped or "\n" in stripped:
        raise InvalidHeaderError(f"header name contains CR/LF: {name!r}")
    if _INVALID_NAME_CHARS.search(stripped):
        raise InvalidHeaderError(f"header name has invalid characters: {name!r}")
    if stripped.lower() in {n.lower() for n in RESERVED_HEADER_NAMES}:
        raise InvalidHeaderError(
            f"header {stripped!r} is reserved and cannot be set by users "
            f"(reserved: {', '.join(RESERVED_HEADER_NAMES)})"
        )
    return stripped


def validate_header_value(name: str, value: Any) -> str:
    """Validate a single header value. Return the value unchanged on success.

    Raises:
        InvalidHeaderError: not a string, empty after strip, or contains CR/LF.
    """
    if not isinstance(value, str):
        raise InvalidHeaderError(
            f"value for header {name!r} must be a string, got {type(value).__name__}"
        )
    if _INVALID_VALUE_CHARS.search(value):
        raise InvalidHeaderError(
            f"value for header {name!r} contains CR/LF (possible header injection)"
        )
    # We intentionally do NOT reject whitespace-only values here — a
    # legitimately empty header (e.g. `X-Debug:`) is rare but valid. We do
    # reject None / missing values, which is the more common bug.
    return value


def parse_header_kv(raw: str) -> Tuple[str, str]:
    """Parse a 'Name: value' / 'Name=value' string into a 2-tuple.

    Splits on the FIRST occurrence of ':' or '='. Whitespace around the name
    and the value is stripped. The name is validated. An empty value is
    rejected — see validate_header_value for the rationale.

    Raises:
        InvalidHeaderError: malformed string, empty parts, or invalid name.
    """
    if not isinstance(raw, str):
        raise InvalidHeaderError(f"header spec must be a string, got {type(raw).__name__}")
    text = raw.strip()
    if not text:
        raise InvalidHeaderError("header spec is empty")

    # Prefer ':' (canonical), fall back to '='. Split only once.
    for sep in (":", "="):
        if sep in text:
            name, _, value = text.partition(sep)
            break
    else:
        raise InvalidHeaderError(
            f"header spec {raw!r} must contain ':' or '=' (e.g. 'X-Bug: bounty')"
        )

    name = validate_header_name(name)
    value = validate_header_value(name, value.strip())
    if not value:
        raise InvalidHeaderError(f"value for header {name!r} is empty")
    return name, value


def resolve_env_placeholders(
    headers: Mapping[str, str],
    env: Optional[Mapping[str, str]] = None,
) -> Dict[str, str]:
    """Expand ${VAR} / $VAR references inside header values.

    Why: the design rule says secrets must come from environment variables, not
    from the .conf file. So a user can write
        DEFAULT_HEADERS_JSON = '{"X-Api-Key": "${MY_API_KEY}"}'
    and the value is expanded at use time. We never log the expanded result —
    callers that need to log must pass the unresolved map.

    Unknown variables are left as literal text (matches shell behaviour and
    avoids accidentally treating a stray "$" as an error).
    """
    env_map = env if env is not None else os.environ
    out: Dict[str, str] = {}
    for name, value in headers.items():
        if "${" in value:
            def _replace(match: "re.Match[str]") -> str:
                key = match.group(1)
                return env_map.get(key, match.group(0))
            value = re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", _replace, value)
        out[name] = value
    return out


def merge_headers(*layers: Optional[Mapping[str, str]]) -> Dict[str, str]:
    """Merge header layers with right-wins precedence.

    Layer 0 (left-most) is the lowest priority. Reserved names are filtered
    out as a defence-in-depth check — the validator on the public entry
    points already rejects them, but a programmatic call into merge_headers
    should never let a reserved name leak through.

    Returns a NEW dict (caller may freely mutate the result).
    """
    reserved_lower = {n.lower() for n in RESERVED_HEADER_NAMES}
    out: Dict[str, str] = {}
    for layer in layers:
        if not layer:
            continue
        for raw_name, value in layer.items():
            try:
                name = validate_header_name(raw_name)
            except InvalidHeaderError:
                # Defence in depth: never merge a forbidden name, no matter
                # which layer it came from.
                continue
            key = name.lower()
            if key in reserved_lower:
                continue
            out[key] = value
    # Restore Title-Case-ish keys (just the raw validated name) for
    # downstream consumers that expect HTTP/1.1 form. aiohttp / httpx are
    # case-insensitive, so this is purely cosmetic.
    return {name: value for name, value in ((n, out[n]) for n in out)}


def parse_default_headers_json(raw: Optional[str]) -> Dict[str, str]:
    """Parse DEFAULT_HEADERS_JSON (a JSON object string) into a header dict.

    The .conf file is INI; we store a single JSON string. We fail loudly on
    malformed input — silently ignoring it would be a security risk (users
    would believe the headers are being sent when they are not).

    Returns {} when raw is empty or None.
    """
    import json

    if not raw:
        return {}
    text = raw.strip()
    if not text:
        return {}
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as e:
        raise InvalidHeaderError(
            f"DEFAULT_HEADERS_JSON is not valid JSON: {e}. "
            f"Refusing to start: a malformed global header config could mask "
            f"missing authentication and produce silent scan misconfiguration."
        ) from e
    if not isinstance(parsed, dict):
        raise InvalidHeaderError(
            f"DEFAULT_HEADERS_JSON must be a JSON object (got {type(parsed).__name__})"
        )
    out: Dict[str, str] = {}
    for k, v in parsed.items():
        name = validate_header_name(k)
        value = validate_header_value(name, v)
        if not value:
            # Silently drop empty entries — the alternative is to refuse to
            # start the whole scan over a typo in the .conf.
            continue
        out[name] = value
    return out


def redact_headers(headers: Optional[Mapping[str, str]]) -> Dict[str, str]:
    """Return a copy of headers with every sensitive value replaced by REDACTED.

    Used when persisting to a finding, a report, or a JSON dump. The header
    NAME is preserved so downstream parsers can still tell the request was
    authenticated, just not what the credential was.
    """
    sensitive = {n.lower() for n in _SENSITIVE_HEADER_NAMES}
    if not headers:
        return {}
    return {
        name: (REDACTED if name.lower() in sensitive else value)
        for name, value in headers.items()
    }


# Regex to find "Name: value" lines inside a raw HTTP message. Anchored to
# the start of a line (multiline) so we don't redact substrings inside a body.
_HEADER_LINE_RE = re.compile(
    r"(?im)^([A-Za-z][A-Za-z0-9\-]*)\s*:\s*(.*?)\s*$"
)

# Lines that look like HTTP status lines (e.g. "HTTP/1.1 200 OK") or
# request lines ("GET / HTTP/1.1") are never treated as header lines, even
# though they share the structure. We strip them explicitly so the regex
# below cannot match them.
_STATUS_OR_REQUEST_RE = re.compile(r"^(?:HTTP/|\w+\s+\S+\s+HTTP/)", re.IGNORECASE)


def redact_text(text: str, extra_names: Iterable[str] = ()) -> str:
    """Scan a raw HTTP request/response (or log line) and replace secret values.

    Replaces ONLY values, never header names, so a reader can still see
    "Authorization: ***REDACTED***" — preserving the contract of "this
    request was authenticated" without leaking the credential.

    Args:
        text: Arbitrary text. Returned unchanged if empty.
        extra_names: Additional header names to treat as sensitive. Names
            are matched case-insensitively.

    Notes:
        - We never raise on parse errors. The redactor is a best-effort pass
          and is invoked inside log / persist paths where exceptions are
          unacceptable.
        - We intentionally do NOT redact query parameters or JSON bodies.
          A future iteration can add a body redaction pass if a specific
          finding needs it.
    """
    if not text:
        return text
    sensitive = {n.lower() for n in _SENSITIVE_HEADER_NAMES}
    sensitive.update(n.lower() for n in extra_names)

    def _replace(match: "re.Match[str]") -> str:
        name = match.group(1)
        # Skip non-header lines (status / request lines).
        if _STATUS_OR_REQUEST_RE.match(match.group(0)):
            return match.group(0)
        if name.lower() in sensitive:
            return f"{name}: {REDACTED}"
        return match.group(0)

    return _HEADER_LINE_RE.sub(_replace, text)


__all__ = [
    "REDACTED",
    "RESERVED_HEADER_NAMES",
    "PROFILE_PROTECTED_HEADER_NAMES",
    "InvalidHeaderError",
    "validate_header_name",
    "validate_header_value",
    "parse_header_kv",
    "resolve_env_placeholders",
    "merge_headers",
    "parse_default_headers_json",
    "redact_headers",
    "redact_text",
]
