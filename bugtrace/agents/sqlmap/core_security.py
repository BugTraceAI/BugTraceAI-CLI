"""
SQLMap Core

PURE functions for SQLMap command building, result parsing,
security validation, data structures, DB fingerprinting,
and WAF bypass strategy.

Extracted from sqlmap_agent.py for modularity.
"""

import re
import json
import hashlib
import base64
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bugtrace.agents.sqlmap.core_types import SAFE_COOKIE_VALUE_PATTERN, SAFE_HEADER_NAME_PATTERN


# =============================================================================
# SECURITY VALIDATION PATTERNS
# =============================================================================

# Regex for safe cookie values (alphanumeric, dash, underscore, equals, dot, slash)
def validate_cookie_value(name: str, value: str, logger=None) -> str:  # PURE
    """
    Validate cookie value to prevent command injection (TASK-32).

    Args:
        name: Cookie name for error messages
        value: Cookie value to validate
        logger: Optional logger for warnings

    Returns:
        Validated value

    Raises:
        ValueError: If value contains dangerous characters
    """
    if not value:
        return value

    # Check for shell metacharacters and SQLMap injection chars
    dangerous_chars = [';', '|', '&', '$', '`', '\n', '\r', '\x00', '--', '#']
    for char in dangerous_chars:
        if char in value:
            raise ValueError(f"Cookie '{name}' contains dangerous character: {repr(char)}")

    # Allow URL-encoded values but validate the pattern
    if not SAFE_COOKIE_VALUE_PATTERN.match(value):
        # Log warning but allow if it's just unusual characters
        if logger:
            logger.warning(f"Cookie '{name}' has unusual characters, sanitizing")
        # Strip anything that's not alphanumeric or safe chars
        value = re.sub(r'[^a-zA-Z0-9_\-=./%+]', '', value)

    return value

def validate_header(name: str, value: str) -> Tuple[str, str]:  # PURE
    """
    Validate HTTP header to prevent injection attacks (TASK-33).

    Args:
        name: Header name
        value: Header value

    Returns:
        Tuple of (validated_name, validated_value)

    Raises:
        ValueError: If header contains newlines or null bytes
    """
    # Check for CRLF injection (HTTP Response Splitting)
    dangerous_chars = ['\n', '\r', '\x00']

    for char in dangerous_chars:
        if char in name:
            raise ValueError(f"Header name contains dangerous character: {repr(char)}")
        if char in value:
            raise ValueError(f"Header '{name}' value contains dangerous character: {repr(char)}")

    # Validate header name format
    if not SAFE_HEADER_NAME_PATTERN.match(name):
        raise ValueError(f"Invalid header name format: {name}")

    return name, value

def validate_post_data(data: str, logger=None) -> str:  # PURE
    """
    Validate POST data to prevent command injection (TASK-30).

    Args:
        data: POST data string
        logger: Optional logger for warnings

    Returns:
        Validated data string

    Note:
        POST data can legitimately contain special characters for SQL testing,
        so we only block shell metacharacters that could escape the subprocess.
    """
    if not data:
        return data

    # Block shell escape sequences that could break out of subprocess
    shell_escape_patterns = [
        r'\$\(',      # Command substitution $(...)
        r'`[^`]+`',   # Backtick command substitution
        r'\|\s*\w+',  # Pipe to command
        r';\s*\w+',   # Command chaining with ;
        r'&&\s*\w+',  # Command chaining with &&
        r'\|\|\s*\w+', # Command chaining with ||
    ]

    for pattern in shell_escape_patterns:
        if re.search(pattern, data):
            if logger:
                logger.warning(f"POST data contains potential shell escape: {pattern}")
            # Remove the dangerous pattern
            data = re.sub(pattern, '', data)

    return data

def strip_ansi_codes(text: str) -> str:  # PURE
    """
    Strip ANSI escape codes from text (TASK-34).

    Args:
        text: Text potentially containing ANSI codes

    Returns:
        Clean text without ANSI codes
    """
    if not text:
        return text
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

