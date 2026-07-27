"""
IDOR Patterns - Pure Functions

Pure functions for ID pattern detection (numeric, UUID, hash, encoded),
resource type inference from URL patterns, and app context inference.

All functions are PURE: no side effects, no self, data as parameters.
"""

import re
import uuid
from typing import List, Tuple
from urllib.parse import urlparse


def detect_id_format(original_value: str) -> Tuple[str, List[str]]:
    """Detect ID format and generate test IDs.

    Args:
        original_value: The original parameter value

    Returns:
        Tuple of (format_type, list_of_test_ids)
        format_type: "numeric", "uuid", "hash_md5", "hash_sha1",
                     "timestamp", "alphanumeric", "unknown"
    """  # PURE
    if not original_value:
        return "numeric", []

    # UUID v4 format (8-4-4-4-12 hex chars)
    if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$', original_value, re.I):
        test_ids = [str(uuid.uuid4()) for _ in range(10)]
        return "uuid", test_ids

    # MD5 hash (32 hex chars)
    if re.match(r'^[0-9a-f]{32}$', original_value, re.I):
        test_ids = []
        for i in range(10):
            modified = original_value[:-1] + format(i, 'x')
            test_ids.append(modified)
        return "hash_md5", test_ids

    # SHA1 hash (40 hex chars)
    if re.match(r'^[0-9a-f]{40}$', original_value, re.I):
        test_ids = []
        for i in range(10):
            modified = original_value[:-1] + format(i, 'x')
            test_ids.append(modified)
        return "hash_sha1", test_ids

    # Unix timestamp (10 digits)
    if re.match(r'^\d{10}$', original_value):
        base_ts = int(original_value)
        test_ids = [str(base_ts + i) for i in range(-5, 5) if i != 0]
        return "timestamp", test_ids

    # Numeric (pure digits) -- generate IDs near the original value
    if original_value.isdigit():
        base = int(original_value)
        above = [str(base + i) for i in range(1, 11)]
        below = [str(base - i) for i in range(1, 3) if base - i > 0]
        return "numeric", above + below

    # Alphanumeric (e.g., "ABC123")
    if re.match(r'^[A-Za-z0-9_-]+$', original_value):
        match = re.match(r'^(.*?)(\d+)$', original_value)
        if match:
            prefix, num = match.groups()
            test_ids = [f"{prefix}{int(num) + i}" for i in range(-5, 6) if i != 0]
            return "alphanumeric", test_ids

    return "unknown", []


def infer_app_context(domain: str, path: str) -> str:
    """Infer application type from domain/path for better LLM context.

    Args:
        domain: Domain name (e.g., "shop.example.com")
        path: URL path (e.g., "/api/products/123")

    Returns:
        Inferred app type string
    """  # PURE
    domain_lower = domain.lower()
    path_lower = path.lower()

    # E-commerce
    if any(kw in domain_lower for kw in ['shop', 'store', 'commerce', 'cart']):
        return "e-commerce"
    if any(kw in path_lower for kw in ['product', 'order', 'cart', 'checkout']):
        return "e-commerce"

    # Social/Blog
    if any(kw in domain_lower for kw in ['social', 'blog', 'forum', 'community']):
        return "social platform"
    if any(kw in path_lower for kw in ['post', 'article', 'comment', 'user', 'profile']):
        return "social platform"

    # SaaS/API
    if 'api' in domain_lower or 'api' in path_lower:
        return "API/SaaS"

    # Admin/Dashboard
    if any(kw in path_lower for kw in ['admin', 'dashboard', 'panel']):
        return "admin panel"

    return "web application"


def generate_horizontal_test_ids(base_id: str, id_format: str, max_count: int) -> List[str]:
    """Generate test IDs for horizontal enumeration.

    Args:
        base_id: Base ID to generate from
        id_format: Detected format type
        max_count: Maximum number of IDs to generate

    Returns:
        List of test ID strings
    """  # PURE
    test_ids = []

    if id_format == "numeric":
        base_int = int(base_id)
        for offset in range(-10, max_count):
            if offset != 0:
                test_ids.append(str(base_int + offset))
    elif id_format == "uuid":
        test_ids = [str(uuid.uuid4()) for _ in range(min(max_count, 20))]
    else:
        test_ids = ["1", "2", "100", "admin", "root", "test"]

    return test_ids[:max_count]


def is_special_account(response_body: str) -> bool:
    """Check if response indicates special/privileged account.

    Args:
        response_body: HTTP response body text

    Returns:
        True if special account markers detected
    """  # PURE
    from bugtrace.agents.idor.types import SPECIAL_MARKERS
    return any(marker in response_body.lower() for marker in SPECIAL_MARKERS)


def detect_privilege_indicators(response_body: str) -> List[str]:
    """Detect privilege indicators in response.

    Args:
        response_body: HTTP response body text

    Returns:
        List of detected indicator type strings
    """  # PURE
    from bugtrace.agents.idor.types import PRIVILEGE_KEYWORDS_MAP

    indicators = []
    body_lower = response_body.lower()

    for indicator_type, keywords in PRIVILEGE_KEYWORDS_MAP.items():
        if any(kw in body_lower for kw in keywords):
            indicators.append(indicator_type)

    return indicators


def is_id_param(param_name: str) -> bool:
    """Check if a parameter name looks like an ID parameter.

    Args:
        param_name: Parameter name string

    Returns:
        True if param looks like an ID parameter
    """  # PURE
    return (
        param_name.endswith('_id') or
        param_name.endswith('Id') or
        param_name.endswith('ID') or
        'user' in param_name.lower() or
        'account' in param_name.lower() or
        'order' in param_name.lower() or
        'profile' in param_name.lower()
    )


def is_id_value(value: str) -> bool:
    """Check if a value looks like an ID (numeric, UUID, hash, base64).

    Args:
        value: Parameter value string

    Returns:
        True if value looks like an ID
    """  # PURE
    if not value:
        return False
    return (
        value.isdigit() or
        bool(re.match(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', value, re.I)) or
        bool(re.match(r'^[a-f0-9]{32,40}$', value, re.I)) or
        bool(re.match(r'^[A-Za-z0-9+/]{20,}={0,2}$', value))
    )


__all__ = [
    "detect_id_format",
    "infer_app_context",
    "generate_horizontal_test_ids",
    "is_special_account",
    "detect_privilege_indicators",
    "is_id_param",
    "is_id_value",
]
