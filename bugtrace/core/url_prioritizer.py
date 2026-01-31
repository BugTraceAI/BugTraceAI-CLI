"""
URL Prioritization Module for BugTraceAI.

Scores and sorts URLs by security relevance, ensuring high-value targets
(admin, API, login, upload) are scanned before low-priority endpoints.

Author: BugtraceAI Team
Version: 1.0.0
Date: 2026-01-31
"""

from urllib.parse import urlparse, parse_qs
from typing import List, Tuple
from loguru import logger


# High-value path patterns (+10 points each)
DEFAULT_HIGH_PRIORITY_PATHS = [
    'admin', 'login', 'signin', 'signup', 'register',
    'api', 'graphql', 'rest', 'v1', 'v2',
    'upload', 'import', 'export', 'download',
    'auth', 'oauth', 'sso', 'saml', 'jwt',
    'dashboard', 'panel', 'console', 'manage',
    'user', 'account', 'profile', 'settings',
    'payment', 'checkout', 'cart', 'order',
    'search', 'query', 'filter',
    'file', 'document', 'attachment',
    'config', 'debug', 'test', 'dev',
]

# High-value parameter names (+5 points each)
DEFAULT_HIGH_PRIORITY_PARAMS = [
    'id', 'user_id', 'uid', 'account_id',
    'token', 'key', 'secret', 'password', 'pass',
    'file', 'filename', 'path', 'dir', 'folder',
    'url', 'redirect', 'return', 'next', 'goto', 'dest',
    'cmd', 'exec', 'command', 'run',
    'query', 'search', 'q', 's',
    'email', 'mail', 'username', 'login',
    'page', 'template', 'view', 'include',
    'callback', 'webhook', 'notify',
]

# Bonus for having any parameters
HAS_PARAMS_BONUS = 15

# Low-value static extensions (penalty)
LOW_VALUE_EXTENSIONS = ['.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.woff', '.woff2']


def calculate_url_priority(url: str, custom_paths: List[str] = None, custom_params: List[str] = None) -> int:
    """
    Calculate priority score for a URL (higher = more important).

    Scoring:
    - +10 for each high-priority path pattern match
    - +5 for each high-priority parameter name
    - +15 bonus for having any parameters
    - -20 penalty for static file extensions

    Args:
        url: The URL to score
        custom_paths: Additional path patterns to prioritize
        custom_params: Additional parameter names to prioritize

    Returns:
        Priority score (0-100+, higher = scan first)
    """
    score = 0
    parsed = urlparse(url)
    path = parsed.path.lower()
    params = parse_qs(parsed.query)

    # Combine defaults with custom patterns
    high_paths = DEFAULT_HIGH_PRIORITY_PATHS + (custom_paths or [])
    high_params = DEFAULT_HIGH_PRIORITY_PARAMS + (custom_params or [])

    # Check path patterns
    for pattern in high_paths:
        if pattern in path:
            score += 10

    # Check parameter names
    for param in params:
        if param.lower() in high_params:
            score += 5

    # Bonus for having any parameters
    if params:
        score += HAS_PARAMS_BONUS

    # Penalty for static files
    for ext in LOW_VALUE_EXTENSIONS:
        if path.endswith(ext):
            score -= 20
            break

    return max(0, score)


def prioritize_urls(urls: List[str], custom_paths: List[str] = None, custom_params: List[str] = None) -> List[Tuple[str, int]]:
    """
    Sort URLs by priority score (descending).

    Args:
        urls: List of URLs to prioritize
        custom_paths: Additional path patterns to prioritize
        custom_params: Additional parameter names to prioritize

    Returns:
        List of (url, score) tuples sorted by score descending
    """
    scored = [(url, calculate_url_priority(url, custom_paths, custom_params)) for url in urls]
    scored.sort(key=lambda x: (-x[1], x[0]))  # Sort by score desc, then URL asc for stability
    return scored


__all__ = [
    "calculate_url_priority",
    "prioritize_urls",
    "DEFAULT_HIGH_PRIORITY_PATHS",
    "DEFAULT_HIGH_PRIORITY_PARAMS",
]
