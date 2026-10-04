import shutil
import asyncio
import json
import re
import os
from typing import List, Dict, Optional, Any, Tuple
from urllib.parse import urlparse, urljoin
from bugtrace.utils.logger import get_logger
from bugtrace.utils.parsers import extract_sqlmap_verdict
logger = get_logger("tools.external")
from bugtrace.core.config import settings
from bugtrace.core.ui import dashboard
from bugtrace.core.http_orchestrator import orchestrator, DestinationType
from bugtrace.core.exceptions import (
    ToolError,
    DockerError,
    DockerTimeoutError,
    DockerNotFoundError,
    SubprocessError,
    FuzzerError,
    FuzzerTimeoutError,
    NucleiError,
    JSONParseError,
)

# Security constants for JSON parsing
MAX_JSON_SIZE = 10_000_000  # 10MB max
MAX_JSON_DEPTH = 20

# Whitelist of trusted Docker images (TASK-111)
TRUSTED_DOCKER_IMAGES = frozenset({
    "projectdiscovery/nuclei:latest",
    "projectdiscovery/nuclei",
    "googlesky/sqlmap:latest",
    "googlesky/sqlmap",
    "trickest/gospider",
    "trickest/gospider:latest",
})


def _validate_docker_image(image: str) -> bool:
    """
    Validate Docker image against whitelist.

    Args:
        image: Docker image name with optional tag

    Returns:
        True if image is trusted, False otherwise
    """
    # Normalize image name (remove tag for comparison)
    base_image = image.split(':')[0] if ':' in image else image

    # Check exact match first
    if image in TRUSTED_DOCKER_IMAGES:
        return True

    # Check base image (without tag)
    if base_image in TRUSTED_DOCKER_IMAGES:
        return True

    # Check with :latest suffix
    if f"{base_image}:latest" in TRUSTED_DOCKER_IMAGES:
        return True

    logger.warning(f"Untrusted Docker image blocked: {image}")
    return False


# ANSI escape sequence pattern (TASK-113)
ANSI_ESCAPE_PATTERN = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')


def _sanitize_output(output: str) -> str:
    """
    Sanitize tool output by removing ANSI escape codes and control characters.

    Args:
        output: Raw tool output

    Returns:
        Sanitized output string
    """
    # Remove ANSI escape sequences
    sanitized = ANSI_ESCAPE_PATTERN.sub('', output)

    # Remove other control characters except newlines and tabs
    sanitized = ''.join(
        char for char in sanitized
        if char == '\n' or char == '\t' or (ord(char) >= 32 and ord(char) != 127)
    )

    return sanitized


def _check_json_depth(obj: Any, current_depth: int = 0) -> None:
    """Check JSON nesting depth to prevent DoS attacks."""
    if current_depth > MAX_JSON_DEPTH:
        raise ValueError(f"JSON depth exceeds maximum allowed ({MAX_JSON_DEPTH})")

    if isinstance(obj, dict):
        for value in obj.values():
            _check_json_depth(value, current_depth + 1)
    elif isinstance(obj, list):
        for item in obj:
            _check_json_depth(item, current_depth + 1)


def _parse_tool_output(output: str, max_size: int = MAX_JSON_SIZE) -> Dict:
    """
    Parse and validate tool output JSON securely.

    Args:
        output: Raw JSON string from tool
        max_size: Maximum allowed output size in bytes

    Returns:
        Parsed and validated dict

    Raises:
        ValueError: If output exceeds size limit or depth limit
        json.JSONDecodeError: If invalid JSON
    """
    if len(output) > max_size:
        raise ValueError(f"Tool output too large: {len(output)} bytes (max: {max_size})")

    try:
        data = json.loads(output)
        _check_json_depth(data)
        return data
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON from tool: {e}", exc_info=True)
        raise

