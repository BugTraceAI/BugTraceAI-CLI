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


# =============================================================================
# SECURITY VALIDATION PATTERNS
# =============================================================================

# Regex for safe cookie values (alphanumeric, dash, underscore, equals, dot, slash)
from bugtrace.agents.sqlmap.core_types import SQLMapConfig, DBType, SQLiEvidence
from bugtrace.agents.sqlmap.core_security import validate_cookie_value, validate_header, validate_post_data
from bugtrace.agents.sqlmap.core_strategy import DBFingerprinter

def build_base_command(url: str, config: SQLMapConfig) -> List[str]:  # PURE
    """Build base SQLMap command with core options.

    Args:
        url: Target URL
        config: SQLMap configuration

    Returns:
        Base command arguments list
    """
    return [
        "-u", url,
        "--batch",
        f"--level={config.level}",
        f"--risk={config.risk}",
        f"--technique={config.technique}",
        f"--timeout={config.timeout}",
        f"--retries={config.retries}",
        f"--threads={config.threads}",
        "--parse-errors",
        "--flush-session",
        "--output-dir=/tmp"
    ]

def is_likely_base64(value: str) -> bool:  # PURE
    """Check if a value looks like Base64 encoding.

    Args:
        value: String to check

    Returns:
        True if value appears to be Base64 encoded
    """
    if not value or len(value) < 4:
        return False

    # Base64 typically has these characteristics:
    # - Length is multiple of 4 (or close with padding)
    # - Contains only A-Z, a-z, 0-9, +, /, =
    # - May end with = or == for padding
    base64_pattern = re.compile(r'^[A-Za-z0-9+/]+=*$')
    if not base64_pattern.match(value):
        return False

    # Try to decode it - if it works, likely Base64
    try:
        # Add padding if needed
        padded = value + '=' * (4 - len(value) % 4) if len(value) % 4 else value
        decoded = base64.b64decode(padded, validate=True)
        # Check if decoded value looks like text (not binary garbage)
        try:
            decoded.decode('utf-8')
            return True
        except UnicodeDecodeError:
            # Could still be valid Base64 of binary data
            return len(value) >= 8  # Longer encoded values more likely to be Base64
    except Exception:
        return False

def add_cookies_to_command(
    cmd: List[str],
    cookies: List[Dict],
    logger=None,
) -> None:  # PURE (mutates cmd in-place)
    """Add cookies to command (TASK-32).

    IMPROVED (2026-01-30): Enable cookie injection testing, not just authentication.
    SQLMap at level >= 2 tests cookies, but we need proper configuration.

    Args:
        cmd: Command list to append to (mutated in-place)
        cookies: List of cookie dicts with 'name' and 'value'
        logger: Optional logger
    """
    if not cookies:
        return

    try:
        validated_cookies = []
        base64_cookies = []
        cookie_names = []

        for c in cookies:
            name = c.get('name', '')
            value = c.get('value', '')
            validated_value = validate_cookie_value(name, value, logger=logger)
            validated_cookies.append(f"{name}={validated_value}")
            cookie_names.append(name)

            # Detect Base64-encoded cookies for special handling
            if is_likely_base64(validated_value):
                base64_cookies.append(name)
                if logger:
                    logger.info(f"Detected Base64-encoded cookie: {name}")

        cookie_str = "; ".join(validated_cookies)
        cmd.append(f"--cookie={cookie_str}")

        # Enable cookie injection testing explicitly
        cmd.append("--cookie-del=;")

        # Tell SQLMap to test ALL cookies explicitly
        if cookie_names:
            cmd.extend(["-p", ",".join(cookie_names)])
            if logger:
                logger.info(f"Explicitly testing cookie parameters: {cookie_names}")

        # For Base64 cookies, add special handling
        for b64_cookie in base64_cookies:
            cmd.append(f"--base64={b64_cookie}")
            if logger:
                logger.info(f"Enabled Base64 decoding for cookie: {b64_cookie}")

    except ValueError as e:
        if logger:
            logger.warning(f"Invalid cookie skipped: {e}")

def add_headers_to_command(
    cmd: List[str],
    headers: Dict[str, str],
    logger=None,
) -> None:  # PURE (mutates cmd in-place)
    """Add custom headers to command (TASK-33).

    Args:
        cmd: Command list to append to (mutated in-place)
        headers: Dict of header name -> value
        logger: Optional logger
    """
    if not headers:
        return

    for name, value in headers.items():
        try:
            validated_name, validated_value = validate_header(name, value)
            cmd.extend(["--header", f"{validated_name}: {validated_value}"])
        except ValueError as e:
            if logger:
                logger.warning(f"Invalid header skipped: {e}")

def add_tamper_scripts_to_command(
    cmd: List[str],
    config: SQLMapConfig,
    db_type: DBType,
) -> None:  # PURE (mutates cmd in-place)
    """Add tamper scripts to command.

    Args:
        cmd: Command list to append to (mutated in-place)
        config: SQLMap configuration
        db_type: Detected database type
    """
    tampers = list(config.tamper_scripts)
    if db_type != DBType.UNKNOWN:
        tampers.extend(DBFingerprinter.get_recommended_tampers(db_type))

    if tampers:
        # Deduplicate while preserving order
        seen = set()
        unique_tampers = [t for t in tampers if not (t in seen or seen.add(t))]
        cmd.append(f"--tamper={','.join(unique_tampers[:5])}")

def build_full_command(
    url: str,
    param: Optional[str],
    config: SQLMapConfig,
    post_data: Optional[str],
    db_type: DBType,
    cookies: List[Dict] = None,
    headers: Dict[str, str] = None,
    logger=None,
) -> List[str]:  # PURE
    """Build complete SQLMap command with all options.

    Security: All user inputs are validated before being added to command.
    (TASK-30, TASK-32, TASK-33)

    Args:
        url: Target URL
        param: Parameter to test
        config: SQLMap configuration
        post_data: POST body data
        db_type: Detected database type
        cookies: List of cookie dicts
        headers: Dict of custom headers
        logger: Optional logger

    Returns:
        Complete command arguments list
    """
    cmd = build_base_command(url, config)

    if config.random_agent:
        cmd.append("--random-agent")

    if param:
        cmd.extend(["-p", param])

    if post_data:
        validated_post_data = validate_post_data(post_data, logger=logger)
        cmd.extend(["--data", validated_post_data])

    add_cookies_to_command(cmd, cookies or [], logger=logger)
    add_headers_to_command(cmd, headers or {}, logger=logger)
    add_tamper_scripts_to_command(cmd, config, db_type)

    if config.extract_dbs:
        cmd.append("--dbs")

    return cmd

def build_reproduction_command(
    url: str,
    param: Optional[str],
    config: SQLMapConfig,
    post_data: Optional[str],
    cookies: List[Dict] = None,
) -> str:  # PURE
    """Build human-readable reproduction command.

    Args:
        url: Target URL
        param: Parameter to test
        config: SQLMap configuration
        post_data: POST body data
        cookies: List of cookie dicts

    Returns:
        Human-readable SQLMap command string
    """
    cmd = f"sqlmap -u '{url}' --batch --level={config.level} --risk={config.risk} --technique={config.technique}"

    if param:
        cmd += f" -p {param}"
    if post_data:
        cmd += f" --data='{post_data}'"
    if cookies:
        cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
        cmd += f" --cookie='{cookie_str}'"
    if config.tamper_scripts:
        cmd += f" --tamper={','.join(config.tamper_scripts)}"

    return cmd

def build_docker_command(docker_cmd: str, cmd: List[str]) -> List[str]:  # PURE
    """Build Docker command for SQLMap execution.

    Args:
        docker_cmd: Path to docker binary
        cmd: SQLMap arguments

    Returns:
        Full Docker + SQLMap command list
    """
    full_cmd = [docker_cmd, "run", "--rm", "--network", "host"]
    full_cmd.append("googlesky/sqlmap:latest")
    full_cmd.extend(cmd)
    return full_cmd

def build_extraction_command(
    url: str,
    param: Optional[str],
    cookies: List[Dict] = None,
) -> List[str]:  # PURE
    """Build SQLMap data extraction command.

    Args:
        url: Target URL
        param: Parameter name
        cookies: List of cookie dicts

    Returns:
        Docker + SQLMap extraction command list
    """
    cmd = [
        "docker", "run", "--rm", "--network", "host",
        "googlesky/sqlmap:latest",
        "-u", url,
        "--batch",
        "--dbs",
        "--threads=4"
    ]

    if param:
        cmd.extend(["-p", param])

    if cookies:
        cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
        cmd.append(f"--cookie={cookie_str}")

    return cmd

