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
from bugtrace.agents.sqlmap.core_types import SQLiEvidence, SQLMapConfig, DBType
from bugtrace.agents.sqlmap.core_security import strip_ansi_codes

def cache_key(url: str, method: str, data: Optional[str]) -> str:  # PURE
    """Generate cache key for SQLMap results (TASK-40).

    Args:
        url: Target URL
        method: HTTP method (GET/POST)
        data: POST data

    Returns:
        SHA256 hash key
    """
    key_string = f"{url}|{method}|{data or ''}"
    return hashlib.sha256(key_string.encode()).hexdigest()

def parse_sqlmap_output(output: str, url: str, param: Optional[str]) -> SQLiEvidence:  # PURE
    """Parse SQLMap output for results.

    2026-01-23 FIX:
    - Extract ALL injection types (not just the first one)
    - Skip banner to capture meaningful output
    - Store clean evidence for reports

    Args:
        output: Raw SQLMap output text
        url: Target URL
        param: Parameter tested

    Returns:
        SQLiEvidence with parsed results
    """
    evidence = SQLiEvidence()

    if not output:
        return evidence

    param_match = re.search(r"Parameter:\s+(.+?)\s+\(", output)
    all_types = re.findall(r"Type:\s+(.+?)[\n\r]", output)

    if param_match or "is vulnerable" in output.lower():
        _populate_vulnerability_evidence(evidence, param_match, all_types, param, output)

    evidence.output_snippet = _extract_meaningful_output(output)
    return evidence

def _populate_vulnerability_evidence(
    evidence: SQLiEvidence,
    param_match: Optional[re.Match],
    all_types: List[str],
    param: Optional[str],
    output: str,
) -> None:  # PURE (mutates evidence in-place)
    """Populate evidence with vulnerability details."""
    evidence.vulnerable = True
    evidence.parameter = param_match.group(1) if param_match else param or "unknown"

    # Store all types found
    evidence.injection_type = ", ".join(all_types) if all_types else "unknown"
    evidence.confidence = 1.0

    _extract_database_info(evidence, output)
    _extract_databases_list(evidence, output)
    _extract_technology_info(evidence, output)
    _extract_union_info(evidence, output)

def _extract_database_info(evidence: SQLiEvidence, output: str) -> None:  # PURE
    """Extract database type and version."""
    db_match = re.search(r"back-end DBMS:\s+(.+?)[\n\r]", output)
    if db_match:
        db_str = db_match.group(1).lower()
        evidence.extracted_data["dbms_full"] = db_match.group(1)
        for db_type in DBType:
            if db_type.value in db_str:
                evidence.db_type = db_type
                break

def _extract_databases_list(evidence: SQLiEvidence, output: str) -> None:  # PURE
    """Extract list of databases found."""
    dbs_section = re.search(r"available databases.*?:\s*\n((?:\[\*\]\s+.+\n)+)", output, re.DOTALL)
    if dbs_section:
        dbs = re.findall(r"\[\*\]\s+(.+)", dbs_section.group(1))
        evidence.extracted_data["databases"] = dbs

def _extract_technology_info(evidence: SQLiEvidence, output: str) -> None:  # PURE
    """Extract web application technology."""
    version_match = re.search(r"web application technology:\s+(.+?)[\n\r]", output, re.IGNORECASE)
    if version_match:
        evidence.extracted_data["technology"] = version_match.group(1)

def _extract_union_info(evidence: SQLiEvidence, output: str) -> None:  # PURE
    """Extract UNION query information."""
    union_match = re.search(r"UNION query.*?(\d+)\s+columns", output, re.IGNORECASE)
    if union_match:
        evidence.extracted_data["union_columns"] = int(union_match.group(1))

    null_match = re.search(r"NULL,?\s*NULL", output)
    if null_match:
        evidence.extracted_data["union_null_based"] = True

def _extract_meaningful_output(output: str) -> str:  # PURE
    """Extract meaningful output, skipping SQLMap banner."""
    meaningful_start = output.find("[*] starting")
    if meaningful_start > 0:
        next_line = output.find("\n", meaningful_start)
        if next_line > 0:
            meaningful_output = output[next_line:].strip()
            vuln_start = meaningful_output.find("Parameter:")
            if vuln_start > 0:
                meaningful_output = meaningful_output[vuln_start:]
            return meaningful_output[:2000]
        else:
            return output[meaningful_start:][:2000]
    else:
        return output[:2000]

def parse_extracted_data(output: str) -> Optional[Dict]:  # PURE
    """Parse extracted data from SQLMap output.

    Args:
        output: SQLMap extraction output

    Returns:
        Dict with extracted data or None
    """
    extracted = {}

    # Databases
    dbs_match = re.search(r"available databases.*?:\s*\n((?:\[\*\]\s+.+\n)+)", output, re.DOTALL)
    if dbs_match:
        extracted["databases"] = re.findall(r"\[\*\]\s+(.+)", dbs_match.group(1))

    # Version
    version_match = re.search(r"back-end DBMS:\s+(.+?)[\n\r]", output)
    if version_match:
        extracted["db_version"] = version_match.group(1)

    return extracted if extracted else None

def check_sqlmap_error_patterns(stdout_text: str, logger=None) -> None:  # PURE
    """Check for SQLMap-specific error patterns (TASK-38).

    Args:
        stdout_text: SQLMap stdout output
        logger: Optional logger
    """
    error_patterns = [
        ("target url is not responding", "TargetUnreachable"),
        ("connection timed out", "ConnectionTimeout"),
        ("no parameter(s) found", "NoParameters"),
        ("unable to connect", "ConnectionFailed"),
    ]
    for pattern, error_type in error_patterns:
        if pattern in stdout_text.lower():
            if logger:
                logger.warning(f"SQLMap error detected: {error_type}")

def check_critical_errors(stderr_text: str) -> None:  # PURE
    """Check for critical error patterns (TASK-38).

    Args:
        stderr_text: SQLMap stderr output

    Raises:
        ConnectionError: If target not reachable
        TimeoutError: If SQLMap needs more time
    """
    if "connection refused" in stderr_text.lower():
        raise ConnectionError("Target not reachable")
    if "not enough time" in stderr_text.lower():
        raise TimeoutError("SQLMap needs more time")

def process_sqlmap_output(
    stdout: bytes,
    stderr: bytes,
    returncode: int,
    max_output_size: int = 10_000_000,
    logger=None,
) -> Tuple[str, str]:  # PURE
    """Process SQLMap output (TASK-34, TASK-37, TASK-38).

    Args:
        stdout: Raw stdout bytes
        stderr: Raw stderr bytes
        returncode: Process return code
        max_output_size: Max output size in bytes
        logger: Optional logger

    Returns:
        Tuple of (cleaned_stdout, cleaned_stderr)
    """
    stdout_text = strip_ansi_codes(stdout.decode())
    stderr_text = strip_ansi_codes(stderr.decode())

    # TASK-37: Limit output size (10MB max)
    if len(stdout_text) > max_output_size:
        if logger:
            logger.warning(f"SQLMap output truncated from {len(stdout_text)} to {max_output_size} bytes")
        stdout_text = stdout_text[:max_output_size]

    # TASK-38: Better error detection
    if returncode != 0:
        if logger:
            logger.error(f"SQLMap failed with return code {returncode}")
            if stderr_text:
                logger.error(f"SQLMap stderr: {stderr_text[:500]}")
        check_critical_errors(stderr_text)

    if stderr_text and ("error" in stderr_text.lower() or returncode != 0):
        if logger:
            logger.warning(f"SQLMap stderr: {stderr_text[:500]}")

    check_sqlmap_error_patterns(stdout_text, logger=logger)

    return stdout_text, stderr_text

