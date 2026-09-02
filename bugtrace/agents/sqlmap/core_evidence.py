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

def evidence_to_finding(evidence: SQLiEvidence, url: str) -> Dict:  # PURE
    """Convert SQLiEvidence to finding dict.

    2026-01-23 FIX: Create human-readable description instead of raw SQLMap output.

    Args:
        evidence: SQLi evidence
        url: Original target URL

    Returns:
        Finding dictionary
    """
    description = build_evidence_description(evidence)
    details = build_evidence_details(evidence, description)

    return {
        "type": "SQLi",
        "url": url,
        "parameter": evidence.parameter,
        "payload": evidence.injection_type,
        "details": json.dumps(details),
        "reproduction": evidence.reproduction_command,
        "validated": True,
        "validation_method": "SQLMap v2",
        "severity": "CRITICAL",
        "status": "VALIDATED_CONFIRMED",
        "evidence": description,
        "note": description,
        # Legacy fields for backward compatibility
        "db_type": evidence.db_type.value,
        "extracted_data": evidence.extracted_data,
        "tamper_used": evidence.tamper_used,
        "confidence": evidence.confidence,
        "raw_sqlmap_output": evidence.output_snippet[:1000]
    }

def build_evidence_description(evidence: SQLiEvidence) -> str:  # PURE
    """Build human-readable description from evidence.

    Args:
        evidence: SQLi evidence

    Returns:
        Multi-line description string
    """
    description_parts = [
        f"SQL Injection vulnerability confirmed via SQLMap.",
        f"Parameter: {evidence.parameter}",
        f"Injection Types: {evidence.injection_type}",
    ]

    if evidence.db_type != DBType.UNKNOWN:
        dbms_full = evidence.extracted_data.get("dbms_full", evidence.db_type.value)
        description_parts.append(f"Database: {dbms_full}")

    if "union_columns" in evidence.extracted_data:
        cols = evidence.extracted_data["union_columns"]
        description_parts.append(f"UNION-based with {cols} columns")

    if "databases" in evidence.extracted_data:
        dbs = evidence.extracted_data["databases"]
        if dbs:
            description_parts.append(f"Databases found: {', '.join(dbs[:5])}")

    if "technology" in evidence.extracted_data:
        description_parts.append(f"Technology: {evidence.extracted_data['technology']}")

    if evidence.tamper_used:
        description_parts.append(f"WAF bypass: {evidence.tamper_used}")

    return "\n".join(description_parts)

def build_evidence_details(evidence: SQLiEvidence, description: str) -> Dict:  # PURE
    """Build metadata dict for detailed storage.

    Args:
        evidence: SQLi evidence
        description: Human-readable description

    Returns:
        Details dictionary
    """
    return {
        "description": description,
        "db_type": evidence.db_type.value,
        "injection_type": evidence.injection_type,
        "tamper_used": evidence.tamper_used,
        "confidence": evidence.confidence,
        "raw_output_snippet": evidence.output_snippet[:1000],
        "reproduction_command": evidence.reproduction_command
    }

def docker_url(url: str) -> str:  # PURE
    """Convert localhost URLs for Docker access.

    Args:
        url: Original URL

    Returns:
        URL with localhost replaced for Docker networking
    """
    return url.replace("127.0.0.1", "172.17.0.1").replace("localhost", "172.17.0.1")

def extract_post_params(post_data: str) -> List[str]:  # PURE
    """Extract parameter names from POST data.

    Args:
        post_data: POST body string

    Returns:
        List of parameter names
    """
    params = []

    # Try URL-encoded format
    if "=" in post_data:
        for pair in post_data.split("&"):
            if "=" in pair:
                params.append(pair.split("=")[0])

    # Try JSON format
    try:
        data = json.loads(post_data)
        if isinstance(data, dict):
            params.extend(data.keys())
    except Exception:
        pass

    return params

def inject_probe_payload(url: str) -> str:  # PURE
    """Inject a simple probe payload to trigger errors.

    Args:
        url: Target URL

    Returns:
        URL with probe payload injected
    """
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    # Pick first param or use 'id'
    if params:
        first_param = list(params.keys())[0]
        params[first_param] = [params[first_param][0] + "'"]
    else:
        params["id"] = ["1'"]

    new_query = urlencode(params, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

def default_error_patterns() -> List[str]:  # PURE
    """Default SQL error patterns.

    IMPROVED (2026-01-30): Added PostgreSQL-specific patterns for ginandjuice.shop.

    Returns:
        List of regex patterns for SQL errors
    """
    return [
        # Generic SQL errors
        r"SQL syntax", r"SQL Error", r"mysql_", r"mysqli_",
        r"Warning:.*\bSQL\b", r"Unclosed quotation mark",
        r"quoted string not properly terminated",
        # PostgreSQL-specific (ADDED 2026-01-30)
        r"PostgreSQL.*ERROR",
        r"pg_query\(\)",
        r"pg_exec\(\)",
        r"PG::SyntaxError",
        r"ERROR:\s+syntax error",
        r"unterminated quoted string",
        r"invalid input syntax",
        r"column.*does not exist",
        # MS SQL Server
        r"ODBC SQL Server Driver",
        r"Incorrect syntax near",
        # SQLite
        r"sqlite3\.OperationalError",
        # Oracle
        r"ORA-\d{5}",
        r"PLS-\d{5}",
        # Other databases
        r"DB2 SQL error", r"Dynamic SQL Error"
    ]

def default_test_payloads() -> List[str]:  # PURE
    """Default test payloads for error detection.

    Returns:
        List of SQL injection test payloads
    """
    return [
        "'",
        "''",
        "1'",
        "1' OR '1'='1",
        "1' AND '1'='2",
        "1; DROP TABLE--",
        "1' UNION SELECT NULL--",
        "1') OR ('1'='1",
        "1\" OR \"1\"=\"1",
        "-1 OR 1=1"
    ]

