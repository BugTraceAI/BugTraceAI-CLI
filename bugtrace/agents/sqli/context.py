"""
SQLi Agent Context Detection (PURE)

Pure functions for SQL injection context analysis:
- Confidence tier determination
- Validation status mapping
- Parameter prioritization
- Technique name mapping
- Infrastructure cookie filtering

All functions are PURE: no self, no I/O, no mutation.
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any

from loguru import logger

from bugtrace.agents.sqli.types import (
    DB_FINGERPRINTS,
    HIGH_PRIORITY_SQLI_PARAMS,
    MEDIUM_PRIORITY_PARAMS,
    SQLiConfidenceTier,
)


# =============================================================================
# INFRASTRUCTURE COOKIE FILTER
# =============================================================================

def load_infrastructure_cookies() -> Tuple[set, tuple]:
    """Load infrastructure cookie list and prefixes from JSON data file.

    Returns:
        Tuple of (cookies_set, prefixes_tuple)
    """
    # PURE: reads a static config file at module load time
    data_path = Path(__file__).parent.parent.parent / "config" / "infrastructure_cookies.json"
    try:
        with open(data_path, "r") as f:
            data = json.load(f)
        cookies = set(data.get("cookies", []))
        prefixes = tuple(data.get("prefixes", []))
        logger.debug(f"Loaded {len(cookies)} infrastructure cookies, {len(prefixes)} prefixes from {data_path.name}")
        return cookies, prefixes
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.warning(f"Failed to load infrastructure_cookies.json: {e}. Using empty defaults.")
        return set(), ()


# Module-level constants loaded once
INFRASTRUCTURE_COOKIES, _INFRASTRUCTURE_COOKIE_PREFIXES = load_infrastructure_cookies()


# =============================================================================
# CONFIDENCE HIERARCHY
# =============================================================================

def get_confidence_tier(technique: str, evidence: Dict) -> int:
    """
    # PURE
    Determine confidence tier based on technique and evidence.

    Args:
        technique: SQLi technique name (e.g., "error_based", "union_based")
        evidence: Dict of evidence collected during testing

    Returns:
        3 = MAXIMUM (data extracted, OOB confirmed)
        2 = HIGH (clear SQL error, strong boolean diff)
        1 = MEDIUM (verified time-based, weak boolean)
        0 = LOW (unverified, likely FP)
    """
    # TIER 3: Maximum confidence
    if evidence.get("data_extracted"):
        return SQLiConfidenceTier.MAXIMUM
    if evidence.get("oob_callback_received"):
        return SQLiConfidenceTier.MAXIMUM
    if technique == "union_based" and evidence.get("columns_found"):
        return SQLiConfidenceTier.MAXIMUM
    if technique == "error_based" and evidence.get("tables_leaked"):
        return SQLiConfidenceTier.MAXIMUM

    # TIER 2: High confidence
    if technique == "error_based" and evidence.get("sql_error_visible"):
        return SQLiConfidenceTier.HIGH
    if technique == "boolean_based" and evidence.get("diff_ratio", 0) > 0.5:
        return SQLiConfidenceTier.HIGH
    if technique == "stacked" and evidence.get("execution_confirmed"):
        return SQLiConfidenceTier.HIGH

    # TIER 1: Medium confidence (needs verification)
    if technique == "time_based" and evidence.get("triple_verified"):
        return SQLiConfidenceTier.MEDIUM
    if technique == "boolean_based" and evidence.get("diff_ratio", 0) > 0.2:
        return SQLiConfidenceTier.MEDIUM

    # TIER 0: Low confidence
    return SQLiConfidenceTier.LOW


def determine_validation_status(technique: str, evidence: Dict) -> str:
    """
    # PURE
    Determine validation status based on confidence tier.

    TIER 3, 2 -> VALIDATED_CONFIRMED
    TIER 1 -> PENDING_VALIDATION
    TIER 0 -> POTENTIAL_SQLI (not reported as finding)

    Args:
        technique: SQLi technique name
        evidence: Evidence dict

    Returns:
        Validation status string
    """
    tier = get_confidence_tier(technique, evidence)

    if tier >= SQLiConfidenceTier.HIGH:
        return "VALIDATED_CONFIRMED"
    elif tier >= SQLiConfidenceTier.MEDIUM:
        return "PENDING_VALIDATION"
    else:
        return "POTENTIAL_SQLI"


def should_stop_testing(
    technique: str, evidence: Dict, findings_count: int
) -> Tuple[bool, str]:
    """
    # PURE
    Determine if we should stop based on confidence achieved.

    Args:
        technique: SQLi technique name
        evidence: Evidence dict
        findings_count: Number of findings so far

    Returns:
        (should_stop, reason) tuple
    """
    tier = get_confidence_tier(technique, evidence)

    if tier >= SQLiConfidenceTier.MAXIMUM:
        return True, "MAXIMUM CONFIDENCE: Data extracted or OOB confirmed"

    if tier >= SQLiConfidenceTier.HIGH and findings_count >= 1:
        return True, "HIGH CONFIDENCE: SQL error confirmed"

    if findings_count >= 2:
        return True, "2 findings found, moving on"

    return False, ""


# =============================================================================
# PARAMETER PRIORITIZATION
# =============================================================================

def prioritize_params(params: List[str]) -> List[str]:
    """
    # PURE
    Prioritize parameters by likelihood of SQLi vulnerability.

    Order: High priority -> Medium priority -> Others

    Args:
        params: List of parameter names

    Returns:
        Sorted list with high priority first
    """
    high = []
    medium = []
    low = []

    for param in params:
        param_lower = param.lower()

        # Check high priority
        is_high = any(
            hp == param_lower or hp in param_lower or param_lower in hp
            for hp in HIGH_PRIORITY_SQLI_PARAMS
        )

        # Check medium priority
        is_medium = any(
            mp == param_lower or mp in param_lower
            for mp in MEDIUM_PRIORITY_PARAMS
        )

        if is_high:
            high.append(param)
        elif is_medium:
            medium.append(param)
        else:
            low.append(param)

    return high + medium + low


# =============================================================================
# TECHNIQUE MAPPING
# =============================================================================

def sqlmap_type_to_technique(sqlmap_type: str) -> str:
    """
    # PURE
    Convert SQLMap type to internal technique code.

    Args:
        sqlmap_type: Type string from SQLMap output

    Returns:
        Internal technique name
    """
    sqlmap_type_lower = (sqlmap_type or "").lower()

    if "time" in sqlmap_type_lower or "sleep" in sqlmap_type_lower:
        return "time_based"
    if "error" in sqlmap_type_lower:
        return "error_based"
    if "boolean" in sqlmap_type_lower or "blind" in sqlmap_type_lower:
        return "boolean_based"
    if "union" in sqlmap_type_lower:
        return "union_based"
    if "stack" in sqlmap_type_lower:
        return "stacked"

    return "error_based"


def get_sqlmap_technique_hint(ai_suggestion: str) -> str:
    """
    # PURE
    Convert AI's suggested technique to SQLMap technique codes.

    Args:
        ai_suggestion: Technique suggestion from LLM (e.g., "union", "time-based")

    Returns:
        SQLMap technique codes (E=Error, B=Boolean, U=Union, T=Time, S=Stacked, Q=Inline)
    """
    ai_lower = (ai_suggestion or "").lower()

    if "union" in ai_lower:
        return "U"
    if "time" in ai_lower or "sleep" in ai_lower or "blind" in ai_lower:
        return "BT"
    if "error" in ai_lower:
        return "E"
    if "boolean" in ai_lower:
        return "B"
    if "stack" in ai_lower:
        return "S"

    # Default: try all common techniques (prioritizing faster ones)
    return "EBUT"


def get_technique_name(technique: str) -> str:
    """
    # PURE
    Get human-readable technique name.

    Args:
        technique: Internal technique code

    Returns:
        Human-readable name
    """
    names = {
        "error_based": "Error-Based",
        "time_based": "Time-Based Blind",
        "boolean_based": "Boolean-Based Blind",
        "union_based": "UNION-Based",
        "stacked": "Stacked Queries",
        "oob": "Out-of-Band",
        "second_order": "Second-Order",
    }
    return names.get(technique, "Unknown")


# =============================================================================
# COOKIE FILTERING
# =============================================================================

def should_test_cookie(cookie_name: str) -> bool:
    """
    # PURE
    Check if a cookie should be tested for SQLi.

    Filters out infrastructure cookies (load balancers, CDNs, WAFs) that
    produce false positives from routing behavior changes. Legitimate
    application cookies (session, TrackingId, etc.) pass through.

    Args:
        cookie_name: The cookie name to evaluate.

    Returns:
        True if the cookie should be tested, False if it's infrastructure.
    """
    normalized = cookie_name.lower().strip()

    # Exact match against known infrastructure cookies
    if normalized in INFRASTRUCTURE_COOKIES:
        return False

    # Prefix match for cookie families (e.g. awsalb-*, __cf_*)
    for prefix in _INFRASTRUCTURE_COOKIE_PREFIXES:
        if normalized.startswith(prefix):
            return False

    return True


# =============================================================================
# VALIDATION
# =============================================================================

def validate_sqli_finding(finding: Dict) -> Tuple[bool, str]:
    """
    # PURE
    SQLi-specific validation before emitting a finding.

    Requirements:
    1. Must have evidence of SQL injection (error, time delay, or data extraction)
    2. Payload should look like SQL (not conversational)

    Args:
        finding: Finding dict to validate

    Returns:
        (is_valid, error_message) tuple
    """
    evidence = finding.get("evidence", {})

    # Check for proof of SQL injection
    has_error = evidence.get("error_message") or evidence.get("sql_error")
    has_time = evidence.get("time_delay") or evidence.get("time_based")
    has_data = evidence.get("data_extracted") or evidence.get("extracted_data")

    if not (has_error or has_time or has_data):
        return False, "SQLi requires proof: SQL error, time delay, or data extraction"

    # Payload sanity check (should have SQL syntax or SQL probe chars)
    payload = str(finding.get("payload", ""))
    sql_probe_chars = ["'", '"', ")", "(", "\\"]
    sql_keywords = ['SELECT', 'UNION', 'AND', 'OR', 'SLEEP', 'WAITFOR', '--', '#', ';', 'WHERE']
    has_probe_char = any(c in payload for c in sql_probe_chars)
    has_keyword = any(kw in payload.upper() for kw in sql_keywords)
    if payload and not (has_probe_char or has_keyword):
        return False, f"SQLi payload missing SQL syntax: {payload[:50]}"

    return True, ""


# =============================================================================
# DBMS DETECTION
# =============================================================================

def detect_dbms_from_output(output: str) -> str:
    """
    # PURE
    Detect DBMS type from SQLMap output text.

    Args:
        output: Raw SQLMap output string

    Returns:
        DBMS name string (e.g., "MySQL", "PostgreSQL", "Unknown")
    """
    output_lower = output.lower()
    if "mysql" in output_lower:
        return "MySQL"
    elif "postgresql" in output_lower or "postgres" in output_lower:
        return "PostgreSQL"
    elif "microsoft sql server" in output_lower or "mssql" in output_lower:
        return "MSSQL"
    elif "oracle" in output_lower:
        return "Oracle"
    elif "sqlite" in output_lower:
        return "SQLite"
    return "Unknown"


__all__ = [
    "INFRASTRUCTURE_COOKIES",
    "load_infrastructure_cookies",
    "get_confidence_tier",
    "determine_validation_status",
    "should_stop_testing",
    "prioritize_params",
    "sqlmap_type_to_technique",
    "get_sqlmap_technique_hint",
    "get_technique_name",
    "should_test_cookie",
    "validate_sqli_finding",
    "detect_dbms_from_output",
]
