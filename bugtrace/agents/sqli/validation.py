"""
SQLi Agent Validation (PURE)

Pure functions for response analysis:
- SQL error detection and database fingerprinting
- Error info extraction (tables, columns, paths, versions)
- Boolean injection analysis
- SQLMap output parsing
- Finding-to-dict conversion

All functions are PURE: no self, no I/O, no mutation.
"""

import re
from typing import Dict, List, Optional, Tuple, Any

from bugtrace.agents.sqli.types import DB_FINGERPRINTS, SQLiFinding
from bugtrace.reporting.standards import (
    get_cwe_for_vuln,
    get_remediation_for_vuln,
)


# =============================================================================
# DATABASE FINGERPRINTING
# =============================================================================

def detect_database_type(response_text: str) -> Optional[str]:
    """
    # PURE
    Fingerprint database type from error messages.

    Args:
        response_text: HTTP response body or error text

    Returns:
        Database name (e.g., "MySQL", "PostgreSQL") or None
    """
    if not response_text:
        return None

    for db_name, patterns in DB_FINGERPRINTS.items():
        for pattern in patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return db_name
    return None


# =============================================================================
# ERROR INFO EXTRACTION
# =============================================================================

def extract_info_from_error(error_response: str) -> Dict:
    """
    # PURE
    Extract useful information from SQL error messages.

    Args:
        error_response: Error response text

    Returns:
        Dict with tables_leaked, columns_leaked, server_paths, db_version, db_type
    """
    info = {
        "tables_leaked": [],
        "columns_leaked": [],
        "server_paths": [],
        "db_version": None,
        "db_type": None,
    }

    if not error_response:
        return info

    info["tables_leaked"] = extract_tables_from_error(error_response)
    info["columns_leaked"] = extract_columns_from_error(error_response)
    info["server_paths"] = extract_paths_from_error(error_response)
    info["db_type"], info["db_version"] = extract_db_version(error_response)

    if not info["db_type"]:
        info["db_type"] = detect_database_type(error_response)

    return info


def extract_tables_from_error(error_response: str) -> List[str]:
    """
    # PURE
    Extract table names from error message.

    Args:
        error_response: Error response text

    Returns:
        Deduplicated list of table names
    """
    table_patterns = [
        r"table ['\"`]?(\w+)['\"`]?",
        r"FROM ['\"`]?(\w+)['\"`]?",
        r"INTO ['\"`]?(\w+)['\"`]?",
        r"UPDATE ['\"`]?(\w+)['\"`]?",
    ]
    tables = []
    for pattern in table_patterns:
        matches = re.findall(pattern, error_response, re.IGNORECASE)
        tables.extend(matches)
    return list(set(tables))


def extract_columns_from_error(error_response: str) -> List[str]:
    """
    # PURE
    Extract column names from error message.

    Args:
        error_response: Error response text

    Returns:
        Deduplicated list of column names
    """
    column_patterns = [
        r"column ['\"`]?(\w+)['\"`]?",
        r"Unknown column ['\"`]?(\w+)['\"`]?",
        r"field ['\"`]?(\w+)['\"`]?",
    ]
    columns = []
    for pattern in column_patterns:
        matches = re.findall(pattern, error_response, re.IGNORECASE)
        columns.extend(matches)
    return list(set(columns))


def extract_paths_from_error(error_response: str) -> List[str]:
    """
    # PURE
    Extract server paths from error message.

    Args:
        error_response: Error response text

    Returns:
        Deduplicated list of server filesystem paths
    """
    path_patterns = [
        r"(/[\w/.-]+\.php)",
        r"(/var/www/[\w/.-]+)",
        r"(C:\\[\w\\.-]+)",
        r"(/home/[\w/.-]+)",
    ]
    paths = []
    for pattern in path_patterns:
        matches = re.findall(pattern, error_response)
        paths.extend(matches)
    return list(set(paths))


def extract_db_version(error_response: str) -> Tuple[Optional[str], Optional[str]]:
    """
    # PURE
    Extract database type and version from error message.

    Args:
        error_response: Error response text

    Returns:
        (db_type, db_version_string) or (None, None)
    """
    version_patterns = [
        r"(MySQL|MariaDB)[\s/]*([\d.]+)",
        r"(PostgreSQL)[\s/]*([\d.]+)",
        r"(Microsoft SQL Server)[\s/]*([\d.]+)",
        r"(Oracle)[\s/]*([\d.]+)",
        r"(SQLite)[\s/]*([\d.]+)",
    ]
    for pattern in version_patterns:
        match = re.search(pattern, error_response, re.IGNORECASE)
        if match:
            return match.group(1), f"{match.group(1)} {match.group(2)}"
    return None, None


# =============================================================================
# BOOLEAN ANALYSIS
# =============================================================================

def is_boolean_vulnerable(true_sim: float, false_sim: float, diff_ratio: float) -> bool:
    """
    # PURE
    Check if boolean-based SQL injection is present.

    Args:
        true_sim: Similarity between baseline and true-condition response
        false_sim: Similarity between baseline and false-condition response
        diff_ratio: Absolute difference between true_sim and false_sim

    Returns:
        True if differential indicates boolean-based SQLi
    """
    return true_sim > 0.9 and false_sim < 0.8 and diff_ratio > 0.15


# =============================================================================
# SQLMAP OUTPUT PARSING
# =============================================================================

def parse_sqlmap_output(output: str) -> Dict:
    """
    # PURE
    Parse raw SQLMap output for reporting details.

    Args:
        output: Raw SQLMap output text

    Returns:
        Dict with injection_type, working_payload, dbms, databases, tables, columns_count
    """
    details = {
        "injection_type": "unknown",
        "working_payload": "",
        "dbms": "unknown",
        "databases": [],
        "tables": [],
        "columns_count": None
    }

    details["working_payload"] = _extract_sqlmap_payload(output)
    details["injection_type"] = _extract_sqlmap_type(output)
    details["dbms"] = _extract_sqlmap_dbms(output)
    details["databases"] = _extract_sqlmap_databases(output)
    details["tables"] = _extract_sqlmap_tables(output)

    return details


def _extract_sqlmap_payload(output: str) -> str:
    """Extract payload from SQLMap output."""
    payload_match = re.search(r"Payload: (.+)", output)
    return payload_match.group(1).strip() if payload_match else ""


def _extract_sqlmap_type(output: str) -> str:
    """Extract injection type from SQLMap output."""
    type_match = re.search(r"Type: (.+)", output)
    return type_match.group(1).strip() if type_match else "unknown"


def _extract_sqlmap_dbms(output: str) -> str:
    """Extract DBMS from SQLMap output."""
    dbms_match = re.search(r"back-end DBMS: (.+)", output)
    return dbms_match.group(1).strip() if dbms_match else "unknown"


def _extract_sqlmap_databases(output: str) -> List[str]:
    """Extract databases from SQLMap output."""
    if "available databases" not in output:
        return []
    dbs = re.findall(r"\[\*\] (.+)", output)
    return [db for db in dbs if not db.startswith("ending") and " " not in db]


def _extract_sqlmap_tables(output: str) -> List[str]:
    """Extract tables from SQLMap output."""
    if "Database:" not in output or "+" not in output:
        return []
    possible_tables = re.findall(r"\| (.+?) \|", output)
    return [t.strip() for t in possible_tables if t.strip() != "table_name"]


# =============================================================================
# FINDING CONVERSION
# =============================================================================

def finding_to_dict(finding: SQLiFinding) -> Dict:
    """
    # PURE
    Convert SQLiFinding object to dictionary for report.

    Args:
        finding: SQLiFinding dataclass instance

    Returns:
        Dictionary representation for JSON serialization
    """
    return {
        "type": finding.type,
        "url": finding.url,
        "parameter": finding.parameter,
        "severity": finding.severity,
        "cwe_id": get_cwe_for_vuln("SQLI"),
        "cve_id": "N/A",
        "remediation": get_remediation_for_vuln("SQLI"),
        "injection_type": finding.injection_type,
        "working_payload": finding.working_payload,
        "payload": finding.working_payload,
        "payload_encoded": finding.payload_encoded,
        "exploit_url": finding.exploit_url,
        "exploit_url_encoded": finding.exploit_url_encoded,
        "columns_detected": finding.columns_detected,
        "column_detection_payload": finding.column_detection_payload,
        "extracted_databases": finding.extracted_databases,
        "extracted_tables": finding.extracted_tables,
        "sample_data": finding.sample_data,
        "dbms_detected": finding.dbms_detected,
        "sqlmap_command": finding.sqlmap_command,
        "curl_command": finding.curl_command,
        "sqlmap_reproduce_command": finding.sqlmap_reproduce_command,
        "validated": finding.validated,
        "evidence": finding.evidence,
        "reproduction_steps": finding.reproduction_steps,
        "status": finding.status,
        "description": finding.exploitation_explanation or f"SQL Injection confirmed in parameter '{finding.parameter}'. Technique: {finding.injection_type}. Payload: {finding.working_payload}",
        "reproduction": "\n".join(finding.reproduction_steps),
        # HTTP evidence fields
        "http_request": finding.evidence.get("http_request", finding.curl_command),
        "http_response": finding.evidence.get("http_response", finding.evidence.get("raw_output", "")[:500] if finding.evidence.get("raw_output") else ""),
        "sqli_metadata": {
            "technique": finding.injection_type,
            "database_type": finding.dbms_detected,
            "detection_tool": "BugTrace SQLi Agent",
            "payload": finding.working_payload,
            "exploit_url": finding.exploit_url,
            "exploit_url_encoded": finding.exploit_url_encoded,
            "extracted_data": {
                "tables": finding.extracted_tables,
                "columns_count": finding.columns_detected,
                "databases": finding.extracted_databases
            },
            "raw_evidence": str(finding.evidence)
        }
    }


def extract_finding_data(finding: Any) -> Dict:
    """
    # PURE
    Extract data from finding (handles both Dict and SQLiFinding).

    Args:
        finding: Either a dict or SQLiFinding instance

    Returns:
        Normalized dict with url, param, technique, db_type, tables, columns
    """
    if isinstance(finding, dict):
        return {
            'url': finding.get('url'),
            'param': finding.get('parameter'),
            'technique': finding.get('technique', 'Unknown'),
            'db_type': finding.get('evidence', {}).get('db_type', 'Unknown'),
            'tables': finding.get('evidence', {}).get('tables_leaked', []),
            'columns': finding.get('evidence', {}).get('columns_leaked', [])
        }
    else:
        return {
            'url': finding.url,
            'param': finding.parameter,
            'technique': finding.injection_type,
            'db_type': finding.dbms_detected,
            'tables': finding.extracted_tables,
            'columns': finding.columns_detected
        }


def build_llm_prompt(finding_data: Dict) -> str:
    """
    # PURE
    Build LLM prompt from finding data.

    Args:
        finding_data: Normalized finding dict

    Returns:
        Formatted prompt string for LLM
    """
    return f"""SQL Injection Finding:
- URL: {finding_data['url']}
- Parameter: {finding_data['param']}
- Technique: {finding_data['technique']}
- Database Type: {finding_data['db_type']}
- Tables Leaked: {finding_data['tables']}
- Columns Leaked: {finding_data['columns']}

Write the exploitation explanation section for the report."""


__all__ = [
    "detect_database_type",
    "extract_info_from_error",
    "extract_tables_from_error",
    "extract_columns_from_error",
    "extract_paths_from_error",
    "extract_db_version",
    "is_boolean_vulnerable",
    "parse_sqlmap_output",
    "finding_to_dict",
    "extract_finding_data",
    "build_llm_prompt",
]
