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

from bugtrace.agents.sqli.types import DB_FINGERPRINTS, SQL_ERROR_SIGNATURES, SQLiFinding
from bugtrace.reporting.standards import (
    get_cwe_for_vuln,
    get_remediation_for_vuln,
)


# =============================================================================
# UNION CANARY CONFIRMATION
# =============================================================================

def union_canary_confirms_execution(content: str, canary: str, payload: str) -> bool:
    """
    # PURE
    True only if `canary` is present in `content` because a UNION SELECT actually EXECUTED,
    not because the parameter echoed the raw injected payload back.

    A reflecting parameter prints our injected input back, so the canary shows up WRAPPED in the
    string delimiter we injected — a raw quote (`'canary'`), a backslash-escaped quote (`\\'canary\\'`),
    or an HTML-encoded one (`&apos;canary&apos;` / `&#39;canary&#39;`). A genuine UNION *additionally*
    returns the BARE canary value in a rendered data cell (e.g. ginandjuice `category`, whose UNION
    columns 2 and 5 are displayed). So strip every quote-wrapped occurrence of the canary (all common
    encodings) and, if a BARE occurrence survives, the query executed -> CONFIRM.

    This subtraction is keyed off our own payload (does my input come back wrapped, or as data?),
    NOT a signature list, so it stays target-agnostic. It both REJECTS reflection-only params
    (searchTerm — the old CRITICAL false positive) and CONFIRMS real UNIONs on params that ALSO
    reflect (category — the false NEGATIVE the earlier over-strict guard caused).
    """
    if not content or not canary or canary not in content:
        return False

    # We inject the canary wrapped in SINGLE quotes (`'canary'`), so an echo reflects it wrapped in a
    # single-quote variant — the finite set of ways one quote can be represented: raw `'`,
    # backslash-escaped `\'`, HTML-encoded `&apos;`/`&#39;`, or URL-encoded `%27`/`%2527` (the latter
    # in reflected <a href> query strings). Strip exactly those (NOT double quotes — a `"canary"` is
    # legitimate extracted JSON/attribute DATA). Whatever survives as a BARE canary is rendered UNION
    # output, not echo.
    delim = r"(?:'|\\'|&apos;|&#0*39;|%27|%2527)"
    stripped = re.sub(delim + r"\s*" + re.escape(canary) + r"\s*" + delim, "", content, flags=re.IGNORECASE)

    # A bare canary survived the strip -> it came from an executed UNION column, not from echo.
    return canary in stripped


def make_split_canary(canary: str) -> Tuple[str, str]:
    """
    # PURE
    Split a canary into two non-empty halves for concatenation-based execution proof.
    'BtAcI998' -> ('BtAc', 'I998'). A <2-char canary degrades to (canary, canary) — callers
    always pass a >=8-char canary so this branch is defensive only.
    """
    if len(canary) < 2:
        return canary, canary
    mid = len(canary) // 2
    return canary[:mid], canary[mid:]


def split_union_payloads(canary: str, cols: int, pos: int) -> List[str]:
    """
    # PURE
    Build UNION SELECT payloads whose canary column is ASSEMBLED BY THE DATABASE via string
    concatenation, not injected as a literal. A reflecting parameter echoes the raw expression
    back (`'BtAc'||'I998'` / `CONCAT('BtAc','I998')`) and can NEVER produce the contiguous
    assembled canary `BtAcI998`; only a UNION the database actually EXECUTED returns the
    concatenated value. So the assembled canary appearing in the response is *unfakeable* proof
    of execution — it closes every reflection-encoding gap the subtraction heuristic can't see
    (hex entities `&#x27;`, unicode escapes `\\u0027`, ...).

    Two concat dialects cover the field: `||` (PostgreSQL/Oracle/SQLite/DB2) and `CONCAT(...)`
    (MySQL/MSSQL/PostgreSQL). The value stays STRING-typed, so it fits the TEXT display columns
    real UNIONs land in — no numeric/type-mismatch wall (a bare number in a text column errors
    on strict engines like PostgreSQL).
    """
    left, right = make_split_canary(canary)
    exprs = [f"'{left}'||'{right}'", f"CONCAT('{left}','{right}')"]
    payloads = []
    for expr in exprs:
        cells = ["NULL"] * cols
        cells[pos] = expr
        payloads.append(f"' UNION SELECT {','.join(cells)}-- -")
    return payloads


def split_canary_confirms_execution(content: str, canary: str) -> bool:
    """
    # PURE
    True iff the DATABASE-ASSEMBLED canary appears in `content`. Companion to
    `split_union_payloads`: the injected expression (`'a'||'b'` / `CONCAT('a','b')`) is echoed
    verbatim by a reflecting parameter, so the contiguous assembled canary can appear ONLY if the
    database concatenated and returned it. Unfakeable by reflection — no strip/subtraction needed.
    """
    return bool(content) and bool(canary) and canary in content


def quote_parity_confirms_sqli(
    baseline_status, unbalanced_status, balanced_status
) -> bool:
    """
    # PURE
    Classic error-based SQLi confirmation via QUOTE PARITY.

    An ODD number of quotes breaks the SQL string literal (server errors); an EVEN number
    re-balances it (server returns to normal). So if the healthy baseline errors on a single
    quote (`'`) but recovers on the balanced double quote (`''`), the response status is
    tracking quote parity — which can only happen when the input sits INSIDE a SQL string.
    A generic application crash on `'` would NOT recover on `''`.

    Confirm iff: baseline healthy (<400) AND unbalanced errors (>=500) AND balanced healthy
    (<400). Differential and target-agnostic — no signature list, no DB fingerprint required.
    """
    return (
        isinstance(baseline_status, int) and baseline_status < 400
        and isinstance(unbalanced_status, int) and unbalanced_status >= 500
        and isinstance(balanced_status, int) and balanced_status < 400
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


def has_sql_error_signature(response_text: str) -> bool:
    """
    # PURE
    True only if the response contains an ACTUAL SQL error message (e.g. "You have an error
    in your SQL syntax", "ORA-01756", "SQLITE_ERROR", "unterminated quoted string"), as opposed
    to merely mentioning a database name. Used to gate error-based confirmation so a page that
    just contains "mysql"/"sqlite" (docs, footer, the /api/debug/vulns catalog) is not a false
    positive. Target-agnostic — no baseline required.
    """
    if not response_text:
        return False
    for pattern in SQL_ERROR_SIGNATURES:
        if re.search(pattern, response_text, re.IGNORECASE):
            return True
    return False


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
