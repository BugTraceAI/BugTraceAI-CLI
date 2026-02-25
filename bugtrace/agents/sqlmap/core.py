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
SAFE_COOKIE_VALUE_PATTERN = re.compile(r'^[a-zA-Z0-9_\-=./%+]+$')
# Regex for safe header names (alphanumeric, dash)
SAFE_HEADER_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9\-]+$')


# =============================================================================
# DATA STRUCTURES
# =============================================================================

class DBType(Enum):  # PURE
    """Known database types for fingerprinting."""
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    MSSQL = "mssql"
    ORACLE = "oracle"
    SQLITE = "sqlite"
    UNKNOWN = "unknown"


@dataclass
class SQLMapConfig:  # PURE
    """Advanced SQLMap configuration for intelligent scanning."""
    # Basic
    level: int = 5  # 1-5, higher = more payloads (increased from 2 for better coverage)
    risk: int = 3   # 1-3, higher = more risky payloads (increased from 2 for comprehensive testing)
    # IMPROVED (2026-01-23): No Time-Based by default to reduce false positives
    # Time-based (T) causes many FPs due to network latency
    technique: str = "BEUS"  # B=Boolean, E=Error, U=Union, S=Stacked (NO T=Time)

    # Timeouts
    timeout: int = 30
    retries: int = 3

    # WAF Bypass
    tamper_scripts: List[str] = field(default_factory=list)
    random_agent: bool = True

    # Headers to test (disabled - requires different implementation)
    # 2026-01-23: Header injection testing not yet implemented correctly
    test_headers: bool = False
    headers_to_test: List[str] = field(default_factory=lambda: [
        "User-Agent", "Referer", "X-Forwarded-For", "X-Real-IP"
    ])

    # Data extraction
    extract_dbs: bool = True
    extract_tables: bool = True
    extract_columns: bool = False  # Only on confirmed vulns

    # Performance
    threads: int = 4
    bulk_file: Optional[str] = None  # For batch URL testing


@dataclass
class SQLiEvidence:  # PURE
    """Evidence collected during SQLi validation."""
    vulnerable: bool = False
    db_type: DBType = DBType.UNKNOWN
    injection_type: str = ""  # error-based, time-based, etc.
    parameter: str = ""
    payload: str = ""
    extracted_data: Dict[str, Any] = field(default_factory=dict)
    reproduction_command: str = ""
    output_snippet: str = ""
    confidence: float = 0.0
    tamper_used: Optional[str] = None


# =============================================================================
# SECURITY VALIDATION FUNCTIONS (TASK-30, TASK-32, TASK-33)
# =============================================================================

def validate_cookie_value(name: str, value: str, logger=None) -> str:  # PURE
    """
    Validate cookie value to prevent command injection (TASK-32).

    Args:
        name: Cookie name for error messages
        value: Cookie value to validate
        logger: Optional logger for warnings

    Returns:
        Validated value

    Raises:
        ValueError: If value contains dangerous characters
    """
    if not value:
        return value

    # Check for shell metacharacters and SQLMap injection chars
    dangerous_chars = [';', '|', '&', '$', '`', '\n', '\r', '\x00', '--', '#']
    for char in dangerous_chars:
        if char in value:
            raise ValueError(f"Cookie '{name}' contains dangerous character: {repr(char)}")

    # Allow URL-encoded values but validate the pattern
    if not SAFE_COOKIE_VALUE_PATTERN.match(value):
        # Log warning but allow if it's just unusual characters
        if logger:
            logger.warning(f"Cookie '{name}' has unusual characters, sanitizing")
        # Strip anything that's not alphanumeric or safe chars
        value = re.sub(r'[^a-zA-Z0-9_\-=./%+]', '', value)

    return value


def validate_header(name: str, value: str) -> Tuple[str, str]:  # PURE
    """
    Validate HTTP header to prevent injection attacks (TASK-33).

    Args:
        name: Header name
        value: Header value

    Returns:
        Tuple of (validated_name, validated_value)

    Raises:
        ValueError: If header contains newlines or null bytes
    """
    # Check for CRLF injection (HTTP Response Splitting)
    dangerous_chars = ['\n', '\r', '\x00']

    for char in dangerous_chars:
        if char in name:
            raise ValueError(f"Header name contains dangerous character: {repr(char)}")
        if char in value:
            raise ValueError(f"Header '{name}' value contains dangerous character: {repr(char)}")

    # Validate header name format
    if not SAFE_HEADER_NAME_PATTERN.match(name):
        raise ValueError(f"Invalid header name format: {name}")

    return name, value


def validate_post_data(data: str, logger=None) -> str:  # PURE
    """
    Validate POST data to prevent command injection (TASK-30).

    Args:
        data: POST data string
        logger: Optional logger for warnings

    Returns:
        Validated data string

    Note:
        POST data can legitimately contain special characters for SQL testing,
        so we only block shell metacharacters that could escape the subprocess.
    """
    if not data:
        return data

    # Block shell escape sequences that could break out of subprocess
    shell_escape_patterns = [
        r'\$\(',      # Command substitution $(...)
        r'`[^`]+`',   # Backtick command substitution
        r'\|\s*\w+',  # Pipe to command
        r';\s*\w+',   # Command chaining with ;
        r'&&\s*\w+',  # Command chaining with &&
        r'\|\|\s*\w+', # Command chaining with ||
    ]

    for pattern in shell_escape_patterns:
        if re.search(pattern, data):
            if logger:
                logger.warning(f"POST data contains potential shell escape: {pattern}")
            # Remove the dangerous pattern
            data = re.sub(pattern, '', data)

    return data


def strip_ansi_codes(text: str) -> str:  # PURE
    """
    Strip ANSI escape codes from text (TASK-34).

    Args:
        text: Text potentially containing ANSI codes

    Returns:
        Clean text without ANSI codes
    """
    if not text:
        return text
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)


# =============================================================================
# DB FINGERPRINTING
# =============================================================================

class DBFingerprinter:  # PURE
    """
    Fingerprint database type from error messages and behavior.
    This helps select optimal tamper scripts and payloads.
    """

    SIGNATURES = {
        DBType.MYSQL: [
            r"mysql", r"mysqli", r"MariaDB", r"SQL syntax.*MySQL",
            r"Warning.*mysql_", r"MySQLSyntaxErrorException",
            r"com\.mysql\.jdbc", r"SQLSTATE\[HY000\]"
        ],
        DBType.POSTGRESQL: [
            r"PostgreSQL", r"pg_", r"PSQLException", r"org\.postgresql",
            r"ERROR:\s+syntax error at or near", r"SQLSTATE\[42"
        ],
        DBType.MSSQL: [
            r"Microsoft SQL Server", r"ODBC SQL Server Driver",
            r"SQLServer JDBC", r"SqlException", r"Unclosed quotation mark",
            r"mssql", r"Incorrect syntax near"
        ],
        DBType.ORACLE: [
            r"Oracle", r"ORA-\d{5}", r"oracle\.jdbc", r"TNS:",
            r"PLS-\d{5}", r"SP2-\d{4}"
        ],
        DBType.SQLITE: [
            r"SQLite", r"sqlite3", r"SQLITE_", r"unrecognized token",
            r"sqlite\.OperationalError"
        ]
    }

    # Optimal tamper scripts per DB type
    TAMPER_RECOMMENDATIONS = {
        DBType.MYSQL: ["space2comment", "randomcase", "between", "equaltolike"],
        DBType.POSTGRESQL: ["space2comment", "randomcase", "between"],
        DBType.MSSQL: ["space2mssqlblank", "randomcase", "charencode"],
        DBType.ORACLE: ["space2comment", "randomcase"],
        DBType.SQLITE: ["space2comment", "randomcase"],
        DBType.UNKNOWN: ["space2comment", "randomcase", "between"]
    }

    @classmethod
    def fingerprint(cls, response_text: str, logger=None) -> DBType:  # PURE
        """
        Analyze response text to determine database type.

        Args:
            response_text: HTTP response body or error message
            logger: Optional logger

        Returns:
            Detected DBType
        """
        for db_type, patterns in cls.SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    if logger:
                        logger.debug(f"DB Fingerprint: {db_type.value} (matched: {pattern})")
                    return db_type

        return DBType.UNKNOWN

    @classmethod
    def get_recommended_tampers(cls, db_type: DBType) -> List[str]:  # PURE
        """Get recommended tamper scripts for detected DB type."""
        return cls.TAMPER_RECOMMENDATIONS.get(db_type, cls.TAMPER_RECOMMENDATIONS[DBType.UNKNOWN])


# =============================================================================
# WAF DETECTION & BYPASS
# =============================================================================

class WAFBypassStrategy:  # PURE (class methods are pure, async methods are I/O)
    """
    Intelligent WAF detection and bypass strategy.

    Uses the framework's WAF intelligence module:
    - waf_fingerprinter: Detects WAF with multiple techniques
    - strategy_router: Q-Learning based strategy selection
    - encoding_techniques: 12+ encoding methods
    """

    # SQLMap tamper script mapping to framework encoding names
    ENCODING_TO_TAMPER_MAP = {
        "unicode_encode": "charunicodeencode",
        "html_entity_hex": "charencode",
        "html_entity_encode": "htmlencode",
        "double_url_encode": "chardoubleencode",
        "case_mixing": "randomcase",
        "comment_injection": "space2comment",
        "null_byte_injection": "space2mysqldash",
        "whitespace_obfuscation": "space2mssqlblank",
        "backslash_escape": "apostrophemask",
        "overlong_utf8": "charunicodeescape",
    }

    # Fallback tampers per WAF (when strategy_router has no data)
    WAF_TAMPER_FALLBACK = {
        "cloudflare": ["space2comment", "randomcase", "between", "charencode", "equaltolike"],
        "aws_waf": ["space2comment", "randomcase", "charencode"],
        "akamai": ["space2comment", "randomcase", "between", "charunicodeencode"],
        "sucuri": ["space2comment", "randomcase", "between"],
        "modsecurity": ["space2comment", "randomcase", "modsecurityversioned", "modsecurityzeroversioned"],
        "imperva": ["space2comment", "randomcase", "between", "charencode"],
        "f5_bigip": ["space2comment", "randomcase", "charencode"],
        "generic": ["space2comment", "randomcase", "between", "equaltolike", "charencode"],
        "unknown": ["space2comment", "randomcase", "between"]
    }

    @classmethod
    def convert_strategies_to_tampers(cls, strategies: List[str]) -> List[str]:  # PURE
        """Convert encoding technique names to SQLMap tamper scripts."""
        tampers = []
        for strat in strategies:
            if strat in cls.ENCODING_TO_TAMPER_MAP:
                tampers.append(cls.ENCODING_TO_TAMPER_MAP[strat])
            else:
                # Some strategy names might already be tamper names
                tampers.append(strat)
        return tampers

    @classmethod
    def add_fallback_tampers(cls, tampers: List[str], waf_name: str, max_strategies: int):  # PURE
        """Add fallback tampers to reach minimum count."""
        fallback = cls.WAF_TAMPER_FALLBACK.get(waf_name, cls.WAF_TAMPER_FALLBACK["generic"])
        for t in fallback:
            if t not in tampers:
                tampers.append(t)
                if len(tampers) >= max_strategies:
                    break

    @classmethod
    def get_bypass_tampers(cls, waf_name: Optional[str]) -> List[str]:  # PURE
        """
        Get tamper scripts to bypass detected WAF (sync fallback).
        Use get_smart_bypass_strategies() for async Q-Learning based selection.
        """
        if not waf_name:
            return []
        return cls.WAF_TAMPER_FALLBACK.get(waf_name, cls.WAF_TAMPER_FALLBACK["generic"])

    @classmethod
    def record_bypass_result(cls, waf_name: str, strategy_name: str, success: bool, strategy_router_ref=None, logger=None):  # I/O
        """
        Record bypass result for Q-Learning feedback.
        This improves future strategy selection.

        Args:
            waf_name: Detected WAF name
            strategy_name: Strategy/tamper name used
            success: Whether the bypass succeeded
            strategy_router_ref: Reference to strategy_router module
            logger: Optional logger
        """
        try:
            # Convert SQLMap tamper name back to encoding name if needed
            encoding_name = strategy_name
            for enc_name, tamper_name in cls.ENCODING_TO_TAMPER_MAP.items():
                if tamper_name == strategy_name:
                    encoding_name = enc_name
                    break

            if strategy_router_ref:
                strategy_router_ref.record_result(waf_name, encoding_name, success)
            if logger:
                logger.debug(f"Recorded bypass result: {waf_name}/{encoding_name} = {'SUCCESS' if success else 'FAIL'}")
        except Exception as e:
            if logger:
                logger.debug(f"Failed to record bypass result: {e}")


# =============================================================================
# COMMAND BUILDING (PURE)
# =============================================================================

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


# =============================================================================
# RESULT PARSING (PURE)
# =============================================================================

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


# =============================================================================
# EVIDENCE TO FINDING CONVERSION (PURE)
# =============================================================================

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


# =============================================================================
# URL & PARAMETER HELPERS (PURE)
# =============================================================================

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


# =============================================================================
# REPORT BUILDING (PURE)
# =============================================================================

def build_report_header(
    url: str,
    stats: Dict,
    detected_waf: Optional[str],
    detected_db_type: DBType,
    agent_name: str,
) -> str:  # PURE
    """Build report header with summary.

    Args:
        url: Target URL
        stats: Agent statistics
        detected_waf: Detected WAF name
        detected_db_type: Detected database type
        agent_name: Agent name

    Returns:
        Markdown report header string
    """
    import datetime
    return f"""# SQL Injection Report
## Target: {url}
## Date: {datetime.datetime.now().isoformat()}
## Agent: {agent_name}

---

## Summary
- **Parameters Tested:** {stats['params_tested']}
- **Vulnerabilities Found:** {stats['vulns_found']}
- **WAF Bypasses:** {stats['waf_bypassed']}
- **Data Extractions:** {stats['data_extracted']}
- **Detected WAF:** {detected_waf or 'None'}
- **Detected DB Type:** {detected_db_type.value}

---

## Findings

"""


def build_single_finding_report(index: int, finding: Dict) -> str:  # PURE
    """Build markdown for a single finding.

    Args:
        index: Finding number
        finding: Finding dictionary

    Returns:
        Markdown string for finding
    """
    content = f"""### Finding #{index}: {finding['type']} CONFIRMED

| Field | Value |
|-------|-------|
| **URL** | `{finding.get('url', 'N/A')}` |
| **Parameter** | `{finding.get('parameter', 'N/A')}` |
| **Injection Type** | {finding.get('payload', 'N/A')} |
| **DB Type** | {finding.get('db_type', 'unknown')} |
| **Validation Method** | {finding.get('validation_method', 'N/A')} |
| **Confidence** | {finding.get('confidence', 1.0):.0%} |
| **Tamper Used** | {finding.get('tamper_used', 'None')} |

**Reproduction Command:**
```bash
{finding.get('reproduction', 'N/A')}
```

"""
    if finding.get('extracted_data'):
        content += f"""**Extracted Data:**
```json
{json.dumps(finding['extracted_data'], indent=2)}
```

"""

    content += f"""**Evidence:**
```
{finding.get('evidence', 'N/A')[:1000]}
```

---

"""
    return content


def build_report_findings(findings: List[Dict]) -> str:  # PURE
    """Build findings section of report.

    Args:
        findings: List of finding dictionaries

    Returns:
        Combined markdown findings string
    """
    content = ""
    for i, f in enumerate(findings, 1):
        content += build_single_finding_report(i, f)
    return content
