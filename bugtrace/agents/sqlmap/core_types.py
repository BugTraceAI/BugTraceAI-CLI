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

SAFE_HEADER_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9\-]+$')


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

