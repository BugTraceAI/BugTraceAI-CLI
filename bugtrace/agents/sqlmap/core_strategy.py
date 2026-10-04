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
from bugtrace.agents.sqlmap.core_types import DBType, SQLMapConfig, SQLiEvidence

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

