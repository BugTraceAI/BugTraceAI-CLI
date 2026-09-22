"""
Consolidation Core

PURE functions for finding classification, deduplication logic,
batch grouping, and severity scoring.

Extracted from thinking_consolidation_agent.py for modularity.
"""

import asyncio
import time
from typing import Dict, List, Any, Optional, Set, Tuple
from collections import OrderedDict
from dataclasses import dataclass, field
from loguru import logger


# =========================================================================
# VULNERABILITY TYPE TO SPECIALIST QUEUE MAPPING
# =========================================================================

VULN_TYPE_TO_SPECIALIST: Dict[str, str] = {
    # XSS variants
    "xss": "xss",
    "cross-site scripting": "xss",
    "reflected xss": "xss",
    "stored xss": "xss",
    "dom xss": "xss",
    "dom-based xss": "xss",

    # SQL Injection variants
    "sql injection": "sqli",
    "sqli": "sqli",
    "sql": "sqli",
    "blind sql injection": "sqli",
    "boolean-based sqli": "sqli",
    "time-based sqli": "sqli",
    "error-based sqli": "sqli",

    # Template injection
    "ssti": "csti",
    "csti": "csti",
    "server-side template injection": "csti",
    "client-side template injection": "csti",
    "template injection": "csti",

    # File inclusion
    "lfi": "lfi",
    "local file inclusion": "lfi",
    "path traversal": "lfi",
    "directory traversal": "lfi",
    "file read": "lfi",

    # Access control
    "idor": "idor",
    "insecure direct object reference": "idor",
    "broken access control": "idor",
    "authorization bypass": "idor",
    "privilege escalation": "idor",

    # Remote code execution
    "rce": "rce",
    "remote code execution": "rce",
    "command injection": "rce",
    "os command injection": "rce",
    "code injection": "rce",
    "deserialization": "rce",

    # Open redirect (BEFORE ssrf -- compound types like "Open Redirect / SSRF"
    # must match "redirect" first, since SSRF substring would match too)
    "open redirect": "openredirect",
    "openredirect": "openredirect",
    "url redirect": "openredirect",
    "redirect": "openredirect",

    # Server-side request forgery
    "ssrf": "ssrf",
    "server-side request forgery": "ssrf",
    "url injection": "ssrf",

    # XML vulnerabilities
    "xxe": "xxe",
    "xml external entity": "xxe",
    "xml injection": "xxe",

    # JWT vulnerabilities
    "jwt": "jwt",
    "jwt vulnerability": "jwt",
    "jwt bypass": "jwt",
    "jwt manipulation": "jwt",
    "authentication bypass": "jwt",
    "jwt_discovered": "jwt",

    # GraphQL vulnerabilities (route to API Security specialist)
    "graphql": "api_security",
    "graphql introspection": "api_security",
    "graphql information disclosure": "api_security",
    "information exposure": "api_security",

    # Prototype pollution
    "prototype pollution": "prototype_pollution",
    "prototype_pollution": "prototype_pollution",
    "__proto__ pollution": "prototype_pollution",

    # Header injection / CRLF
    "header injection": "header_injection",
    "crlf": "header_injection",
    "crlf injection": "header_injection",
    "http response header injection": "header_injection",
    "response splitting": "header_injection",
    "http header injection": "header_injection",
    "http response splitting": "xss",

    # Mass assignment
    "mass assignment": "mass_assignment",
    "overposting": "mass_assignment",

    # Broken authentication / access control variants
    "bola": "idor",
    "broken object level authorization": "idor",

    # Insecure deserialization
    "insecure deserialization": "rce",

    # Misconfiguration types
    "broken access control (admin)": "idor",
    "no rate limiting": "idor",
    "rate limiting": "idor",

    # Input validation
    "input validation": "sqli",
    "type confusion": "sqli",
}


# =========================================================================
# SEMANTIC DESCRIPTIONS FOR EMBEDDINGS-BASED CLASSIFICATION (Phase 42: v3.3)
# =========================================================================

SPECIALIST_DESCRIPTIONS: Dict[str, str] = {
    "xss": (
        "Cross-site scripting XSS vulnerability involving HTML injection, "
        "JavaScript execution, script tags, DOM manipulation, alert popups, "
        "reflected or stored user input rendering in browser context without sanitization"
    ),
    "sqli": (
        "SQL injection database vulnerability with query manipulation, "
        "boolean-based blind time-based error-based union-based attacks, "
        "quote escaping, UNION SELECT statements, database enumeration"
    ),
    "csti": (
        "Client-side or server-side template injection SSTI CSTI vulnerability, "
        "template engine exploitation, Jinja2 AngularJS expression evaluation, "
        "{{payload}} syntax, code execution through template rendering"
    ),
    "lfi": (
        "Local file inclusion LFI path traversal directory traversal vulnerability, "
        "file read access, ../ sequences, /etc/passwd access, arbitrary file disclosure"
    ),
    "idor": (
        "Insecure direct object reference IDOR broken access control vulnerability, "
        "authorization bypass, horizontal vertical privilege escalation, "
        "session cookie manipulation, user ID parameter tampering, accessing other users data"
    ),
    "rce": (
        "Remote code execution RCE command injection OS command vulnerability, "
        "shell command execution, deserialization attacks, arbitrary code execution, "
        "system compromise, ping curl wget exploits"
    ),
    "ssrf": (
        "Server-side request forgery SSRF vulnerability, internal network access, "
        "URL injection, localhost 127.0.0.1 access, cloud metadata exploitation, "
        "port scanning through server, HTTP request manipulation"
    ),
    "xxe": (
        "XML external entity XXE vulnerability, XML injection, "
        "DTD entity expansion, SYSTEM ENTITY declarations, "
        "file disclosure through XML parsing, out-of-band data exfiltration"
    ),
    "jwt": (
        "JSON Web Token JWT authentication vulnerability, bearer token manipulation, "
        "none algorithm bypass, weak secret key cracking, signature verification bypass, "
        "authorization header exploitation, token forgery"
    ),
    "openredirect": (
        "Open redirect URL redirection vulnerability, unvalidated redirects, "
        "phishing attacks, return_url redirect_uri parameter manipulation, "
        "Location header injection, unsafe HTTP redirects"
    ),
    "prototype_pollution": (
        "Prototype pollution JavaScript vulnerability, __proto__ manipulation, "
        "constructor.prototype modification, Node.js object pollution, "
        "merge deep clone vulnerabilities affecting JavaScript objects"
    ),
    "header_injection": (
        "HTTP header injection CRLF injection vulnerability, response splitting, "
        "carriage return line feed injection, newline character injection, "
        "Set-Cookie header manipulation, HTTP response header control"
    ),
    "file_upload": (
        "File upload vulnerability, unrestricted file upload, malicious file upload, "
        "webshell upload, executable file bypass, MIME type validation bypass, "
        "arbitrary file write, dangerous file extension"
    ),
    "chain_discovery": (
        "Vulnerability chain discovery, multi-step exploitation path, "
        "chained vulnerabilities, combined attack vectors, "
        "escalation through multiple weaknesses"
    ),
    "api_security": (
        "API security vulnerability, REST API GraphQL security issues, "
        "API authentication bypass, rate limiting issues, API key exposure, "
        "endpoint security misconfiguration"
    ),
    "mass_assignment": (
        "Mass assignment overposting vulnerability, parameter pollution, "
        "privilege escalation through unprotected model binding, "
        "role/admin field injection, price manipulation, "
        "insecure direct object property modification"
    ),
}


# =========================================================================
# SEVERITY TO BASE PRIORITY SCORE MAPPING
# =========================================================================

SEVERITY_PRIORITY: Dict[str, int] = {
    "critical": 100,
    "high": 75,
    "medium": 50,
    "low": 25,
    "info": 10,
    "information": 10,
}


# =========================================================================
# DATA CLASSES
# =========================================================================

@dataclass
class FindingRecord:
    """Record of a finding for deduplication and processing."""
    key: str  # vuln_type:parameter:url_path
    finding: Dict[str, Any]
    received_at: float = field(default_factory=time.monotonic)
    scan_context: str = ""
    processed: bool = False


@dataclass
class PrioritizedFinding:
    """Finding with classification and priority for queue distribution."""
    finding: Dict[str, Any]
    specialist: str  # Queue name (e.g., "xss", "sqli")
    priority: float  # 0-100, higher = more urgent
    scan_context: str
    classified_at: float = field(default_factory=time.monotonic)

    @property
    def queue_payload(self) -> Dict[str, Any]:  # PURE
        """Prepare payload for specialist queue."""
        return {
            "finding": self.finding,
            "priority": self.priority,
            "scan_context": self.scan_context,
            "classified_at": self.classified_at,
        }


# =========================================================================
# DEDUPLICATION CACHE
# =========================================================================

class DeduplicationCache:
    """
    LRU cache for finding deduplication.

    Tracks seen findings using vuln_type:parameter:url_path keys.
    Evicts oldest entries when max_size is reached.
    """

    def __init__(self, max_size: int = 1000):
        self.max_size = max_size
        self._cache: OrderedDict[str, FindingRecord] = OrderedDict()
        self._lock = asyncio.Lock()

    async def check_and_add(self, finding: Dict[str, Any], scan_context: str) -> tuple[bool, str]:
        """
        Check if finding is duplicate and add if not.

        Returns:
            (is_duplicate, key): Tuple of duplicate status and the key
        """
        key = make_dedup_key(finding)

        async with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
                logger.debug(f"[ThinkingAgent] Duplicate: {key}")
                return (True, key)

            record = FindingRecord(
                key=key,
                finding=finding.copy(),
                scan_context=scan_context
            )
            self._cache[key] = record

            while len(self._cache) > self.max_size:
                oldest_key = next(iter(self._cache))
                del self._cache[oldest_key]
                logger.debug(f"[ThinkingAgent] Evicted oldest: {oldest_key}")

            return (False, key)

    def clear(self) -> None:  # PURE
        """Clear the deduplication cache."""
        self._cache.clear()

    @property
    def size(self) -> int:  # PURE
        """Current cache size."""
        return len(self._cache)

    def get_stats(self) -> Dict[str, Any]:  # PURE
        """Get cache statistics."""
        return {
            "size": len(self._cache),
            "max_size": self.max_size,
            "fill_ratio": len(self._cache) / self.max_size if self.max_size > 0 else 0
        }


# =========================================================================
# PURE CLASSIFICATION FUNCTIONS
# =========================================================================

def normalize_parameter(param: str, vuln_type: str) -> str:  # PURE
    """
    Normalize parameter names for better deduplication.

    Prevents duplicate findings caused by inconsistent parameter naming
    from the LLM (e.g., "POST Body", "POST Body (Stock Check)", "XML Payload").

    Args:
        param: Raw parameter string from finding
        vuln_type: Vulnerability type (e.g., "xxe", "sqli")

    Returns:
        Normalized parameter name
    """
    param_lower = param.lower()

    # XXE: Normalize all POST body variations
    if vuln_type == "xxe":
        xxe_indicators = ["post", "body", "xml", "stock", "form"]
        if any(indicator in param_lower for indicator in xxe_indicators):
            return "post_body"

    # SQLi: Normalize cookie names
    if "cookie:" in param_lower:
        parts = param_lower.split("cookie:")
        if len(parts) > 1:
            cookie_name = parts[1].strip().split()[0]
            return f"cookie:{cookie_name}"

    # Header injection: Normalize header names
    if "header" in param_lower and ":" in param:
        parts = param_lower.split(":", 1)
        if len(parts) > 1:
            header_name = parts[1].strip().split()[0]
            return f"header:{header_name}"

    return param_lower


def make_dedup_key(finding: Dict[str, Any]) -> str:  # PURE
    """
    Create deduplication key from finding.

    Format: vuln_type:parameter:url_path
    Example: "XSS:id:/api/users"

    Args:
        finding: Finding dictionary

    Returns:
        Deduplication key string
    """
    vuln_type = finding.get("type", "Unknown").lower()
    parameter_raw = finding.get("parameter", "unknown")
    url = finding.get("url", "")

    parameter = normalize_parameter(parameter_raw, vuln_type)

    # Extract path from URL
    url_path = url
    if "://" in url:
        parts = url.split("/", 3)
        url_path = "/" + parts[3] if len(parts) > 3 else "/"

    # Normalize: remove query params
    if "?" in url_path:
        url_path = url_path.split("?")[0]

    # GLOBAL PARAMETER CHECK
    if any(p in parameter for p in ["cookie", "header", "user-agent", "referer", "bearer", "authorization"]):
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
            url_path = f"GLOBAL_HOST:{parsed.netloc}"
        except Exception:
            url_path = "GLOBAL_HOST:unknown"

    return f"{vuln_type}:{parameter}:{url_path}"


def classify_finding(
    finding: Dict[str, Any],
    stats: Dict[str, Any],
    embeddings_classify_fn=None,
    embeddings_initialized: bool = False,
    embeddings_init_fn=None,
    use_embeddings: bool = False,
    confidence_threshold: float = 0.75,
    manual_review_threshold: float = 0.5,
    log_confidence: bool = False,
    agent_name: str = "ThinkingAgent",
) -> Optional[str]:  # PURE (except optional embedding calls)
    """
    Classify finding to determine target specialist queue.

    Uses hybrid approach (Phase 42: v3.3):
    1. Fast keyword matching (exact -> substring)
    2. Embeddings similarity (if enabled and keywords fail)
    3. Manual review flag (if confidence low)

    Args:
        finding: Finding dict with 'type' field
        stats: Statistics dict (mutated for tracking)
        embeddings_classify_fn: Optional callable for embeddings classification
        embeddings_initialized: Whether embeddings are ready
        embeddings_init_fn: Optional callable to initialize embeddings
        use_embeddings: Whether to use embeddings classification
        confidence_threshold: Minimum confidence for embeddings
        manual_review_threshold: Minimum for manual review flagging
        log_confidence: Whether to log confidence details
        agent_name: Name for logging

    Returns:
        Specialist queue name (e.g., "xss") or None if unclassifiable
    """
    vuln_type = finding.get("type", "").lower().strip()

    # PHASE 1: Keyword matching (fast path)
    # Direct exact match
    if vuln_type in VULN_TYPE_TO_SPECIALIST:
        specialist = VULN_TYPE_TO_SPECIALIST[vuln_type]
        if log_confidence:
            logger.debug(
                f"[{agent_name}] Classification: '{vuln_type}' -> {specialist} "
                f"(method: keyword_exact, confidence: 1.0)"
            )
        stats["classification_methods"]["keyword_exact"] += 1
        return specialist

    # Substring partial match
    for pattern, specialist in VULN_TYPE_TO_SPECIALIST.items():
        if pattern in vuln_type:
            if log_confidence:
                logger.debug(
                    f"[{agent_name}] Classification: '{vuln_type}' -> {specialist} "
                    f"(method: keyword_substring, pattern: '{pattern}', confidence: 0.9)"
                )
            stats["classification_methods"]["keyword_substring"] += 1
            return specialist

    # PHASE 2: Embeddings similarity (if enabled)
    if use_embeddings:
        if not embeddings_initialized and embeddings_init_fn:
            if not embeddings_init_fn():
                logger.warning(
                    f"[{agent_name}] Unknown vulnerability type (embeddings unavailable): {vuln_type}"
                )
                stats["classification_methods"]["unknown"] += 1
                return None

        if embeddings_classify_fn:
            result = embeddings_classify_fn(finding)
            if result is not None:
                specialist, confidence = result

                if confidence >= confidence_threshold:
                    logger.info(
                        f"[{agent_name}] Classification: '{vuln_type}' -> {specialist} "
                        f"(method: embeddings, confidence: {confidence:.3f})"
                    )
                    stats["classification_methods"]["embeddings_high_confidence"] += 1
                    return specialist

                elif confidence >= manual_review_threshold:
                    logger.warning(
                        f"[{agent_name}] Classification: '{vuln_type}' -> {specialist} "
                        f"(method: embeddings, confidence: {confidence:.3f}, "
                        f"flag: MANUAL_REVIEW_RECOMMENDED)"
                    )
                    finding["_classification_confidence"] = confidence
                    finding["_requires_manual_review"] = True
                    stats["classification_methods"]["embeddings_medium_confidence"] += 1
                    return specialist

                else:
                    logger.warning(
                        f"[{agent_name}] Classification failed: '{vuln_type}' "
                        f"(method: embeddings, best_match: {specialist}, "
                        f"confidence: {confidence:.3f} < threshold: {confidence_threshold})"
                    )
                    stats["classification_methods"]["embeddings_low_confidence"] += 1
                    return None

    # PHASE 3: Unknown type
    logger.warning(f"[{agent_name}] Unknown vulnerability type: {vuln_type}")
    stats["classification_methods"]["unknown"] += 1
    return None


def calculate_priority(finding: Dict[str, Any]) -> float:  # PURE
    """
    Calculate exploitation probability priority score.

    Priority Formula:
    priority = (severity_base * 0.4) + (fp_confidence * 100 * 0.35) + (skeptical_score * 10 * 0.25)

    Components:
    - Severity base (40%): Critical=100, High=75, Medium=50, Low=25
    - FP confidence (35%): 0.0-1.0 scaled to 0-100
    - Skeptical score (25%): 0-10 scaled to 0-100

    Args:
        finding: Finding dictionary with severity, fp_confidence, skeptical_score

    Returns:
        Priority score 0-100 (higher = more likely to be exploitable)
    """
    severity = finding.get("severity", "medium").lower()
    severity_base = SEVERITY_PRIORITY.get(severity, 50)

    fp_confidence = finding.get("fp_confidence", 0.5)
    skeptical_score = finding.get("skeptical_score", 5)

    priority = (
        (severity_base * 0.40) +
        (fp_confidence * 100 * 0.35) +
        (skeptical_score * 10 * 0.25)
    )

    # Boost for validated findings
    if finding.get("validated", False):
        priority = min(100, priority * 1.2)

    # Boost for high vote count
    votes = finding.get("votes", 1)
    if votes >= 4:
        priority = min(100, priority * 1.1)

    return round(priority, 2)


def classify_and_prioritize(
    finding: Dict[str, Any],
    scan_context: str,
    stats: Dict[str, Any],
    agent_name: str = "ThinkingAgent",
    **classify_kwargs,
) -> Optional[PrioritizedFinding]:  # PURE
    """
    Classify finding and calculate priority for queue distribution.

    Args:
        finding: Finding dict from url_analyzed event
        scan_context: Scan context for tracking
        stats: Statistics dict
        agent_name: Name for logging
        **classify_kwargs: Passed to classify_finding

    Returns:
        PrioritizedFinding ready for queue, or None if unclassifiable
    """
    specialist = classify_finding(finding, stats, agent_name=agent_name, **classify_kwargs)
    if not specialist:
        logger.debug(f"[{agent_name}] Unclassifiable: {finding.get('type')}")
        return None

    priority = calculate_priority(finding)

    prioritized = PrioritizedFinding(
        finding=finding,
        specialist=specialist,
        priority=priority,
        scan_context=scan_context,
    )

    logger.debug(
        f"[{agent_name}] Classified: {finding.get('type')} -> {specialist} "
        f"(priority: {priority:.1f})"
    )

    return prioritized
