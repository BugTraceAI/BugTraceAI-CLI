"""
Prototype Pollution Agent - PURE functions

All functions here are free functions (no self), take all data as parameters,
and perform no I/O. They are deterministic and side-effect free.

Responsibilities:
- Response analysis for pollution markers
- JSON deep search for markers
- RCE output detection in responses
- Severity ranking and validation status determination
- Fingerprinting and deduplication
- Finding construction and report building
- LLM prompt generation

Note: Payload data (BASIC_POLLUTION_PAYLOADS, ENCODING_BYPASSES, etc.)
lives in bugtrace.agents.prototype_pollution_payloads and is referenced
directly from there.
"""

import json
import re
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse, parse_qs

# Re-export payload constants from the canonical payload module
from bugtrace.agents.prototype_pollution_payloads import (
    POLLUTION_MARKER,
    VULNERABLE_PARAMS,
    BASIC_POLLUTION_PAYLOADS,
    ENCODING_BYPASSES,
    GADGET_CHAIN_PAYLOADS,
    RCE_GADGETS,
    PAYLOAD_TIERS,
    TIER_SEVERITY,
    get_payloads_for_tier,
    get_query_param_payloads,
    get_all_payloads,
    build_data_uri_payload,
    DATA_URI_PAYLOADS,
    QUERY_PARAM_PAYLOADS,
    SAFE_RCE_COMMANDS,
    FORBIDDEN_COMMANDS,
)


# ============================================================================
# RESPONSE ANALYSIS (PURE)
# ============================================================================

# PURE
def search_json_for_marker(obj: Any, marker: str) -> bool:
    """
    Recursively search JSON object for pollution marker.

    Args:
        obj: JSON-parsed object (dict, list, str, etc.)
        marker: Pollution marker string to search for

    Returns:
        True if marker found in object tree
    """
    if isinstance(obj, str) and marker in obj:
        return True
    if isinstance(obj, dict):
        for key, value in obj.items():
            if marker in str(key) or search_json_for_marker(value, marker):
                return True
    if isinstance(obj, list):
        for item in obj:
            if search_json_for_marker(item, marker):
                return True
    return False


# PURE
def verify_pollution_in_text(response_text: str, marker: str) -> bool:
    """
    Verify pollution by checking if marker appears in response.

    Pollution is confirmed when:
    1. Marker appears in JSON response (inherited property)
    2. Response structure changes indicating pollution

    Args:
        response_text: HTTP response body text
        marker: Pollution marker to search for

    Returns:
        True if pollution confirmed
    """
    # Direct marker check
    if marker in response_text:
        return True

    # Check for JSON response with polluted property
    try:
        resp_json = json.loads(response_text)
        if search_json_for_marker(resp_json, marker):
            return True
    except json.JSONDecodeError:
        pass

    return False


# PURE
def check_rce_output(response_text: str) -> Optional[str]:
    """
    Check response for RCE command output indicators.

    Looks for:
    - whoami output (username patterns)
    - id output (uid/gid patterns)
    - cat /etc/passwd output (root:x:0 pattern)
    - hostname output

    Args:
        response_text: HTTP response body text

    Returns:
        Description of RCE evidence, or None
    """
    rce_indicators = [
        # whoami patterns
        (r'\b(root|admin|www-data|node|ubuntu|ec2-user|nobody)\b', "whoami_output"),
        # id command patterns
        (r'uid=\d+.*gid=\d+', "id_output"),
        # /etc/passwd patterns
        (r'root:x:0:0', "passwd_read"),
        # hostname output
        (r'hostname\s*[:=]\s*\S+', "hostname_output"),
    ]

    for pattern, indicator_type in rce_indicators:
        match = re.search(pattern, response_text, re.IGNORECASE)
        if match:
            return f"{indicator_type}: {match.group(0)}"

    return None


# ============================================================================
# VECTOR DISCOVERY (PURE)
# ============================================================================

# PURE
def discover_param_vectors(url: str, explicit_params: List[str]) -> List[Dict]:
    """
    Discover pollution vectors in existing query parameters.

    Args:
        url: Target URL
        explicit_params: Params explicitly provided to agent

    Returns:
        List of vector dicts
    """
    vectors = []
    parsed = urlparse(url)
    existing_params = parse_qs(parsed.query)

    # Check if any existing params match vulnerable patterns
    for param in existing_params.keys():
        param_lower = param.lower()

        if any(vuln_param in param_lower for vuln_param in VULNERABLE_PARAMS):
            vectors.append({
                "type": "QUERY_PARAM",
                "param": param,
                "value": existing_params[param][0] if existing_params[param] else "",
                "source": "URL_EXISTING",
                "confidence": "MEDIUM",
                "reason": "Parameter name suggests object merging",
            })

    # Also include params provided to agent
    if explicit_params:
        for param in explicit_params:
            if not any(v.get("param") == param for v in vectors):
                vectors.append({
                    "type": "QUERY_PARAM",
                    "param": param,
                    "value": "",
                    "source": "AGENT_INPUT",
                    "confidence": "HIGH",
                })

    return vectors


# PURE
def analyze_response_for_vulnerable_patterns(content: str) -> List[Dict]:
    """
    Analyze response content for vulnerable merge/extend patterns.

    Looks for:
    - JavaScript code with Object.assign, lodash.merge, $.extend
    - Error messages revealing merge operations
    - Response structure suggesting object manipulation

    Args:
        content: HTTP response body text

    Returns:
        List of vector dicts
    """
    vectors = []
    content_lower = content.lower()

    # Check for vulnerable JavaScript patterns
    js_patterns = [
        ("object.assign", "Object.assign usage detected"),
        ("lodash.merge", "Lodash merge detected"),
        ("_.merge", "Lodash merge (underscore) detected"),
        ("$.extend", "jQuery extend detected"),
        ("deep-extend", "deep-extend package detected"),
        ("merge-deep", "merge-deep package detected"),
        ("deepmerge", "deepmerge package detected"),
    ]

    for pattern, reason in js_patterns:
        if pattern in content_lower:
            vectors.append({
                "type": "JS_PATTERN",
                "pattern": pattern,
                "source": "RESPONSE_ANALYSIS",
                "confidence": "LOW",
                "reason": reason,
            })
            break  # One pattern is enough

    # Check for server error messages that reveal merge operations
    error_patterns = [
        "cannot read property",
        "undefined is not an object",
        "cannot convert undefined",
        "merge",
        "deep copy",
        "prototype",
    ]

    for pattern in error_patterns:
        if pattern in content_lower:
            vectors.append({
                "type": "ERROR_PATTERN",
                "pattern": pattern,
                "source": "ERROR_MESSAGE",
                "confidence": "LOW",
                "reason": f"Error message suggests object manipulation: {pattern}",
            })
            break

    return vectors


# PURE
def deduplicate_vectors(vectors: List[Dict]) -> List[Dict]:
    """
    Deduplicate and sort vectors by confidence.

    Args:
        vectors: List of discovered vectors

    Returns:
        Deduplicated, sorted list
    """
    seen: set = set()
    unique_vectors = []
    for v in vectors:
        key = f"{v['type']}:{v.get('param', '')}:{v.get('pattern', '')}"
        if key not in seen:
            seen.add(key)
            unique_vectors.append(v)

    # Sort by confidence (HIGH > MEDIUM > LOW)
    confidence_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    unique_vectors.sort(key=lambda v: confidence_order.get(v.get("confidence", "LOW"), 2))

    return unique_vectors


# ============================================================================
# SEVERITY AND VALIDATION (PURE)
# ============================================================================

# PURE
def severity_rank(severity: str) -> int:
    """
    Convert severity to numeric rank for comparison.

    Args:
        severity: Severity string (LOW/MEDIUM/HIGH/CRITICAL)

    Returns:
        Numeric rank (0-4)
    """
    ranks = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    return ranks.get(severity, 0)


# PURE
def get_validation_status(evidence: Dict) -> str:
    """
    Determine tiered validation status for Prototype Pollution finding.

    TIER 1 (VALIDATED_CONFIRMED): Definitive proof
        - Object.prototype polluted and verified (marker appears in response)
        - RCE escalation confirmed (command output or timing attack)
        - Gadget chain exploitation successful

    TIER 2 (PENDING_VALIDATION): Needs verification
        - Pollution attempt detected but not verified
        - Pattern suggests vulnerability but unconfirmed

    Args:
        evidence: Dict with boolean evidence flags

    Returns:
        Validation status string
    """
    # Import here to avoid circular imports at module level
    from bugtrace.core.validation_status import ValidationStatus

    # TIER 1: Pollution verified (marker in response)
    if evidence.get("pollution_verified"):
        return ValidationStatus.VALIDATED_CONFIRMED.value

    # TIER 1: RCE confirmed (highest severity)
    if evidence.get("rce_confirmed"):
        return ValidationStatus.VALIDATED_CONFIRMED.value

    # TIER 1: Gadget chain exploitation
    if evidence.get("gadget_chain_confirmed"):
        return ValidationStatus.VALIDATED_CONFIRMED.value

    # TIER 2: Pollution attempt without verification
    if evidence.get("pollution_attempt") and not evidence.get("pollution_verified"):
        return ValidationStatus.PENDING_VALIDATION.value

    # TIER 2: Vulnerable pattern detected but unconfirmed
    if evidence.get("vulnerable_pattern"):
        return ValidationStatus.PENDING_VALIDATION.value

    # Default: Confirmed if exploitation was successful
    return ValidationStatus.VALIDATED_CONFIRMED.value


# ============================================================================
# VALIDATION (PURE)
# ============================================================================

# PURE
def validate_prototype_pollution_finding(finding: Dict) -> Tuple[bool, str]:
    """
    Prototype Pollution-specific validation logic.

    Validates:
    1. Has pollution evidence (property set, RCE achieved)
    2. Payload contains prototype pollution patterns

    Args:
        finding: Finding dict to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    nested = finding.get("finding", {})
    evidence = finding.get("evidence", nested.get("evidence", {}))
    status = finding.get("status", nested.get("status", ""))

    # PP-specific: Must have evidence or confirmed status
    if status not in ["VALIDATED_CONFIRMED", "PENDING_VALIDATION"]:
        has_pollution = evidence.get("pollution_confirmed") if isinstance(evidence, dict) else False
        has_rce = evidence.get("rce_achieved") if isinstance(evidence, dict) else False
        if not (has_pollution or has_rce):
            return False, "Prototype Pollution requires proof: pollution confirmed or RCE achieved"

    # PP-specific: Payload should contain prototype pollution patterns
    payload = finding.get("payload", nested.get("payload", ""))
    pp_markers = ['__proto__', 'constructor', 'prototype', '.polluted', 'toString']
    if payload and not any(m in str(payload) for m in pp_markers):
        return False, f"Prototype Pollution payload missing pollution patterns: {payload[:50]}"

    return True, ""


# ============================================================================
# FINGERPRINTING (PURE)
# ============================================================================

# PURE
def generate_protopollution_fingerprint(url: str, parameter: str) -> Tuple:
    """
    Generate Prototype Pollution finding fingerprint for expert deduplication.

    Args:
        url: Target URL
        parameter: Parameter name

    Returns:
        Tuple fingerprint for deduplication
    """
    parsed = urlparse(url)
    normalized_path = parsed.path.rstrip('/')
    return ("PROTOTYPE_POLLUTION", parsed.netloc, normalized_path, parameter.lower())


# PURE
def fallback_fingerprint_dedup(wet_findings: List[Dict]) -> List[Dict]:
    """
    Fallback fingerprint-based deduplication if LLM fails.

    Args:
        wet_findings: List of WET findings

    Returns:
        Deduplicated list
    """
    seen: set = set()
    dry_list: List[Dict] = []

    for finding in wet_findings:
        url = finding.get("url", "")
        parameter = finding.get("parameter", "")
        fingerprint = generate_protopollution_fingerprint(url, parameter)

        if fingerprint not in seen:
            seen.add(fingerprint)
            dry_list.append(finding)

    return dry_list


# ============================================================================
# FINDING / REPORT CONSTRUCTION (PURE)
# ============================================================================

# PURE
def build_reproduction(url: str, result: Dict) -> str:
    """
    Build curl command for reproducing the vulnerability.

    Args:
        url: Target URL
        result: Exploitation result dict

    Returns:
        Curl command string
    """
    method = result.get("method", "GET")
    if method == "JSON_BODY":
        payload_json = json.dumps(result.get("payload_obj", {}))
        return f"curl -X POST -H 'Content-Type: application/json' -d '{payload_json}' '{url}'"
    elif method == "QUERY_PARAM":
        return f"curl '{result.get('test_url', url)}'"
    return f"curl '{url}'"


# PURE
def build_specialist_report(
    agent_name: str,
    scan_context: str,
    dry_findings: List[Dict],
    validated_findings: List[Dict],
) -> Dict:
    """
    Build specialist report dictionary for Prototype Pollution findings.

    Args:
        agent_name: Name of the agent
        scan_context: Scan identifier
        dry_findings: DRY (deduplicated) findings
        validated_findings: Validated findings from Phase B

    Returns:
        Report dict ready for serialization
    """
    return {
        "agent": agent_name,
        "vulnerability_type": "PROTOTYPE_POLLUTION",
        "scan_context": scan_context,
        "phase_a": {
            "wet_count": len(dry_findings) + (len(validated_findings) - len(dry_findings)),
            "dry_count": len(dry_findings),
            "deduplication_method": "LLM + fingerprint fallback",
        },
        "phase_b": {
            "exploited_count": len(dry_findings),
            "validated_count": len(validated_findings),
        },
        "findings": validated_findings,
        "summary": {
            "total_validated": len(validated_findings),
            "javascript_specific": True,
        },
    }


# PURE
def build_dedup_prompt(
    wet_findings: List[Dict],
    tech_stack: Dict,
    prime_directive: str,
    dedup_context: str,
) -> Tuple[str, str]:
    """
    Build LLM prompt and system prompt for prototype pollution deduplication.

    Args:
        wet_findings: WET findings to deduplicate
        tech_stack: Technology stack context
        prime_directive: Agent-specific prime directive
        dedup_context: Agent-specific dedup context

    Returns:
        Tuple of (user_prompt, system_prompt)
    """
    prompt = f"""You are analyzing {len(wet_findings)} potential Prototype Pollution findings.

{prime_directive}

{dedup_context}

DEDUPLICATION RULES FOR PROTOTYPE POLLUTION:

1. **CRITICAL - Autonomous Discovery:**
   - If items have "_discovered": true, they are DIFFERENT PARAMETERS discovered autonomously
   - Even if they share the same "finding" object, treat them as SEPARATE based on "parameter" field
   - Same URL + DIFFERENT param -> DIFFERENT (keep all)
   - Same URL + param + DIFFERENT context -> DIFFERENT (keep both)

2. **Standard Deduplication:**
   - Same endpoint + parameter + same method = DUPLICATE (keep only one)
   - Different endpoints = DIFFERENT vulnerabilities
   - Different parameters = DIFFERENT vulnerabilities
   - JSON body vs query param = DIFFERENT (different attack vectors)

3. **JavaScript-specific Context:**
   - Focus on Node.js APIs and frontend code
   - Prioritize params with PP-relevant names: merge, extend, options, config, settings, data

EXAMPLES:
- /api/merge?obj[__proto__][polluted]=1 + /api/merge?obj[__proto__][polluted]=2 = DUPLICATE
- /api/merge?obj[__proto__]=X + /api/extend?obj[__proto__]=X = DIFFERENT
- /api/merge?obj=X + /api/merge?data=Y = DIFFERENT (different params discovered autonomously)
- /api/merge (JSON body) + /api/merge?param=X = DIFFERENT

WET FINDINGS (may contain duplicates):
{json.dumps(wet_findings, indent=2)}

Return ONLY unique findings in JSON format:
{{
  "findings": [
    {{"url": "...", "parameter": "...", "rationale": "why this is unique", ...}},
    ...
  ]
}}"""

    system_prompt = """You are an expert Prototype Pollution deduplication analyst. Your job is to identify and remove duplicate findings while preserving unique attack vectors in JavaScript/Node.js environments."""

    return prompt, system_prompt


# PURE
def build_client_side_finding(
    url: str,
    param: str,
    successful_payloads: List[str],
    impact_details: Dict[str, str],
) -> Dict:
    """
    Build a finding dict for client-side prototype pollution.

    Args:
        url: Target URL
        param: Parameter name
        successful_payloads: List of successful payload descriptions
        impact_details: Dict mapping polluted properties to impact descriptions

    Returns:
        Complete finding dict
    """
    return {
        "type": "PROTOTYPE_POLLUTION",
        "url": url,
        "parameter": param or "__proto__",
        "payload": successful_payloads[0] if successful_payloads else "__proto__[btCSPP]=1",
        "technique": "client-side prototype pollution",
        "tier": "pollution_detection",
        "severity": "HIGH",
        "status": "VALIDATED_CONFIRMED",
        "validated": True,
        "exploitable": True,
        "pollution_confirmed": True,
        "engine_type": "client-side",
        "evidence": {
            "pollution_verified": True,
            "client_side": True,
            "successful_payloads": successful_payloads,
            "impact": impact_details,
            "method": "Playwright browser evaluation",
        },
        "description": (
            f"Client-side Prototype Pollution confirmed via browser. "
            f"Object.prototype is pollutable via query parameters. "
            f"{len(successful_payloads)} payloads confirmed."
        ),
        "successful_payloads": successful_payloads,
    }
