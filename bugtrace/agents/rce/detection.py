"""
PURE functions for RCE / Command Injection detection, classification, and validation.

All functions depend only on their arguments.  No network I/O.
"""
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from bugtrace.core.validation_status import ValidationStatus
from bugtrace.reporting.standards import (
    get_cwe_for_vuln,
    get_remediation_for_vuln,
)


# =========================================================================
# Payload data (PURE DATA)
# =========================================================================

TIME_PAYLOADS: Tuple[str, ...] = (
    ";sleep 5", "|sleep 5", "&sleep 5", "`sleep 5`",
    "$(sleep 5)", "\nsleep 5\n",
    "__import__('time').sleep(5)", "eval('sleep(5)')", "1+1",
)

RCE_PRIORITY_KEYWORDS: Tuple[str, ...] = (
    "cmd", "command", "exec", "execute", "run", "shell", "system",
    "eval", "code", "script", "ping", "wget", "curl", "bash",
    "powershell", "process", "task", "job",
)

DESER_KEYWORDS: Tuple[str, ...] = (
    "invalid load key", "could not find MARK", "unpickling",
    "pickle.loads", "_pickle.UnpicklingError", "pickle data", "_pickle.",
    "java.io.ObjectInputStream", "ClassNotFoundException",
    "java.io.InvalidClassException", "readObject",
    "unserialize()", "allowed_classes",
    "BinaryFormatter", "ObjectStateFormatter",
    "Marshal.load",
)


# =========================================================================
# Validation (PURE)
# =========================================================================

def validate_before_emit(
    finding: Dict, parent_validate_fn,
) -> Tuple[bool, str]:
    """
    RCE-specific pre-emit validation.

    Args:
        finding:           Finding dict.
        parent_validate_fn: Parent class ``_validate_before_emit`` callable.

    Returns:
        (is_valid, error_message) tuple.
    """  # PURE
    is_valid, error = parent_validate_fn(finding)
    if not is_valid:
        return False, error

    nested = finding.get("finding", {})
    evidence = finding.get("evidence", nested.get("evidence", ""))
    status = finding.get("status", nested.get("status", ""))

    # RCE-specific: Must have evidence
    if status not in ["VALIDATED_CONFIRMED", "PENDING_VALIDATION"]:
        has_time = "delay" in str(evidence).lower() or "sleep" in str(evidence).lower()
        has_output = evidence.get("command_output") if isinstance(evidence, dict) else False
        has_callback = evidence.get("interactsh_callback") if isinstance(evidence, dict) else False
        if not (has_time or has_output or has_callback):
            return False, "RCE requires proof: time delay, command output, or callback"

    # RCE-specific: Payload should contain command patterns
    payload = finding.get("payload", nested.get("payload", ""))
    rce_markers = [
        "sleep", "ping", "id", "whoami", "echo", "cat ", "ls ",
        "|", ";", "&", "`", "$(", "eval(", "__import__",
        "exec(", "system(", "passthru(",
    ]
    if payload and not any(m in str(payload).lower() for m in rce_markers):
        return False, f"RCE payload missing command patterns: {payload[:50]}"

    return True, ""


def get_time_payloads() -> List[str]:
    """
    Return the list of time-based RCE payloads.

    Returns:
        List of payload strings.
    """  # PURE
    return list(TIME_PAYLOADS)


# =========================================================================
# Finding creation (PURE)
# =========================================================================

def create_time_based_finding(
    url: str, param: str, payload: str, elapsed: float,
) -> Dict:
    """
    Create finding dict for time-based RCE.

    Args:
        url:     Target URL.
        param:   Vulnerable parameter name.
        payload: The payload that caused the delay.
        elapsed: Measured delay in seconds.

    Returns:
        Finding dict.
    """  # PURE
    test_url = inject_payload(url, param, payload)
    return {
        "type": "RCE",
        "url": url,
        "parameter": param,
        "payload": payload,
        "severity": "CRITICAL",
        "validated": True,
        "status": "VALIDATED_CONFIRMED",
        "evidence": f"Delay of {elapsed:.2f}s detected with payload: {payload}",
        "description": (
            f"Time-based Command Injection confirmed. Parameter '{param}' "
            f"executes OS commands. Payload caused {elapsed:.2f}s delay "
            f"(expected 5s+)."
        ),
        "reproduction": f"# Time-based RCE test:\ntime curl '{test_url}'",
        "cwe_id": get_cwe_for_vuln("RCE"),
        "remediation": get_remediation_for_vuln("RCE"),
        "cve_id": "N/A",
        "http_request": f"GET {test_url}",
        "http_response": f"Time delay: {elapsed:.2f}s (indicates command execution)",
    }


def create_eval_finding(
    url: str, param: str, payload: str,
) -> Dict:
    """
    Create finding dict for eval-based RCE.

    Args:
        url:     Target URL.
        param:   Vulnerable parameter name.
        payload: The eval payload (e.g. "1+1").

    Returns:
        Finding dict.
    """  # PURE
    target = inject_payload(url, param, payload)
    return {
        "type": "RCE",
        "url": url,
        "parameter": param,
        "payload": payload,
        "severity": "CRITICAL",
        "validated": True,
        "status": "VALIDATED_CONFIRMED",
        "evidence": "Mathematical expression '1+1' evaluated to '2' in response.",
        "description": (
            f"Remote Code Execution via eval() confirmed. Parameter '{param}' "
            f"evaluates arbitrary code. Expression '1+1' returned '2'."
        ),
        "reproduction": f"curl '{target}' | grep -i 'result'",
        "cwe_id": get_cwe_for_vuln("RCE"),
        "remediation": get_remediation_for_vuln("RCE"),
        "cve_id": "N/A",
        "http_request": f"GET {target}",
        "http_response": "Result: 2 (indicates code evaluation)",
    }


def create_output_finding(
    url: str, param: str, payload: str, output: str,
) -> Dict:
    """
    Create finding dict for output-based RCE.

    Args:
        url:     Target URL.
        param:   Vulnerable parameter name.
        payload: The command that produced output.
        output:  The detected command output.

    Returns:
        Finding dict.
    """  # PURE
    test_url = inject_payload(url, param, payload)
    return {
        "type": "RCE",
        "url": url,
        "parameter": param,
        "payload": payload,
        "severity": "CRITICAL",
        "validated": True,
        "status": "VALIDATED_CONFIRMED",
        "evidence": f"Command output detected: {output[:200]}",
        "description": (
            f"Command Injection confirmed. Parameter '{param}' executes "
            f"OS commands. Command '{payload}' produced output."
        ),
        "reproduction": f"curl '{test_url}'",
        "cwe_id": get_cwe_for_vuln("RCE"),
        "remediation": get_remediation_for_vuln("RCE"),
        "cve_id": "N/A",
        "http_request": f"GET {test_url}",
        "http_response": f"Command output: {output[:200]}",
    }


def create_deserialization_finding(
    url: str, param: str, probe_value: str, matched: List[str],
) -> Dict:
    """
    Create finding dict for insecure deserialization.

    Args:
        url:         Target URL.
        param:       Cookie / parameter name.
        probe_value: The probe payload sent.
        matched:     List of matched deserialization keywords.

    Returns:
        Finding dict.
    """  # PURE
    cookie_name = param.replace("Cookie: ", "").strip() if param.startswith("Cookie:") else param
    return {
        "type": "Insecure Deserialization",
        "url": url,
        "parameter": param,
        "payload": probe_value,
        "severity": "CRITICAL",
        "validated": True,
        "status": "VALIDATED_CONFIRMED",
        "evidence": f"Deserialization error keywords in response: {matched}",
        "description": (
            f"Insecure deserialization confirmed in cookie '{cookie_name}' at {url}. "
            f"Non-serialized data triggers deserialization error messages, confirming "
            f"the server deserializes cookie values unsafely."
        ),
        "reproduction": f"curl -b '{cookie_name}={probe_value}' '{url}'",
        "cwe_id": "CWE-502",
        "remediation": get_remediation_for_vuln("RCE"),
        "cve_id": "N/A",
        "http_request": f"GET {url} (Cookie: {cookie_name}={probe_value})",
        "http_response": f"Error keywords: {matched}",
    }


# =========================================================================
# URL manipulation (PURE)
# =========================================================================

def inject_payload(url: str, param: str, payload: str) -> str:
    """
    Inject *payload* into *param* of *url*'s query string.

    Args:
        url:     Target URL.
        param:   Parameter name.
        payload: Value to inject.

    Returns:
        Modified URL string.
    """  # PURE
    parsed = urlparse(url)
    q = parse_qs(parsed.query)
    q[param] = [payload]
    new_query = urlencode(q, doseq=True)
    return urlunparse((
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, new_query, parsed.fragment,
    ))


# =========================================================================
# Fingerprinting and deduplication (PURE)
# =========================================================================

def generate_rce_fingerprint(url: str, parameter: str) -> tuple:
    """
    Generate RCE finding fingerprint for expert deduplication.

    RCE is URL-specific and parameter-specific.

    Args:
        url:       Target URL.
        parameter: Parameter name.

    Returns:
        Tuple fingerprint for deduplication.
    """  # PURE
    parsed = urlparse(url)
    normalized_path = parsed.path.rstrip("/")
    return ("RCE", parsed.netloc, normalized_path, parameter.lower())


def fallback_fingerprint_dedup(wet_findings: List[Dict]) -> List[Dict]:
    """
    Fingerprint-based deduplication fallback.

    Args:
        wet_findings: List of WET finding dicts.

    Returns:
        Deduplicated list.
    """  # PURE
    seen: set = set()
    dry_list: List[Dict] = []
    for f in wet_findings:
        fp = generate_rce_fingerprint(f.get("url", ""), f.get("parameter", ""))
        if fp not in seen:
            seen.add(fp)
            dry_list.append(f)
    return dry_list


def check_deser_keywords(body: str) -> List[str]:
    """
    Check response body for deserialization error keywords.

    Args:
        body: HTTP response body.

    Returns:
        List of matched keywords (empty if none).
    """  # PURE
    return [kw for kw in DESER_KEYWORDS if kw.lower() in body.lower()]


def exploit_dry_sort_key(finding: Dict) -> int:
    """
    Sort key for exploit_dry_list: cookies/deserialization first, URL params last.

    This gives JWTAgent more time to crack secrets before we hit
    auth-gated endpoints.

    Args:
        finding: DRY finding dict.

    Returns:
        Sort priority (0 = first, 1 = last).
    """  # PURE
    p = finding.get("parameter", "")
    r = finding.get("rationale", "").lower()
    if p.startswith("Cookie:") or "deserialization" in r or "pickle" in r:
        return 0  # Process cookies first (no auth needed)
    return 1  # URL params last (may need auth)
