"""
Pure XSS finding construction and serialization.

Creates and converts XSS finding objects without side effects.
All functions are pure - they take explicit data and return results.

Extracted from xss_agent.py:
- _validate_before_emit (line 798) -> validate_before_emit (PURE)
- _emit_xss_finding (line 840) - partially, event emission stays in agent
- _update_learned_breakouts (line 867) -> update_learned_breakouts (PURE)
- _add_safety_net_payloads (line 6847) -> add_safety_net_payloads (PURE)
- _finding_to_dict (line 8873) -> finding_to_dict (PURE)
- _fragment_build_finding - build_fragment_finding (PURE)
"""

from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from bugtrace.utils.logger import get_logger
from bugtrace.reporting.standards import (
    get_cwe_for_vuln,
    get_remediation_for_vuln,
    normalize_severity,
)
from bugtrace.reporting.poc_format import curl_form_field, md_code_block

logger = get_logger("agents.xss.finding_builder")


# =========================================================================
# FINDING VALIDATION (PURE)
# =========================================================================

def validate_before_emit(
    finding: Dict,
    base_is_valid: bool = True,
    base_error: str = "",
) -> Tuple[bool, str]:
    """
    XSS-specific validation before emitting a finding.

    Requirements for XSS findings:
    1. Base validation passed (type, url)
    2. Must have evidence dict
    3. Evidence should have confirmation (screenshot, alert, vision, etc.)
    4. Payload should look like XSS (not conversational)

    PURE function.

    Args:
        finding: Finding dict with type, url, parameter, payload, evidence.
        base_is_valid: Whether base (parent) validation passed.
        base_error: Error message from base validation.

    Returns:
        Tuple of (is_valid: bool, error_message: str).
    """
    # Check parent validation first
    if not base_is_valid:
        return False, base_error

    # XSS-specific validation
    evidence = finding.get("evidence", {})

    # Check for proof of execution
    has_screenshot = evidence.get("screenshot") or evidence.get("screenshot_path")
    has_alert = evidence.get("alert_triggered")
    has_vision = evidence.get("vision_confirmed")
    has_interactsh = evidence.get("interactsh_callback")
    has_http_confirmed = (
        evidence.get("http_confirmed") or evidence.get("manipulator_confirmed")
    )

    if not (has_screenshot or has_alert or has_vision or has_interactsh or has_http_confirmed):
        return False, (
            "XSS requires proof: screenshot, alert, vision confirmation, "
            "HTTP confirmation, or Interactsh callback"
        )

    # Payload sanity check (should have XSS chars)
    payload = finding.get("payload", "")
    if payload and not any(c in str(payload) for c in '<>\'"();`'):
        return False, f"XSS payload missing attack characters: {payload[:50]}"

    # All checks passed
    return True, ""


# =========================================================================
# FINDING SERIALIZATION (PURE)
# =========================================================================

def build_raw_http(req: Dict[str, Any]) -> str:
    """Render a captured request dict as a raw HTTP request string (for the report)."""
    method = req.get("method", "GET")
    p = urlparse(req.get("url", "") or "")
    path = (p.path or "/") + (("?" + p.query) if p.query else "")
    lines = [f"{method} {path} HTTP/1.1"]
    headers = dict(req.get("headers") or {})
    if p.netloc and not any(isinstance(h, str) and h.lower() == "host" for h in headers):
        lines.append(f"Host: {p.netloc}")
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    body = req.get("body") or ""
    return "\n".join(lines) + "\n\n" + body


# =========================================================================
# SEED / REPRO ENRICHMENT (PURE) — WEB AI Repeater + report file safety
# =========================================================================

SENSITIVE_HEADERS = (
    "authorization",
    "cookie",
    "x-csrf-token",
    "x-api-key",
    "x-auth-token",
    "x-session-token",
)


def mask_auth_headers(headers: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Redact sensitive auth header VALUES (short prefix kept). Pure."""
    masked: Dict[str, Any] = {}
    for k, v in (headers or {}).items():
        if (
            isinstance(k, str)
            and k.lower() in SENSITIVE_HEADERS
            and isinstance(v, str)
            and v
        ):
            masked[k] = f"{v[:6]}…<redacted>"
        else:
            masked[k] = v
    return masked


def auth_meta(auth_headers: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Record that auth was used (scheme + masked token) without leaking secrets."""
    if not auth_headers:
        return {
            "auth_used": False,
            "auth_role": None,
            "auth_scheme": "none",
            "auth_token_masked": None,
        }
    scheme, token = "header", None
    for k, v in auth_headers.items():
        if not isinstance(v, str) or not v:
            continue
        kl = k.lower()
        if kl == "authorization":
            scheme = v.split(" ", 1)[0] if " " in v else "Bearer"
            token = f"{v[:8]}…<redacted>"
            break
        if kl == "cookie":
            scheme = "Cookie"
            token = f"{v[:8]}…<redacted>"
            break
    return {
        "auth_used": True,
        "auth_role": "user",
        "auth_scheme": scheme,
        "auth_token_masked": token,
    }


def excerpt_around(text: str, marker: str, radius: int = 2000) -> str:
    """Return ~radius chars centered on the payload reflection (not from byte 0)."""
    if not text:
        return ""
    idx = text.find(marker) if marker else -1
    if idx < 0 and marker:
        for token in (marker[:24], "BTXSS", "BUGTRACE"):
            if token:
                j = text.find(token)
                if j >= 0:
                    idx = j
                    break
    if idx < 0:
        return text[: radius * 2]
    start = max(0, idx - radius)
    end = min(len(text), idx + len(marker or "") + radius)
    return text[start:end]


def promote_repro(d: Dict[str, Any]) -> Dict[str, Any]:
    """Ensure an XSS finding dict exposes top-level ``repro`` + ``http_request``.

    Idempotent: findings that already carry ``repro`` are returned untouched.
    Mutates and returns the same dict for pipeline compatibility.
    """
    if not isinstance(d, dict) or d.get("repro"):
        return d
    ev = d.get("evidence") or {}
    cr = ev.get("confirming_request") if isinstance(ev, dict) else None
    capture = ev.get("capture_method") if isinstance(ev, dict) else None
    if not cr:
        method = str(d.get("http_method") or d.get("method") or "GET").upper()
        url = d.get("url") or ""
        param = d.get("parameter") or ""
        payload = d.get("payload") or ""
        if method == "POST":
            cr = {
                "method": "POST",
                "url": url,
                "headers": {},
                "body": f"{param}={payload}",
                "body_content_type": "application/x-www-form-urlencoded",
            }
        else:
            try:
                p = urlparse(url)
                qs = parse_qs(p.query)
                if param:
                    qs[param] = [payload]
                url = urlunparse(
                    (p.scheme, p.netloc, p.path, "", urlencode(qs, doseq=True), "")
                )
            except Exception:
                pass
            cr = {
                "method": "GET",
                "url": url,
                "headers": {},
                "body": None,
                "body_content_type": None,
            }
        capture = "reconstructed_from_finding"
    d["repro"] = {
        "confirming_request": cr,
        "confirming_response": ev.get("confirming_response") if isinstance(ev, dict) else None,
        "readback_request": ev.get("readback_request") if isinstance(ev, dict) else None,
        "auth": ev.get("repro_auth") if isinstance(ev, dict) else None,
        "capture_method": capture,
    }
    if not d.get("http_request"):
        try:
            d["http_request"] = build_raw_http(cr)
        except Exception:
            pass
    return d


def _build_repro_seed(finding, *, test_url: str) -> Dict[str, Any]:
    """Build the nested ``repro`` object used by the WEB AI Repeater.

    Prefer live-captured confirming_request on evidence; otherwise reconstruct
    from finding fields so repro is never null for confirmed XSS paths.
    """
    evidence = getattr(finding, "evidence", None) or {}
    if not isinstance(evidence, dict):
        evidence = {}
    method = (getattr(finding, "http_method", None) or "GET").upper()
    confirming = evidence.get("confirming_request")
    capture = evidence.get("capture_method")
    if not confirming:
        if method == "POST":
            confirming = {
                "method": "POST",
                "url": finding.url,
                "headers": {},
                "body": f"{finding.parameter}={finding.payload}",
                "body_content_type": "application/x-www-form-urlencoded",
            }
        else:
            confirming = {
                "method": "GET",
                "url": test_url,
                "headers": {},
                "body": None,
                "body_content_type": None,
            }
        capture = "reconstructed_from_finding"
    return {
        "confirming_request": confirming,
        "confirming_response": evidence.get("confirming_response"),
        "readback_request": evidence.get("readback_request"),
        "auth": evidence.get("repro_auth"),
        "capture_method": capture,
    }


def finding_to_dict(finding) -> Dict:
    """
    Convert an XSSFinding dataclass to dictionary for JSON output.

    Generates reproduction URL/command based on HTTP method.

    PURE function.

    Args:
        finding: XSSFinding dataclass instance with url, parameter, payload,
            context, reflection_context, surviving_chars, validation_method,
            evidence, confidence, screenshot_path, validated, status,
            xss_type, injection_context_type, vulnerable_code_snippet,
            server_escaping, escape_bypass_technique, bypass_explanation,
            exploit_url, exploit_url_encoded, verification_methods,
            verification_warnings, reproduction_steps, successful_payloads,
            http_method.

    Returns:
        Dict suitable for JSON serialization.
    """
    # Generate reproduction URL/command.
    # Both shapes carry the payload through a BYTE-SAFE channel: percent-encoding for the
    # GET URL, a quoted shell word + --data-urlencode for the POST command. Interpolating
    # the payload raw into `-d '...'` used to break the command outright on a payload
    # containing a quote, and — worse — silently deliver an EMPTY parameter on payloads
    # whose quotes happened to balance.
    try:
        if finding.http_method == "POST":
            reproduction = (
                "# POST request to trigger XSS:\n"
                + curl_form_field(finding.url, finding.parameter, finding.payload)
            )
            test_url = finding.url
        else:
            parsed = urlparse(finding.url)
            qs = parse_qs(parsed.query)
            qs[finding.parameter] = [finding.payload]
            new_query = urlencode(qs, doseq=True)
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path, '', new_query, '',
            ))
            reproduction = f"# Open in browser to trigger XSS:\n{test_url}"
    except Exception:
        # No usable URL: point at the injection point and ship the payload in a fenced
        # block, never bare in a comment line where markdown would eat its backticks.
        reproduction = (
            f"# XSS: inject the payload below into parameter '{finding.parameter}'\n"
            + md_code_block(finding.payload)
        )
        test_url = finding.url

    return {
        "type": "XSS",
        "url": finding.url,
        "parameter": finding.parameter,
        "payload": finding.payload,
        "context": finding.context,
        "reflection_context": finding.reflection_context,
        "surviving_chars": finding.surviving_chars,
        "validation_method": finding.validation_method,
        "evidence": finding.evidence,
        "confidence": finding.confidence,
        "screenshot_path": finding.screenshot_path,
        "validated": finding.validated,
        "status": finding.status,
        "severity": normalize_severity("HIGH").value,
        "cwe_id": get_cwe_for_vuln("XSS"),
        "cve_id": "N/A",
        "remediation": get_remediation_for_vuln("XSS"),
        "description": (
            f"Reflected XSS confirmed in parameter '{finding.parameter}'. "
            f"Context: {finding.reflection_context}. "
            f"Payload executed successfully via {finding.validation_method}."
        ),
        "reproduction": reproduction,
        # Seed enrichment for WEB AI Repeater (parity with monolith _finding_to_dict).
        "repro": (repro := _build_repro_seed(finding, test_url=test_url)),
        # HTTP evidence fields — raw HTTP block from confirming request when possible.
        "http_request": (
            finding.evidence.get("http_request")
            or build_raw_http(repro.get("confirming_request") or {"method": finding.http_method, "url": test_url})
        ),
        "http_response": finding.evidence.get(
            "http_response",
            finding.evidence.get("page_html", "")[:500]
            if finding.evidence.get("page_html")
            else "",
        ),
        # Enhanced fields
        "xss_type": finding.xss_type,
        "injection_context_type": finding.injection_context_type,
        "vulnerable_code_snippet": finding.vulnerable_code_snippet,
        "server_escaping": finding.server_escaping,
        "escape_bypass_technique": finding.escape_bypass_technique,
        "bypass_explanation": finding.bypass_explanation,
        "exploit_url": finding.exploit_url,
        "exploit_url_encoded": finding.exploit_url_encoded,
        "verification_methods": finding.verification_methods,
        "verification_warnings": finding.verification_warnings,
        "reproduction_steps": finding.reproduction_steps,
        "successful_payloads": finding.successful_payloads or [],
        "http_method": finding.http_method,
    }


# =========================================================================
# FRAGMENT FINDING BUILDER (PURE)
# =========================================================================

def build_fragment_finding(
    url: str,
    param: str,
    payload: str,
    result: Any,
) -> Dict:
    """
    Build XSS finding dict from a validated fragment injection result.

    Fragment-based XSS uses location.hash to bypass WAFs.

    PURE function.

    Args:
        url: Target URL.
        param: Parameter that was bypassed.
        payload: Fragment payload that succeeded.
        result: Verification result with .details, .method, .screenshot_path,
            .console_logs attributes.

    Returns:
        Dict with all fields needed to create an XSSFinding.
    """
    evidence = result.details or {}
    evidence["method"] = result.method
    evidence["screenshot_path"] = result.screenshot_path
    if result.console_logs:
        evidence["console_logs"] = result.console_logs

    return {
        "url": url,
        "parameter": f"#fragment (bypassed {param})",
        "payload": payload,
        "context": "dom_xss_fragment",
        "validation_method": f"vision+{result.method}",
        "evidence": evidence,
        "confidence": 1.0,
        "status": "VALIDATED_CONFIRMED",
        "validated": True,
        "screenshot_path": result.screenshot_path,
        "reflection_context": "location.hash -> innerHTML",
        "surviving_chars": "N/A (client-side)",
    }


# =========================================================================
# LEARNED BREAKOUTS (PURE)
# =========================================================================

def update_learned_breakouts(
    learned_breakouts: Dict,
    payload: str,
    prefixes: List[str],
) -> Dict:
    """
    Return a NEW dict with updated breakout success counts.

    Extracts the breakout prefix from a successful payload and
    increments its success_count for future prioritization.
    Does NOT mutate the input dict.

    PURE function.

    Args:
        learned_breakouts: Current breakout success counts dict.
        payload: Successful payload string.
        prefixes: List of known breakout prefixes.

    Returns:
        New dict with updated success counts.
    """
    new_breakouts = dict(learned_breakouts)

    for prefix in prefixes:
        if prefix and payload.startswith(prefix):
            current_count = new_breakouts.get(prefix, 0)
            new_breakouts[prefix] = current_count + 1
            logger.debug(f"Learned successful breakout: {prefix}")
            break

    return new_breakouts


# =========================================================================
# SAFETY NET PAYLOADS (PURE)
# =========================================================================

def add_safety_net_payloads(
    filtered: List[str],
    all_payloads: List[str],
    safety_net_count: int = 10,
) -> List[str]:
    """
    Add top killer payloads as safety net if not already included.

    Ensures the top N payloads from the full list are present in
    the filtered list, adding any that are missing.

    PURE function.

    Args:
        filtered: Current filtered payload list.
        all_payloads: Full payload list (safety net drawn from top N).
        safety_net_count: Number of top payloads to ensure are included.

    Returns:
        New list with safety net payloads appended if needed.
    """
    result = list(filtered)
    safety_net = all_payloads[:safety_net_count]
    for sn in safety_net:
        if sn not in result:
            result.append(sn)
    return result


def create_reflected_xss_finding(
    *,
    url: str,
    parameter: str,
    payload: str,
    context: str,
    validation_method: str,
    evidence: Dict,
    confidence: float,
    status: str,
    validated: bool,
    reflection_context: str,
    surviving_chars: str,
    successful_payloads: List[str],
    injection_context_type: str,
    vulnerable_code_snippet: str,
    server_escaping: Dict,
    escape_bypass_technique: str,
    bypass_explanation: str,
    exploit_url: str,
    exploit_url_encoded: str,
    verification_methods: List,
    verification_warnings: List,
    reproduction_steps: List,
    screenshot_path: Optional[str] = None,
    finding_cls: Any = None,
):
    """PURE: assemble a reflected XSSFinding from precomputed fields."""
    if finding_cls is None:
        from bugtrace.agents.xss.types import XSSFinding as finding_cls
    return finding_cls(
        url=url,
        parameter=parameter,
        payload=payload,
        context=context,
        validation_method=validation_method,
        evidence=evidence,
        confidence=confidence,
        status=status,
        validated=validated,
        screenshot_path=screenshot_path,
        reflection_context=reflection_context,
        surviving_chars=surviving_chars,
        successful_payloads=successful_payloads,
        xss_type="reflected",
        injection_context_type=injection_context_type,
        vulnerable_code_snippet=vulnerable_code_snippet,
        server_escaping=server_escaping,
        escape_bypass_technique=escape_bypass_technique,
        bypass_explanation=bypass_explanation,
        exploit_url=exploit_url,
        exploit_url_encoded=exploit_url_encoded,
        verification_methods=verification_methods,
        verification_warnings=verification_warnings,
        reproduction_steps=reproduction_steps,
    )


def create_authority_xss_finding(
    *,
    url: str,
    parameter: str,
    payload: str,
    ref_context: str,
    injection_context_type: str,
    vulnerable_code_snippet: str,
    server_escaping: Dict,
    exploit_url: str,
    exploit_url_encoded: str,
    verification_methods: List,
    verification_warnings: List,
    reproduction_steps: List,
    finding_cls: Any = None,
):
    """PURE: authority-confirmed unencoded reflection finding."""
    if finding_cls is None:
        from bugtrace.agents.xss.types import XSSFinding as finding_cls
    evidence = {
        "payload": payload,
        "unencoded_reflection": True,
        "reflection_context": ref_context,
        "description": (
            f"Reflected without encoding in {ref_context} context "
            "(Go Fuzzer Authority)."
        ),
    }
    return finding_cls(
        url=url,
        parameter=parameter,
        payload=payload,
        context="reflected_unencoded",
        validation_method="go_fuzzer_authority",
        evidence=evidence,
        confidence=1.0,
        status="VALIDATED_CONFIRMED",
        reflection_context=ref_context,
        xss_type="reflected",
        injection_context_type=injection_context_type,
        vulnerable_code_snippet=vulnerable_code_snippet,
        server_escaping=server_escaping,
        escape_bypass_technique="none_needed",
        bypass_explanation="Payload was reflected without encoding.",
        exploit_url=exploit_url,
        exploit_url_encoded=exploit_url_encoded,
        verification_methods=verification_methods,
        verification_warnings=verification_warnings,
        reproduction_steps=reproduction_steps,
    )


__all__ = [
    # Validation
    "validate_before_emit",
    # Serialization
    "finding_to_dict",
    # Building
    "build_fragment_finding",
    "create_reflected_xss_finding",
    "create_authority_xss_finding",
    # Learned breakouts
    "update_learned_breakouts",
    # Safety net
    "add_safety_net_payloads",
]
