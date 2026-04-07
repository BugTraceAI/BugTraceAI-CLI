"""
PURE functions for vulnerability classification, scoring, and deduplication.

All functions depend only on their arguments -- no network, no filesystem,
no global state mutation.
"""
from typing import Dict, List, Optional

from loguru import logger

from bugtrace.agents.dastysast.types import (
    LFI_PARAM_HINTS,
    FILE_EXTENSIONS,
    REDIRECT_PARAM_HINTS,
    RCE_PARAM_HINTS,
    SSRF_PARAM_HINTS,
)


# =========================================================================
# Vulnerability name / severity helpers
# =========================================================================

def normalize_vulnerability_name(
    v_name: str, v_desc: str, v: Dict
) -> str:
    """
    Normalise a generic vulnerability name to something more descriptive.

    Args:
        v_name: Raw vulnerability name from LLM.
        v_desc: Vulnerability description text.
        v:      Full vulnerability dict (for ``type`` fallback).

    Returns:
        Normalised vulnerability name string.
    """  # PURE
    if v_name.lower() not in ("vulnerability", "security issue", "finding"):
        return v_name

    desc_lower = str(v_desc).lower()
    if "xss" in desc_lower or "script" in desc_lower:
        return "Potential XSS Issue"
    if "sql" in desc_lower:
        return "Potential SQL Injection Issue"
    return f"Potential {v.get('type', 'Security')} Issue"


def get_severity_for_type(
    vuln_type: str, llm_severity: Optional[str] = None
) -> str:
    """
    Map vulnerability type string to severity level.

    Severity tiers:
      - **Critical** : SQLi, RCE, XXE, SSTI, Deserialization, NoSQLi
      - **High**     : XSS, Header Injection, LFI, CSTI, Session
      - **Medium**   : IDOR, SSRF, CSRF, Prototype Pollution, Open Redirect
      - **Low**      : Information Disclosure, Debug, Verbose

    Args:
        vuln_type:    Vulnerability type string (case-insensitive).
        llm_severity: Optional severity from LLM for fallback.

    Returns:
        One of ``Critical``, ``High``, ``Medium``, ``Low``.
    """  # PURE
    vuln_type_upper = vuln_type.upper()

    critical_patterns = [
        "SQL", "SQLI", "RCE", "REMOTE CODE", "COMMAND INJECTION",
        "XXE", "XML EXTERNAL", "DESERIALIZATION", "NOSQL", "SSTI",
    ]
    for pattern in critical_patterns:
        if pattern in vuln_type_upper:
            return "Critical"

    high_patterns = [
        "XSS", "CROSS-SITE SCRIPTING", "HEADER INJECTION", "CRLF",
        "RESPONSE SPLITTING", "LFI", "LOCAL FILE", "PATH TRAVERSAL",
        "AUTHENTICATION BYPASS", "SESSION", "CSTI",
    ]
    for pattern in high_patterns:
        if pattern in vuln_type_upper:
            return "High"

    medium_patterns = [
        "IDOR", "INSECURE DIRECT", "OBJECT REFERENCE", "BROKEN ACCESS",
        "SSRF", "SERVER-SIDE REQUEST", "CSRF", "CROSS-SITE REQUEST",
        "PROTOTYPE POLLUTION", "BUSINESS LOGIC", "OPEN REDIRECT",
    ]
    for pattern in medium_patterns:
        if pattern in vuln_type_upper:
            return "Medium"

    low_patterns = [
        "INFORMATION", "DISCLOSURE", "VERBOSE", "DEBUG", "STACK TRACE",
    ]
    for pattern in low_patterns:
        if pattern in vuln_type_upper:
            return "Low"

    if llm_severity and llm_severity.capitalize() in (
        "Critical", "High", "Medium", "Low", "Information"
    ):
        return llm_severity.capitalize()
    return "High"


def get_safe_name(url: str) -> str:
    """
    Generate a filesystem-safe name fragment from a URL.

    Args:
        url: Full URL string.

    Returns:
        Sanitised string (max 50 chars).
    """  # PURE
    return (
        url.replace("://", "_")
        .replace("/", "_")
        .replace("?", "_")
        .replace("&", "_")
        .replace("=", "_")[:50]
    )


# =========================================================================
# FP confidence scoring
# =========================================================================

def calculate_fp_confidence(
    finding: Dict,
    num_core_approaches: int,
    fp_skeptical_weight: float = 0.4,
    fp_votes_weight: float = 0.3,
    fp_evidence_weight: float = 0.3,
) -> float:
    """
    Calculate false-positive confidence for *finding*.

    FP Confidence Scale (0.0--1.0):
      - 0.0 : Almost certainly a FALSE POSITIVE
      - 0.5 : Uncertain -- needs specialist investigation
      - 1.0 : Almost certainly a TRUE POSITIVE

    Args:
        finding:              Vulnerability finding dict.
        num_core_approaches:  Number of core LLM approaches used.
        fp_skeptical_weight:  Weight for skeptical component.
        fp_votes_weight:      Weight for votes component.
        fp_evidence_weight:   Weight for evidence component.

    Returns:
        Float between 0.0 and 1.0.
    """  # PURE
    # 1. Skeptical component
    skeptical_score = finding.get("skeptical_score", 5)
    skeptical_component = (skeptical_score / 10.0) * fp_skeptical_weight

    # 2. Votes component
    votes = finding.get("votes", 1)
    max_votes = max(num_core_approaches, 1)
    votes_component = min(votes / max_votes, 1.0) * fp_votes_weight

    # 3. Evidence component
    evidence_quality = assess_evidence_quality(finding)
    evidence_component = evidence_quality * fp_evidence_weight

    fp_confidence = skeptical_component + votes_component + evidence_component
    return max(0.0, min(1.0, fp_confidence))


def assess_evidence_quality(finding: Dict) -> float:
    """
    Assess the quality of evidence for a finding.

    Evidence Quality Scale (0.0--1.0):
      - 0.0 : No concrete evidence (parameter name only)
      - 0.5 : Some patterns / indicators
      - 1.0 : Concrete proof (error messages, reflection, OOB callback)

    Args:
        finding: Vulnerability finding dict.

    Returns:
        Float between 0.0 and 1.0.
    """  # PURE
    evidence_score = 0.0
    reasoning = str(finding.get("reasoning", "")).lower()
    payload = str(
        finding.get("exploitation_strategy", finding.get("payload", ""))
    ).lower()
    vuln_type = str(finding.get("type", "")).lower()

    # Strong evidence indicators (+0.3 each, max 1.0)
    strong_indicators = [
        (
            "sql" in vuln_type
            and any(
                err in reasoning
                for err in [
                    "syntax error", "mysql", "postgresql", "sqlite", "ora-",
                ]
            )
        ),
        (
            "xss" in vuln_type
            and any(
                ind in reasoning
                for ind in ["unescaped", "reflected", "rendered", "executed"]
            )
        ),
        any(
            err in reasoning
            for err in ["stack trace", "exception", "error message", "debug"]
        ),
        "callback" in reasoning or "oob" in reasoning or "interactsh" in reasoning,
        finding.get("validated", False) or "confirmed" in reasoning,
    ]

    for indicator in strong_indicators:
        if indicator:
            evidence_score += 0.3

    # Medium evidence indicators (+0.15 each)
    medium_indicators = [
        len(payload) > 10 and any(c in payload for c in ["'", '"', "<", ">", "{", "}"]),
        finding.get("confidence_score", 5) >= 7,
        finding.get("votes", 1) >= 3,
    ]

    for indicator in medium_indicators:
        if indicator:
            evidence_score += 0.15

    # Weak evidence penalty (-0.2 each)
    weak_indicators = [
        "parameter name" in reasoning or "common parameter" in reasoning,
        "could be" in reasoning or "might be" in reasoning or "potentially" in reasoning,
        len(payload) < 5,
    ]

    for indicator in weak_indicators:
        if indicator:
            evidence_score -= 0.2

    return max(0.0, min(1.0, evidence_score))


# =========================================================================
# Deduplication
# =========================================================================

def deduplicate_vulnerabilities(
    vulns: List[Dict], url: str, agent_name: str = "DASTySAST"
) -> List[Dict]:
    """
    Remove duplicate vulnerabilities based on type + normalised parameter + url.

    Safety-net layer that catches duplicates the LLM may have missed.

    Args:
        vulns:      List of vulnerability finding dicts.
        url:        Default URL (used when finding lacks ``url`` key).
        agent_name: Agent name for log context.

    Returns:
        Deduplicated list of findings.
    """  # PURE
    if not vulns:
        return vulns

    seen: Dict[tuple, Dict] = {}
    deduped: List[Dict] = []

    def _normalize_param(param: str, vuln_type: str) -> str:
        param_lower = param.lower()
        if vuln_type.lower() == "xxe":
            xxe_indicators = ["post", "body", "xml", "stock", "form"]
            if any(ind in param_lower for ind in xxe_indicators):
                return "post_body"
        if "cookie:" in param_lower:
            parts = param_lower.split("cookie:")
            if len(parts) > 1:
                cookie_name = parts[1].strip().split()[0]
                return f"cookie:{cookie_name}"
        return param_lower

    for v in vulns:
        vuln_type = v.get("type", "Unknown")
        param_raw = v.get("parameter", "unknown")
        v_url = v.get("url", url)
        param_normalized = _normalize_param(param_raw, vuln_type)
        key = (vuln_type.lower(), param_normalized, v_url)

        if key not in seen:
            seen[key] = v
            deduped.append(v)
        else:
            existing = seen[key]
            if v.get("fp_confidence", 0) > existing.get("fp_confidence", 0):
                deduped.remove(existing)
                deduped.append(v)
                seen[key] = v

    if len(vulns) != len(deduped):
        logger.info(
            f"[{agent_name}] Post-deduplication: {len(vulns)} -> "
            f"{len(deduped)} findings "
            f"({len(vulns) - len(deduped)} duplicates removed)"
        )

    return deduped


def count_by_type(findings: List[Dict]) -> Dict[str, int]:
    """
    Count findings by vulnerability type.

    Args:
        findings: List of finding dicts.

    Returns:
        Dict mapping type string to count.
    """  # PURE
    counts: Dict[str, int] = {}
    for f in findings:
        v_type = f.get("type", "Unknown")
        counts[v_type] = counts.get(v_type, 0) + 1
    return counts


# =========================================================================
# Auto-candidate injection (parameter-based)
# =========================================================================

def inject_param_based_candidates(
    consolidated: List[Dict],
    url: str,
    reflection_probes: List[Dict],
    agent_name: str = "DASTySAST",
) -> List[Dict]:
    """
    Auto-generate specialist candidates based on parameter names / values.

    Ensures file-related params always reach LFI specialist, redirect-related
    params reach OpenRedirect specialist, etc. -- even when the LLM only
    detected XSS reflection.

    Args:
        consolidated:     Current consolidated findings list.
        url:              Target URL.
        reflection_probes: Probe results from active recon.
        agent_name:       Agent name for log context.

    Returns:
        Extended consolidated list (original + injected candidates).
    """  # PURE
    from urllib.parse import urlparse, parse_qs

    parsed = urlparse(url)
    url_params = parse_qs(parsed.query)

    # Collect all known params
    all_params: Dict[str, str] = {}
    for k, v in url_params.items():
        all_params[k] = v[0] if v else ""
    for probe in reflection_probes:
        pname = probe.get("parameter", "")
        if pname and pname not in all_params:
            all_params[pname] = ""

    if not all_params:
        return consolidated

    # Track existing finding types per parameter
    existing: set = set()
    for f in consolidated:
        ftype = f.get("type", "").lower()
        fparam = f.get("parameter", "").lower()
        existing.add(f"{ftype}:{fparam}")

    injected: List[Dict] = []

    for param_name, param_value in all_params.items():
        param_lower = param_name.lower()

        # --- LFI candidate ---
        is_lfi_name = param_lower in LFI_PARAM_HINTS or any(
            h in param_lower
            for h in ("file", "path", "dir", "doc", "include", "load", "read")
        )
        is_file_value = (
            any(param_value.lower().endswith(ext) for ext in FILE_EXTENSIONS)
            if param_value
            else False
        )
        has_path_sep = (
            ("/" in param_value or "\\" in param_value) if param_value else False
        )

        if is_lfi_name or is_file_value or has_path_sep:
            has_lfi = any(
                fparam == param_lower
                and ("lfi" in ftype or "traversal" in ftype or "file" in ftype)
                for ftype_param in existing
                for ftype, fparam in [ftype_param.split(":", 1)]
            )
            if not has_lfi:
                injected.append({
                    "type": "LFI",
                    "parameter": param_name,
                    "confidence_score": 7,
                    "votes": 4,
                    "probe_validated": True,
                    "fp_confidence": 0.8,
                    "skeptical_score": 8,
                    "reasoning": (
                        f"Parameter '{param_name}' suggests file operations "
                        f"(value: '{param_value}'). Auto-candidate for LFI specialist."
                    ),
                    "exploitation_strategy": "../../../etc/passwd",
                    "url": url,
                    "_auto_dispatched": True,
                })
                existing.add(f"lfi:{param_lower}")
                logger.info(
                    f"[{agent_name}] Auto-injected LFI candidate: "
                    f"param='{param_name}', value='{param_value}'"
                )

        # --- Open Redirect candidate ---
        is_redirect_name = param_lower in REDIRECT_PARAM_HINTS or any(
            h in param_lower
            for h in ("url", "redirect", "return", "goto", "dest", "next")
        )
        has_url_value = (
            param_value.startswith(("http", "//", "/")) if param_value else False
        )

        if is_redirect_name or has_url_value:
            has_redirect = any(
                fparam == param_lower
                and ("redirect" in ftype or "open redirect" in ftype)
                for ftype_param in existing
                for ftype, fparam in [ftype_param.split(":", 1)]
            )
            if not has_redirect:
                injected.append({
                    "type": "Open Redirect",
                    "parameter": param_name,
                    "confidence_score": 6,
                    "votes": 4,
                    "probe_validated": True,
                    "fp_confidence": 0.7,
                    "skeptical_score": 7,
                    "reasoning": (
                        f"Parameter '{param_name}' suggests URL redirect "
                        f"(value: '{param_value}'). Auto-candidate for OpenRedirect specialist."
                    ),
                    "url": url,
                    "_auto_dispatched": True,
                })
                existing.add(f"open redirect:{param_lower}")
                logger.info(
                    f"[{agent_name}] Auto-injected Open Redirect candidate: "
                    f"param='{param_name}'"
                )

        # --- RCE candidate ---
        is_rce_name = param_lower in RCE_PARAM_HINTS or any(
            h in param_lower
            for h in ("cmd", "exec", "command", "shell", "run")
        )
        if is_rce_name:
            has_rce = any(
                fparam == param_lower
                and ("rce" in ftype or "command" in ftype or "injection" in ftype)
                for ftype_param in existing
                for ftype, fparam in [ftype_param.split(":", 1)]
            )
            if not has_rce:
                injected.append({
                    "type": "RCE",
                    "parameter": param_name,
                    "confidence_score": 7,
                    "votes": 4,
                    "probe_validated": True,
                    "fp_confidence": 0.8,
                    "skeptical_score": 8,
                    "reasoning": (
                        f"Parameter '{param_name}' suggests command execution. "
                        f"Auto-candidate for RCE specialist."
                    ),
                    "exploitation_strategy": "id",
                    "url": url,
                    "_auto_dispatched": True,
                })
                existing.add(f"rce:{param_lower}")
                logger.info(
                    f"[{agent_name}] Auto-injected RCE candidate: "
                    f"param='{param_name}'"
                )

        # --- SSRF candidate ---
        is_ssrf_name = param_lower in SSRF_PARAM_HINTS
        is_ssrf_value = (
            param_value.startswith(("http", "//", "ftp")) if param_value else False
        )
        if is_ssrf_name or is_ssrf_value:
            has_ssrf = any(
                fparam == param_lower
                and ("ssrf" in ftype or "server-side" in ftype)
                for ftype_param in existing
                for ftype, fparam in [ftype_param.split(":", 1)]
            )
            if not has_ssrf:
                injected.append({
                    "type": "SSRF",
                    "parameter": param_name,
                    "confidence_score": 6,
                    "votes": 4,
                    "probe_validated": True,
                    "fp_confidence": 0.7,
                    "skeptical_score": 7,
                    "reasoning": (
                        f"Parameter '{param_name}' suggests URL fetching "
                        f"(value: '{param_value}'). Auto-candidate for SSRF specialist."
                    ),
                    "url": url,
                    "_auto_dispatched": True,
                })
                existing.add(f"ssrf:{param_lower}")
                logger.info(
                    f"[{agent_name}] Auto-injected SSRF candidate: "
                    f"param='{param_name}'"
                )

    if injected:
        consolidated = list(consolidated) + injected
        logger.info(
            f"[{agent_name}] Auto-injected {len(injected)} "
            f"parameter-based candidates"
        )

    return consolidated
