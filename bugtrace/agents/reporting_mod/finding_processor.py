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
def upgrade_payload(
    payload: str,
    vuln_type: str,
    engine_type: Optional[str] = None,
) -> Optional[str]:
    """Return the visual-PoC upgrade of a silent payload, or None if none applies.

    Single source of truth for the silent → visual "HACKED BY BUGTRACEAI" transform,
    shared by the reporting upgrade pass (`upgrade_finding_payloads`) and the XSS
    proof-screenshot capture (`XSSAgentV4._capture_proof_screenshot`). Keeping it
    here — next to the maps — avoids a second copy of the transform in the agent.

    `engine_type` is the template-injection discriminator. CSTIAgent labels EVERY
    template finding `type: "CSTI"` — server-side Jinja2 included — and records the
    real distinction in `engine_type`, so vuln_type alone cannot tell a browser-side
    engine from a server-side one. The banner is a client-side sandbox escape: on a
    server-side engine it renders nothing, so a server-side finding keeps the
    arithmetic proof that was actually observed rather than a PoC that cannot fire.
    """
    if not payload:
        return None
    vt = (vuln_type or "").upper()

    if vt in ("XSS", "DOM-XSS", "REFLECTED_XSS", "STORED_XSS"):
        upgrade_map = _PAYLOAD_UPGRADE_MAP
    elif vt in ("CSTI", "SSTI"):
        if "server" in (engine_type or "").lower():
            return None
        upgrade_map = _CSTI_UPGRADE_MAP
    else:
        return None

    # Exact match first
    new_payload = upgrade_map.get(payload)

    # Substring fallback (e.g. an LLM-built payload wrapping document.title=..., or
    # a confirmed XSS proven via an alert() canary).
    if not new_payload:
        already_visual = (
            _VISUAL_BANNER_TEXT in payload or _VISUAL_BANNER_TEXT_ESCAPED in payload
        )
        if vt in ("XSS", "DOM-XSS", "REFLECTED_XSS", "STORED_XSS") and not already_visual:
            banner_block = "{" + _VISUAL_BANNER_JS + "}"
            if "document.title=document.domain" in payload:
                new_payload = payload.replace("document.title=document.domain", banner_block)
            elif "alert(document.domain)" in payload:
                new_payload = payload.replace("alert(document.domain)", banner_block)
            else:
                # Confirmed XSS proven via an alert() canary, e.g.
                # `onerror=alert('BUGTRACEAI_7x7')`: swap the alert call for the
                # visible banner so the proof screenshot shows real impact instead
                # of a fired-and-dismissed dialog. Validated on BugStore that the
                # banner renders in <img>/<svg> attribute contexts (quoted and
                # unquoted). Match our own BUGTRACEAI canary only — never a
                # user/site alert — and upgrade the first occurrence.
                m = re.search(r"alert\(\s*['\"`]?BUGTRACEAI[^)]*\)", payload)
                if m:
                    new_payload = payload[:m.start()] + banner_block + payload[m.end():]
        elif vt in ("CSTI", "SSTI"):
            for silent, visual in _CSTI_UPGRADE_MAP.items():
                if silent in payload:
                    new_payload = payload.replace(silent, visual)
                    break

    if new_payload and new_payload != payload:
        return new_payload
    return None


# =============================================================================
# BOUNDARY COERCION for captured requests
# =============================================================================
# A `confirming_request` is assembled by many different producers (specialists,
# DB rows, LLM-authored repro blocks), so its fields are NOT guaranteed to be the
# types the report-time rewrite wants: bodies arrive as bytes or as parsed JSON
# dicts, URLs as None or malformed IPv6 literals, headers as a list of raw lines.
# These helpers normalize at the boundary so the pure rewriters below only ever see
# text — a cosmetic report enhancement must never be able to abort the whole report.


# PURE
def _as_text(value, lossy: bool = False) -> str:
    """Coerce a captured request field to text, or "" when it is not usable text.

    `lossy=False` (the default) is for rewrite decisions: undecodable bytes yield ""
    so the caller DECLINES instead of silently corrupting the request. `lossy=True`
    is for rendering only, where showing replacement characters beats dropping the
    body from the displayed request.
    """
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        try:
            return bytes(value).decode("utf-8", "replace" if lossy else "strict")
        except (UnicodeDecodeError, ValueError):
            return ""
    return ""


# PURE
def _as_header_map(value) -> Dict[str, str]:
    """Coerce a captured `headers` field into a name → value mapping.

    Accepts a mapping, a sequence of (name, value) pairs, or a sequence of raw
    "Name: value" header lines. Anything unreadable yields {} rather than raising.
    """
    if isinstance(value, dict):
        return {str(k): str(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        headers: Dict[str, str] = {}
        for item in value:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                headers[str(item[0])] = str(item[1])
                continue
            name, sep, val = _as_text(item, lossy=True).partition(":")
            if sep and name.strip():
                headers[name.strip()] = val.strip()
        return headers
    return {}


# PURE
def _split_url(url):
    """`urlparse` that never raises — None when the URL cannot be parsed.

    `urlparse` raises ValueError on malformed IPv6 literals (`http://[::1/x`), which
    a captured request can legitimately contain.
    """
    try:
        return urlparse(_as_text(url, lossy=True))
    except Exception:
        return None


# PURE
def _rewrite_query_payload(query, old_payload, new_payload) -> Optional[str]:
    """Swap `old_payload` for `new_payload` inside a query string / urlencoded body.

    Returns None when the old payload is present neither raw nor percent-encoded, so
    a caller never rewrites a request it cannot rebuild with confidence.

    Two styles are handled, matching how the XSS agent builds its URLs
    (`build_exploit_url`, encoded=False / encoded=True):
    - raw query: only the payload bytes change, every other parameter keeps its
      exact original encoding (no blind whole-URL unquote/requote);
    - encoded query: the payload is matched on the DECODED value and the query is
      re-encoded from its decoded pairs.
    """
    query = _as_text(query)
    old_payload = _as_text(old_payload)
    new_payload = _as_text(new_payload)
    if not query or not old_payload or not new_payload:
        return None

    if old_payload in query:
        return query.replace(old_payload, new_payload)

    pairs = parse_qsl(query, keep_blank_values=True)
    new_pairs = [(k, v.replace(old_payload, new_payload)) for k, v in pairs]
    if new_pairs == pairs:
        return None
    return urlencode(new_pairs)


# PURE
def _rewrite_url_payload(url, old_payload, new_payload) -> Optional[str]:
    """Rebuild `url` carrying the upgraded payload, or None if it cannot be done safely.

    Only the query string is touched: a payload injected into the path/fragment cannot
    be swapped without guessing, so those URLs are left exactly as captured.
    """
    url = _as_text(url)
    if not url:
        return None
    parts = _split_url(url)
    if parts is None:
        return None
    new_query = _rewrite_query_payload(parts.query, old_payload, new_payload)
    if new_query is None:
        return None
    return urlunparse((parts.scheme, parts.netloc, parts.path, parts.params,
                       new_query, parts.fragment))


# PURE
def _rewrite_body_payload(body, content_type, old_payload, new_payload) -> Optional[str]:
    """Rewrite a urlencoded form body only.

    A JSON/XML/multipart body embeds the payload with its own escaping rules; a
    substring swap there could produce an invalid request, so those bodies are left
    untouched (an unchanged original beats a corrupted repro). A body that is not
    text at all — a parsed JSON dict, undecodable bytes — is declined for the same
    reason.
    """
    body = _as_text(body)
    if not body:
        return None
    ct = _as_text(content_type).lower()
    if ct and "form-urlencoded" not in ct:
        return None
    return _rewrite_query_payload(body, old_payload, new_payload)


# PURE
def _render_raw_http(req: Dict) -> str:
    """Render a captured request dict as a raw HTTP request string.

    Mirrors `xss_agent._build_raw_http` byte for byte for a well-formed request. It is
    duplicated here rather than imported because pulling the XSS monolith into the
    reporting path just to format five lines of text would drag in the whole
    browser/tooling stack.

    TOTAL: every field goes through the boundary coercions above, so a malformed
    capture degrades the rendering instead of raising into the reporting pipeline.
    """
    method = _as_text(req.get("method")) or "GET"
    url = _as_text(req.get("url"), lossy=True)
    parts = _split_url(url)
    if parts is None:
        # Unparsable URL (malformed IPv6 literal, ...): show it verbatim on the
        # request line rather than dropping the rendered request entirely.
        path, netloc = url or "/", ""
    else:
        path = (parts.path or "/") + (("?" + parts.query) if parts.query else "")
        netloc = parts.netloc
    lines = [f"{method} {path} HTTP/1.1"]
    headers = _as_header_map(req.get("headers"))
    if netloc and not any(h.lower() == "host" for h in headers):
        lines.append(f"Host: {netloc}")
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    body = _as_text(req.get("body"), lossy=True)
    return "\n".join(lines) + "\n\n" + body


# PURE
def _rewrite_raw_http_payload(raw, old_payload, new_payload) -> Optional[str]:
    """Swap the payload inside an ALREADY rendered raw HTTP request.

    Used only when the finding carries no structured confirming_request to re-render
    from. Touches the request-line query and a urlencoded body; headers are never
    modified. Returns None when nothing could be rewritten.
    """
    raw = _as_text(raw)
    old_payload = _as_text(old_payload)
    new_payload = _as_text(new_payload)
    if not raw or not old_payload or not new_payload:
        return None

    head, sep, body = raw.partition("\n\n")
    lines = head.split("\n")
    if not lines:
        return None

    changed = False
    tokens = lines[0].split(" ")
    if len(tokens) >= 2 and "?" in tokens[1]:
        path, _, query = tokens[1].partition("?")
        new_query = _rewrite_query_payload(query, old_payload, new_payload)
        if new_query is not None:
            tokens[1] = f"{path}?{new_query}"
            lines[0] = " ".join(tokens)
            changed = True

    if sep and body:
        new_body = _rewrite_query_payload(body, old_payload, new_payload)
        if new_body is not None:
            body = new_body
            changed = True

    if not changed:
        return None
    return "\n".join(lines) + sep + body


# PURE
def _rewrite_repro_text(repro, old_payload, new_payload) -> Optional[str]:
    """Re-point a free-text reproduction block at the upgraded payload.

    A reproduction is a small script: comment lines plus one payload-bearing line, which
    is either a URL (``# Open in browser…`` + exploit URL) or a shell command. URL lines
    go through the query rewriter so the payload stays correctly percent-encoded; every
    other line takes a literal swap, which is safe because a shell word built by
    `poc_format.shell_word` contains the payload verbatim.

    Returns None when the payload appears on no line, so a reproduction that was never
    about this payload is left exactly as the specialist wrote it.
    """
    repro = _as_text(repro)
    old_payload = _as_text(old_payload)
    new_payload = _as_text(new_payload)
    if not repro or not old_payload or not new_payload:
        return None

    out, changed = [], False
    for line in repro.split("\n"):
        rewritten = None
        if "?" in line and "://" in line:
            candidate = line.strip()
            rewritten = _rewrite_url_payload(candidate, old_payload, new_payload)
            if rewritten:
                rewritten = line.replace(candidate, rewritten)
        if rewritten is None and old_payload in line:
            rewritten = line.replace(old_payload, new_payload)
        if rewritten is not None and rewritten != line:
            changed = True
            out.append(rewritten)
        else:
            out.append(line)
    return "\n".join(out) if changed else None


def _sync_repro_with_payload(finding: Dict, old_payload: str, new_payload: str) -> bool:
    """Re-point the finding's REPORTED request at the payload the report displays.

    Without this the report shows the visual banner payload while
    `repro.confirming_request` / `http_request` / `exploit_url*` still carry the silent
    detection probe, so a human copy-pastes a request that cannot reproduce what the
    report claims. The silent probe is not lost: it is preserved as
    `repro.detection_request` (never clobbering one the agent already stamped).

    Mutates `finding` in place — all parsing/decision logic lives in the pure helpers
    above. Returns True if anything was rewritten.

    TOTAL: this is a cosmetic report-time enhancement running inside
    `generate_all_deliverables`, which has no enclosing try — a single malformed
    finding raising here would cost the user the ENTIRE report. So it may decline to
    rewrite (leaving the captured request exactly as-is) but it never propagates an
    exception: the pure helpers above coerce at the boundary, and this last-resort
    guard covers anything they did not anticipate.
    """
    if not isinstance(finding, dict):
        return False
    old_payload = _as_text(old_payload)
    new_payload = _as_text(new_payload)
    if not old_payload or not new_payload:
        return False

    changed = False
    try:
        # `url` is printed as the finding's headline endpoint (finding_template.md,
        # report_viewer.html) and OFTEN already carries the payload — a URL still showing
        # the silent probe next to a banner Payload block is the desync the report shows
        # the reader. `_rewrite_url_payload` returns None when the payload is not in the
        # query, so a plain endpoint URL is left exactly as captured.
        for key in ("url", "exploit_url", "exploit_url_encoded"):
            value = _as_text(finding.get(key))
            if value:
                rewritten = _rewrite_url_payload(value, old_payload, new_payload)
                if rewritten and rewritten != value:
                    finding[key] = rewritten
                    changed = True

        # `reproduction` is Priority 1 for every reproduction renderer (the monolith's
        # _generate_curl, formatters.generate_curl, report_viewer.html), so an unsynced
        # one silently outranks everything rewritten below.
        repro_text = _as_text(finding.get("reproduction"))
        if repro_text:
            rewritten = _rewrite_repro_text(repro_text, old_payload, new_payload)
            if rewritten and rewritten != repro_text:
                finding["reproduction"] = rewritten
                changed = True

        # The captured request lives under `repro` for some producers and under
        # `evidence` for others (the XSS specialist stamps BOTH); syncing one and not the
        # other leaves the report quoting two different exploits for one finding.
        rendered_from_structured = False
        for container in (finding.get("repro"), finding.get("evidence")):
            if not isinstance(container, dict):
                continue
            confirming = container.get("confirming_request")
            if not isinstance(confirming, dict):
                continue
            new_url = _rewrite_url_payload(confirming.get("url"), old_payload, new_payload)
            new_body = _rewrite_body_payload(
                confirming.get("body"), confirming.get("body_content_type"),
                old_payload, new_payload,
            )
            if not (new_url or new_body):
                continue
            upgraded = dict(confirming)
            if new_url:
                upgraded["url"] = new_url
            if new_body:
                upgraded["body"] = new_body
            # Render BEFORE touching the finding: every mutation below is a plain
            # assignment, so the finding can never be left half-synced.
            rendered = _render_raw_http(upgraded)
            container.setdefault("detection_request", confirming)
            container["confirming_request"] = upgraded
            # Keep the rendered request identical to the structured one it came from.
            finding["http_request"] = rendered
            rendered_from_structured = True
            changed = True

        # Only when no structured request could be re-rendered: patch the already
        # rendered raw request in place (headers untouched).
        if not rendered_from_structured:
            raw = _as_text(finding.get("http_request"))
            if raw:
                rewritten = _rewrite_raw_http_payload(raw, old_payload, new_payload)
                if rewritten:
                    finding["http_request"] = rewritten
                    changed = True
    except Exception as e:
        logger.debug(
            f"[ReportingAgent] Repro sync declined for {finding.get('type')}/"
            f"{finding.get('parameter')} ({type(e).__name__}: {e}); "
            f"leaving the captured request untouched"
        )

    return changed


# PURE
def upgrade_finding_payloads(findings: List[Dict]) -> List[Dict]:
    """
    Upgrade silent/technical payloads to visual PoC equivalents for reports.

    The scanner uses stealthy payloads (document.title, 7*7) for speed and
    reliability. This function replaces them with impactful visual payloads
    (HACKED BY BUGTRACEAI banner) so the final report always looks professional.

    The original payload is preserved in evidence['original_payload'].
    """
    for finding in findings:
        vuln_type = (finding.get("type") or "").upper()
        payload = finding.get("payload", "")
        if not payload:
            continue

        new_payload = upgrade_payload(payload, vuln_type, finding.get("engine_type"))

        if new_payload and new_payload != payload:
            # Preserve original for traceability
            evidence = finding.get("evidence", {})
            if isinstance(evidence, dict):
                evidence["original_payload"] = payload
                finding["evidence"] = evidence

            finding["payload"] = new_payload

            # Also upgrade successful_payloads list
            sp = finding.get("successful_payloads", [])
            if isinstance(sp, list) and payload in sp:
                sp[sp.index(payload)] = new_payload
                finding["successful_payloads"] = sp

            # NOT substituted: `exploitation_details` and `llm_reproduction_steps`.
            # Those are LLM PROSE, written about the detection payload and asserting what
            # that payload does. A blind .replace() swapped the payload token and left the
            # claim standing, so a 277-byte visual banner ended up in a sentence promising
            # it "changes the page title to the domain name" — a false claim in a report
            # whose whole value is that it does not overstate. The prose keeps describing
            # the probe it was written about; `md_injection_point` labels the two payloads
            # (shipped PoC vs detection probe) so the reader is never guessing which is which.

            # Keep the reproduction REQUEST in sync with the payload we just put in
            # the report — otherwise the reader copies a request that does not carry
            # the displayed payload.
            repro_synced = _sync_repro_with_payload(finding, payload, new_payload)

            logger.info(
                f"[ReportingAgent] Payload upgrade: {vuln_type}/{finding.get('parameter')} "
                f"silent → visual PoC (repro {'synced' if repro_synced else 'unchanged'})"
            )

    return findings


# PURE
def meets_report_quality(finding: Dict) -> bool:
    """
    Quality gate for the final report. Ensures findings meet pentest-grade
    standards. Weak findings are routed to manual_review instead.

    Filters:
    - XSS/DOM-XSS with static-analysis payloads (no real exploit)
    - XSS validated only via HTTP response analysis (no browser execution)
    """
    vuln_type = (finding.get("type") or "").upper()
    payload = (finding.get("payload") or "").lower()
    evidence = finding.get("evidence") or {}
    level = ""
    if isinstance(evidence, dict):
        level = evidence.get("level", "") or ""
    validation_method = (finding.get("validation_method") or "").lower()

    # --- Filter 1: Static analysis payloads are not real exploits ---
    for pattern in STATIC_ANALYSIS_PATTERNS:
        if pattern in payload:
            logger.info(
                f"[ReportingAgent] Report quality gate: {vuln_type}/{finding.get('parameter')} "
                f"has static-analysis payload, routing to manual_review"
            )
            return False

    # --- Filter 2: XSS without browser-confirmed execution ---
    if vuln_type == "XSS" and level in XSS_UNCONFIRMED_LEVELS:
        # v3.5 Hotfix: If the agent explicitly confirmed via HTTP smart probe
        if isinstance(evidence, dict) and evidence.get("http_confirmed") is True:
            logger.info(
                f"[ReportingAgent] Report quality gate: XSS/{finding.get('parameter')} "
                f"is {level} but has http_confirmed=True. Allowing in report."
            )
            return True
        logger.info(
            f"[ReportingAgent] Report quality gate: XSS/{finding.get('parameter')} "
            f"validated at {level} (HTTP-only), routing to manual_review"
        )
        return False

    # --- Filter 3: SQLi without solid exploitation evidence ---
    if vuln_type == "SQLI":
        # Strong evidence indicators
        has_sqlmap_confirmed = evidence.get("sqlmap_confirmed") is True
        has_data_extracted = bool(
            finding.get("extracted_databases") or 
            finding.get("extracted_tables") or 
            finding.get("sample_data")
        )
        has_oob_callback = evidence.get("oob_callback_received") is True
        
        # Error-based requires DB type identified + not just "unknown"
        has_solid_error = (
            finding.get("dbms_detected") not in (None, "unknown") and
            level in ("L1", "L2", "L3")
        )
        
        # Time-based requires triple verification
        has_verified_time = (
            evidence.get("time_based_triple_verified") is True
        )
        
        # Boolean requires at least medium confidence
        has_confirmed_boolean = (
            finding.get("type") == "SQLI" and
            evidence.get("boolean_confidence") in ("HIGH", "MAXIMUM")
        )
        
        has_solid_evidence = (
            has_sqlmap_confirmed or
            has_data_extracted or
            has_oob_callback or
            has_solid_error or
            has_verified_time or
            has_confirmed_boolean
        )
        
        if not has_solid_evidence:
            logger.info(
                f"[ReportingAgent] Report quality gate: SQLI/{finding.get('parameter')} "
                f"lacks solid exploitation evidence (status_differential/weak boolean), "
                f"routing to manual_review"
            )
            return False

    return True


# PURE
def deduplicate_exact(findings: List[Dict]) -> List[Dict]:
    """Deduplicate findings by exact (url, parameter, payload) key."""
    seen = set()
    unique = []
    for f in findings:
        key = (f.get("url"), f.get("parameter"), f.get("payload"))
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


# PURE
def normalize_type_for_dedup(vuln_type: str) -> str:
    """
    Normalize vulnerability type for deduplication grouping.

    Strips technique suffixes so variants group together:
    - "SQL Injection (Error-Based)" -> "SQL INJECTION"
    - "XSS" -> "XSS"
    - "CSTI (AngularJS)" -> "CSTI"
    """
    normalized = vuln_type.upper().strip()
    paren_idx = normalized.find("(")
    if paren_idx > -1:
        normalized = normalized[:paren_idx].strip()
    return normalized


# PURE
def normalize_parameter_for_dedup(param: str) -> str:
    """
    Normalize parameter for deduplication grouping.

    Handles variations like:
    - "Cookie: TrackingId" / "cookie: trackingid" / "TrackingId (cookie)"
    - "Header: X-Forwarded-For" / "x-forwarded-for header"

    Returns lowercase normalized key for grouping.
    """
    param_lower = param.lower().strip()

    # Cookie normalization: extract just the cookie name
    if "cookie" in param_lower:
        clean = param_lower.replace("cookie:", "").replace("cookie", "").strip()
        clean = clean.split()[0] if clean else "unknown"
        clean = clean.strip(":").strip()
        return f"cookie:{clean}" if clean else "cookie:unknown"

    # Header normalization
    if "header" in param_lower:
        clean = param_lower.replace("header:", "").replace("header", "").strip()
        clean = clean.split()[0] if clean else "unknown"
        clean = clean.strip(":").strip()
        return f"header:{clean}" if clean else "header:unknown"

    return param_lower


# PURE
def deduplicate_findings(findings: List[Dict]) -> List[Dict]:
    """
    Deduplicate findings by (type, normalized_parameter).

    For example, if we have 4 SQLi findings on Cookie: TrackingId across
    different URLs, we'll return 1 representative finding.

    Returns: List of deduplicated findings with 'affected_urls' metadata.
    """
    groups = defaultdict(list)
    for f in findings:
        param_raw = f.get("parameter", "")
        param_normalized = normalize_parameter_for_dedup(param_raw)
        vuln_type = normalize_type_for_dedup(f.get("type", "Unknown"))
        key = (vuln_type, param_normalized)
        groups[key].append(f)

    deduplicated = []
    for (vuln_type, param_key), group in groups.items():
        if len(group) == 1:
            deduplicated.append(group[0])
        else:
            # Multiple findings - pick the best one as representative
            sorted_group = sorted(
                group,
                key=lambda x: (
                    x.get("status") == "VALIDATED_CONFIRMED",
                    {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(
                        normalize_severity(x.get("severity") or "medium").lower(), 2
                    )
                ),
                reverse=True
            )
            representative = sorted_group[0].copy()

            # Collect all affected URLs (deduplicated)
            affected_urls = list(set(f.get("url", "") for f in group if f.get("url")))
            representative["affected_urls"] = affected_urls
            representative["affected_count"] = len(affected_urls)

            original_param = representative.get("parameter", param_key)

            original_desc = representative.get("description", "")
            if len(affected_urls) > 1:
                dedup_note = f"\n\n**Note:** This vulnerability affects {len(affected_urls)} endpoints with parameter `{original_param}`."
                representative["description"] = original_desc + dedup_note

            deduplicated.append(representative)

            logger.info(f"[ReportingAgent] Deduplicated {len(group)} {vuln_type} findings on '{param_key}' -> 1 finding")

    return deduplicated


# PURE
def count_by_severity(validated: List[Dict]) -> Dict[str, int]:
    """Count findings by severity level."""
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in validated:
        sev = normalize_severity(f.get("severity") or "medium").lower()
        if sev in by_severity:
            by_severity[sev] += 1
    return by_severity


# PURE
def event_finding_to_db_format(event_finding: Dict) -> Dict:
    """
    Convert event finding structure to DB-compatible structure.

    Args:
        event_finding: Finding from event bus accumulator

    Returns:
        Dictionary with DB-compatible field names
    """
    evidence = event_finding.get("evidence", {})
    if not isinstance(evidence, dict):
        evidence = {}

    return {
        "id": None,
        "type": event_finding.get("type") or event_finding.get("vuln_type", "Unknown"),
        "severity": event_finding.get("severity", "HIGH"),
        "url": event_finding.get("url", ""),
        "parameter": event_finding.get("parameter", ""),
        "payload": event_finding.get("payload", ""),
        "description": event_finding.get("description") or evidence.get("description", ""),
        "status": event_finding.get("status", "VALIDATED_CONFIRMED"),
        "validator_notes": (
            (event_finding.get("cdp_reasoning") or event_finding.get("reasoning", "")) +
            (" [EXPLOIT CHAINED]" if event_finding.get("_chain_exploit") else "")
        ).strip(),

        "screenshot_path": event_finding.get("screenshot_path"),
        "validation_method": event_finding.get("validation_method", "event_bus"),
        "source": "event_bus",
        "specialist": event_finding.get("specialist"),
        "scan_context": event_finding.get("scan_context"),
        "cdp_validated": event_finding.get("cdp_validated", False),
        "cdp_confidence": event_finding.get("cdp_confidence"),
    }


# PURE
def merge_event_findings(
    db_findings: List[Dict],
    event_findings: List[Dict],
) -> List[Dict]:
    """
    Merge event-sourced validated findings with database findings.

    Deduplicates based on (url, parameter, payload) to prevent duplicates.
    Event findings are marked with source='event_bus'.

    Args:
        db_findings: Findings from database and Nuclei
        event_findings: Findings from event bus accumulator

    Returns:
        Merged list with event findings appended (no duplicates)
    """
    if not event_findings:
        return db_findings

    def dedup_key(f: Dict) -> tuple:
        return (f.get("url"), f.get("parameter"), f.get("payload"))

    seen_keys = set(dedup_key(f) for f in db_findings)

    for f in db_findings:
        if "source" not in f:
            f["source"] = "database"

    merged = list(db_findings)
    added_count = 0

    for ef in event_findings:
        key = dedup_key(ef)
        if key not in seen_keys:
            formatted = event_finding_to_db_format(ef)
            merged.append(formatted)
            seen_keys.add(key)
            added_count += 1

    logger.info(f"[ReportingAgent] Merged {added_count} event findings with {len(db_findings)} DB findings")
    return merged


# PURE
def consolidate_informational(findings: List[Dict]) -> List[Dict]:
    """
    Consolidate informational findings into grouped entries.

    - All missing security header findings -> 1 consolidated finding
    - All API documentation exposure findings -> 1 consolidated finding
    - Other informational types pass through unchanged
    """
    header_findings = []
    api_docs_findings = []
    other_findings = []

    for f in findings:
        tmpl = _safe_evidence_get(f, "nuclei_template", f.get("parameter", "")).lower()
        ftype = f.get("type", "").upper()

        if ftype == "MISSING_SECURITY_HEADER" and tmpl in HEADER_TEMPLATES:
            header_findings.append(f)
        elif ftype in ("API DOCUMENTATION EXPOSURE", "MISSING_SECURITY_HEADER") and tmpl in API_DOCS_TEMPLATES:
            api_docs_findings.append(f)
        else:
            other_findings.append(f)

    result = list(other_findings)

    if header_findings:
        result.append(build_consolidated_header_finding(header_findings))

    if api_docs_findings:
        result.append(build_consolidated_api_docs_finding(api_docs_findings))

    consolidated_count = len(header_findings) + len(api_docs_findings)
    if consolidated_count > 0:
        logger.info(
            f"[ReportingAgent] Consolidated {consolidated_count} informational findings -> "
            f"{int(bool(header_findings)) + int(bool(api_docs_findings))} grouped entries"
        )

    return result


# PURE
def build_consolidated_header_finding(findings: List[Dict]) -> Dict:
    """Build a single consolidated finding from multiple missing header findings."""
    headers_detail = []
    urls_seen = set()
    for f in findings:
        tmpl = _safe_evidence_get(f, "nuclei_template", f.get("parameter", ""))
        desc = f.get("description", "").strip()
        url = f.get("url", "")
        if url:
            urls_seen.add(url)
        name = tmpl.replace("security-headers-", "").replace("http-missing-security-headers", "Multiple Headers").upper()
        readable = HEADER_READABLE_MAP.get(name, name)
        one_liner = desc.split("\n")[0][:120] if desc else ""
        headers_detail.append({"header": readable, "template": tmpl, "description": one_liner})

    header_lines = []
    for h in headers_detail:
        header_lines.append(f"| {h['header']} | {h['description']} |")

    description = (
        f"The target is missing {len(headers_detail)} recommended security headers. "
        "These are defense-in-depth measures and best practices — not directly exploitable vulnerabilities. "
        "In bug bounty programs, missing headers are typically classified as **Informational**.\n\n"
        "| Missing Header | Details |\n"
        "|---|---|\n"
        + "\n".join(header_lines) + "\n\n"
        "**Recommendation:** Configure the web server or application to include all standard "
        "security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)."
    )

    base = dict(findings[0])
    base["type"] = "MISSING_SECURITY_HEADER"
    base["parameter"] = "security-headers-consolidated"
    base["title"] = f"Missing Security Headers ({len(headers_detail)} headers)"
    base["description"] = description
    base["severity"] = "INFO"
    base["cvss_score"] = 0.0
    base["cvss_vector"] = "N/A"
    base["cvss_rationale"] = "Informational — defense-in-depth headers, not directly exploitable."
    base["enriched"] = True
    base["evidence"] = {
        "nuclei_template": "security-headers-consolidated",
        "missing_headers": [h["header"] for h in headers_detail],
        "original_count": len(findings),
    }
    base["exploitation_details"] = description
    base["url"] = sorted(urls_seen)[0] if urls_seen else base.get("url", "")
    base.pop("cwe", None)
    base.pop("cve", None)
    return base


# PURE
def build_consolidated_api_docs_finding(findings: List[Dict]) -> Dict:
    """Build a single consolidated finding from multiple API documentation exposure findings."""
    endpoints = []
    urls_seen = set()
    for f in findings:
        tmpl = _safe_evidence_get(f, "nuclei_template", f.get("parameter", ""))
        url = f.get("url", "")
        desc = f.get("description", "").strip().split("\n")[0][:120]
        if url:
            urls_seen.add(url)
        endpoints.append({"template": tmpl, "url": url, "description": desc})

    endpoint_lines = []
    for ep in endpoints:
        endpoint_lines.append(f"| {ep['url']} | {ep['description']} |")

    description = (
        f"The application exposes {len(endpoints)} API documentation endpoint(s) without authentication. "
        "While this aids development, in production it reveals internal API structure to potential attackers. "
        "In bug bounty programs, API documentation exposure is typically classified as **Informational**.\n\n"
        "| Endpoint | Details |\n"
        "|---|---|\n"
        + "\n".join(endpoint_lines) + "\n\n"
        "**Recommendation:** Restrict API documentation endpoints to authenticated users or internal networks only."
    )

    base = dict(findings[0])
    base["type"] = "API DOCUMENTATION EXPOSURE"
    base["parameter"] = "api-docs-consolidated"
    base["title"] = f"API Documentation Exposure ({len(endpoints)} endpoints)"
    base["description"] = description
    base["severity"] = "INFO"
    base["cvss_score"] = 0.0
    base["cvss_vector"] = "N/A"
    base["cvss_rationale"] = "Informational — API documentation exposure aids reconnaissance but is not directly exploitable."
    base["enriched"] = True
    base["evidence"] = {
        "nuclei_template": "api-docs-consolidated",
        "exposed_endpoints": [ep["url"] for ep in endpoints],
        "original_count": len(findings),
    }
    base["exploitation_details"] = description
    base["url"] = sorted(urls_seen)[0] if urls_seen else base.get("url", "")
    base.pop("cwe", None)
    base.pop("cve", None)
    return base


# PURE
def db_build_finding_dict(f) -> Dict:
    """Build finding dictionary from database record."""
    return {
        "id": f.id,
        "type": str(f.type.value if hasattr(f.type, 'value') else f.type),
        "severity": normalize_severity(f.severity),
        "url": f.attack_url,
        "parameter": f.vuln_parameter,
        "payload": f.payload_used,
        "description": f.details,
        "status": f.status,
        "validator_notes": f.validator_notes,
        "screenshot_path": f.proof_screenshot_path,
        "reproduction": getattr(f, 'reproduction_command', None),
        "created_at": None
    }


# PURE
def db_enrich_sqli_metadata(finding: Dict, f) -> None:
    """Parse and enrich SQLMap metadata from details JSON."""
    import json

    if finding["type"] not in ["SQLI", "SQLi"]:
        return
    if not f.details:
        return

    try:
        details_json = json.loads(f.details)
        finding["db_type"] = details_json.get("db_type")
        finding["tamper_used"] = details_json.get("tamper_used")
        finding["confidence"] = details_json.get("confidence")
        finding["evidence"] = details_json.get("evidence")
        finding["description"] = details_json.get("description", f.details)
        if details_json.get("reproduction_command"):
            finding["reproduction"] = details_json.get("reproduction_command")
    except (json.JSONDecodeError, TypeError):
        pass


# PURE
def nuclei_map_severity(nuclei_sev: Optional[str]) -> str:
    """Map Nuclei severity to our severity scale."""
    nuclei_sev = (nuclei_sev or "info").upper()
    severity_map = {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
        "INFO": "INFO"
    }
    return severity_map.get(nuclei_sev, "INFO")


# PURE
def nuclei_parse_findings(tech_profile: Dict) -> List[Dict]:
    """Parse Nuclei findings from tech profile."""
    nuclei_findings = []
    for finding in (tech_profile.get("raw_tech_findings") or []) + (tech_profile.get("raw_vuln_findings") or []):
        info = finding.get("info", {})
        severity = nuclei_map_severity(info.get("severity"))
        status = "VALIDATED_CONFIRMED" if severity in ["CRITICAL", "HIGH"] else "PENDING_VALIDATION"

        nuclei_findings.append({
            "id": None,
            "type": f"NUCLEI:{info.get('name', 'Unknown')}",
            "severity": severity,
            "url": finding.get("matched-at", finding.get("matched_at", "")),
            "parameter": info.get("name", ""),
            "payload": finding.get("template_id", ""),
            "description": info.get("description", f"Detected by Nuclei template: {finding.get('template_id', 'unknown')}"),
            "status": status,
            "validator_notes": f"Nuclei detection (template: {finding.get('template_id', 'unknown')})",
            "screenshot_path": None,
            "reproduction": None,
            "source": "nuclei",
            "nuclei_template": finding.get("template_id"),
            "nuclei_tags": info.get("tags", [])
        })
    return nuclei_findings


# PURE
def nuclei_extract_tech_stack(tech_profile: Dict) -> Dict:
    """Extract full tech stack info from tech profile."""
    return {
        "frameworks": tech_profile.get("frameworks", []),
        "languages": tech_profile.get("languages", []),
        "servers": tech_profile.get("servers", []),
        "waf": tech_profile.get("waf", []),
        "infrastructure": tech_profile.get("infrastructure", []),
        "cdn": tech_profile.get("cdn", []),
        "cms": tech_profile.get("cms", []),
        "tech_tags": tech_profile.get("tech_tags", []),
    }


# PURE
def group_findings_by_type(findings: List[Dict]) -> Dict[str, List[Dict]]:
    """Group findings by normalized vulnerability type for batch PoC enrichment."""
    groups: Dict[str, List[Dict]] = {}
    for f in findings:
        vtype = normalize_type_for_dedup(f.get("type", "UNKNOWN"))
        groups.setdefault(vtype, []).append(f)
    return groups
