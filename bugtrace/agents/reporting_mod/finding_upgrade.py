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
from bugtrace.agents.reporting_mod.finding_baseline import (
    _VISUAL_BANNER_JS,
    _VISUAL_BANNER_TEXT,
    _VISUAL_BANNER_TEXT_ESCAPED,
    _PAYLOAD_UPGRADE_MAP,
    _CSTI_UPGRADE_MAP,
)

logger = get_logger("agents.reporting.finding_processor")


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
