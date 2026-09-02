"""Pure XSS breakout prefix selection and context ranking helpers.

Extracted from xss_agent.py (P4-XSS-9). Owns:

- context → ReflectionContext key normalisation
- context-aware breakout prefixes (shared CONTEXT_BREAKOUTS table)
- merge of context + global rankings under L3 budget
- deterministic tag-closing breakout candidates

No network, agent state, or LLM. Monolith re-exports for call sites and
smoke_xss_cspine.
"""

from __future__ import annotations

import re
from typing import Dict, List, Tuple

from bugtrace.tools.manipulator.context_analyzer import ContextAnalyzer, ReflectionContext
from bugtrace.agents.xss.context_reflection import (
    CONTEXT_EXPLOITABILITY,
    FILTERABLE_CONTEXTS,
    most_exploitable_context,
)

# Monolith historical names (underscore prefix) as aliases of package constants.
_CONTEXT_EXPLOITABILITY = CONTEXT_EXPLOITABILITY
_FILTERABLE_CONTEXTS = FILTERABLE_CONTEXTS

# Map this agent's reflection-context vocabulary onto the shared ReflectionContext table
# so breakout prefixes keep ONE definition (tools/manipulator/context_analyzer).
#
# FIVE independent label vocabularies reach the breakout helpers below:
#   reflection analyser  : script, style, html_text, raw_text, attribute_value,
#                          event_handler, url_context, comment, tag_name, unknown, blocked
#   HTML position class. : rawtext_inert, rawtext_breakout, attribute_quoted_inert,
#                          attribute_quoted_breakout, attribute_unquoted, comment_inert, ...
#   LLM / DRY dedup      : html_body, attribute, javascript, url, css
#   execution evidence   : html_tag, event_handler, javascript_uri, script_block,
#                          template_expression, js_string_breakout
#   whatever an LLM invents, because the DRY label is model output, not a closed set.
# Matching is therefore done on the label's WORD TOKENS (universal parse-state names), not
# on the label as a whole, so "attribute_quoted_inert", "script_block" and
# "js-template-literal" all resolve without being enumerated anywhere.
_CONTEXT_TOKEN_KEYS = {
    # JavaScript execution / JS string literals
    "script": (ReflectionContext.SCRIPT_TAG, ReflectionContext.JAVASCRIPT_STRING_SINGLE,
               ReflectionContext.JAVASCRIPT_STRING_DOUBLE, ReflectionContext.JAVASCRIPT_TEMPLATE),
    "javascript": (ReflectionContext.SCRIPT_TAG, ReflectionContext.JAVASCRIPT_STRING_SINGLE,
                   ReflectionContext.JAVASCRIPT_STRING_DOUBLE, ReflectionContext.JAVASCRIPT_TEMPLATE),
    "js": (ReflectionContext.SCRIPT_TAG, ReflectionContext.JAVASCRIPT_STRING_SINGLE,
           ReflectionContext.JAVASCRIPT_STRING_DOUBLE, ReflectionContext.JAVASCRIPT_TEMPLATE),
    "string": (ReflectionContext.JAVASCRIPT_STRING_SINGLE, ReflectionContext.JAVASCRIPT_STRING_DOUBLE),
    "literal": (ReflectionContext.JAVASCRIPT_STRING_SINGLE, ReflectionContext.JAVASCRIPT_STRING_DOUBLE),
    # HTML attribute values (an event handler IS an attribute value that holds JS)
    "attribute": (ReflectionContext.HTML_ATTRIBUTE_DOUBLE, ReflectionContext.HTML_ATTRIBUTE_SINGLE),
    "attr": (ReflectionContext.HTML_ATTRIBUTE_DOUBLE, ReflectionContext.HTML_ATTRIBUTE_SINGLE),
    "event": (ReflectionContext.HTML_ATTRIBUTE_DOUBLE, ReflectionContext.HTML_ATTRIBUTE_SINGLE,
              ReflectionContext.JAVASCRIPT_STRING_SINGLE, ReflectionContext.JAVASCRIPT_STRING_DOUBLE),
    "handler": (ReflectionContext.HTML_ATTRIBUTE_DOUBLE, ReflectionContext.HTML_ATTRIBUTE_SINGLE,
                ReflectionContext.JAVASCRIPT_STRING_SINGLE, ReflectionContext.JAVASCRIPT_STRING_DOUBLE),
    # Document body / any position parsed as markup
    "body": (ReflectionContext.HTML_TAG_BODY,),
    "text": (ReflectionContext.HTML_TAG_BODY,),
    "rawtext": (ReflectionContext.HTML_TAG_BODY,),
    "rcdata": (ReflectionContext.HTML_TAG_BODY,),
    "tag": (ReflectionContext.HTML_TAG_BODY,),
    "html": (ReflectionContext.HTML_TAG_BODY,),
    "markup": (ReflectionContext.HTML_TAG_BODY,),
    "dom": (ReflectionContext.HTML_TAG_BODY,),
    "element": (ReflectionContext.HTML_TAG_BODY,),
    # URL-bearing attribute values
    "url": (ReflectionContext.URL_PARAMETER,),
    "uri": (ReflectionContext.URL_PARAMETER,),
    "href": (ReflectionContext.URL_PARAMETER,),
    "src": (ReflectionContext.URL_PARAMETER,),
    "link": (ReflectionContext.URL_PARAMETER,),
    "location": (ReflectionContext.URL_PARAMETER,),
    "redirect": (ReflectionContext.URL_PARAMETER,),
    # Remaining parse states
    "comment": (ReflectionContext.HTML_COMMENT,),
    "style": (ReflectionContext.STYLE_TAG,),
    "css": (ReflectionContext.STYLE_TAG,),
    "json": (ReflectionContext.JSON_STRING,),
    "template": (ReflectionContext.TEMPLATE_ENGINE, ReflectionContext.JAVASCRIPT_TEMPLATE),
    "interpolation": (ReflectionContext.TEMPLATE_ENGINE,),
    "mustache": (ReflectionContext.TEMPLATE_ENGINE,),
}

# The SAFE SUPERSET every label gets, matched tokens or not: body + both attribute
# families cover the common reflection shapes without assuming anything about the target.
# INVARIANT: an unrecognised (or plain wrong) context label must NEVER mean "fire fewer
# payloads" — it is only ever allowed to mean "fire the broad set". Keep it that way.
_CONTEXT_FALLBACK_KEYS = (
    ReflectionContext.HTML_TAG_BODY,
    ReflectionContext.HTML_ATTRIBUTE_DOUBLE,
    ReflectionContext.HTML_ATTRIBUTE_SINGLE,
)

# Emission order of the matched keys: most context-specific / most likely to execute
# first, so that a downstream slice keeps the highest-value prefixes.
_CONTEXT_KEY_ORDER = (
    ReflectionContext.SCRIPT_TAG,
    ReflectionContext.JAVASCRIPT_STRING_SINGLE,
    ReflectionContext.JAVASCRIPT_STRING_DOUBLE,
    ReflectionContext.JAVASCRIPT_TEMPLATE,
    ReflectionContext.HTML_ATTRIBUTE_DOUBLE,
    ReflectionContext.HTML_ATTRIBUTE_SINGLE,
    ReflectionContext.HTML_TAG_BODY,
    ReflectionContext.HTML_COMMENT,
    ReflectionContext.STYLE_TAG,
    ReflectionContext.TEMPLATE_ENGINE,
    ReflectionContext.JSON_STRING,
    ReflectionContext.URL_PARAMETER,
)

# Explicit L3 request budget for the CONTEXT-specific prefixes. L3 fires
# (1 + len(prefixes)) requests per LLM payload and _ask_deepseek_visual_payloads() returns
# at most 10, so the merged list sets L3's cost directly: 10 x (1 + N). The globally
# ranked prefixes are never counted against this budget — dropping one of those is a
# straight capability loss (see merge_breakout_prefixes). 56 sits above the longest union
# the shared CONTEXT_BREAKOUTS table can produce for any label today (measured worst case
# 50, typical 21-40), so it currently truncates nothing and no prefix that ever fired can
# be lost to it. It is a GUARD: growing that shared table cannot silently multiply L3
# traffic without someone raising this number on purpose.
_L3_CONTEXT_PREFIX_BUDGET = 56


# PURE
def _dedup_prefixes(prefixes: List[str]) -> List[str]:
    """Order-preserving dedup that drops empty/whitespace-only prefixes.

    prefix+payload == payload for an empty prefix, so those only burn requests.
    """
    seen: set = set()
    out: List[str] = []
    for prefix in prefixes or ():
        if not prefix or not prefix.strip() or prefix in seen:
            continue
        seen.add(prefix)
        out.append(prefix)
    return out


# PURE
def context_reflection_keys(context: str) -> Tuple[ReflectionContext, ...]:
    """Normalise ANY context label onto the shared ReflectionContext table.

    ONE mapping for every label vocabulary that can reach the breakout helpers (see
    _CONTEXT_TOKEN_KEYS). The label is split into word tokens and every token that names a
    parse state contributes its keys; the SAFE SUPERSET (_CONTEXT_FALLBACK_KEYS) is then
    appended unconditionally.

    INVARIANT — an unrecognised label degrades to a SUPERSET, never to a smaller set. A
    label from the "wrong" vocabulary (an LLM-invented DRY label, a position-classifier
    label) must never silently reduce what gets fired: fail OPEN on uncertainty.
    """
    tokens = set(re.split(r"[^a-z0-9]+", (context or "").lower()))
    matched = {
        key
        for token in tokens
        for key in _CONTEXT_TOKEN_KEYS.get(token, ())
    }
    ordered = tuple(k for k in _CONTEXT_KEY_ORDER if k in matched)
    return ordered + tuple(k for k in _CONTEXT_FALLBACK_KEYS if k not in matched)


# PURE
def context_breakout_prefixes(context: str, surviving_chars: str = "") -> List[str]:
    """Breakout prefixes the shared context table prescribes for a reflection context.

    `surviving_chars` (from the L0.5 character probe) only narrows the attribute families:
    if the response proves the double quote survives we keep the '"' family (which is
    where the '">' tag-closing breakout lives) and drop the single-quote one, and vice
    versa. Empty `surviving_chars` means "unknown" → keep both. It deliberately does NOT
    narrow the JS-string families: those breakouts (\\' , \\") exist precisely for the
    server that escapes the raw quote away.
    """
    prefixes: List[str] = []
    for key in context_reflection_keys(context):
        if surviving_chars:
            if key is ReflectionContext.HTML_ATTRIBUTE_DOUBLE and '"' not in surviving_chars:
                continue
            if key is ReflectionContext.HTML_ATTRIBUTE_SINGLE and "'" not in surviving_chars:
                continue
        prefixes.extend(ContextAnalyzer.CONTEXT_BREAKOUTS.get(key, []))
    return _dedup_prefixes(prefixes)


# PURE
def merge_breakout_prefixes(
    context_prefixes: List[str], global_prefixes: List[str],
    context_budget: int = _L3_CONTEXT_PREFIX_BUDGET,
) -> List[str]:
    """Union context-appropriate breakouts with the globally-ranked ones. ADDITIVE.

    The global ranking is sorted by success_count ALONE (no context, no surviving-chars
    filter), so a breakout that actually fits the detected context can fall outside its
    limit and never be tried — that is why the context list is unioned in. But capping the
    UNION is just as damaging in the other direction: the context list eats the whole cap
    and globally ranked prefixes that used to fire fall off the end (the JS-string
    breakouts \\' and \\'; , the CSTI one {{ ...). So EVERY global prefix is kept, and the
    bound applies only to the context contribution.

    The two rankings are then interleaved, context first (it carries the stronger,
    response-derived evidence), so that ANY downstream slice keeps the head of BOTH.
    """
    ctx = _dedup_prefixes(context_prefixes)[:max(0, context_budget)]
    glob = _dedup_prefixes(global_prefixes)
    merged: List[str] = []
    seen: set = set()
    for i in range(max(len(ctx), len(glob))):
        for source in (ctx, glob):
            if i < len(source) and source[i] not in seen:
                seen.add(source[i])
                merged.append(source[i])
    return merged


# PURE
def tag_closing_breakout_payloads(
    context: str, surviving_chars: str, smart_payloads: Dict[str, str]
) -> List[str]:
    """Deterministic tag-closing candidates — emitted for EVERY context label.

    L3 only ever fires LLM payloads multiplied by breakout prefixes, so when the LLM does
    not propose a tag-closing payload AND the '">' prefix falls outside the global
    ranking cut, the whole '"><svg onload=...>' family is unreachable. These candidates
    make it reachable. They keep the silent document.title probe convention so the
    report-time upgrade (reporting_mod.finding_processor.upgrade_payload) still
    recognises them and swaps in the visual banner PoC.

    INVARIANT — the context LABEL must never subtract. `context` reaches here from any of
    the vocabularies listed on _CONTEXT_TOKEN_KEYS, so allow-listing labels meant an
    unrecognised one yielded ZERO payloads, i.e. silently disabled the very fix this
    function is. It is only ever read to ADD (a script-context label also gets the
    </script> close-tag breakout, the RAWTEXT equivalent of '">'). The only subtraction is
    `surviving_chars`, which is MEASURED from the response, not guessed from a label: a
    quote the server provably encodes cannot close the tag. Unknown ⇒ fire everything.
    """
    keys = []
    if not surviving_chars or '"' in surviving_chars:
        keys.append("attr_dq_tag_breakout")
    if not surviving_chars or "'" in surviving_chars:
        keys.append("attr_sq_tag_breakout")
    if ReflectionContext.SCRIPT_TAG in context_reflection_keys(context):
        if not surviving_chars or "<" in surviving_chars:
            keys.append("script_breakout")
    return [p for p in (smart_payloads.get(k, "") for k in keys) if p]


