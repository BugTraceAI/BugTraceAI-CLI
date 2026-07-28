"""
Byte-exact rendering of proof-of-concept payloads.

A PoC is only useful if the reader can copy it back out of the report UNCHANGED. Two
renderers stand between a payload and the reader's clipboard, and both are lossy unless
the payload is encoded for them:

* Markdown (the .md deliverable, the WEB's marked+DOMPurify viewer). An inline code
  span ``` `x` ``` deletes every backtick inside it, collapses runs of spaces and turns
  newlines into spaces; a payload dropped BARE into prose additionally loses its
  backslashes and — if it looks like a tag — is parsed as HTML and then removed by the
  sanitizer's allowlist. Only a FENCED block round-trips byte-for-byte, and only when the
  fence is longer than the longest backtick run in the payload (CommonMark 4.5).
* The POSIX shell (every ``curl`` reproduction command). A payload interpolated raw into
  ``-d '...'`` either fails to parse (an embedded quote) or — the dangerous case — parses
  fine and silently delivers an EMPTY value, so the reader concludes the finding is bogus.
  Only a properly quoted shell word delivers the payload byte-for-byte.

Everything here is PURE and target-agnostic: the rules come from the CommonMark/GFM
grammar and POSIX shell quoting, never from a payload we happen to have seen.
"""

import json
import re
from typing import List, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

# CommonMark 4.5: a fenced block opens with at least three backticks and closes on the
# first line with at least as many, so a fence one longer than the payload's longest
# backtick run can never be closed early by the payload itself.
_MIN_FENCE = 3

# A shell word can carry any byte except NUL, but a line break inside it turns a
# copy-pasteable one-liner into a multi-line paste that most terminals mangle — those
# payloads get a non-shell reproduction shape instead.
_SHELL_HOSTILE = ("\x00", "\n", "\r")


# =============================================================================
# MARKDOWN
# =============================================================================

# PURE
def md_code_block(text, lang: str = "text") -> str:
    """Render `text` as a fenced code block that round-trips BYTE-EXACT.

    The fence is one backtick longer than the longest backtick run in the payload, so
    payloads that themselves contain fences (```` ```js ... ``` ````) stay intact.
    """
    body = "" if text is None else str(text)
    longest = max((len(run) for run in re.findall(r"`+", body)), default=0)
    fence = "`" * max(_MIN_FENCE, longest + 1)
    return f"{fence}{lang}\n{body}\n{fence}"


# PURE
def md_labeled_block(label: str, text, lang: str = "text") -> str:
    """A bold label followed by a byte-exact fenced block (the report's payload shape).

    The blank line matters: without it the label and the fence merge into one paragraph
    and the fence is rendered as literal backticks.
    """
    return f"**{label}:**\n\n{md_code_block(text, lang)}"


# PURE
def md_step_with_block(text: str, payload, lang: str = "text", indent: int = 3) -> str:
    """A numbered reproduction step followed by an INDENTED fenced block.

    Reproduction steps are markdown-active prose, so a payload written into the sentence
    is mangled exactly like anywhere else. The block is indented so it stays inside the
    list item and the step numbering keeps running (CommonMark 5.2, list item content).
    """
    pad = " " * indent
    block = "\n".join(pad + line if line else line
                      for line in md_code_block(payload, lang).split("\n"))
    return f"{text}\n\n{block}"


# PURE
def md_step_with_value(text: str, value, lang: str = "text", indent: int = 3) -> str:
    """A reproduction step that quotes `value` without the renderer eating it.

    A URL or a parameter name is not inert data: specialists store the EXPLOIT url, so the
    value routinely carries payload bytes, and written into the sentence they are parsed as
    markup (``<svg …>`` is then deleted outright by the viewer's sanitizer allowlist).
    Inert values ride in an inline code span, which keeps the step readable; anything the
    grammar can act on gets its own fenced block, which round-trips byte-exact.
    """
    v = "" if value is None else str(value)
    if not v.strip():
        # Nothing to quote: an empty fenced block would read as a missing artifact.
        return text
    if markdown_inert(v):
        return f"{text} `{v}`"
    return md_step_with_block(text, v, lang, indent)


# PURE
def md_injection_point(url, parameter, payload, detection_payload=None) -> str:
    """The URL / Parameter / Payload trio every deliverable prints, as fenced blocks.

    None of these three can safely live in a markdown TABLE cell or an inline code span:
    a table cell cannot hold a newline or an unescaped pipe, and a code span collapses
    runs of spaces and deletes backticks. All of them can carry payload bytes — a
    finding's `url` often IS the exploit URL — so all of them get a block.

    `detection_payload` is rendered only when it differs from the shipped payload, which
    is exactly the case where the report would otherwise show one payload while the
    captured evidence proves another.
    """
    blocks = [md_labeled_block("URL", url)]
    if parameter:
        blocks.append(md_labeled_block("Parameter", parameter))
    blocks.append(md_labeled_block("Payload", payload))
    if detection_payload and str(detection_payload) != str(payload):
        blocks.append(
            "**Detection payload** (the probe that CONFIRMED the finding; the payload "
            "above is the visual proof-of-concept shown in the screenshot):\n\n"
            + md_code_block(detection_payload)
        )
    return "\n\n".join(blocks)


# CommonMark 0.31 §6 (Inlines) lists every construct a literal string can accidentally
# OPEN inside prose: backslash escapes (\), entity references (&), code spans (`),
# emphasis (* _), links and images ([ ] !), raw HTML and autolinks (< >). GFM adds
# strikethrough (~) and tables (|). A string containing none of these renders as its own
# bytes; a string containing any of them may not, so it goes in a fenced block instead.
# This is the grammar's set, not a set of characters observed in payloads.
_MD_INLINE_STARTERS = frozenset("`*_[]<>&\\~!|")


# PURE
def markdown_inert(value) -> bool:
    """True when `value` reaches the reader as its own literal bytes inside prose.

    False for anything the renderer may transform: an inline construct starter (which can
    turn the value into markup, or — for a tag — get it deleted outright by the viewer's
    DOMPurify allowlist), a line break (which ends the paragraph), a tab or a run of
    spaces (which HTML whitespace collapsing folds into one), and leading/trailing
    whitespace (stripped on render).
    """
    text = "" if value is None else str(value)
    if not text or text != text.strip():
        return False
    if any(ch in text for ch in ("\n", "\r", "\t")):
        return False
    if "  " in text:
        return False
    return not any(ch in _MD_INLINE_STARTERS for ch in text)


# PURE
def md_prose_with_values(prose, *values) -> str:
    """LLM narrative that quotes finding data, rendered so that data survives the viewer.

    The enrichment model interpolates the payload straight into its sentence. Markdown
    then reads the payload's OWN backticks as code-span delimiters and DELETES them, so
    ``d.setAttribute(`style`,…)`` reaches the reader as ``d.setAttribute( style ,…)`` — a
    payload nobody can copy — while the identical bytes sit correct in raw_findings.json.
    The loss is purely at render time, and it lands on the one field the report exists to
    deliver.

    Each value that the grammar could transform (`markdown_inert`) is lifted out of the
    sentence into its own fenced block, which round-trips byte-exact via `md_code_block`.
    Values are matched longest-first so a short one cannot split a longer one that
    contains it. Anything the renderer cannot transform stays inline and the prose reads
    as written.

    A backtick left in the prose afterwards is the model's own. An ODD count means one
    delimiter is unpaired, which silently swallows the rest of the paragraph into a code
    span, so those are escaped (``\\```renders as a literal backtick). An even count is
    left alone: it is most likely deliberate inline code, and rewriting it would trade a
    real defect for a cosmetic one.
    """
    text = "" if prose is None else str(prose)
    if not text:
        return text

    # Placeholders use NUL, which cannot occur in LLM output or in a URL/payload field,
    # so the substitution can never collide with the prose it is protecting.
    blocks = []
    seen = set()
    for value in sorted(
        (str(v) for v in values if v not in (None, "")), key=len, reverse=True
    ):
        if value in seen or markdown_inert(value):
            continue
        start = text.find(value)
        if start < 0:
            continue
        seen.add(value)
        end = start + len(value)
        # The model usually quotes the value as an inline code span. Those delimiters
        # belong to the span being replaced, not to the sentence: leaving them behind
        # strands a lone backtick on either side of the block. Absorb them only when
        # they balance, so a backtick that is genuinely part of the prose survives.
        lead, tail = 0, 0
        while start - lead - 1 >= 0 and text[start - lead - 1] == "`":
            lead += 1
        while end + tail < len(text) and text[end + tail] == "`":
            tail += 1
        if lead and lead == tail:
            start -= lead
            end += tail
        token = f"\x00{len(blocks)}\x00"
        text = text[:start] + token + text[end:]
        blocks.append((token, value))

    if text.count("`") % 2:
        text = text.replace("`", "\\`")

    for token, value in blocks:
        text = text.replace(token, f"\n\n{md_code_block(value)}\n\n")

    return text.strip()


# CommonMark 4.5: a fence opens on a line whose first non-space character starts a run of
# three or more backticks or tildes, indented at most three spaces.
_FENCE_LINE = re.compile(r"^ {0,3}(`{3,}|~{3,})")


# PURE
def md_document_with_values(document, *values) -> str:
    """`md_prose_with_values` applied to a whole markdown DOCUMENT.

    Enrichment has two shapes. One returns parsed fields that the reporter assembles into
    sections; the other returns a finished markdown document that is stored verbatim. Only
    the first was protected, so the payload still reached the reader mangled through the
    second — which is the path a single-finding enrichment actually takes.

    A document may already contain fenced blocks, and a value quoted INSIDE one is already
    byte-exact. Lifting it again would open a nested fence and corrupt the block, so the
    document is split on fence boundaries and only the prose between them is rewritten.
    """
    text = "" if document is None else str(document)
    if not text:
        return text

    out, buf, in_fence, marker = [], [], False, ""
    for line in text.split("\n"):
        m = _FENCE_LINE.match(line)
        if not in_fence and m:
            if buf:
                out.append(md_prose_with_values("\n".join(buf), *values))
                buf = []
            in_fence, marker = True, m.group(1)[0]
            out.append(line)
        elif in_fence:
            out.append(line)
            # A closing fence uses the same character and needs no info string.
            if m and m.group(1)[0] == marker:
                in_fence = False
        else:
            buf.append(line)
    if buf:
        out.append(md_prose_with_values("\n".join(buf), *values))
    return "\n".join(out)


# PURE
def truncate_marked(value, budget: int) -> Tuple[str, int]:
    """`value` cut to `budget` characters, plus the number of characters dropped.

    Returning the drop count is the point: a report may bound how much evidence it prints,
    but it must never do so silently — the caller states the loss next to the value.
    A non-positive budget means "no bound".
    """
    text = "" if value is None else str(value)
    if budget <= 0 or len(text) <= budget:
        return text, 0
    return text[:budget], len(text) - budget


# PURE
def md_bullet_value(label: str, value, indent: int = 2) -> str:
    """A ``- **label:** value`` bullet whose value survives the markdown renderer.

    Inert values stay inline so the panel reads as a compact list; anything the renderer
    could transform gets an indented fenced block (indented by the width of the ``- ``
    marker so it stays inside the list item, CommonMark 5.2).
    """
    text = "" if value is None else str(value)
    head = f"- **{label}:**"
    if markdown_inert(text):
        return f"{head} {text}"
    pad = " " * indent
    block = "\n".join(pad + line if line else line
                      for line in md_code_block(text).split("\n"))
    return f"{head}\n\n{block}"


# PURE
def evidence_pairs(evidence, limit: int, value_budget: int
                   ) -> Tuple[List[Tuple[str, str, int]], int]:
    """Flatten a specialist's structured ``evidence`` dict into printable triples.

    Returns ``([(label, text, dropped_chars), …], dropped_keys)``. Empty values are
    skipped (they say nothing), nested structures are JSON-encoded so their bytes are
    still exact, and both bounds are reported rather than applied silently.
    """
    if not isinstance(evidence, dict) or not evidence:
        return [], 0
    kept: List[Tuple[str, str, int]] = []
    dropped_keys = 0
    for key, value in evidence.items():
        if value in (None, "", [], {}, False):
            continue
        if limit > 0 and len(kept) >= limit:
            dropped_keys += 1
            continue
        raw = (json.dumps(value, ensure_ascii=False)
               if isinstance(value, (dict, list)) else str(value))
        text, dropped = truncate_marked(raw, value_budget)
        kept.append((str(key).replace("_", " ").strip(), text, dropped))
    return kept, dropped_keys


# PURE
def md_evidence_block(pairs: Sequence[Tuple[str, str, int]], dropped_keys: int = 0) -> str:
    """Render `evidence_pairs` output as markdown that round-trips byte-exact.

    A truncation note sits OUTSIDE the fenced block, so the bytes the reader copies are
    still exactly the bytes the scanner saw — just fewer of them, and it says so.
    """
    lines: List[str] = []
    for label, text, dropped in pairs:
        lines.append(md_bullet_value(label, text))
        if dropped:
            lines.append(f"  _(truncated: {len(text)} of {len(text) + dropped} characters "
                         f"shown — full value in raw_findings.json)_")
    if dropped_keys:
        lines.append(f"- _({dropped_keys} further evidence field(s) not shown — "
                     f"full evidence in raw_findings.json)_")
    return "\n".join(lines)


# PURE
def plain_evidence_block(pairs: Sequence[Tuple[str, str, int]], dropped_keys: int = 0) -> str:
    """Render `evidence_pairs` output for a consumer that does NOT parse markdown.

    The static HTML viewer HTML-escapes this into a ``<pre>``-styled block and the LLM
    prompts read it as plain text, so markdown fences would show up literally there.
    """
    lines: List[str] = []
    for label, text, dropped in pairs:
        lines.append(f"{label}: {text}")
        if dropped:
            lines.append(f"  (truncated: {len(text)} of {len(text) + dropped} characters shown)")
    if dropped_keys:
        lines.append(f"({dropped_keys} further evidence field(s) not shown)")
    return "\n".join(lines)


# =============================================================================
# SHELL
# =============================================================================

# PURE
def shell_word(value) -> str:
    """A single POSIX shell word that delivers `value` byte-for-byte.

    Always quoted (never `shlex.quote`'s bare-word shortcut) so the reproduction command
    has one predictable shape whatever the payload looks like.
    """
    text = "" if value is None else str(value)
    return "'" + text.replace("'", "'\"'\"'") + "'"


# PURE
def shell_deliverable(value) -> bool:
    """True when `value` can travel in a copy-pasteable single-line shell word."""
    text = "" if value is None else str(value)
    return not any(ch in text for ch in _SHELL_HOSTILE)


# PURE
def curl_get(url) -> str:
    """`curl -i` against a URL that already carries everything it needs."""
    return f"curl -i {shell_word(url)}"


# PURE
def curl_form_field(url, field: str, value, method: str = "POST", extra: str = "") -> str:
    """A curl that posts ONE urlencoded form field carrying `value` byte-for-byte.

    `--data-urlencode` (not `-d`) because the raw form encoding is the payload's second
    lossy channel: a payload containing `&` or `=` would otherwise be split into extra
    parameters by the server's form parser.
    """
    parts = [f"curl -i -X {method.upper()}", shell_word(url),
             "--data-urlencode", shell_word(f"{field}={value}")]
    if extra:
        parts.append(extra)
    return " ".join(parts)


# PURE
def curl_raw_body(url, body, method: str = "POST", extra: str = "") -> str:
    """A curl that sends `body` as the request body, byte-for-byte.

    `--data-binary` (not `-d`) because `-d` strips newlines and carriage returns from the
    body it is given, which silently truncates any multi-line payload.
    """
    parts = [f"curl -i -X {method.upper()}", shell_word(url), "--data-binary", shell_word(body)]
    if extra:
        parts.append(extra)
    return " ".join(parts)


# PURE
def header_deliverable(value) -> bool:
    """True when `value` can be an HTTP field value at all.

    RFC 9110 §5.5: a field value is a sequence of field-vchar/SP/HTAB — CR and LF are
    not representable, and curl silently drops the rest of the value rather than
    erroring. A payload that cannot ride a header needs a different reproduction shape,
    not a command that appears to work and delivers half the payload.
    """
    text = "" if value is None else str(value)
    return not any(ch in text for ch in ("\r", "\n", "\x00"))


# PURE
def curl_header(url, header: str, value, extra: str = "") -> Optional[str]:
    """A curl that sends ONE header carrying `value` byte-for-byte, or None when the
    value cannot legally be a header field value."""
    if not header_deliverable(value):
        return None
    parts = ["curl -i -H", shell_word(f"{header}: {value}"), shell_word(url)]
    if extra:
        parts.append(extra)
    return " ".join(parts)


# =============================================================================
# URL-CARRIED PAYLOADS
# =============================================================================

# PURE
def build_query_url(url, param: str, payload) -> Optional[str]:
    """Return `url` with `param` set to `payload`, percent-encoded.

    Percent-encoding is the byte-safe channel for a URL-carried payload: the result has
    no shell metacharacters and no markdown-active characters left, so it survives a
    terminal, an address bar and a code span alike. None when the URL cannot be parsed.
    """
    if not url or not param:
        return None
    try:
        parts = urlparse(str(url))
    except ValueError:
        return None
    pairs = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != param]
    pairs.append((param, "" if payload is None else str(payload)))
    return urlunparse((parts.scheme, parts.netloc, parts.path, parts.params,
                       urlencode(pairs), parts.fragment))


# PURE
def template_expression_result(payload) -> Optional[str]:
    """The value a template engine prints for an arithmetic probe like
    ``{{1000003*1000003}}``.

    Used to give a template-injection reproduction a REAL success indicator instead of a
    hardcoded one: the expected output is derived from the probe the scanner actually
    sent, so an upgraded (non-arithmetic) payload gets no bogus `grep` promise.
    """
    if not payload:
        return None
    m = re.search(r"\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}", str(payload))
    if not m:
        return None
    return str(int(m.group(1)) * int(m.group(2)))


__all__ = [
    "md_code_block",
    "md_labeled_block",
    "md_step_with_block",
    "md_step_with_value",
    "md_injection_point",
    "markdown_inert",
    "md_prose_with_values",
    "md_document_with_values",
    "md_bullet_value",
    "truncate_marked",
    "evidence_pairs",
    "md_evidence_block",
    "plain_evidence_block",
    "shell_word",
    "shell_deliverable",
    "header_deliverable",
    "curl_get",
    "curl_form_field",
    "curl_raw_body",
    "curl_header",
    "build_query_url",
    "template_expression_result",
]
