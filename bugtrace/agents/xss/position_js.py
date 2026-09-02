"""JS tokenisation / breakout pure helpers for reflection position.

Split from position.py so each pure module stays under the 1500 LOC agent-workable max.
"""
from __future__ import annotations

import re
import urllib.parse
from bisect import bisect_right
from functools import lru_cache
from typing import Dict, List, NamedTuple, Optional, Tuple



# =============================================================================
# JAVASCRIPT TOKEN STATE (PURE)
# =============================================================================
# A reflection inside an inline <script> is NOT judged by markup: <script> content never
# contains tags, so "no </script> in the payload" only proves it cannot escape the
# ELEMENT — it says nothing about escaping the JS STRING, which is how script-context XSS
# actually works (var q = '<?= $q ?>', wp_localize_script, drupalSettings, __NUXT__, gon).
# These are the ECMAScript lexical token kinds, not a heuristic list.

# HTML "classic script" / module: a <script> whose type is absent, empty, a JavaScript
# MIME type or "module" is executed as JS. Any other type (application/json,
# text/x-template, text/x-handlebars) is DATA, so its content stays inert.
_JS_SCRIPT_TYPES = frozenset({
    "", "module", "text/javascript", "application/javascript", "text/ecmascript",
    "application/ecmascript", "text/jscript", "text/livescript", "text/x-javascript",
    "text/x-ecmascript", "application/x-javascript", "application/x-ecmascript",
    "text/javascript1.0", "text/javascript1.1", "text/javascript1.2",
    "text/javascript1.3", "text/javascript1.4", "text/javascript1.5",
})

# After these keywords a '/' opens a REGULAR EXPRESSION; after an identifier, a number,
# ')' or ']' it is the division operator. Standard ECMAScript lexical-goal disambiguation.
_JS_REGEX_KEYWORDS = frozenset({
    "return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw",
    "case", "do", "else", "yield", "await",
})
_JS_IDENT_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$")
_JS_SPACE = frozenset(" \t\r\n\f\v   ")


class _JsToken(NamedTuple):
    """One non-code ECMAScript token: [start, end] inclusive of both delimiters."""
    start: int   # index of the opening delimiter
    end: int     # index of the CLOSING delimiter (len(js) when never closed)
    kind: str    # string | template | regex | line_comment | block_comment


# PURE
def _js_scan_quoted(js: str, i: int, quote: str) -> int:
    """Index of the delimiter closing the string/template opened at `i` (len when open).

    Backslash-escape aware, which is the whole point of the control this must preserve:
    a server that doubled the backslash (\\\\' ) leaves a FREE quote that closes the
    string, one that escaped the quote itself (\\\\\\' ) does not.
    """
    n = len(js)
    k = i + 1
    while k < n:
        ch = js[k]
        if ch == "\\":
            k += 2
            continue
        if ch == quote:
            return k
        k += 1
    return n


# PURE
def _js_scan_regex(js: str, i: int) -> int:
    """Index of the '/' closing the regex literal opened at `i` (len when unterminated)."""
    n = len(js)
    k = i + 1
    in_class = False
    while k < n:
        ch = js[k]
        if ch == "\\":
            k += 2
            continue
        if ch == "\n":
            return k  # a regex literal cannot span lines
        if ch == "[":
            in_class = True
        elif ch == "]":
            in_class = False
        elif ch == "/" and not in_class:
            return k
        k += 1
    return n


# PURE
def _js_regex_allowed(js: str, i: int) -> bool:
    """True when the '/' at `i` starts a regex literal rather than a division operator.

    Walks backwards over the preceding token INDEX BY INDEX. Slicing `js[:i]` here would
    copy the whole prefix at every '/' in the file, which is quadratic on a script full of
    divisions or URLs — the same shape as the catastrophic-backtracking incident this
    parser exists to avoid. The backward walk is bounded by the length of the token it
    steps over, so the total stays linear in len(js).
    """
    k = i - 1
    while k >= 0 and js[k] in _JS_SPACE:
        k -= 1
    if k < 0:
        return True
    prev = js[k]
    if prev in ")]":
        return False
    if prev in _JS_IDENT_CHARS:
        word_end = k + 1
        while k >= 0 and js[k] in _JS_IDENT_CHARS:
            k -= 1
        return js[k + 1:word_end] in _JS_REGEX_KEYWORDS
    return True


# PURE
@lru_cache(maxsize=16)
def _js_tokens(js: str) -> Tuple[_JsToken, ...]:
    """Lex `js` into its non-code tokens, left to right. Linear, no backtracking."""
    n = len(js)
    out: List[_JsToken] = []
    i = 0
    while i < n:
        ch = js[i]
        if ch in "'\"":
            end = _js_scan_quoted(js, i, ch)
            out.append(_JsToken(i, end, "string"))
            i = end + 1
            continue
        if ch == "`":
            end = _js_scan_quoted(js, i, ch)
            out.append(_JsToken(i, end, "template"))
            i = end + 1
            continue
        if ch == "<" and js.startswith("<!--", i):
            # ECMAScript Annex B.1.1 (normative for web browsers): "<!--" is a
            # SingleLineHTMLOpenComment. Legacy pages that wrap an inline script in
            # `<!-- ... //-->` really do comment out everything after it on that line.
            close = js.find("\n", i + 4)
            end = n if close == -1 else close
            out.append(_JsToken(i, end, "line_comment"))
            i = end + 1
            continue
        if ch == "/" and i + 1 < n:
            nxt = js[i + 1]
            if nxt == "/":
                close = js.find("\n", i + 2)
                end = n if close == -1 else close
                out.append(_JsToken(i, end, "line_comment"))
                i = end + 1
                continue
            if nxt == "*":
                close = js.find("*/", i + 2)
                end = n if close == -1 else close + 1
                out.append(_JsToken(i, end, "block_comment"))
                i = end + 1
                continue
            if _js_regex_allowed(js, i):
                end = _js_scan_regex(js, i)
                out.append(_JsToken(i, end, "regex"))
                i = end + 1
                continue
        i += 1
    return tuple(out)


# PURE
@lru_cache(maxsize=16)
def _js_index(js: str) -> Tuple[Tuple[_JsToken, ...], Tuple[int, ...]]:
    """Tokens plus their start offsets, so a bisect key is never rebuilt per occurrence."""
    tokens = _js_tokens(js)
    return tokens, tuple(t.start for t in tokens)


# PURE
def _js_span_escapes(js: str, start: int, end: int) -> bool:
    """True when the payload occupying [start, end) of `js` reaches the JS engine as CODE.

    Three ways, all of them token-state facts rather than payload signatures:
      * the injection point is already in code position (nothing wraps it);
      * the token wrapping it CLOSES inside the payload span — the payload wrote the
        delimiter that ends the string / template / comment / regex;
      * the wrapper is a template literal and the payload opens an ${...} interpolation,
        which is code without closing the literal.
    Everything else is data. That is exactly the control that must keep rejecting a server
    which escaped the quote away.
    """
    try:
        tokens, starts = _js_index(js)
    except Exception:  # unknown state → fail OPEN
        return True
    idx = bisect_right(starts, start) - 1
    if idx < 0:
        return True  # before every token → code position
    token = tokens[idx]
    if start <= token.start or start > token.end:
        return True  # between tokens, or the payload wrote the opening delimiter → code
    if token.end < end:
        return True  # the payload carries the delimiter that closes the token
    if token.kind == "template":
        if "${" in js[start:end]:
            return True
        if js.rfind("${", token.start, start) > js.rfind("}", token.start, start):
            return True  # the injection point sits inside an ${...} interpolation
    return False


_JS_BRACKET_RE = re.compile(r"[()\[\]{}]")
_JS_BRACKET_OPENER = {")": "(", "]": "[", "}": "{"}

# The DOM/HTML entry points that run the HTML FRAGMENT PARSING ALGORITHM on a string.
# A payload that is inert as JavaScript — safely inside a string literal — is still live
# MARKUP when that literal is handed to one of these, which is the whole of "the server
# escaped my quotes so I am safe" being wrong. The set is the standard's list of
# HTML-parsing sinks, not names harvested off a site; the assignment targets that only
# ever set TEXT (textContent, innerText, setAttribute, value) are deliberately absent.
#
# Anchored at the END of the code that precedes the literal, so only a literal passed
# DIRECTLY to the sink counts. `unescape`/`decodeURI`/`decodeURIComponent` are allowed in
# between because they are pure, total percent-decoders whose output we can reproduce.
_JS_HTML_SINK_RE = re.compile(
    r"(?:"
    r"(?:inner|outer)HTML\s*\+?=|srcdoc\s*\+?="
    r"|document\s*\.\s*(?:write|writeln)\s*\("
    r"|insertAdjacentHTML\s*\(\s*[^,()]{0,32},"
    r")\s*(?:(unescape|decodeURI|decodeURIComponent)\s*\(\s*)?$",
    re.IGNORECASE)
# ECMAScript StringEscapeSequence. The decoded literal is what the parser actually sees,
# so `'\u003cimg src=x onerror=alert(1)\u003e'` is markup even though the response body
# contains no '<' at all.
_JS_ESCAPE_RE = re.compile(
    r"\\(?:u\{([0-9a-fA-F]+)\}|u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2})|\r\n|(.))", re.S)
_JS_ESCAPE_SHORT = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v",
                    "0": "\0"}


# PURE
def _js_unescape(text: str) -> str:
    """Resolve ECMAScript escape sequences in a string-literal body."""
    def sub(m):
        long_hex, u4, x2, other = m.groups()
        if long_hex is not None or u4 is not None:
            try:
                return chr(int(long_hex or u4, 16))
            except (ValueError, OverflowError):
                return m.group(0)
        if x2 is not None:
            return chr(int(x2, 16))
        if other is None:
            return ""  # escaped line terminator: line continuation
        return _JS_ESCAPE_SHORT.get(other, other)
    return _JS_ESCAPE_RE.sub(sub, text)


# PURE
def _js_wrapping_token(js: str, start: int) -> Optional[_JsToken]:
    """The string/template token that CONTAINS the offset `start`, if any."""
    tokens, starts = _js_index(js)
    idx = bisect_right(starts, start) - 1
    if idx < 0:
        return None
    token = tokens[idx]
    if token.start < start <= token.end and token.kind in ("string", "template"):
        return token
    return None


# PURE
def _js_literal_reaches_html_sink(js: str, start: int, end: int) -> bool:
    """True when the payload sits in a string literal that is PARSED AS HTML by the DOM.

    The classifier's "inside a JS string with no breakout ⇒ inert" rule is right about the
    HTML parser and silent about the DOM: `el.innerHTML = '<payload>'` and
    `document.write('<payload>')` re-parse that same string as markup. The payload is
    judged in the DECODED fragment with the ordinary position rules, so a string the
    server did escape (`&lt;img`) still comes out inert, and a sibling assignment to
    textContent / setAttribute is not a sink at all.
    """
    from bugtrace.agents.xss.position import _position_executes, _reflection_occurrences
    token = _js_wrapping_token(js, start)
    if token is None or token.end >= len(js):
        return False
    m = _JS_HTML_SINK_RE.search(js[:token.start].rstrip())
    if m is None:
        return False
    fragment = _js_unescape(js[token.start + 1:token.end])
    forms = [js[start:end]]
    decoded = _js_unescape(forms[0])
    if decoded != forms[0]:
        forms.append(decoded)
    if m.group(1):  # the literal is percent-decoded on its way into the sink
        fragment = urllib.parse.unquote(fragment)
        forms += [urllib.parse.unquote(f) for f in tuple(forms)]
    for form in dict.fromkeys(forms):
        if form and form in fragment and any(
                _position_executes(p, form, tag, tail, host)
                for p, tag, tail, host in _reflection_occurrences(fragment, form)):
            return True
    return False


# PURE
def _js_code_balanced(js: str) -> bool:
    """True when `js` shows no structural sign of being unparseable.

    Two one-way tests, both of which prove a SyntaxError when they fail:
      * every bracket OUTSIDE a string/template/regex/comment is matched — a well-formed
        ECMAScript program always balances (), [] and {};
      * no string or template literal runs off the end of the program.
    The converse of neither holds, so this is only ever used to prove FAILURE.
    """
    n = len(js)
    tokens, _ = _js_index(js)
    stack: List[str] = []
    segments: List[str] = []
    pos = 0
    for tok in tokens:
        if tok.end >= n and (tok.kind == "string" or tok.kind == "template"):
            return False  # unterminated literal: the program cannot be compiled
        if tok.start > pos:
            segments.append(js[pos:tok.start])
        pos = min(n, tok.end + 1)
    if pos < len(js):
        segments.append(js[pos:])
    for segment in segments:
        for ch in _JS_BRACKET_RE.findall(segment):
            if ch in "([{":
                stack.append(ch)
            elif not stack or stack.pop() != _JS_BRACKET_OPENER[ch]:
                return False
    return not stack


# PURE
def _js_breakout_parses(js: str, start: int, end: int) -> bool:
    """False when the breakout at [start, end) leaves a program the engine cannot compile.

    An inline classic script (and an event handler, and a javascript: URL) is compiled as
    a WHOLE unit: a SyntaxError anywhere in it discards ALL of it, including the code the
    payload smuggled in. That is why `{query:'PAYLOAD', page:1}` with a `';alert(1);//`
    payload runs nothing — the `//` eats the object literal's own closing brace and the
    script never compiles — while the same payload in `var q='PAYLOAD'` does run.

    DIFFERENTIAL, not absolute: the imbalance only counts against the payload when the
    SAME script balances without it. If our lexer cannot make sense of the page's own
    JavaScript, that is our problem, not evidence of inertness, and we fail OPEN.
    The removal span absorbs any backslash run immediately before the reflection, because
    that escaping is the server's rewrite OF the reflection (see _reflected_forms).
    """
    try:
        if _js_code_balanced(js):
            return True
        at = start
        while at > 0 and js[at - 1] == "\\":
            at -= 1
        return not _js_code_balanced(js[:at] + js[end:])
    except Exception:  # unknown state → fail OPEN
        return True


# HTML event handler content attributes are the `on<eventname>` family — a naming rule in
# the standard, not a list of handler names we would have to keep guessing at.
_EVENT_HANDLER_NAME_RE = re.compile(r"^on[a-z]+$")
# Leading characters a URL parser strips before the scheme (C0 controls + space).
_URL_LEADING_STRIP = "".join(chr(c) for c in range(0x21)) + "\x7f"


# PURE

# PURE
def _js_value_executes(value: str, payload: str, js_start: int) -> bool:
    """True when `payload`, as reflected in `value`, reaches the JS engine as code.

    `js_start` is where the JavaScript begins inside the attribute value (0 for an event
    handler, past "javascript:" for a URI). A payload that overlaps the scheme itself wrote
    the scheme, so it executes by construction.

    A handler body and a javascript: URL are compiled as whole scripts, so a breakout that
    leaves them unparseable creates no handler and runs no code.
    """
    js = value[js_start:]
    at = value.find(payload)
    while at != -1:
        if at < js_start:
            return True  # the payload supplied (part of) the javascript: scheme
        s, e = at - js_start, at - js_start + len(payload)
        if _js_span_escapes(js, s, e) and _js_breakout_parses(js, s, e):
            return True
        at = value.find(payload, at + 1)
    return False


# PURE

