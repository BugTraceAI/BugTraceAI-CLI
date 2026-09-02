"""Shell-level constants shared by XSSAgent mixins.

Keep under agent-workable size; pure domain constants stay in constants.py.
"""
from __future__ import annotations

import asyncio

from bugtrace.agents.openredirect_payloads import REDIRECT_PARAMS

# Serializes CDP-based proof-screenshot fallbacks (Chrome CDP is single-threaded).
_CDP_PROOF_LOCK = asyncio.Lock()

# Browser-only XSS candidates: redirect/DOM-sink params and contexts that only
# confirm in a real browser (auto-escalate to L5/L6 regardless of scan depth).
# len>=3 drops noisy 1-2 char entries that would over-escalate common params.
_REDIRECT_PARAM_SET = frozenset(p.lower() for p in REDIRECT_PARAMS if len(p) >= 3)
_BROWSER_ONLY_CONTEXTS = frozenset({"href", "url_context", "dom_xss", "js_url"})

# Historical hardcoded reflection marker for _analyze_reflection_context.
_LEGACY_PROBE_MARKER = "BT7331"

# HTML window around reflection point handed to L3 LLM prompts.
_REFLECTION_SNIPPET_RADIUS = 250

# L0.5 char-survival probe: each special char bracketed by its own marker pair.
# Format: BT7331A"BT7331B'BT7331C<BT7331D>BT7331E`BT7331F\BT7331G
_L05_CHAR_PROBE = 'BT7331A"BT7331B\'BT7331C<BT7331D>BT7331E`BT7331F\\BT7331G'

# L0.5 probe outcome vocabulary (response vs no-reflection are opposite facts).
_PROBE_NO_RESPONSE = "no_response"
_PROBE_NO_REFLECTION = "no_reflection"
_PROBE_REFLECTED = "reflected"
