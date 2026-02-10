---
phase: lonewolf
plan: 01
type: execute
wave: 1
depends_on: []
files_modified:
  - bugtrace/core/config.py
  - bugtraceaicli.conf
  - bugtrace/agents/lone_wolf.py
  - bugtrace/core/team.py
autonomous: true

must_haves:
  truths:
    - "LoneWolf runs in background during Phases 2-5 without affecting pipeline"
    - "LoneWolf uses LLM reasoning to explore target autonomously"
    - "LoneWolf findings appear in final report alongside specialist findings"
    - "LoneWolf crash does not crash or delay the pipeline"
    - "LoneWolf is disabled by default and can be enabled via config"
    - "LoneWolf can inject in ALL vectors: query params, POST body, JSON body, cookies, headers, path segments"
    - "LoneWolf confirms findings with multiple methods: reflection, encoded reflection, time-based, error-based"
  artifacts:
    - path: "bugtrace/agents/lone_wolf.py"
      provides: "Autonomous exploration agent"
      min_lines: 180
    - path: "bugtrace/core/config.py"
      provides: "LONEWOLF_* config fields"
      contains: "LONEWOLF_ENABLED"
    - path: "bugtrace/core/team.py"
      provides: "Pipeline integration (launch/stop/collect)"
      contains: "LoneWolf"
    - path: "bugtraceaicli.conf"
      provides: "LONEWOLF section with config options"
      contains: "[LONEWOLF]"
  key_links:
    - from: "bugtrace/core/team.py"
      to: "bugtrace/agents/lone_wolf.py"
      via: "asyncio.create_task(wolf.run()) fire-and-forget in _run_sequential_pipeline"
      pattern: "LoneWolf\\(.*target.*scan_dir"
    - from: "bugtrace/agents/lone_wolf.py"
      to: "specialists/results/lone_wolf_results.json"
      via: "_save_results() writes JSON"
      pattern: "lone_wolf_results\\.json"
    - from: "bugtrace/agents/reporting.py"
      to: "specialists/results/lone_wolf_results.json"
      via: "_load_findings_from_results_file() glob picks up the file"
      pattern: "\\*_results\\.json"
---

<objective>
Implement the LoneWolf autonomous agent -- a parallel exploration agent that runs alongside the main 6-phase pipeline during Phases 2-5. The wolf uses raw HTTP + LLM reasoning (DeepSeek R1) to explore the target independently, finding vulnerabilities the structured pipeline might miss.

Purpose: Add a creative, LLM-driven exploration layer that complements the deterministic specialist pipeline. The wolf explores paths, parameters, and attack vectors that the pipeline's structured approach never tries.

Output: A working LoneWolf agent that launches in background, explores autonomously, saves findings to `specialists/results/lone_wolf_results.json`, and gets picked up by ReportingAgent automatically. Disabled by default.
</objective>

<context>
@.planning/LONEWOLF-RESEARCH.md
@bugtrace/core/config.py
@bugtrace/core/team.py (lines 1871-2109: _run_sequential_pipeline)
@bugtrace/agents/reporting.py (lines 270-354: _load_specialist_results, _load_findings_from_results_file)
@bugtrace/core/llm_client.py (generate() signature, validate_json_response())
</context>

<tasks>

<task type="auto">
  <name>Task 1: Config entries + lone_wolf.py agent</name>
  <files>
    bugtrace/core/config.py
    bugtraceaicli.conf
    bugtrace/agents/lone_wolf.py
  </files>
  <action>
**1a. Config entries in `bugtrace/core/config.py`:**

Add these fields to the `Settings` class (after the MANIPULATOR config block, around line 871):

```python
# --- LONEWOLF Autonomous Agent Configuration ---
LONEWOLF_ENABLED: bool = False          # Disabled by default until tested
LONEWOLF_MODEL: str = "deepseek/deepseek-r1"  # LLM for reasoning
LONEWOLF_RATE_LIMIT: float = 1.0       # HTTP requests per second
LONEWOLF_MAX_CONTEXT: int = 20         # Sliding window size (actions remembered)
LONEWOLF_RESPONSE_TRUNCATE: int = 2000 # Max chars kept from HTTP responses
```

Add a `_load_lonewolf_config` method to the Settings class (after `_load_authority_config`):

```python
def _load_lonewolf_config(self, config):
    """Load LONEWOLF section config."""
    if "LONEWOLF" not in config:
        return
    section = config["LONEWOLF"]
    if "ENABLED" in section:
        self.LONEWOLF_ENABLED = section.getboolean("ENABLED")
    if "MODEL" in section:
        self.LONEWOLF_MODEL = section["MODEL"]
    if "RATE_LIMIT" in section:
        self.LONEWOLF_RATE_LIMIT = section.getfloat("RATE_LIMIT")
    if "MAX_CONTEXT" in section:
        self.LONEWOLF_MAX_CONTEXT = section.getint("MAX_CONTEXT")
    if "RESPONSE_TRUNCATE" in section:
        self.LONEWOLF_RESPONSE_TRUNCATE = section.getint("RESPONSE_TRUNCATE")
```

Call `self._load_lonewolf_config(config)` in `load_from_conf()` after `self._load_authority_config(config)` (line 579).

**1b. Config section in `bugtraceaicli.conf`:**

Add at the end of the file:

```ini
# =============================================================================
# LONEWOLF - Autonomous Exploration Agent
# =============================================================================
# The LoneWolf runs in parallel with the pipeline (Phases 2-5) using only
# raw HTTP + LLM reasoning to explore the target independently.
# It finds vulnerabilities the structured pipeline might miss.
# Findings are deduplicated against specialist findings automatically.

[LONEWOLF]
# Enable/disable the autonomous exploration agent
# WARNING: Keep disabled until you've tested on a safe target first
ENABLED = False

# OpenRouter model for reasoning (DeepSeek R1 for chain-of-thought)
# The wolf uses this model for ALL its reasoning - choosing what to explore,
# analyzing responses, deciding what payloads to test
MODEL = deepseek/deepseek-r1

# HTTP request rate limit (requests per second to target)
# At 1.0 req/s over a 1-hour scan, the wolf makes ~3600 requests
# This is negligible compared to the pipeline's thousands
RATE_LIMIT = 1.0

# Sliding window size for context (number of recent actions remembered)
# Higher = more context for LLM = better reasoning but more tokens
MAX_CONTEXT = 20

# Max characters to keep from HTTP responses (truncation)
# Keeps LLM prompts manageable while preserving enough for analysis
RESPONSE_TRUNCATE = 2000
```

**1c. Create `bugtrace/agents/lone_wolf.py`:**

Create the full LoneWolf agent. This is the core of the feature. Key design decisions:

- **Completely decoupled**: Own aiohttp session, own rate limiter, no shared tools
- **LLM-driven**: Every action decided by DeepSeek R1 via `llm_client.generate(model_override=...)`
- **Sliding window context**: Last N actions kept in memory, older ones dropped
- **Error-isolated**: Entire `run()` wrapped in try/except, always returns findings (even partial)
- **Finding validation**: Multi-method confirmation — reflection check, encoded reflection, time-based detection, error-based detection. Not just `payload in response`
- **Full HTTP control**: Cookies, custom headers, JSON body — the wolf can test any injection vector, not just query params

The agent structure:

```python
import asyncio
import aiohttp
import json
import time
from pathlib import Path
from typing import List, Dict, Optional
from bugtrace.core.config import settings
from bugtrace.core.llm_client import llm_client
from bugtrace.utils.logger import get_logger

logger = get_logger("agents.lone_wolf")
```

**System prompt** (this is where the real value is -- the LLM needs to think like an autonomous pentester):

```python
SYSTEM_PROMPT = """You are an autonomous penetration tester exploring a web application to find security vulnerabilities. You work alone -- no tools, no frameworks, just raw HTTP requests and your expertise.

EXPLORATION STRATEGY:
1. START by fetching the target page and analyzing the HTML structure
2. DISCOVER: Find all links, forms, parameters, JavaScript files, API endpoints, cookies
3. MAP: Build a mental model of the application -- what framework, what parameters accept user input, where does input reflect
4. PROBE: Test interesting parameters with probe strings to see what reflects and where
5. EXPLOIT: When you find reflection or suspicious behavior, craft targeted payloads
6. CHAIN: Combine findings -- an open redirect can enable SSRF, a cookie injection can lead to SQLi

INJECTION VECTORS (test ALL of these, not just query params):
- Query parameters (?param=value)
- POST body (form-encoded and JSON)
- Cookies (decode Base64/JSON cookies, inject inside decoded values)
- HTTP headers (Referer, X-Forwarded-For, Host, custom headers)
- Path segments (/api/users/INJECT_HERE/profile)
- JSON body fields ({"key": "INJECT_HERE"})

WHAT TO LOOK FOR:
- Parameters that reflect user input (XSS candidates)
- Parameters used in database queries (SQLi candidates -- error messages, behavior changes with ' or ")
- Cookies that contain structured data (Base64, JSON) -- decode and probe for SQLi/injection inside
- File path parameters (LFI -- ../../../etc/passwd patterns)
- URL/redirect parameters (SSRF/Open Redirect)
- Template syntax evaluation (CSTI/SSTI -- {{7*7}} = 49)
- Hidden forms, admin panels, API endpoints not linked from main page
- JavaScript files that reveal API routes or sensitive endpoints
- Error pages that leak stack traces or framework versions
- Security headers missing (HSTS, X-Frame-Options, CSP) -- note in response headers
- Set-Cookie without Secure/HttpOnly flags

PAYLOAD RULES:
- NEVER use alert(1) -- use document.domain or visual DOM manipulation instead
- For XSS: Try context-aware breakouts (single quote for JS strings, angle brackets for HTML, backslash-quote for escaped contexts)
- For SQLi: Use time-based (sleep(5)), error-based (extractvalue), or UNION-based detection. Compare response TIME and CONTENT for time-based.
- For CSTI: Try {{7*7}} first, then engine-specific payloads
- Always check if your probe string reflects BEFORE sending exploit payloads

OUTPUT FORMAT -- respond with EXACTLY ONE JSON action:

To fetch a page:
{"action": "fetch", "url": "https://example.com/page", "method": "GET"}

To fetch with query parameters:
{"action": "fetch", "url": "https://example.com/search", "method": "GET", "params": {"q": "test"}}

To POST form data:
{"action": "fetch", "url": "https://example.com/login", "method": "POST", "data": {"user": "admin", "pass": "test"}}

To POST JSON data:
{"action": "fetch", "url": "https://example.com/api/users", "method": "POST", "json_body": {"name": "test", "role": "admin"}}

To fetch with custom cookies (e.g. testing cookie injection):
{"action": "fetch", "url": "https://example.com/page", "method": "GET", "cookies": {"TrackingId": "abc' OR 1=1--"}}

To fetch with custom headers:
{"action": "fetch", "url": "https://example.com/page", "method": "GET", "headers": {"X-Forwarded-For": "127.0.0.1", "Referer": "javascript:alert(document.domain)"}}

To test a specific payload (multiple confirmation methods):
{"action": "test", "url": "https://example.com/search", "parameter": "q", "payload": "<img src=x onerror=alert(document.domain)>", "vuln_type": "XSS", "severity": "HIGH", "method": "GET", "inject_in": "param"}

To test cookie injection:
{"action": "test", "url": "https://example.com/page", "parameter": "TrackingId", "payload": "abc' AND SLEEP(5)--", "vuln_type": "SQLi", "severity": "CRITICAL", "inject_in": "cookie"}

To test header injection:
{"action": "test", "url": "https://example.com/page", "parameter": "Referer", "payload": "javascript:alert(document.domain)", "vuln_type": "XSS", "severity": "HIGH", "inject_in": "header"}

When you've exhausted exploration:
{"action": "done", "reason": "All discovered parameters tested, no more paths to explore"}

IMPORTANT:
- Output ONLY the JSON, no explanation before or after
- Explore BROADLY first (discover all endpoints), then DEEPLY (test each parameter)
- Each action should build on what you learned from previous results
- If a page returns an error, analyze the error -- it may reveal framework/technology info
- Follow redirects mentally but note them (redirect targets may be interesting)
- Check robots.txt, sitemap.xml, .well-known/ paths early
- ALWAYS inspect response headers (Set-Cookie, security headers) -- report missing security headers
- When you see a cookie with Base64 or JSON, DECODE IT and test injection inside the decoded value
- For time-based SQLi, note the response time -- if a sleep(5) payload takes 5+ seconds, that's confirmation
"""
```

**LoneWolf class implementation:**

```python
class LoneWolf:
    """Autonomous exploration agent that runs parallel to the pipeline.

    Uses raw HTTP + LLM reasoning to explore the target independently.
    Completely decoupled from the pipeline -- own session, own rate limiter.
    """

    def __init__(self, target_url: str, scan_dir: Path):
        self.target_url = target_url
        self.scan_dir = scan_dir
        self.findings: List[Dict] = []
        self.context: List[Dict] = []  # Sliding window of actions+results
        self.session: Optional[aiohttp.ClientSession] = None
        self.max_context = settings.LONEWOLF_MAX_CONTEXT
        self.model = settings.LONEWOLF_MODEL
        self.rate_limit = settings.LONEWOLF_RATE_LIMIT
        self.truncate_len = settings.LONEWOLF_RESPONSE_TRUNCATE
        self._last_request_time = 0.0
        self._urls_visited: set = set()  # Track visited URLs to avoid loops
        self._cycle_count = 0
        self._max_cycles = 500  # Safety valve — stop after N cycles
```

**Core methods:**

1. `async def run(self) -> List[Dict]` -- Entry point. Creates aiohttp session, runs exploration loop, always returns findings (even on crash). Closes session in `finally`.

2. `async def _exploration_loop(self) -> List[Dict]` -- Main loop. Fetches target URL first, then enters think-execute-update cycle. Stops when: LLM returns `"done"` action, or `_cycle_count >= _max_cycles` (500), or LLM fails 3 times consecutively. Sleeps via rate limiter between requests. Calls `_save_results()` after each confirmed finding (incremental). Calls `_write_progress()` every ~20 cycles for DB status updates.

3. `async def _think(self) -> Optional[Dict]` -- Builds prompt from sliding window context, calls `llm_client.generate(prompt=..., module_name="LoneWolf", model_override=self.model, system_prompt=SYSTEM_PROMPT, temperature=0.7, max_tokens=2000)`. Parses response with `llm_client.validate_json_response()`. Returns None if LLM fails.

4. `async def _execute(self, action: Dict) -> str` -- Dispatches action by type: "fetch" calls `_fetch()`, "test" calls `_test_payload()`. Returns result string that includes response headers summary (status code, key headers like Set-Cookie, security headers) + truncated body.

5. `async def _fetch(self, url: str, method: str = "GET", params: dict = None, data: dict = None, json_body: dict = None, cookies: dict = None, headers: dict = None) -> tuple[str, float]` -- Rate-limited HTTP request with **built-in retry** for transient failures. Supports ALL injection vectors: query params, form POST, JSON POST, cookies, custom headers. Returns tuple of (response_text truncated to `self.truncate_len`, elapsed_seconds). The response_text includes a header summary block: `[STATUS: 200] [TIME: 0.3s] [HEADERS: Set-Cookie: ..., X-Frame-Options: ...]` followed by the body. Returns ("ERROR: ...", 0.0) only after all retries exhausted. Tracks visited URLs.

   **Retry logic (inline, no external library):**
   - Max 3 attempts per request
   - Retries on: `asyncio.TimeoutError`, `aiohttp.ClientError` (connection reset, DNS failure), HTTP 429 (rate limited), HTTP 503 (service unavailable)
   - Does NOT retry on: HTTP 4xx (except 429), HTTP 5xx (except 503), successful responses
   - Backoff: 1s, 2s, 4s (exponential) — between retries only, not before first attempt
   - On 429: reads `Retry-After` header if present, otherwise uses backoff
   - If all 3 attempts fail, returns ("ERROR: {last_error}", 0.0) — the LLM sees the error and can decide to try a different approach instead of the same request

6. `async def _test_payload(self, action: Dict) -> str` -- Tests a payload with multi-method confirmation:
   - **`inject_in`** field determines where to inject: `"param"` (query/POST), `"cookie"`, `"header"`, `"json"`, `"path"`
   - **Reflection check**: `payload in response` (literal match)
   - **Encoded reflection**: Also checks HTML-encoded (`&lt;script&gt;`), URL-encoded (`%3Cscript%3E`), and backslash-escaped (`\"` → `\\"`) variants
   - **Time-based detection**: If `elapsed_seconds > 4.5` and payload contains time-based indicators (`sleep`, `WAITFOR`, `pg_sleep`), confirms as time-based SQLi
   - **Error-based detection**: If response contains SQL error signatures (`SQL syntax`, `ORA-`, `PostgreSQL`, `sqlite3`) and payload contains SQL metacharacters, confirms as error-based SQLi
   - Creates finding dict with: type, url, parameter, payload, evidence (snippet around match or timing info), severity, status="VALIDATED_CONFIRMED", source="lone_wolf", specialist="LoneWolf", confirmation_method (reflection/time-based/error-based)
   - Returns descriptive result: "CONFIRMED (reflection)", "CONFIRMED (time-based: 5.2s)", "CONFIRMED (error-based)", or "Not confirmed."

7. `def _add_context(self, action_type: str, detail: str, result: str)` -- Appends to sliding window, trims to `max_context` entries.

8. `def _build_prompt(self) -> str` -- Formats sliding window context into a prompt. Includes: target URL, findings count, URLs visited count, recent actions with results.

9. `async def _rate_limit_wait(self)` -- Simple rate limiter: tracks `_last_request_time`, sleeps if needed. Uses `time.monotonic()`.

10. `def _save_results(self)` -- Writes `{"specialist": "lone_wolf", "findings": [...]}` to `self.scan_dir / "specialists" / "results" / "lone_wolf_results.json"`. Creates directories with `mkdir(parents=True, exist_ok=True)`. Called **after every confirmed finding** (incremental save), not just at the end. This ensures reporting picks up findings even if the wolf is still running when Phase 6 starts.

11. `async def _write_progress(self, message: str)` -- Optional DB write-only progress updates so the web UI can show wolf status. Uses the existing DB write pattern (INSERT only, NEVER SELECT). Writes to a simple progress log:
    - "LoneWolf started exploring {target_url}"
    - "LoneWolf explored {n} URLs, tested {m} parameters"
    - "LoneWolf confirmed finding: {vuln_type} on {parameter}"
    - "LoneWolf finished: {n} findings in {elapsed} minutes"

    **DB WRITE-ONLY RULE**: This method does INSERT only. The wolf NEVER reads from DB. The API/WEB reads these entries to show progress.

**Important implementation details:**
- The `_test_payload` method uses MULTIPLE confirmation methods — not just `payload in response`. Also checks: HTML-encoded variants, time-based (elapsed > 4.5s with sleep payload), error-based (SQL error strings). This prevents both false negatives (encoded reflection missed) and hallucinated findings.
- For POST requests in `_fetch`: `data=data` for form-encoded, `json=json_body` for JSON body. Both supported.
- For cookie injection: `cookies=cookies` parameter passed to `session.request()`.
- For header injection: merge `headers` dict with default User-Agent header.
- `_fetch()` returns `(response_text, elapsed_seconds)` tuple — elapsed is needed for time-based SQLi detection.
- Response text includes header summary: `[STATUS: 200] [TIME: 0.3s] [HEADERS: Set-Cookie: ..., X-Frame-Options: ...]` so the LLM can reason about headers.
- The session should use `ssl=False` in the connector (security testing targets may have self-signed certs).
- Add a `TCPConnector(limit=5)` to prevent connection exhaustion.
- The exploration loop should have a maximum cycle count (e.g., 500) as a safety valve.
- Log at INFO level: start, each finding, finish with count. Log at DEBUG level: each action.
- `run()` saves results to disk via `_save_results()` and returns the findings list. team.py only uses the return for logging the count — reporting reads from disk.
  </action>
  <verify>
1. `python -c "from bugtrace.core.config import settings; print(settings.LONEWOLF_ENABLED, settings.LONEWOLF_MODEL)"` prints `False deepseek/deepseek-r1`
2. `python -c "from bugtrace.agents.lone_wolf import LoneWolf; print('OK')"` prints `OK`
3. `grep -c 'LONEWOLF' bugtraceaicli.conf` returns at least 6 (section + 5 settings)
4. `grep 'LONEWOLF_ENABLED' bugtrace/core/config.py` finds the field definition
5. `grep '_load_lonewolf_config' bugtrace/core/config.py` finds the loader method AND the call in `load_from_conf`
  </verify>
  <done>
- Settings class has 5 LONEWOLF_* fields with correct defaults (ENABLED=False)
- bugtraceaicli.conf has [LONEWOLF] section with all 5 settings documented
- load_from_conf() calls _load_lonewolf_config()
- lone_wolf.py contains LoneWolf class with: run(), _exploration_loop(), _think(), _execute(), _fetch(), _test_payload(), _save_results()
- System prompt guides LLM to explore like an autonomous pentester
- _test_payload only records findings with concrete HTTP evidence (payload reflected)
- Module imports cleanly without errors
  </done>
</task>

<task type="auto">
  <name>Task 2: Pipeline integration in team.py</name>
  <files>
    bugtrace/core/team.py
  </files>
  <action>
Add ~10 lines to `_run_sequential_pipeline()` in `bugtrace/core/team.py` at two specific locations:

**2a. LAUNCH POINT -- After Phase 1 RECONNAISSANCE completes, before Phase 2 starts (line ~1919, after `if await self._check_stop_requested(dashboard): return`):**

```python
# ========== LONEWOLF: Fire and forget ==========
if settings.LONEWOLF_ENABLED:
    from bugtrace.agents.lone_wolf import LoneWolf
    wolf = LoneWolf(self.target, self.scan_dir)
    asyncio.create_task(wolf.run())
    logger.info("[Pipeline] LoneWolf launched in background")
```

This goes RIGHT BEFORE the `# ========== PHASE 2: DISCOVERY (Batch DAST) ==========` comment block.

**That's it. No stop point. No await. No collect. Fire and forget.**

**Why this works:**
- Phase 1 gives us the target URL and scan_dir (both set before Phase 2)
- The wolf is a fire-and-forget `asyncio.create_task` — pipeline doesn't wait for it, ever
- The wolf saves findings to `specialists/results/lone_wolf_results.json` **incrementally** (after each confirmed finding), not just at the end
- The wolf has its own internal stop: max_cycles (500) as safety valve
- When Phase 6 REPORTING runs, it globs `specialists/results/*_results.json` and picks up whatever the wolf saved so far
- If the wolf is still running when reporting reads the file, that's fine — it already saved what it found
- If the wolf hasn't found anything, the file doesn't exist, reporting skips it
- Pipeline NEVER waits, NEVER blocks, NEVER interacts with the wolf after launch

**Zero impact on pipeline flow:**
- No `await` on wolf — zero delay
- No stop event needed — wolf runs until max_cycles or process exits
- No error handling needed in team.py — if wolf crashes, the create_task silently dies
- No variables tracked (`wolf_task`, `wolf_stop`) — truly fire and forget
- If `LONEWOLF_ENABLED=False`, it's 0 lines of code executed
  </action>
  <verify>
1. `grep -n 'LoneWolf' bugtrace/core/team.py` shows ONLY the launch block (no stop/collect block)
2. `grep 'wolf_task\|wolf_stop\|wait_for.*wolf' bugtrace/core/team.py` returns ZERO matches — no awaiting, no stopping
3. `grep 'create_task.*wolf\|create_task.*run' bugtrace/core/team.py` shows the fire-and-forget launch
4. Verify the launch block is between Phase 1 and Phase 2 comments (and NOWHERE else)
5. `python -c "from bugtrace.core.team import TeamOrchestrator; print('OK')"` imports without error
  </verify>
  <done>
- team.py has wolf fire-and-forget launch after Phase 1, before Phase 2 (4 lines only)
- NO stop block, NO await, NO collect — truly independent
- Wolf launch is conditional on `settings.LONEWOLF_ENABLED`
- Pipeline never waits for wolf — zero impact on flow
- Wolf saves findings incrementally to disk — reporting reads whatever is there
- No changes to reporting.py needed (existing glob handles it)
  </done>
</task>

</tasks>

<verification>
1. **Import chain**: `python -c "from bugtrace.core.config import settings; from bugtrace.agents.lone_wolf import LoneWolf; from bugtrace.core.team import TeamOrchestrator; print('All imports OK')"` succeeds
2. **Config defaults**: `LONEWOLF_ENABLED` is `False` by default -- wolf does NOT run unless explicitly enabled
3. **Config override**: Setting `ENABLED = True` in `[LONEWOLF]` section of bugtraceaicli.conf enables the wolf
4. **Finding format**: Wolf writes `{"specialist": "lone_wolf", "findings": [...]}` matching the schema expected by `_load_findings_from_results_file()`
5. **Dedup**: If wolf finds same (url, param, payload) as a specialist, `_deduplicate_exact()` removes the duplicate
6. **Zero pipeline impact**: Wolf is fire-and-forget — no await, no stop, no blocking. Pipeline flow is identical with wolf enabled vs disabled (except 4 lines of launch code)
7. **No pipeline impact when disabled**: When `LONEWOLF_ENABLED=False`, zero additional code executes during scan
8. **Incremental saves**: Wolf saves findings to disk after each confirmation — reporting reads whatever is there
9. **DB write-only**: Wolf writes progress to DB (INSERT only, NEVER SELECT) so web UI shows wolf status
10. **Full injection vector coverage**: `_fetch()` supports params, data, json_body, cookies, headers
</verification>

<success_criteria>
- LoneWolf agent exists as single file `bugtrace/agents/lone_wolf.py` (~250+ lines)
- Config has 5 LONEWOLF_* fields with `ENABLED=False` default
- bugtraceaicli.conf has documented [LONEWOLF] section
- team.py launches wolf after Phase 1, stops before Phase 6
- Wolf findings saved to `specialists/results/lone_wolf_results.json`
- ReportingAgent picks up wolf findings via existing glob pattern
- Wolf crash never affects pipeline execution
- All imports work without circular dependency issues
- `_fetch()` supports: params, data (form), json_body, cookies, headers
- `_test_payload()` confirms via: literal reflection, encoded reflection, time-based (elapsed > 4.5s), error-based (SQL error strings)
- System prompt instructs LLM to test cookies, headers, JSON bodies — not just query params
</success_criteria>
