# LoneWolf Autonomous Agent - Research

**Researched:** 2026-02-09
**Domain:** Async autonomous security agent with LLM-driven exploration
**Confidence:** HIGH (all findings from direct codebase analysis)

## Summary

This research investigates the exact integration points, interfaces, and patterns needed to implement a LoneWolf autonomous agent that runs in parallel with the existing 6-phase pipeline. All findings are derived from direct analysis of the BugTraceAI-CLI codebase.

The LoneWolf agent needs: (1) its own LLM client instance configured for DeepSeek R1, (2) its own aiohttp session for HTTP requests, (3) its own rate limiter, (4) integration into the pipeline via `asyncio.create_task()` in `team.py`, (5) finding output written to `specialists/results/lone_wolf_results.json`, and (6) a stop signal via `asyncio.Event`.

The codebase already provides all the patterns needed. The `LLMClient` class supports `model_override` on every call. The pipeline has clear phase boundaries where the wolf can be launched (start of Phase 2) and stopped (end of Phase 5). The `ReportingAgent` already handles deduplication via `_deduplicate_exact()` using `(url, parameter, payload)` keys. The finding format is well-defined from `state_manager.py`.

**Primary recommendation:** Implement as a single file `bugtrace/agents/lone_wolf.py` with ~200 lines, using the existing `LLMClient.generate()` with `model_override` for DeepSeek R1, and a simple `asyncio.Event` stop mechanism. Integration requires ~10 lines in `team.py` and ~5 lines in `reporting.py`.

## Standard Stack

### Core (Already in Project)
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| aiohttp | >=3.9.0,<4.0 | HTTP requests | Already in requirements.txt, used by LLMClient |
| asyncio | stdlib | Async coordination | Already used everywhere in pipeline |
| LLMClient | internal | LLM API calls | Singleton at `bugtrace/core/llm_client.py` |

### No New Dependencies Required
The LoneWolf uses only what already exists:
- `aiohttp` for raw HTTP (already installed)
- `LLMClient.generate()` with `model_override` for DeepSeek R1
- `asyncio.Event` for stop signaling
- `json` for finding serialization
- `settings` for configuration

**Installation:** No new packages needed.

## Architecture Patterns

### 1. LLM Client Interface (HIGH Confidence)

**Source:** `bugtrace/core/llm_client.py` lines 595-603

The `LLMClient.generate()` signature is:
```python
async def generate(
    self,
    prompt: str,
    module_name: str,
    model_override: Optional[str] = None,
    system_prompt: Optional[str] = None,
    temperature: float = 0.7,
    max_tokens: int = 1500
) -> Optional[str]:
```

**Key findings:**
- `model_override` is supported -- pass `"deepseek/deepseek-r1"` (or whatever the R1 model ID is on OpenRouter)
- When `model_override` is provided, it tries that model FIRST, then falls back to `PRIMARY_MODELS` (line 639): `models_to_try = [model_override] + [m for m in self.models if m != model_override]`
- Returns `Optional[str]` -- can be None if all models fail
- Has built-in circuit breaker, retry with exponential backoff, model shifting
- The singleton is at `bugtrace/core/llm_client.py` line 1470: `llm_client = LLMClient()`
- Token usage is tracked automatically via `token_tracker.record_usage()` -- wolf LLM calls will appear in cost reports with `module_name="LoneWolf"`
- There is also `generate_with_thread()` which takes a `ConversationThread` for multi-turn context, but for LoneWolf the simpler `generate()` with a sliding window context in the prompt is recommended (less overhead)

**Usage pattern for LoneWolf:**
```python
from bugtrace.core.llm_client import llm_client

response = await llm_client.generate(
    prompt="<sliding window context + current question>",
    module_name="LoneWolf",
    model_override="deepseek/deepseek-r1",  # Or configured model
    system_prompt="You are an autonomous penetration tester...",
    temperature=0.7,
    max_tokens=2000
)
```

### 2. Pipeline Lifecycle and Integration Points (HIGH Confidence)

**Source:** `bugtrace/core/team.py` lines 1871-2109

The V3 Batch Pipeline flow is:
```
_run_sequential_pipeline()
    Phase 1: RECONNAISSANCE   --> _phase_1_reconnaissance()
    Phase 2: DISCOVERY (DAST)  --> _phase_2_batch_dast()     <-- LAUNCH WOLF HERE
    Phase 3: STRATEGY          --> _phase_3_strategy()
    Phase 4: EXPLOITATION      --> _init_specialist_workers()
    Phase 5: VALIDATION        --> _phase_3_global_review()   <-- STOP WOLF HERE
    Phase 6: REPORTING         --> _phase_4_reporting()       <-- COLLECT WOLF FINDINGS
```

**Launch point (after Phase 1, before Phase 2 starts):**
Line ~1929 in `_run_sequential_pipeline()`, right before `_phase_2_batch_dast()`. The wolf needs the target URL (available as `self.target`) and the scan_dir (available as `self.scan_dir`).

```python
# Launch LoneWolf as background task
wolf_stop_event = asyncio.Event()
wolf_task = asyncio.create_task(
    self._run_lone_wolf(wolf_stop_event)
)
```

**Stop point (after Phase 5 VALIDATION completes):**
Line ~2074 in `_run_sequential_pipeline()`, after `_phase_3_global_review()` returns (Phase 5 VALIDATION).

```python
# Stop the wolf and collect findings
wolf_stop_event.set()
try:
    wolf_findings = await asyncio.wait_for(wolf_task, timeout=30.0)
except asyncio.TimeoutError:
    logger.warning("LoneWolf did not stop in time, cancelling")
    wolf_task.cancel()
    wolf_findings = []
```

**Collection point (Phase 6 REPORTING):**
Line ~2089, `_phase_4_reporting()` calls `ReportingAgent.generate_all_deliverables()` which reads from `specialists/results/*.json`. If the wolf writes its findings to `specialists/results/lone_wolf_results.json`, they get picked up automatically.

### 3. Stop Event Pattern (HIGH Confidence)

**Source:** `bugtrace/core/team.py` line 86

The codebase already uses `asyncio.Event()` for stop signaling:
```python
self._stop_event = asyncio.Event()  # line 86
```

It's checked throughout the pipeline:
```python
if dashboard.stop_requested or self._stop_event.is_set():  # line 2807
```

**Pattern for LoneWolf:**
```python
class LoneWolf:
    def __init__(self, target_url: str, scan_dir: Path, stop_event: asyncio.Event):
        self.target_url = target_url
        self.scan_dir = scan_dir
        self.stop_event = stop_event

    async def run(self) -> List[Dict]:
        while not self.stop_event.is_set():
            # Do one exploration cycle
            action = await self._think()
            result = await self._execute(action)
            self._update_context(result)

            # Check stop between cycles
            if self.stop_event.is_set():
                break

            # Rate limit
            await asyncio.sleep(1.0)  # ~1 req/s

        return self.findings
```

### 4. Finding Format (HIGH Confidence)

**Source:** `bugtrace/core/state_manager.py` lines 222-233

The normalized finding format expected by reporting is:
```python
{
    "type": "XSS",             # Required: vulnerability type
    "url": "https://...",      # Required: affected URL
    "parameter": "searchTerm", # Required: affected parameter
    "payload": "...",          # Required: the payload that worked
    "evidence": "...",         # Required: proof (response snippet, etc.)
    "severity": "HIGH",        # Required: CRITICAL/HIGH/MEDIUM/LOW/INFO
    "status": "VALIDATED_CONFIRMED",  # Required for report inclusion
    "source": "lone_wolf",    # Identifies origin
}
```

Additional fields accepted by `_build_finding_entry()` (line 1087-1146):
- `description`: Human-readable description
- `cvss_score`: Numeric CVSS score
- `screenshot_path`: Path to screenshot
- `successful_payloads`: List of alternative payloads
- `specialist`: Agent name string

### 5. Results File Writing Pattern (HIGH Confidence)

**Source:** `bugtrace/agents/reporting.py` lines 276-301

ReportingAgent reads results from:
1. `specialists/*_report.json` -- primary (report files written by specialist agents)
2. `specialists/results/*_results.json` -- secondary (results files)

The format for a results file:
```python
{
    "specialist": "lone_wolf",
    "findings": [
        {
            "type": "XSS",
            "url": "https://example.com/search",
            "parameter": "q",
            "payload": "<script>alert(document.domain)</script>",
            "evidence": "Payload reflected in response body",
            "severity": "HIGH",
            "status": "VALIDATED_CONFIRMED"
        }
    ]
}
```

**Write location:** `self.scan_dir / "specialists" / "results" / "lone_wolf_results.json"`

The `specialists/results/` directory is read by `_load_findings_from_results_file()` which processes `data.get("findings", [])` and sets source to `f"specialist:{specialist}"`.

### 6. Deduplication (HIGH Confidence)

**Source:** `bugtrace/agents/reporting.py` lines 383-392, 999-1059

Two levels of dedup already exist:
1. **Exact dedup** via `_deduplicate_exact()`: key = `(url, parameter, payload)` -- prevents identical findings
2. **Semantic dedup** via `_deduplicate_findings()`: key = `(normalized_type, normalized_parameter)` -- groups same vuln on same param across URLs

**No additional dedup needed for wolf findings.** If the wolf finds the same `(url, parameter, payload)` as a specialist, `_deduplicate_exact()` will remove the duplicate. If the wolf finds the same vuln type on the same parameter as a specialist (but different URL), `_deduplicate_findings()` will merge them with `affected_urls`.

The wolf just needs to write standard findings to `specialists/results/lone_wolf_results.json` and the existing dedup handles the rest.

### 7. Config Pattern (HIGH Confidence)

**Source:** `bugtrace/core/config.py`

Config uses Pydantic Settings with `bugtraceaicli.conf` overrides. Pattern:

```python
# In config.py Settings class:
LONEWOLF_ENABLED: bool = True
LONEWOLF_MODEL: str = "deepseek/deepseek-r1"
LONEWOLF_RATE_LIMIT: float = 1.0  # req/s
LONEWOLF_MAX_CONTEXT: int = 20    # sliding window size
LONEWOLF_RESPONSE_TRUNCATE: int = 2000  # chars

# In bugtraceaicli.conf:
[LONEWOLF]
ENABLED = True
MODEL = deepseek/deepseek-r1
RATE_LIMIT = 1.0

# In load_from_conf(), add:
def _load_lonewolf_config(self, config):
    if "LONEWOLF" not in config:
        return
    section = config["LONEWOLF"]
    if "ENABLED" in section:
        self.LONEWOLF_ENABLED = section.getboolean("ENABLED")
    if "MODEL" in section:
        self.LONEWOLF_MODEL = section["MODEL"]
    if "RATE_LIMIT" in section:
        self.LONEWOLF_RATE_LIMIT = section.getfloat("RATE_LIMIT")
```

### 8. Rate Limiter Pattern (HIGH Confidence)

**Source:** `bugtrace/tools/manipulator/global_rate_limiter.py`

The existing GlobalRateLimiter is a singleton (shared across all ManipulatorOrchestrator instances). The LoneWolf should NOT use this -- it should have its own independent rate limiter.

The pattern is simple enough to inline:
```python
class WolfRateLimiter:
    def __init__(self, requests_per_second: float = 1.0):
        self.min_interval = 1.0 / requests_per_second
        self.last_request_time = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self):
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_request_time
            if elapsed < self.min_interval:
                await asyncio.sleep(self.min_interval - elapsed)
            self.last_request_time = time.monotonic()
```

At ~1 req/s, over a 1-hour scan, the wolf makes ~3600 requests. This is negligible compared to the pipeline's thousands.

### 9. Error Handling Pattern (HIGH Confidence)

**Source:** `bugtrace/core/team.py` lines 261, 2275, 2319-2324

The codebase uses `asyncio.gather(*tasks, return_exceptions=True)` pattern to prevent one failing task from killing others. For the wolf:

```python
# In team.py, wrap the wolf task:
wolf_task = asyncio.create_task(self._run_lone_wolf(wolf_stop_event))

# ... later, in a try/except:
try:
    wolf_stop_event.set()
    wolf_findings = await asyncio.wait_for(wolf_task, timeout=30.0)
except asyncio.TimeoutError:
    logger.warning("[LoneWolf] Did not stop within timeout, cancelling")
    wolf_task.cancel()
    wolf_findings = []
except Exception as e:
    logger.error(f"[LoneWolf] Crashed: {e}", exc_info=True)
    wolf_findings = []
```

The wolf itself should never raise -- wrap the entire `run()` in try/except:
```python
async def run(self) -> List[Dict]:
    try:
        return await self._exploration_loop()
    except asyncio.CancelledError:
        logger.info("[LoneWolf] Cancelled by pipeline")
        return self.findings  # Return what we found so far
    except Exception as e:
        logger.error(f"[LoneWolf] Fatal error: {e}", exc_info=True)
        return self.findings  # Return what we found so far
```

### 10. HTTP Session for Target (HIGH Confidence)

**Source:** `bugtrace/core/http_orchestrator.py` lines 1-40

The codebase has an `HTTPClientOrchestrator` with destination-based isolation (LLM, TARGET, SERVICE, PROBE). However, the wolf should create its own simple aiohttp session to remain fully decoupled:

```python
async def _create_session(self) -> aiohttp.ClientSession:
    timeout = aiohttp.ClientTimeout(total=15, connect=5)
    return aiohttp.ClientSession(
        timeout=timeout,
        headers={"User-Agent": settings.USER_AGENT},
        connector=aiohttp.TCPConnector(
            limit=5,           # Max concurrent connections
            ssl=False,         # Configurable
            enable_cleanup_closed=True
        )
    )
```

The wolf must close its session on cleanup:
```python
async def run(self) -> List[Dict]:
    self.session = await self._create_session()
    try:
        return await self._exploration_loop()
    finally:
        await self.session.close()
```

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| LLM API calls | Custom HTTP to OpenRouter | `llm_client.generate(model_override=...)` | Circuit breaker, retry, model shifting, token tracking all built-in |
| Finding deduplication | Custom dedup in wolf | Write to `specialists/results/` | `ReportingAgent._deduplicate_exact()` already handles it |
| LLM response parsing | Custom JSON extraction | `llm_client.validate_json_response()` | Handles markdown-wrapped JSON, schema validation |
| Config management | Custom env parsing | `settings.LONEWOLF_*` fields | Pydantic validation, .conf override, type safety |
| Token cost tracking | Custom counter | `llm_client.token_tracker` | Automatic when using `generate()` with `module_name="LoneWolf"` |

**Key insight:** The wolf's autonomy is in its exploration logic and LLM prompts. Everything else (LLM calls, HTTP error handling, finding format, dedup, reporting) should use existing infrastructure.

## Common Pitfalls

### Pitfall 1: Wolf Blocks Pipeline Shutdown
**What goes wrong:** If the wolf's exploration loop doesn't check `stop_event` frequently, the pipeline hangs waiting for the wolf to finish.
**Why it happens:** LLM calls take 5-30 seconds. If stop is signaled during an LLM call, the wolf won't notice until the call returns.
**How to avoid:** Check `stop_event.is_set()` after every LLM call and every HTTP request. Use `asyncio.wait_for()` with timeout when collecting wolf results.
**Warning signs:** Pipeline Phase 6 takes longer than expected.

### Pitfall 2: Wolf Crashes Kills Pipeline
**What goes wrong:** An unhandled exception in the wolf task propagates and kills the scan.
**Why it happens:** `asyncio.create_task()` exceptions propagate when the task is awaited.
**How to avoid:** Wrap the entire wolf in try/except that returns partial findings. Use `return_exceptions=True` if gathering.
**Warning signs:** Scan crashes during Phase 2-5 with wolf-related stack trace.

### Pitfall 3: LLM Context Overflow
**What goes wrong:** Wolf sends increasingly large prompts as context grows, hitting token limits or causing slow/expensive responses.
**Why it happens:** Accumulating action history without truncation.
**How to avoid:** Sliding window of last ~20 actions. Truncate HTTP responses to ~2000 chars. Set `max_tokens=2000` on generate calls.
**Warning signs:** LLM calls getting progressively slower or returning errors.

### Pitfall 4: Wolf Findings Without Evidence
**What goes wrong:** Wolf reports vulnerabilities based on LLM reasoning alone, without actual HTTP evidence.
**Why it happens:** The LLM might "think" it found something but the actual HTTP response doesn't confirm it.
**How to avoid:** Only add to findings when there is concrete HTTP evidence (payload reflected, error message, status code change). The wolf should validate its own discoveries with a follow-up request before reporting.
**Warning signs:** Wolf findings are all false positives.

### Pitfall 5: DeepSeek R1 Model ID Wrong
**What goes wrong:** Wolf fails to make LLM calls because the model ID is incorrect.
**Why it happens:** OpenRouter model IDs change. The R1 model might be `deepseek/deepseek-r1` or `deepseek/deepseek-reasoner` or another variant.
**How to avoid:** Make the model configurable via `settings.LONEWOLF_MODEL`. Verify the model ID works in the connectivity check or fallback to PRIMARY_MODELS.
**Warning signs:** All wolf LLM calls return None.

### Pitfall 6: Wolf Requests Interfere with Specialists
**What goes wrong:** Wolf sends requests to the same parameters that specialists are actively testing, causing WAF blocks or rate limits that affect both.
**Why it happens:** Wolf explores independently and may discover the same parameters.
**How to avoid:** Keep wolf rate at ~1 req/s (negligible vs specialist volume). The wolf is exploring broadly, not hammering a single parameter.
**Warning signs:** Increased 429 or WAF blocks during exploitation phase.

### Pitfall 7: Session Leak
**What goes wrong:** If the wolf crashes or is cancelled, the aiohttp session is never closed, leaking connections.
**Why it happens:** Missing `finally` block on session cleanup.
**How to avoid:** Always use `try/finally` to close the session, even on CancelledError.
**Warning signs:** Resource warnings about unclosed sessions in logs.

## Code Examples

### Complete LoneWolf Skeleton

```python
# bugtrace/agents/lone_wolf.py
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

SYSTEM_PROMPT = """You are an autonomous penetration tester exploring a web application.
You can: fetch pages, analyze responses, test parameters, follow links.
Your goal: find security vulnerabilities by exploring creatively.

Output your next action as JSON:
{"action": "fetch", "url": "...", "method": "GET", "params": {...}}
or
{"action": "test", "url": "...", "parameter": "...", "payload": "..."}
or
{"action": "analyze", "url": "...", "focus": "..."}
or
{"action": "done", "reason": "..."}

After each action result, reason about what you learned and what to try next.
"""


class LoneWolf:
    def __init__(self, target_url: str, scan_dir: Path, stop_event: asyncio.Event):
        self.target_url = target_url
        self.scan_dir = scan_dir
        self.stop_event = stop_event
        self.findings: List[Dict] = []
        self.context: List[Dict] = []  # Sliding window
        self.session: Optional[aiohttp.ClientSession] = None
        self.max_context = getattr(settings, 'LONEWOLF_MAX_CONTEXT', 20)
        self.model = getattr(settings, 'LONEWOLF_MODEL', 'deepseek/deepseek-r1')
        self.rate_limit = getattr(settings, 'LONEWOLF_RATE_LIMIT', 1.0)
        self._last_request = 0.0

    async def run(self) -> List[Dict]:
        """Main entry point. Returns list of findings."""
        logger.info(f"[LoneWolf] Starting autonomous exploration of {self.target_url}")
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=15, connect=5),
            headers={"User-Agent": settings.USER_AGENT},
        )
        try:
            return await self._exploration_loop()
        except asyncio.CancelledError:
            logger.info("[LoneWolf] Cancelled by pipeline")
            return self.findings
        except Exception as e:
            logger.error(f"[LoneWolf] Fatal error: {e}", exc_info=True)
            return self.findings
        finally:
            await self.session.close()
            self._save_results()

    async def _exploration_loop(self) -> List[Dict]:
        """Core exploration loop."""
        # Initial fetch
        initial_response = await self._fetch(self.target_url)
        self._add_context("fetch", self.target_url, initial_response)

        while not self.stop_event.is_set():
            # Ask LLM what to do next
            action = await self._think()
            if not action or action.get("action") == "done":
                break

            # Execute the action
            result = await self._execute(action)
            self._add_context(action.get("action", "unknown"), str(action), result)

            # Rate limit
            await self._rate_limit_wait()

        logger.info(f"[LoneWolf] Finished with {len(self.findings)} findings")
        return self.findings

    async def _think(self) -> Optional[Dict]:
        """Ask LLM to decide next action."""
        if self.stop_event.is_set():
            return None

        prompt = self._build_prompt()
        response = await llm_client.generate(
            prompt=prompt,
            module_name="LoneWolf",
            model_override=self.model,
            system_prompt=SYSTEM_PROMPT,
            temperature=0.7,
            max_tokens=2000
        )
        if not response:
            return None

        return llm_client.validate_json_response(response)

    async def _fetch(self, url: str, method: str = "GET", **kwargs) -> str:
        """Fetch a URL with rate limiting."""
        await self._rate_limit_wait()
        try:
            async with self.session.request(method, url, **kwargs) as resp:
                text = await resp.text()
                return text[:2000]  # Truncate
        except Exception as e:
            return f"ERROR: {e}"

    async def _execute(self, action: Dict) -> str:
        """Execute an LLM-decided action."""
        action_type = action.get("action", "")
        if action_type == "fetch":
            return await self._fetch(
                action.get("url", self.target_url),
                action.get("method", "GET"),
                params=action.get("params")
            )
        elif action_type == "test":
            return await self._test_payload(action)
        elif action_type == "analyze":
            return await self._fetch(action.get("url", self.target_url))
        return "Unknown action"

    async def _test_payload(self, action: Dict) -> str:
        """Test a payload and check if it's reflected/executed."""
        url = action.get("url", self.target_url)
        param = action.get("parameter", "")
        payload = action.get("payload", "")
        response = await self._fetch(url, params={param: payload})

        if payload in response:
            # Potential finding - record it
            self.findings.append({
                "type": action.get("vuln_type", "Unknown"),
                "url": url,
                "parameter": param,
                "payload": payload,
                "evidence": response[:500],
                "severity": action.get("severity", "MEDIUM"),
                "status": "VALIDATED_CONFIRMED",
                "source": "lone_wolf",
                "description": f"LoneWolf autonomous discovery: {param} reflects payload"
            })
            return f"REFLECTED! Payload found in response."
        return f"Not reflected. Response length: {len(response)}"

    def _add_context(self, action: str, detail: str, result: str):
        """Add to sliding window context."""
        self.context.append({
            "action": action,
            "detail": detail[:200],
            "result": result[:500],
            "timestamp": time.time()
        })
        # Trim to sliding window
        if len(self.context) > self.max_context:
            self.context = self.context[-self.max_context:]

    def _build_prompt(self) -> str:
        """Build prompt with sliding window context."""
        context_str = "\n".join(
            f"[{i+1}] {c['action']}: {c['detail']}\n    Result: {c['result']}"
            for i, c in enumerate(self.context[-self.max_context:])
        )
        return f"""Target: {self.target_url}
Findings so far: {len(self.findings)}

## Recent Actions:
{context_str}

What should I do next? Output a JSON action."""

    async def _rate_limit_wait(self):
        """Simple rate limiter."""
        min_interval = 1.0 / self.rate_limit
        elapsed = time.monotonic() - self._last_request
        if elapsed < min_interval:
            await asyncio.sleep(min_interval - elapsed)
        self._last_request = time.monotonic()

    def _save_results(self):
        """Save findings to specialists/results/ for ReportingAgent."""
        results_dir = self.scan_dir / "specialists" / "results"
        results_dir.mkdir(parents=True, exist_ok=True)
        output_path = results_dir / "lone_wolf_results.json"

        data = {
            "specialist": "lone_wolf",
            "findings": self.findings
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

        logger.info(f"[LoneWolf] Saved {len(self.findings)} findings to {output_path}")
```

### Integration in team.py (~10 lines)

```python
# In _run_sequential_pipeline(), after Phase 1 reconnaissance:

# Launch LoneWolf (runs in background during Phases 2-5)
wolf_task = None
wolf_stop = None
if getattr(settings, 'LONEWOLF_ENABLED', False):
    wolf_stop = asyncio.Event()
    from bugtrace.agents.lone_wolf import LoneWolf
    wolf = LoneWolf(self.target, self.scan_dir, wolf_stop)
    wolf_task = asyncio.create_task(wolf.run())
    logger.info("[Pipeline] LoneWolf launched in background")

# ... Phases 2-5 run normally ...

# After Phase 5 VALIDATION, before Phase 6 REPORTING:
if wolf_task and wolf_stop:
    wolf_stop.set()
    try:
        wolf_findings = await asyncio.wait_for(wolf_task, timeout=30.0)
        logger.info(f"[Pipeline] LoneWolf returned {len(wolf_findings)} findings")
    except (asyncio.TimeoutError, Exception) as e:
        logger.warning(f"[Pipeline] LoneWolf collection failed: {e}")
        wolf_task.cancel()
```

### Config in bugtraceaicli.conf

```ini
[LONEWOLF]
# Enable/disable the autonomous exploration agent
ENABLED = True
# OpenRouter model for reasoning (DeepSeek R1 for chain-of-thought)
MODEL = deepseek/deepseek-r1
# HTTP request rate limit (requests per second)
RATE_LIMIT = 1.0
# Sliding window size for context
MAX_CONTEXT = 20
# Max characters to keep from HTTP responses
RESPONSE_TRUNCATE = 2000
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Specialists only | Specialists + autonomous agent | This feature | Catches vulns that pipeline's structured approach misses |
| Sequential exploration | LLM-driven creative exploration | This feature | Agent discovers paths/params the pipeline never tests |

## Open Questions

1. **DeepSeek R1 Model ID on OpenRouter**
   - What we know: The config shows `deepseek/deepseek-chat` and `deepseek/deepseek-v3.2` as existing models
   - What's unclear: The exact OpenRouter model ID for DeepSeek R1 (could be `deepseek/deepseek-r1`, `deepseek/deepseek-reasoner`, etc.)
   - Recommendation: Make configurable via `settings.LONEWOLF_MODEL`, default to `deepseek/deepseek-r1`, fallback through model shifting if invalid

2. **Prompt Engineering for Autonomous Exploration**
   - What we know: The system prompt and action format need careful design
   - What's unclear: Exactly how much structure to give the LLM vs. letting it explore freely
   - Recommendation: Start with structured JSON actions (fetch, test, analyze, done), iterate based on results

3. **Finding Confidence Threshold**
   - What we know: Wolf findings should be marked `VALIDATED_CONFIRMED` to appear in reports
   - What's unclear: Whether wolf findings should have a lower confidence or go through additional validation
   - Recommendation: Start with wolf findings in report but tagged with `source: "lone_wolf"` so triagers can distinguish them. The wolf should only report findings with actual HTTP evidence (payload reflected in response).

4. **Context Between Wolf and Pipeline**
   - What we know: The wolf and pipeline are fully decoupled by design
   - What's unclear: Whether the wolf should receive any signal about what the pipeline found (to avoid duplicate exploration)
   - Recommendation: Keep decoupled for V1. The wolf's value is in exploring different paths than the pipeline.

## Sources

### Primary (HIGH confidence)
All findings from direct codebase analysis:
- `bugtrace/core/llm_client.py` -- LLMClient interface, generate() signature, model_override behavior
- `bugtrace/core/team.py` -- Pipeline lifecycle, phase boundaries, error handling patterns
- `bugtrace/agents/reporting.py` -- Finding format, dedup logic, results file loading
- `bugtrace/core/state_manager.py` -- Normalized finding schema, file-based storage
- `bugtrace/core/config.py` -- Settings pattern, .conf loading
- `bugtrace/tools/manipulator/global_rate_limiter.py` -- Rate limiter pattern
- `bugtrace/core/event_bus.py` -- Event system (not needed for wolf V1)
- `bugtrace/core/conversation_thread.py` -- Multi-turn context (available but not recommended for wolf)
- `bugtrace/core/http_orchestrator.py` -- HTTP client architecture (wolf uses own session)
- `requirements.txt` -- aiohttp >=3.9.0,<4.0

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH -- all libraries already in project
- Architecture/Integration: HIGH -- exact line numbers and method signatures from codebase
- Finding format: HIGH -- normalized schema from state_manager.py matches reporting expectations
- Pipeline lifecycle: HIGH -- exact phase boundaries identified with line numbers
- Pitfalls: HIGH -- derived from actual codebase patterns and async programming fundamentals

**Research date:** 2026-02-09
**Valid until:** 2026-03-09 (codebase is actively developed, integration points may shift)
