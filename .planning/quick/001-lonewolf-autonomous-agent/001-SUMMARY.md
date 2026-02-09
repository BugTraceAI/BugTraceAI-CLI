---
phase: lonewolf
plan: 01
subsystem: agents
tags: [lonewolf, autonomous, llm-driven, exploration, parallel-agent]
dependency-graph:
  requires: []
  provides: [lone-wolf-agent, lonewolf-config, pipeline-integration]
  affects: [reporting, pipeline-flow]
tech-stack:
  added: []
  patterns: [fire-and-forget-asyncio-task, sliding-window-context, multi-method-confirmation]
key-files:
  created:
    - bugtrace/agents/lone_wolf.py
  modified:
    - bugtrace/core/config.py
    - bugtraceaicli.conf
    - bugtrace/core/team.py
decisions:
  - Fire-and-forget pattern: no stop event, no await, no collect. Wolf self-terminates.
  - Incremental save after each confirmed finding (not just at end).
  - Multi-method confirmation: reflection, encoded reflection, time-based, error-based.
  - DB write-only for progress (INSERT only, never SELECT).
metrics:
  duration: ~5 minutes
  completed: 2026-02-09
---

# Quick Task 001: LoneWolf Autonomous Agent Summary

Implemented LoneWolf autonomous exploration agent using raw HTTP + LLM reasoning (DeepSeek R1) that runs as a fire-and-forget background task during the scan pipeline.

## What Was Built

### bugtrace/agents/lone_wolf.py (663 lines)
- **LoneWolf class**: Autonomous agent with own aiohttp session, rate limiter, LLM-driven reasoning
- **System prompt**: Detailed pentester persona guiding LLM to explore all injection vectors (params, POST, JSON, cookies, headers, path segments)
- **Exploration loop**: think -> execute -> update context cycle with 3 stop conditions (max_cycles=500, LLM "done" action, 3 consecutive LLM failures)
- **_fetch()**: HTTP client with built-in retry (3 attempts, exponential backoff 1s/2s/4s), retries on timeout/connection error/429/503
- **_test_payload()**: Multi-method confirmation:
  - Literal reflection (payload in response)
  - HTML-encoded reflection (`&lt;script&gt;`)
  - URL-encoded reflection (`%3Cscript%3E`)
  - Backslash-escaped reflection (`\"` -> `\\"`)
  - Time-based SQLi (elapsed > 4.5s with sleep/WAITFOR indicators)
  - Error-based SQLi (SQL error signatures with SQL metacharacters)
- **_save_results()**: Incremental save after each confirmed finding to `specialists/results/lone_wolf_results.json`
- **Sliding window context**: Last N actions kept for LLM prompt (configurable via MAX_CONTEXT)
- **Header summary in responses**: LLM sees status code, timing, security headers for reasoning

### bugtrace/core/config.py
- 5 new LONEWOLF_* fields in Settings class:
  - `LONEWOLF_ENABLED: bool = False` (disabled by default)
  - `LONEWOLF_MODEL: str = "deepseek/deepseek-r1"`
  - `LONEWOLF_RATE_LIMIT: float = 1.0`
  - `LONEWOLF_MAX_CONTEXT: int = 20`
  - `LONEWOLF_RESPONSE_TRUNCATE: int = 2000`
- `_load_lonewolf_config()` method for .conf file overrides
- Called in `load_from_conf()` after `_load_authority_config()`

### bugtraceaicli.conf
- `[LONEWOLF]` section with all 5 settings fully documented
- Includes comments explaining each setting's purpose and trade-offs

### bugtrace/core/team.py
- 4-line fire-and-forget launch block in `_run_sequential_pipeline()`
- Located after Phase 1 RECONNAISSANCE, before Phase 2 DISCOVERY
- Conditional on `settings.LONEWOLF_ENABLED`
- Uses `asyncio.create_task(wolf.run())` -- no await, no stop, no collect

## Design Decisions

1. **Fire-and-forget**: Wolf is launched as an asyncio task and never awaited. Pipeline flow is identical whether wolf is enabled or not (except 4 lines of launch code). Wolf self-terminates via max_cycles, LLM "done", or 3 consecutive failures.

2. **Incremental saves**: Findings are written to disk after each confirmation, not just at the end. This ensures ReportingAgent picks up findings even if the wolf is still running when Phase 6 starts.

3. **Multi-method confirmation**: Not just `payload in response`. Also checks HTML/URL-encoded variants, time-based SQLi (elapsed > 4.5s), and error-based SQLi (SQL error signatures). Prevents both false negatives and hallucinated findings.

4. **Full injection vector support**: The LLM can test query params, POST form data, JSON body, cookies, custom headers, and path segments. The system prompt explicitly guides exploration of all vectors.

5. **No shared resources**: Own aiohttp session (TCPConnector limit=5, ssl=False), own rate limiter, no shared tools. Cannot interfere with pipeline.

## Deviations from Plan

None -- plan executed exactly as written.

## Commits

| Task | Commit | Description |
|------|--------|-------------|
| 1 | 093f357 | Config entries + lone_wolf.py agent |
| 2 | c305d37 | Pipeline integration in team.py |
