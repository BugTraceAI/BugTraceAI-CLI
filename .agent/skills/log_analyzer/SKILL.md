---
name: log_analyzer
description: Expert debugging helper that knows how to parse BugTraceAI logs (`bugtrace.log`) to identify root causes of failures. Use this when a scan fails or behaves unexpectedly.
---

# Log Analyzer Skill

This skill provides the knowledge to interpret the specific logging format of BugTraceAI.

## 1. Log Location

- Primary Log: `logs/bugtrace.log`
- Rotation: `logs/bugtrace.log.1`, etc.

## 2. Key Error Patterns to Look For

### A. "Reactor Stalled"

- *Symptom*: Scan hangs at 0% or specific %, no new events.
- *Trace*: `WorkerPool exhausted` or `Queue full`.
- *Fix*: Check `CONCURRENCY` setting or infinite loops in an Agent.

### B. "Browser Validation Failed"

- *Symptom*: Findings stay "PENDING" forever.
- *Trace*: `Playwright Error: Target closed` or `Timeout`.
- *Fix*: Check if `chromium` is installed or if the site blocks headless mode (`--safe-mode`).

### C. "Vision API Error"

- *Symptom*: "Error calling Gemini/Vertex".
- *Trace*: `401 Unauthorized` or `429 Too Many Requests`.
- *Fix*: Check `.env` keys.

## 3. Analysis Workflow

1. **Locate Error**:

   ```bash
   grep -C 5 "ERROR" logs/bugtrace.log | tail -n 20
   ```

2. **Find Context**:
   Look for the `[ScanID: ...]` tag to isolate the specific run.
3. **Trace Execution**:
   If an agent failed, grep for its thread name (e.g., `[XSSAgent-1]`).

## 4. Instructions for the Agent

- If the user says "Scan failed", AUTOMATICALLY run the grep command above.
- Do NOT ask the user to paste logs if you can read them.
- Summarize the error in plain English before proposing a code fix.
