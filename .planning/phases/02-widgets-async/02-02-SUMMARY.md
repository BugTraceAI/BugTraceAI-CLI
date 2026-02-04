# Phase 02 Plan 02: Async Engine Wiring Summary

## Frontmatter

```yaml
phase: 02
plan: 02
subsystem: tui-backend
tags: [textual, async, messages, workers, conductor]

dependency-graph:
  requires: [01-01]
  provides: [tui-pipeline-bridge, message-system, ui-callback]
  affects: [02-01, 03-01]

tech-stack:
  added: []
  patterns: [message-driven-ui, callback-injection, worker-threads]

key-files:
  created:
    - bugtrace/core/ui/tui/messages.py
    - bugtrace/core/ui/tui/workers.py
  modified:
    - bugtrace/core/ui/tui/app.py
    - bugtrace/core/conductor.py
    - bugtrace/__main__.py

decisions:
  - id: msg-types
    choice: 7 distinct message types
    rationale: Clear separation of concerns for each event type
  - id: callback-injection
    choice: Optional ui_callback in Conductor
    rationale: Backward compatible with legacy dashboard
  - id: worker-thread
    choice: thread=True for @work decorator
    rationale: Pipeline has blocking I/O operations

metrics:
  duration: 5m
  completed: 2026-02-05
```

## One-Liner

Event-driven messaging bridge between scanning pipeline and Textual TUI using UICallback, 7 message types, and @work threaded scan execution.

## What Was Done

### Task 1: Define Message Types (messages.py)
Created 7 Textual Message classes for pipeline-to-UI communication:
- `AgentUpdate`: Agent status changes (name, status, queue, processed, vulns)
- `PipelineProgress`: Phase/progress updates (phase, progress, status_msg)
- `NewFinding`: Vulnerability discoveries (type, details, severity, param, payload)
- `PayloadTested`: Payload test results (payload, result, agent)
- `LogEntry`: Log routing (level, message)
- `MetricsUpdate`: System metrics (cpu, ram, req_rate, urls_discovered/analyzed)
- `ScanComplete`: Scan completion (total_findings, duration)

### Task 2: Create UICallback and TUILoggingHandler (workers.py)
- `UICallback`: Bridge class that translates pipeline events to Textual messages
  - on_phase_change(), on_agent_update(), on_finding()
  - on_payload_tested(), on_log(), on_metrics(), on_complete()
- `TUILoggingHandler`: Python logging.Handler that routes logs to TUI

### Task 3: Patch Conductor for Callback Injection
Modified `ConductorV2` in conductor.py:
- Added optional `ui_callback` parameter to `__init__()`
- Added `set_ui_callback()` for dynamic registration
- Added notify_* methods: phase_change, agent_update, finding, log, metrics, complete
- Each notify method falls back to legacy dashboard if no callback set

### Task 4-5: Add @work Scan Method and Message Handlers
Enhanced `BugTraceApp` in app.py:
- Added `target` parameter to constructor
- Added `run_scan()` with `@work(thread=True, exclusive=True)`
- Implemented all 7 message handlers (on_agent_update, etc.)
- Added `action_start_scan()` binding (key 's')
- Track `scan_worker` reference for cancellation

### Task 6: TUI Logging Integration
- `TUILoggingHandler` installed on mount, removed on unmount
- Routes Python logging to TUI via LogEntry messages
- Configurable log level (default: INFO)

### Task 7: CLI Target Argument
Updated `bugtrace/__main__.py`:
- TUI command now accepts optional target URL argument
- Auto-starts scan if target provided
- Updated help text with examples

### Task 8: Graceful Shutdown
- `action_quit()` cancels running scan with notification
- `on_unmount()` cleans up worker and logging handler
- Small delay before exit to allow cancellation to propagate

## Deviations from Plan

None - plan executed exactly as written.

## Testing Notes

All verification criteria passed:
- messages.py defines all 7 message types
- workers.py has UICallback and TUILoggingHandler classes
- Conductor accepts ui_callback parameter with backward compatibility
- @work decorator runs scan in background thread
- Message handlers implemented (widget integration in Plan 02-01)
- Logging integrates with TUI via TUILoggingHandler
- CTRL+C (q) stops scan and exits cleanly

## Commits

| Hash | Message |
|------|---------|
| 3702335 | feat(02-02): add Textual message types for TUI |
| d56c0ca | feat(02-02): add UICallback and TUILoggingHandler |
| 4af7185 | feat(02-02): add UI callback injection to Conductor |
| 48c2cdc | feat(02-02): add @work scan method and message handlers to App |
| 43ea70e | feat(02-02): add target argument to TUI command |
| b74e3f3 | feat(02-02): implement graceful shutdown for TUI |

## Next Phase Readiness

Ready for Phase 03 (High-Fidelity Interaction):
1. **Notification system**: `self.notify()` works for finding alerts
2. **Widget queries**: All widgets accessible via `query_one("#id")` (when Plan 02-01 completes)
3. **Worker state**: Can check if scan is running via `is_scan_running` property
4. **Clean cancellation**: Worker can be cancelled mid-scan via action_quit

## Architecture

```
Pipeline (TeamOrchestrator)
    |
    v
Conductor.notify_*()
    |
    v
UICallback.on_*()
    |
    v
App.post_message(Message)
    |
    v
App.on_*_message() handlers
    |
    v
Widget updates (Plan 02-01)
```
