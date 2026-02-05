# Project State

## Current Status

**Milestone:** v5.0 - Textual TUI Migration
**Phase:** 02 - Widget Migration & Async Engine
**Status:** Gap Closure Pending

## Phase Progress

| Phase | Name | Status | Plans |
|-------|------|--------|-------|
| 01 | Foundation & Structure | **Complete** | 1/1 |
| 02 | Widget Migration & Async Engine | **Gap Closure** | 2/3 |
| 03 | High-Fidelity Interaction | Ready | 0/1 |

**Progress:** [========....] 67% (2/3 plans complete, 1 gap closure pending)

## Gap Closure Required

**Gap identified by:** 02-VERIFICATION.md (2026-02-05)
**Root cause:** Message handlers in app.py were implemented as stubs that only log, but do not call widget methods.

**What's missing:**
- `on_agent_update()` must call `swarm.update_agent()`
- `on_pipeline_progress()` must set `pipeline.phase`, `pipeline.progress`
- `on_new_finding()` must call `findings.add_finding()`
- `on_payload_tested()` must call `feed.add_payload()`
- `on_log_entry()` must call `logs.log()`
- `on_metrics_update()` must set `metrics.cpu_usage`, `metrics.ram_usage`

**Plan created:** 02-03-PLAN.md (gap_closure: true)

## Decisions Made

- **2026-02-04:** Chose Textual over alternatives (blessed, urwid) for OpenCode-like UX
- **2026-02-04:** Architecture: Decouple rendering from logic via event-driven model
- **2026-02-04:** Phase 2 split into parallel tracks: Widgets (frontend) + Async (backend)
- **2026-02-04:** Used Textual's built-in Header/Footer for Phase 1, custom widgets in Phase 2
- **2026-02-04:** Renamed ui.py to ui_legacy.py with proxy __init__.py for backward compatibility
- **2026-02-04:** LoaderScreen auto-transitions after 2s delay with spinner animation
- **2026-02-05:** 7 distinct message types for pipeline-UI communication
- **2026-02-05:** Optional ui_callback in Conductor for backward compatibility with legacy dashboard
- **2026-02-05:** thread=True for @work decorator (pipeline has blocking I/O)
- **2026-02-05:** SparklineBuffer utility shared between ActivityGraph and SystemMetrics widgets
- **2026-02-05:** Each widget has demo_mode reactive attribute for visual testing

## Patterns Established

- **compose() pattern:** All screens yield widgets via compose() generator
- **CSS Grid layout:** 3-row structure (header 3, content 1fr, footer 1)
- **Screen transitions:** push_screen() for stacking, switch_screen() for replacement
- **Message-driven UI:** Pipeline posts messages, App handles them to update widgets
- **Callback injection:** UICallback bridges pipeline to Textual messages
- **Worker threads:** @work(thread=True) for blocking operations
- **Reactive widgets:** All widget data exposed via reactive() for auto-refresh
- **Demo mode:** --demo flag enables animated mock data for testing

## Context

**Legacy file:** `bugtrace/core/ui_legacy.py` (1,673 lines, renamed from ui.py)
- Rich-based dashboard with threading
- SparklineBuffer, Dashboard class
- Multi-page UI (main, findings, logs, stats, agents, queues, config)

**New TUI:** `bugtrace/core/ui/tui/` (Phase 2 in gap closure)
- CSS grid layout with Textual
- BugTraceApp with loader/main screens
- 7 custom widgets: Pipeline, Activity, Metrics, Swarm, PayloadFeed, Findings, LogPanel
- Message types: AgentUpdate, PipelineProgress, NewFinding, etc.
- UICallback bridges pipeline to TUI
- CLI entry point: `bugtrace tui [target] [--demo]`

## Known Issues

**CLI Option Parsing (Pre-existing)**
The `--demo` flag and all subcommand options fail due to `allow_interspersed_args=True` in CONTEXT_SETTINGS. This affects all CLI subcommand options, not just TUI. Requires architectural fix.

## Session Continuity

**Last session:** 2026-02-05 01:00 UTC
**Stopped at:** Verification found gaps, created 02-03-PLAN.md
**Resume file:** None

## Next Action

Execute `/gsd:execute-phase 02` to run gap closure plan 02-03

## Plan Summary

**Phase 01:** 1 plan (foundation, CSS, app skeleton) - **COMPLETE**
**Phase 02:** 3 plans (widgets + async + gap closure) - **GAP CLOSURE PENDING**
  - 02-01: Widget Migration - **COMPLETE**
  - 02-02: Async Engine Wiring - **COMPLETE**
  - 02-03: Gap Closure (wire message handlers) - **PENDING**
**Phase 03:** 1 plan (interactions, modals, commands) - **READY**

## Completed Summaries

- `.planning/phases/01-foundation/01-01-SUMMARY.md` - TUI Foundation & Structure
- `.planning/phases/02-widgets-async/02-01-SUMMARY.md` - Widget Migration (Frontend)
- `.planning/phases/02-widgets-async/02-02-SUMMARY.md` - Async Engine Wiring
