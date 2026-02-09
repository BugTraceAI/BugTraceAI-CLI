# Project State

## Current Status

**Milestone:** v5.0 - Textual TUI Migration
**Phase:** 04 - Gap Closure (EventBus → TUI)
**Status:** Pending Planning

## Phase Progress

| Phase | Name | Status | Plans |
|-------|------|--------|-------|
| 01 | Foundation & Structure | **Complete** | 1/1 |
| 02 | Widget Migration & Async Engine | **Complete** | 3/3 |
| 03 | High-Fidelity Interaction | **Complete** | 3/3 |
| 04 | Gap Closure (EventBus → TUI) | Pending | 0/? |

**Progress:** [==========░░] 87% (7/8+ plans complete)

## Last Completed Plan

**Plan:** 03-03 (Integration & Polish)
**What:** Integrated FindingsTable, LogInspector, CommandInput into MainScreen with row-to-modal navigation, ChatOps commands, and keyboard shortcuts
**Commits:** 296a3a7, 33db40d, 5d3c0c5, 5d6c689, ddcbe01, d801efd, 9befb4b
**Summary:** `.planning/phases/03-interactions/03-03-SUMMARY.md`

## Decisions Made

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-02-04 | Chose Textual over alternatives (blessed, urwid) | OpenCode-like UX |
| 2026-02-04 | Architecture: Decouple rendering from logic | Event-driven model |
| 2026-02-04 | Phase 2 split into parallel tracks | Widgets (frontend) + Async (backend) |
| 2026-02-04 | Used Textual's built-in Header/Footer | Phase 1, custom widgets in Phase 2 |
| 2026-02-04 | Renamed ui.py to ui_legacy.py | Proxy __init__.py for backward compatibility |
| 2026-02-04 | LoaderScreen auto-transitions | 2s delay with spinner animation |
| 2026-02-05 | 7 distinct message types | Pipeline-UI communication |
| 2026-02-05 | Optional ui_callback in Conductor | Backward compatibility with legacy dashboard |
| 2026-02-05 | thread=True for @work decorator | Pipeline has blocking I/O |
| 2026-02-05 | SparklineBuffer utility | Shared between ActivityGraph and SystemMetrics |
| 2026-02-05 | Each widget has demo_mode | reactive attribute for visual testing |
| 2026-02-05 | Wrap query_one() in try/except | Graceful degradation when widgets not mounted |
| 2026-02-05 | DataTable extension for FindingsTable | O(1) lookup via row key |
| 2026-02-05 | Inline CSS for modal | Self-contained component |
| 2026-02-05 | Optional pyperclip for clipboard | Graceful degradation |
| 2026-02-05 | LogInspector stores up to 2000 logs | Prevents OOM while allowing history |
| 2026-02-05 | 8 ChatOps commands in COMMANDS dict | /stop, /pause, /resume, /help, /filter, /show, /clear, /export |
| 2026-02-05 | Keep legacy widgets hidden but mounted | Backward compatibility |
| 2026-02-05 | Dual-path message handlers | Update both legacy and new widgets |
| 2026-02-05 | Keyboard shortcuts: f, l, :, ?, q | vim-like muscle memory |

## Patterns Established

- **compose() pattern:** All screens yield widgets via compose() generator
- **CSS Grid layout:** 3-row structure (header 3, content 1fr, footer 1)
- **Screen transitions:** push_screen() for stacking, switch_screen() for replacement
- **Message-driven UI:** Pipeline posts messages, App handles them to update widgets
- **Callback injection:** UICallback bridges pipeline to Textual messages
- **Worker threads:** @work(thread=True) for blocking operations
- **Reactive widgets:** All widget data exposed via reactive() for auto-refresh
- **Demo mode:** --demo flag enables animated mock data for testing
- **Query-one pattern:** try query_one("#id", WidgetClass) + call method, except pass
- **ModalScreen pattern:** Escape binding + dismiss action for modals
- **TYPE_CHECKING guard:** For circular import avoidance in modals
- **Filter pattern:** Store all data, re-render on filter change
- **History pattern:** List with index navigation, max entries limit
- **ChatOps pattern:** Parse command + args, dispatch to handler methods
- **Focus actions:** action_focus_* pattern with try/except
- **Dual-path handlers:** Update both legacy and new widgets

## Context

**Legacy file:** `bugtrace/core/ui_legacy.py` (1,673 lines, renamed from ui.py)
- Rich-based dashboard with threading
- SparklineBuffer, Dashboard class
- Multi-page UI (main, findings, logs, stats, agents, queues, config)

**New TUI:** `bugtrace/core/ui/tui/` (Phase 3 COMPLETE)
- CSS grid layout with Textual
- BugTraceApp with loader/main screens
- 9 custom widgets: Pipeline, Activity, Metrics, Swarm, PayloadFeed, Findings, LogPanel, LogInspector, CommandInput
- **FindingsTable:** Interactive DataTable for vulnerability browsing
- **FindingDetailsModal:** Full details with payload/request/response
- **LogInspector:** Filterable log viewer with RichLog
- **CommandInput:** ChatOps command bar with history
- Message types: AgentUpdate, PipelineProgress, NewFinding, etc.
- UICallback bridges pipeline to TUI
- CLI entry point: `bugtrace tui [target] [--demo]`
- Keyboard shortcuts: f (findings), l (logs), : (command), ? (help), q (quit)
- ChatOps commands: /stop, /help, /filter, /show, /clear, /export

## Known Issues

**CLI Option Parsing (Pre-existing)**
The `--demo` flag and all subcommand options fail due to `allow_interspersed_args=True` in CONTEXT_SETTINGS. This affects all CLI subcommand options, not just TUI. Requires architectural fix.

## Quick Tasks

| ID | Name | Status | Summary |
|----|------|--------|---------|
| 001 | LoneWolf Autonomous Agent | **Complete** | `.planning/quick/001-lonewolf-autonomous-agent/001-SUMMARY.md` |

## Session Continuity

**Last session:** 2026-02-09 10:55 UTC
**Stopped at:** Completed quick task 001 (LoneWolf Autonomous Agent)
**Resume file:** None

## Next Action

Phase 04 (Gap Closure) added after milestone audit found critical integration gap.

**Critical Gap:** EventBus VULNERABILITY_DETECTED events not routed to TUI.
- Specialists emit findings via `self.emit_finding()`
- ReportingAgent collects them
- **TUI never receives them** - conductor.notify_finding() is never called
- Result: FindingsTable stays empty during real scans

**Next:** `/gsd:plan-phase 04` to create execution plan

## Plan Summary

**Phase 01:** 1 plan (foundation, CSS, app skeleton) - **COMPLETE**
**Phase 02:** 3 plans (widgets + async + gap closure) - **COMPLETE**
**Phase 03:** 3 plans (interactions, modals, commands) - **COMPLETE**
  - 03-01: FindingsTable + Modal - **COMPLETE**
  - 03-02: LogInspector + CommandInput - **COMPLETE**
  - 03-03: Integration & Polish - **COMPLETE**
**Phase 04:** Gap Closure (EventBus → TUI) - **PENDING**
  - Context: `.planning/phases/04-gap-closure/04-CONTEXT.md`

## Completed Summaries

- `.planning/phases/01-foundation/01-01-SUMMARY.md` - TUI Foundation & Structure
- `.planning/phases/02-widgets-async/02-01-SUMMARY.md` - Widget Migration (Frontend)
- `.planning/phases/02-widgets-async/02-02-SUMMARY.md` - Async Engine Wiring
- `.planning/phases/02-widgets-async/02-03-SUMMARY.md` - Gap Closure (Message Handler Wiring)
- `.planning/phases/03-interactions/03-01-SUMMARY.md` - FindingsTable + Modal
- `.planning/phases/03-interactions/03-02-SUMMARY.md` - LogInspector + CommandInput
- `.planning/phases/03-interactions/03-03-SUMMARY.md` - Integration & Polish
