# Textual TUI Migration Roadmap

## Milestone: v5.0 - Textual TUI

**Objective:** Migrate BugTraceAI from Rich + threading dashboard to modern Textual TUI with OpenCode-like interactivity.

**Source:** `.ai-context/planning/TEXTUAL_MIGRATION_MASTER_PLAN.md`

---

## Phase 01: Foundation & Structure

**Goal:** Establish Textual app skeleton with CSS grid layout

**Deliverables:**
- Directory structure: `bugtrace/core/ui/tui/`
- Main app entry point (`app.py`)
- Global stylesheet (`styles.tcss`)
- Screen scaffolding (main, loader)
- Basic widgets (header, footer)

**Acceptance:**
- `bugtraceai --tui` launches full-screen app
- Header/Footer visible
- Terminal resize works
- CTRL+C exits cleanly

**Blocks:** Phase 02, Phase 03

**Plans:** 1 plan
- [x] 01-01-PLAN.md - TUI Foundation & Structure

---

## Phase 02: Widget Migration & Async Engine

**Goal:** Port Rich rendering to Textual widgets AND wire async pipeline

**Track A - Widgets (Frontend):**
- Port `ui.py` rendering logic to Textual widgets
- Metrics widget (CPU/RAM)
- Pipeline widget (phase progress)
- Activity widget (sparkline graph)
- Swarm widget (agent list)
- Use mock data for visual testing

**Track B - Async (Backend):**
- Create ScanWorker for pipeline execution
- Define Message types (AgentUpdate, PipelineProgress, NewFinding)
- Patch conductor to accept ui_callback
- Wire message handlers in app

**Acceptance:**
- All 4 panels render (visual 1:1 with legacy)
- Widgets resize gracefully
- Real-time scan updates flow to UI
- App remains responsive during scan

**Depends on:** Phase 01

**Plans:** 3 plans ✓
- [x] 02-01-PLAN.md - Widget Migration (Frontend)
- [x] 02-02-PLAN.md - Async Engine Wiring (Backend)
- [x] 02-03-PLAN.md - Gap Closure: Wire message handlers to widgets

---

## Phase 03: High-Fidelity Interaction

**Goal:** Enable TUI-first features for polished UX

**Deliverables:**
- Interactive DataTable for findings (sortable, navigable)
- Finding details modal (full request/response, clipboard copy)
- Log inspector with filter
- Command input bar (ChatOps)

**Acceptance:**
- Scroll through hundreds of findings
- Click finding opens modal
- Escape closes modals
- Logs filterable in real-time
- Experience feels native and polished

**Depends on:** Phase 02

**Plans:** 3 plans
- [x] 03-01-PLAN.md - FindingsTable + Modal (Wave 1)
- [x] 03-02-PLAN.md - LogInspector + CommandInput (Wave 1)
- [ ] 03-03-PLAN.md - Integration & Polish (Wave 2)

---

## Architecture

```
[ BugTrace Pipeline ]  <-- Async Messages -->  [ Textual App (Main Thread) ]
        |                                             |
   (Background)                                  (UI Layer)
        |                                             |
    [ Worker ]                                [ Screens (View) ]
                                              |-- Header
                                              |-- Main Dashboard
                                              |-- Agent Swarm
                                              |-- Command Palette
```

## Developer Guidelines

1. **CSS-First:** No dimension calculations in Python, use `.tcss`
2. **Async All The Way:** Never `time.sleep()`, use `asyncio.sleep()`
3. **No Global State:** Pass data via Messages or reactive props
