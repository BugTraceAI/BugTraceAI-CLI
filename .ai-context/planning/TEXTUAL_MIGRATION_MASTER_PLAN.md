# Textual TUI Migration Master Plan

## 🎯 Objective
Migrate the existing BugTraceAI legacy CLI dashboard (built with raw `Rich` + `threading`) to a modern, robust TUI using the **Textual** framework.

**Goal:** Achieve "OpenCode-like" interactivity (scroll, mouse support, resizing) while preserving the current aesthetic identity.

## 🏗️ Architecture Overview

The new architecture decouples the **Rendering** from the **Logic** using Textual's event-driven model.

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

## 📅 Phased Execution Plan

The project is divided into 4 discrete tasks. Developers should execute them sequentially.

### 📌 Phase 1: Foundation & Structure
**Tracking File:** `TASK_001_FOUNDATION.md`
- **Goal:** Establish the file structure and CSS Layout.
- **Output:** A running app displaying the layout grid (placeholders).
- **Key Tech:** `App`, `Screen`, `CSS Grid`.

### 📌 Phase 2: Widget Porting
**Tracking File:** `TASK_002_WIDGETS.md`
- **Goal:** Port existing `Rich` render logic into reusable Textual Widgets.
- **Output:** The app looks identical to the legacy version but running on Textual.
- **Key Tech:** `Static`, `Reactive Attributes`.

### 📌 Phase 3: The Async Engine
**Tracking File:** `TASK_003_ASYNC_WIRE.md`
- **Goal:** Connect the scanning pipeline to the UI without blocking.
- **Output:** Live updates, metrics, and logs flowing into the UI.
- **Key Tech:** `Worker`, `MessageClient`, `post_message()`.

### 📌 Phase 4: High-Fidelity Interaction
**Tracking File:** `TASK_004_INTERACTION.md`
- **Goal:** Enable TUI-first features (Scroll, Click, Modals).
- **Output:** Interactive tables, finding details modal, command palette.
- **Key Tech:** `DataTable`, `ModalScreen`, `Input`.

---

## 🛠️ Developer Guidelines

1.  **Keep it CSS-First:** Do not calculate dimensions in Python. Use `.tcss`.
2.  **Async All The Way:** Never use `time.sleep()`. Use `asyncio.sleep()`.
3.  **No Global State:** Pass data via Messages or reactive props.
