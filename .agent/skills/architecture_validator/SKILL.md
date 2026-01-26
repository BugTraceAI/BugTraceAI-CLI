---
name: architecture_validator
description: Validates that code changes and new features align with the BugTraceAI V5 "Reactor" architecture. Use this when reviewing code, refactoring, or planning new features.
---

# Architecture Validator Skill

This skill helps ensure that all modifications to `BugTraceAI` respect the core principles of the V5 Architecture (Reactor + EventBus + Specialized Agents).

## 1. Key Architectural Principles (The "Golden Rules")

### A. The Reactor Pattern (Core)

- **NO Linear Scripts**: The main logic acts as an orchestrator, dispatching jobs. It should NOT be a single linear `while` loop.
- **Async/Event-Driven**: Communication between components should primarily happen via the `EventBus` (`bugtrace/core/event_bus.py`).
  - *Good*: `await event_bus.publish(Event(Type.URL_FOUND, ...))`
  - *Bad*: Directly instantiating an Agent inside the crawler loop and waiting for it.

### B. Specialized Agents

- **Single Responsibility**: Each Agent (`XSSAgent`, `SQLiAgent`) must focus on ONE vulnerability class.
- **Inheritance**: All agents must inherit from `BaseAgent` (`bugtrace/core/agent_base.py`).
- **Statelessness**: Agents should process a target and return findings; they should not hold global state.

### C. The 3-Layer Validation (The "Triad")

Any new vulnerability detection logic MUST support the 3 layers:

1. **Payload**: Syntax check.
2. **Browser (CDP)**: Execution verification.
3. **Vision AI**: Visual confirmation (screen analysis).

## 2. Review Checklist

When you are asked to review code or implement a feature, check against this list:

- [ ] Does the new code block the main event loop? (It shouldn't).
- [ ] Are we bypassing the `EventBus` for critical communications?
- [ ] Are we creating a new "God Class" instead of a specialized Agent?
- [ ] Does the new standard support the Validation Triad?

## 3. Instructions for the Agent

1. **Read Context**: Use `view_file` on related files.
2. **Compare**: Check the code against the principles above.
3. **Report**: If you find violations, warn the user explicitly:
   > "⚠️ **Architecture Warning**: This change seems to bypass the EventBus system. In V5, we should dispatch an event instead..."
