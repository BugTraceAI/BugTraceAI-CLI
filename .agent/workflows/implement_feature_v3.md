---
description: Guide for implementing new features following the BugTraceAI V5 Reactor Architecture.
---

# Workflow: Implement New V5 Feature

Follow this strict procedure when adding new capabilities (Agents, Scanners, Reporters) to ensuring architectural compliance.

## 1. Pre-Coding Analysis

- [ ] **Read Architecture**: Use `view_file .ai-context/ARCHITECTURE_V3.md`.
- [ ] **Identify Components**:
  - Does this need a new `Event`? (Check `bugtrace/core/events.py`)
  - Does this need a new `Agent`? (Must inherit `BaseAgent`)
  - Does this touch the Database? (Check `bugtrace/core/database.py`)

## 2. Implementation Steps

### Step A: Define Interfaces (if needed)

If adding a new vulnerability type:

1. Define the `VulnerabilityType` enum in `bugtrace/core/types.py`.
2. Define the Event Type in `bugtrace/core/events.py`.

### Step B: Create the Agent/Component

1. Create file `bugtrace/agents/[name]_agent.py`.
2. **CRITICAL**: Implement the `Validator Triad` inside the agent (Payload -> Browser -> Vision) OR ensure it emits events for the `AgenticValidator` to pick up.
3. Use the `architecture_validator` skill to check the code.

### Step C: Register in Reactor

1. Update `bugtrace/core/reactor.py` or `team.py` to listener for the new events.
2. Ensure it respects `MAX_CONCURRENCY`.

### Step D: Unit Testing (Mandatory)

1. Create `tests/test_[feature_name].py`.
2. Mock external calls (Network, AI).
3. Run test using `test_runner` skill.

## 3. Verification

// turbo

1. Run a generic sanity check:

   ```bash
   pytest tests/test_bugtrace_sanity.py
   ```

2. Run the specific test created in Step D.

## 4. Documentation

1. Use the `documentation_helper` skill to generate the update entry.
   - Update `PROJECT_STORYLINE.md`.
   - Create a technical spec if the feature is complex.
