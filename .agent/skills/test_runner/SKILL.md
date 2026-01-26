---
name: test_runner
description: Intelligent test execution helper for BugTraceAI. Knows which tests to run for specific changes (Agents, Reactor, Reporting) and how to interpret pytest output. Use this when the user asks to "run tests", "verify changes", or "check regression".
---

# Test Runner Skill

This skill maps high-level testing intent to specific `pytest` commands for the BugTraceAI project.

## 1. Test Categories

### A. Smoke / Sanity Tests

*Use when*: Quick check after minor edits.
*Command*:

```bash
pytest tests/test_smoke.py tests/test_bugtrace_sanity.py -v
```

### B. Agent-Specific Tests

*Use when*: Modifying detection logic.

- **XSS**: `pytest tests/test_phase1_agents.py tests/test_xss_visual.py -k xss`
- **SQLi**: `pytest tests/test_phase1_agents.py -k sqli`
- **General**: `pytest tests/test_phase1_agents.py`

### C. Core Architecture Tests

*Use when*: Touching `Reactor`, `EventBus`, or `Conductor`.
*Command*:

```bash
pytest tests/test_reactor.py tests/test_event_bus.py tests/test_conductor_v2.py
```

### D. Full Regression (Slow)

*Use when*: Before a major handoff or release.
*Command*:

```bash
pytest tests/ -v
```

### E. Dojo Validation (Internal App)

*Use when*: Validating end-to-end framework execution against specific environments.

#### Dojo Selection Guide

- **Reporting & Traceability**: Use the **Reporting Lab** (`lab/app.py` on port 5005). Best for verifying PoC quality, screenshots, and report formatting without noise.
- **Agent Benchmarking (Scoring)**: Use the **Comprehensive Dojo** (`testing/dojos/dojo_training.py` on port 5090). Best for individual agent testing from Level 0 to 10.
- **Extreme Exploitation & Handoffs**: Use the **Mega Mixed Gauntlet** (`testing/dojos/dojo_benchmark.py` on port 5150). Best for testing Surgical Orchestrator, multi-layer bypasses, and complex attack paths.
- **General Flow**: Use the **Mixed Dojo** (`testing/dojos/dojo_basic.py` on port 5100). Balanced for general integration testing.

*Command*:

```bash
# Ensure the chosen Dojo is running, then run validation:
python3 testing/dojos/dojo_validation.py --target [URL_OF_CHOICE]
```

## 2. Instructions for the Agent

1. **Identify Intent**: Determine what component was modified (Agent vs Core vs UI).
2. **Select Category**: Pick the most relevant test subset to save time.
3. **Run Command**: execute the `pytest` command.
4. **Analyze Output**:
   - If green: Report success.
   - If red: Read the failure trace, identify the file/line, and propose a fix.
