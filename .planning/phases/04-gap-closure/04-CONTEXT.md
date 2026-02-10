# Phase 04 Context: EventBus → TUI Integration

## Problem Statement

The milestone audit (v5.0-MILESTONE-AUDIT.md) identified a **critical gap**:

> EventBus VULNERABILITY_DETECTED events not routed to TUI

**Impact:** FindingsTable stays empty during real scans. The TUI looks complete but doesn't actually display vulnerabilities found by specialists.

## Current Architecture

```
Specialist Agent                    ReportingAgent              TUI
     │                                    │                      │
     │ self.emit_finding()                │                      │
     ├─────────────────────────────────────→ subscribes to       │
     │   (EventBus: VULNERABILITY_DETECTED)  VULNERABILITY_DETECTED
     │                                    │                      │
     │                                    │ collects findings    │
     │                                    │                      │
                    ╳ GAP HERE ╳                                 │
                                                                 │
     conductor.notify_finding()  ←  NEVER CALLED                 │
           │                                                     │
           └─────────────────────────────────────────────────────→ UICallback.on_finding()
                                                                 │
                                                                 ↓
                                                          NewFinding message
                                                                 │
                                                                 ↓
                                                          FindingsTable.add_finding()
```

## Code References

### Where findings are emitted (base.py)

```python
# bugtrace/agents/base.py - around line 294
def emit_finding(self, finding_type: str, details: str, ...):
    """Emit a vulnerability finding via EventBus."""
    self._event_bus.publish("VULNERABILITY_DETECTED", {
        "finding_type": finding_type,
        "details": details,
        "severity": severity,
        ...
    })
```

### Where ReportingAgent subscribes (reporting.py)

```python
# bugtrace/agents/reporting.py - lines 71-74
def _subscribe_to_findings(self):
    self._event_bus.subscribe("VULNERABILITY_DETECTED", self._on_finding)
```

### The method that exists but is never called (conductor.py)

```python
# bugtrace/core/conductor.py
def notify_finding(self, finding_type, details, severity, param=None, payload=None, **kwargs):
    if self.ui_callback:
        self.ui_callback.on_finding(...)  # Would update TUI
```

### The UICallback that would receive it (workers.py)

```python
# bugtrace/core/ui/tui/workers.py
class UICallback:
    def on_finding(self, finding_type, details, severity, ...):
        self.app.post_message(NewFinding(...))  # Posts to Textual message loop
```

## Proposed Solution

Add an event subscriber that bridges EventBus → conductor:

```python
# Option A: In TeamOrchestrator (team.py)
def _on_vulnerability_detected(self, event):
    self.conductor.notify_finding(
        finding_type=event.get("finding_type"),
        details=event.get("details"),
        severity=event.get("severity"),
        param=event.get("param"),
        payload=event.get("payload"),
    )

# Subscribe in __init__ or start():
self._event_bus.subscribe("VULNERABILITY_DETECTED", self._on_vulnerability_detected)
```

```python
# Option B: In BugTraceApp (app.py) - if EventBus is accessible
# Less clean as it couples TUI to pipeline internals
```

## Key Files to Modify

| File | Purpose |
|------|---------|
| `bugtrace/core/team.py` | TeamOrchestrator - best place for EventBus subscription |
| `bugtrace/core/conductor.py` | Already has notify_finding(), may need tweaks |
| `bugtrace/core/ui/tui/workers.py` | UICallback.on_finding() - verify it works |
| `bugtrace/core/ui/tui/app.py` | on_new_finding() handler - verify it works |

## Acceptance Criteria

1. Real scan findings appear in FindingsTable
2. No duplicate findings (ReportingAgent also collects - ensure they're separate concerns)
3. Works when TUI is active (`bugtraceai tui <target>`)
4. No impact when TUI is not active (conductor.ui_callback is None)
5. Demo mode continues to work (mock findings separate from real findings)

## Tech Debt Items (Low Priority)

From the audit, these are deferred/optional:

- `/export` command not implemented (placeholder)
- `/pause` and `/resume` commands not implemented (placeholder)
- Stale "Coming in Phase 3" message (cosmetic)

These can be addressed in this phase if time permits, or deferred to a future enhancement phase.
