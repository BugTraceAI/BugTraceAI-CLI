# Handoff: TUI Resilience & Hang Prevention

**Date**: January 21, 2026
**Status**: COMPLETED

## 1. Problem Statement

The framework would occasionally "hang" (quedarse enganchado) during execution, particularly during the Auditor phase when the `AgenticValidator` was processing findings. The main issues were:

1. **Infinite Feedback Loops**: The validator's recursive feedback mechanism could get stuck in infinite retries
2. **No Timeout Enforcement**: Long-running validations had no hard timeout
3. **Tight Coupling**: The validator directly imported `dashboard`, breaking architectural separation
4. **No Cancellation Propagation**: Pressing 'q' wouldn't stop in-progress validations

## 2. Solutions Implemented

### 2.1. Recursion Depth Limiting

**File**: `bugtrace/agents/agentic_validator.py`

Added a `MAX_FEEDBACK_DEPTH = 2` constant and tracking parameter `_recursion_depth` to prevent infinite loops in the feedback mechanism.

```python
async def validate_finding_agentically(
    self,
    finding: Dict[str, Any],
    _recursion_depth: int = 0
) -> Dict[str, Any]:
    # Prevent infinite recursion
    if _recursion_depth >= self.MAX_FEEDBACK_DEPTH:
        logger.warning(f"Max feedback depth ({self.MAX_FEEDBACK_DEPTH}) reached")
        return {"validated": False, "reasoning": "Max feedback retries exceeded"}
```

### 2.2. Aggressive Timeout Reduction

Reduced global validation timeout from **10 minutes to 5 minutes**:

```python
MAX_TOTAL_VALIDATION_TIME = 300.0  # 5 minutes (was 600.0)
```

This ensures that even if individual validations hang, the entire batch will timeout and allow the framework to continue.

### 2.3. Cancellation Token Architecture (Decoupling)

**Problem**: The validator was directly importing `dashboard`, creating tight coupling.

**Solution**: Implemented a **cancellation token pattern**:

1. **ValidationEngine** creates a shared dict: `{"cancelled": False}`
2. Passes it to `AgenticValidator` constructor
3. Updates the token when `dashboard.stop_requested` is detected
4. Validator checks the token instead of importing dashboard

**Files Modified**:

- `bugtrace/agents/agentic_validator.py`: Added `cancellation_token` parameter
- `bugtrace/core/validator_engine.py`: Creates and manages the token

```python
# In ValidationEngine.__init__
self._cancellation_token = {"cancelled": False}
self.validator = AgenticValidator(cancellation_token=self._cancellation_token)

# In validation loop
if dashboard.stop_requested:
    self._cancellation_token["cancelled"] = True
    break

# In AgenticValidator
if self._cancellation_token.get("cancelled", False):
    return {"validated": False, "reasoning": "Validation cancelled by user"}
```

### 2.4. Multiple Cancellation Checkpoints

Added cancellation checks at critical points:

- Before starting batch validation
- Before each recursive feedback loop iteration
- At the start of each individual validation

## 3. Architecture Benefits

### Before (Tight Coupling)

```
AgenticValidator → imports dashboard directly
                 → Violates separation of concerns
                 → Hard to test in isolation
```

### After (Loose Coupling)

```
ValidationEngine → Creates cancellation_token
                → Monitors dashboard.stop_requested
                → Updates token
                
AgenticValidator → Receives token via constructor
                → Checks token (no dashboard import)
                → Can be tested independently
```

## 4. Testing & Verification

To verify the fixes work:

1. **Start a scan**: `./bugtraceai-cli https://ginandjuice.shop`
2. **Wait for Auditor phase** to begin (you'll see "AgenticValidator" in the TUI)
3. **Press 'q'** during validation
4. **Expected behavior**:
   - Validation stops within 1-2 seconds
   - "Validation cancelled by user" messages appear in logs
   - All processes terminate cleanly via the hard-kill mechanism

## 5. Performance Impact

- **Timeout reduction**: Prevents runaway validations from blocking the pipeline
- **Recursion limit**: Caps worst-case feedback loop at 2 levels deep
- **Early cancellation**: User can abort expensive validations immediately

## 6. Future Improvements

1. **Per-Validation Timeout**: Add individual timeout per finding (currently only batch timeout)
2. **Progress Indicators**: Show which finding is being validated in real-time
3. **Graceful Degradation**: If validation times out, mark as "NEEDS_MANUAL_REVIEW" instead of failing
4. **Async Cancellation**: Use `asyncio.CancelledError` for even cleaner cancellation

## 7. Related Changes

This work complements the earlier TUI fixes:

- **Keyboard Listener**: Non-blocking 'q' detection (see `GEMINI_HANDOFF_TUI_AND_CLEANUP_2026-01-21.md`)
- **Hard-Kill Mechanism**: `os.killpg` for process cleanup
- **Dashboard Reset**: Clean state between scans

Together, these changes ensure the framework **never hangs** and always responds to user input within seconds.
