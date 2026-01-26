# FIX-003: Event Loop Cleanup Warning

## 🟠 MEDIUM PRIORITY - Fix This Week (1 hour)

---

## Problem

**File**: `bugtrace/core/team.py`

**Issue**: Async subprocesses try to cleanup after event loop is closed, causing warnings at shutdown.

**Evidence from logs**:
```
[stderr] Exception ignored in: <function BaseSubprocessTransport.__del__ at 0x77375521f240>
Traceback (most recent call last):
  File "/usr/lib/python3.12/asyncio/base_subprocess.py", line 126, in __del__
  File "/usr/lib/python3.12/asyncio/base_subprocess.py", line 104, in close
  File "/usr/lib/python3.12/asyncio/unix_events.py", line 767, in close
  File "/usr/lib/python3.12/asyncio/unix_events.py", line 753, in write_eof
  File "/usr/lib/python3.12/asyncio/base_events.py", line 795, in call_soon
  File "/usr/lib/python3.12/asyncio/base_events.py", line 541, in _check_closed
RuntimeError: Event loop is closed
```

**Frequency**: Once at the end of EVERY scan

---

## Impact

### User Experience Impact
- ⚠️ **Cosmetic issue** - Doesn't affect functionality
- ⚠️ **Unprofessional** - Last thing user sees is an error
- ⚠️ **Confusing** - Users think something went wrong (but scan succeeded)

### Actual Functionality Impact
- ✅ **Scan works fine** - All findings are saved
- ✅ **Reports generated** - Everything completes successfully
- ✅ **No data loss** - Just a cleanup warning

**This is P1 (not P0) because it's cosmetic, but still should be fixed.**

---

## Root Cause

### What's Happening

1. **TeamOrchestrator.start()** runs the scan
2. Scan completes, findings saved
3. Event loop closes
4. Python garbage collector tries to cleanup subprocess transports
5. **BUT** event loop is already closed → `RuntimeError`

### Why It Happens

**Async subprocesses created by**:
- SQLMap Docker container
- Go tools (GoSpider, XSS Fuzzer, IDOR Fuzzer)
- Browser automation (Playwright)

**These are launched with**:
```python
# sqlmap_agent.py:700
process = await asyncio.create_subprocess_exec(...)

# external.py:381 (GoSpider)
process = await asyncio.create_subprocess_exec("gospider", ...)
```

**Problem**: When `start()` finishes, event loop closes immediately, but subprocess cleanup is deferred to Python's garbage collector, which runs AFTER loop closure.

---

## Solution

### Add Explicit Cleanup Before Event Loop Closes

**Add cleanup method to TeamOrchestrator that waits for all subprocesses to finish.**

---

## Implementation

### Step 1: Track Active Subprocesses

**Add to TeamOrchestrator.__init__()** (around line 59):

```python
# team.py:59 (ADD AFTER __init__)
def __init__(self, target: str, resume: bool = False, ...):
    self.target = target
    self.output_dir = output_dir
    # ... existing code ...

    # Track active subprocesses for cleanup
    self._active_processes = []  # ✅ ADD THIS LINE
```

### Step 2: Register Subprocesses When Created

**Modify subprocess creation** (this is the hard part - need to track all places):

```python
# Example in sqlmap_agent.py or external.py
process = await asyncio.create_subprocess_exec(...)
if hasattr(self, 'orchestrator') and self.orchestrator:
    self.orchestrator._active_processes.append(process.wait())
```

**OR (simpler)**: Use context manager pattern:

```python
# team.py - Add context manager
@asynccontextmanager
async def track_subprocess(self, process):
    """Context manager to track subprocess for cleanup."""
    try:
        yield process
    finally:
        await process.wait()  # Ensure process cleanup
```

### Step 3: Add Cleanup Method

**Add to TeamOrchestrator** (at end of class, around line 1200):

```python
# team.py:1200 (ADD NEW METHOD)
async def cleanup(self):
    """
    Cleanup all resources before event loop closes.

    This prevents "Event loop is closed" warnings by ensuring
    all subprocesses are properly terminated before loop shutdown.
    """
    logger.debug("Starting TeamOrchestrator cleanup...")

    # 1. Wait for all tracked subprocesses
    if self._active_processes:
        logger.debug(f"Waiting for {len(self._active_processes)} subprocesses to finish...")
        await asyncio.gather(*self._active_processes, return_exceptions=True)
        self._active_processes.clear()

    # 2. Cleanup browser if still running
    try:
        from bugtrace.tools.visual.browser import browser_manager
        if hasattr(browser_manager, 'cleanup'):
            await browser_manager.cleanup()
    except Exception as e:
        logger.debug(f"Browser cleanup warning: {e}")

    # 3. Cleanup any other async resources
    # (Add more as needed)

    logger.debug("TeamOrchestrator cleanup complete.")
```

### Step 4: Call Cleanup in start()

**Modify TeamOrchestrator.start()** (around line 176):

**Before**:
```python
# team.py:176 (CURRENT)
async def start(self):
    try:
        # ... existing scan code ...
        await self._run_hunter_core()
        # ... existing code ...
    except Exception as e:
        logger.error(f"TeamOrchestrator error: {e}")
        raise
```

**After**:
```python
# team.py:176 (FIXED)
async def start(self):
    try:
        # ... existing scan code ...
        await self._run_hunter_core()
        # ... existing code ...
    except Exception as e:
        logger.error(f"TeamOrchestrator error: {e}")
        raise
    finally:
        # ✅ ALWAYS cleanup, even on error
        await self.cleanup()
```

---

## Simpler Alternative (If Above is Too Complex)

### Just Suppress the Warning

If tracking all subprocesses is too much work, you can suppress the warning:

**Add to __main__.py** (at the very end, after event loop closes):

```python
# __main__.py:200 (or wherever event loop closes)
import warnings
import asyncio

# Suppress "Event loop is closed" warnings from subprocess cleanup
warnings.filterwarnings("ignore", category=RuntimeWarning,
                       message=".*Event loop is closed.*")
warnings.filterwarnings("ignore", category=ResourceWarning,
                       message=".*subprocess.*")
```

**OR** use proper asyncio shutdown:

```python
# __main__.py - When closing event loop
loop = asyncio.get_event_loop()
try:
    loop.run_until_complete(orchestrator.start())
finally:
    # Proper shutdown sequence
    pending = asyncio.all_tasks(loop)
    for task in pending:
        task.cancel()
    loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
    loop.close()
```

---

## Recommended Approach

**For now**: Use the **simpler alternative** (suppress warnings)
**Later (when refactoring)**: Implement proper cleanup tracking

**Why**:
- Full subprocess tracking requires changes in 10+ files
- Risk of breaking working code
- Benefit is purely cosmetic
- Suppressing warning is safe and immediate

---

## Implementation Steps (Simple Version)

### Step 1: Add Warning Suppression

```bash
cd /home/albert/Tools/BugTraceAI/BugTraceAI-CLI
nano bugtrace/__main__.py
```

**Find the end of the main() function** (around line 200):

**Add BEFORE the event loop closes**:

```python
# __main__.py:195 (ADD THIS)
import warnings

# Suppress subprocess cleanup warnings (cosmetic issue only)
# These occur when subprocesses cleanup after event loop closes
# Functionality is not affected - just prevents confusing error messages
warnings.filterwarnings("ignore", category=RuntimeWarning,
                       module="asyncio.base_subprocess")
warnings.filterwarnings("ignore", message=".*Event loop is closed.*")

# ... existing loop.run_until_complete() code ...
```

---

## Testing Checklist

- [ ] Scan runs successfully
- [ ] No "Event loop is closed" warning at end
- [ ] All findings still saved
- [ ] Reports generated correctly
- [ ] No new warnings introduced

---

## Verification

### Before Fix
```bash
./bugtraceai-cli https://ginandjuice.shop 2>&1 | tail -20
# Expected: RuntimeError: Event loop is closed
```

### After Fix (Simple Version)
```bash
./bugtraceai-cli https://ginandjuice.shop 2>&1 | tail -20
# Expected: Clean exit, no RuntimeError
# Should end with: "✅ Auditor Phase Complete."
```

---

## Expected Outcome

**Before**:
```
✅ Auditor Phase Complete.
INFO     Learning data saved                              strategy_router.py:553
[stderr] Exception ignored in: <function BaseSubprocessTransport.__del__ at 0x77375521f240>
Traceback (most recent call last):
  File "/usr/lib/python3.12/asyncio/base_subprocess.py", line 126, in __del__
  [... 8 lines of traceback ...]
RuntimeError: Event loop is closed
```

**After**:
```
✅ Auditor Phase Complete.
INFO     Learning data saved                              strategy_router.py:553
```

**Clean exit** ✅

---

## Estimated Time

### Simple Version (Recommended)
- **Reading this doc**: 10 minutes
- **Adding warning suppression**: 5 minutes
- **Testing**: 10 minutes

**Total**: 25 minutes

### Full Version (Future Refactor)
- **Adding cleanup tracking**: 2 hours
- **Testing all subprocess types**: 1 hour
- **Debugging edge cases**: 1 hour

**Total**: 4 hours (NOT worth it for cosmetic fix)

---

## Priority Justification

**Why P1 (Fix this week, not TODAY)**:
- Purely cosmetic issue
- Doesn't affect functionality
- Last thing in logs (easy to ignore)
- Simple suppression is good enough for now

**But should still be fixed because**:
- Users see errors and get confused
- Looks unprofessional
- 5-minute fix with suppression

---

## Future Proper Fix (Optional)

When you have time for proper refactoring:

1. Create `ProcessManager` class to track all subprocesses
2. Use context managers for subprocess creation
3. Implement proper cleanup sequence
4. Add unit tests for cleanup

**Example architecture**:
```python
class ProcessManager:
    def __init__(self):
        self._processes = []

    @asynccontextmanager
    async def create_subprocess(self, *args, **kwargs):
        process = await asyncio.create_subprocess_exec(*args, **kwargs)
        self._processes.append(process)
        try:
            yield process
        finally:
            await process.wait()
            self._processes.remove(process)

    async def cleanup_all(self):
        for proc in self._processes:
            if proc.returncode is None:
                proc.terminate()
                await proc.wait()
```

**But for now**: Just suppress the warning. It's good enough.

---

## Related Issues

- This cleanup warning is partially caused by FIX-001 (DEBUG logging)
- Once logs are cleaner, this warning stands out more
- Proper async cleanup would also help with resource management (memory leaks)

---

## Notes

This is the least important of the 3 emergency fixes:
- FIX-001 (DEBUG logs): CRITICAL - fix first
- FIX-002 (EventBus): HIGH - fix second
- FIX-003 (Event loop): MEDIUM - fix last (or never if you suppress)

**Recommended**: Do simple suppression now, proper cleanup later if needed.
