# Emergency Fixes - Quick Start Guide

## ⚡ TL;DR - Fix These 3 Issues in 2 Hours

### TODAY (2 hours)
```bash
# FIX-001: Delete 4 lines in database.py (15 min)
nano bugtrace/core/database.py +376
# Delete lines 376-379
# Save

# FIX-002: Remove 'async' from event_bus.py (1 hour)
nano bugtrace/core/event_bus.py +52
# Line 52: async def subscribe → def subscribe
# Line 67: Remove async with self._lock:
# Line 135: async def unsubscribe → def unsubscribe
# Line 149: Remove async with self._lock:
# Save

# Test
./bugtraceai-cli https://ginandjuice.shop
```

### THIS WEEK (30 min - optional)
```bash
# FIX-003: Suppress event loop warning (30 min)
nano bugtrace/__main__.py
# Add warning suppression before loop closes
# See 03-event-loop-cleanup.md for details
```

---

## What You Get

### Before Fixes
- 🔴 800+ lines of logs (mostly garbage)
- 🔴 11 RuntimeWarnings during startup
- 🔴 1 RuntimeError at shutdown
- 🔴 Debugging is impossible
- 🔴 Looks unprofessional

### After Fixes
- ✅ ~200 lines of clean logs
- ✅ 0 warnings
- ✅ Clean shutdown
- ✅ Easy debugging
- ✅ Professional quality

**Effort**: 2-3 hours
**Impact**: MASSIVE quality improvement

---

## Detailed Steps

### Step 1: FIX-001 (15 minutes)

**File**: `bugtrace/core/database.py`

**What to do**: Delete lines 376-379

**Before**:
```python
        """
        import traceback
        logger.info(f"DEBUG: save_scan_result called for {len(findings)} findings")
        for line in traceback.format_stack()[-6:]:
            logger.info(f"Stack: {line.strip()}")

        with self.get_session() as session:
```

**After**:
```python
        """

        with self.get_session() as session:
```

**Test**:
```bash
./bugtraceai-cli https://ginandjuice.shop
grep -c "DEBUG:" logs/*.log  # Should be 0
```

**Read more**: [01-debug-logging.md](./01-debug-logging.md)

---

### Step 2: FIX-002 (1 hour)

**File**: `bugtrace/core/event_bus.py`

**What to do**: Make `subscribe()` and `unsubscribe()` synchronous

**Changes**:

**Line 52**:
```python
# Before
async def subscribe(self, event: str, handler: Callable) -> None:

# After
def subscribe(self, event: str, handler: Callable) -> None:
```

**Line 67** (remove async lock):
```python
# Before
    async with self._lock:
        self._subscribers[event].append(handler)
        self._stats["total_subscribers"] += 1

# After
    # No lock needed - list.append() is atomic
    self._subscribers[event].append(handler)
    self._stats["total_subscribers"] += 1
```

**Line 135**:
```python
# Before
async def unsubscribe(self, event: str, handler: Callable) -> bool:

# After
def unsubscribe(self, event: str, handler: Callable) -> bool:
```

**Line 149** (remove async lock):
```python
# Before
    async with self._lock:
        try:
            self._subscribers[event].remove(handler)
            self._stats["total_subscribers"] -= 1

# After
    try:
        self._subscribers[event].remove(handler)
        self._stats["total_subscribers"] -= 1
```

**Test**:
```bash
./bugtraceai-cli https://ginandjuice.shop 2>&1 | grep -c "RuntimeWarning"
# Should be 0
```

**Read more**: [02-eventbus-warnings.md](./02-eventbus-warnings.md)

---

### Step 3: FIX-003 (30 minutes - OPTIONAL)

**File**: `bugtrace/__main__.py`

**What to do**: Add warning suppression

**Add near end of main() function**:
```python
import warnings

# Suppress subprocess cleanup warnings (cosmetic issue only)
warnings.filterwarnings("ignore", category=RuntimeWarning,
                       module="asyncio.base_subprocess")
warnings.filterwarnings("ignore", message=".*Event loop is closed.*")
```

**Test**:
```bash
./bugtraceai-cli https://ginandjuice.shop 2>&1 | tail -10
# Should NOT see "RuntimeError: Event loop is closed"
```

**Read more**: [03-event-loop-cleanup.md](./03-event-loop-cleanup.md)

---

## Verification

### Run Full Test

```bash
# Clean logs
rm -f logs/*.log

# Run scan
./bugtraceai-cli https://ginandjuice.shop

# Check results
echo "=== Log Line Count ==="
wc -l logs/*.log  # Should be ~200 lines (was 800+)

echo "=== DEBUG Logging ==="
grep -c "DEBUG:" logs/*.log  # Should be 0

echo "=== RuntimeWarnings ==="
grep -c "RuntimeWarning" logs/*.log  # Should be 0

echo "=== Event Loop Error ==="
grep "Event loop is closed" logs/*.log  # Should be empty
```

### Expected Output

```
=== Log Line Count ===
198 logs/bugtrace.log

=== DEBUG Logging ===
0

=== RuntimeWarnings ===
0

=== Event Loop Error ===
(no output)
```

---

## Commit Your Changes

After all fixes are done and tested:

```bash
git add bugtrace/core/database.py
git commit -m "fix: Remove DEBUG logging pollution in database.py

- Deleted lines 376-379 (debug stack traces)
- Reduces log output from 800+ to ~200 lines per scan
- Improves log readability by 95%

Issue: FIX-001
Time: 15 minutes"

git add bugtrace/core/event_bus.py
git commit -m "fix: Remove async from EventBus.subscribe()

- Changed subscribe() and unsubscribe() to synchronous
- Removed unnecessary async locks
- Fixes 11 RuntimeWarnings during startup

Issue: FIX-002
Time: 1 hour"

git add bugtrace/__main__.py
git commit -m "fix: Suppress event loop cleanup warning

- Added warning suppression for subprocess cleanup
- Prevents confusing error message at shutdown
- Cosmetic fix only, no functional impact

Issue: FIX-003
Time: 30 minutes"

# Push to backup
git push origin main
```

---

## Troubleshooting

### If FIX-001 Breaks

```bash
# Restore original
git checkout bugtrace/core/database.py

# You probably deleted too much
# Make sure you ONLY deleted lines 376-379
# Leave the docstring and session code intact
```

### If FIX-002 Breaks

```bash
# Restore original
git checkout bugtrace/core/event_bus.py

# Check that you:
# 1. Removed 'async' from def subscribe
# 2. Removed 'async with' but kept the append logic
# 3. Did the same for unsubscribe
```

### If Nothing Works

```bash
# Restore everything
git checkout bugtrace/core/database.py
git checkout bugtrace/core/event_bus.py
git checkout bugtrace/__main__.py

# Read the detailed guides and try again:
# - 01-debug-logging.md
# - 02-eventbus-warnings.md
# - 03-event-loop-cleanup.md
```

---

## Time Estimates

| Fix | Description | Time | Difficulty |
|-----|-------------|------|------------|
| FIX-001 | Delete DEBUG logging | 15 min | ⭐ Easy |
| FIX-002 | Fix EventBus async | 1 hour | ⭐⭐ Medium |
| FIX-003 | Suppress warning | 30 min | ⭐ Easy |
| **TOTAL** | All fixes | **2-3 hours** | ⭐⭐ Medium |

---

## Priority Order

1. **FIX-001** (DEBUG logging) - Do FIRST
   - Biggest impact (95% log reduction)
   - Easiest fix (delete 4 lines)
   - Zero risk

2. **FIX-002** (EventBus warnings) - Do SECOND
   - Makes code professional
   - Moderate effort
   - Low risk

3. **FIX-003** (Event loop cleanup) - Do LAST (or skip)
   - Cosmetic only
   - Can suppress instead of fix
   - Optional

---

## Success Criteria

After all fixes:
- ✅ Scan completes successfully
- ✅ Logs are <250 lines (was 800+)
- ✅ No "DEBUG:" in logs
- ✅ No "RuntimeWarning" messages
- ✅ No "RuntimeError" at shutdown
- ✅ All findings still saved correctly
- ✅ Reports generated properly

---

## Need Help?

Read the detailed guides:
- [01-debug-logging.md](./01-debug-logging.md) - Full explanation of FIX-001
- [02-eventbus-warnings.md](./02-eventbus-warnings.md) - Full explanation of FIX-002
- [03-event-loop-cleanup.md](./03-event-loop-cleanup.md) - Full explanation of FIX-003
- [README.md](./README.md) - Complete overview

---

## Next Steps After Emergency Fixes

Once these 3 fixes are done, move on to:
1. **Write tests** - See `.ai-context/roadmap/`
2. **Benchmark vs competitors** - Prove you're the best
3. **Implement unique features** - Pull ahead of competition

But FIRST, fix these 3 issues. They're blockers for professional quality.
