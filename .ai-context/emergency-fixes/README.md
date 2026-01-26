# Emergency Fixes - Critical Issues to Fix NOW

## Overview

**Total Issues**: 3 critical bugs affecting production quality
- 🔴 **P0**: 2 issues (Fix TODAY - <2 hours total)
- 🟠 **P1**: 1 issue (Fix this week - 1 hour)

**Total Estimated Time**: 3-4 hours
**Impact**: Massive improvement in log readability and code quality

---

## Priority Summary

### 🔴 P0 - Fix TODAY (2 hours)

**Top 2 Most Critical**:
1. **[FIX-001] DEBUG Logging Pollution** → 600+ lines of garbage per scan
2. **[FIX-002] EventBus RuntimeWarnings** → 11 files with coroutine warnings

**Recommended Order**:
1. **15 minutes**: Fix DEBUG logging (database.py)
2. **1 hour**: Fix EventBus subscribe() (event_bus.py)

---

### 🟠 P1 - Fix This Week (1 hour)

**[FIX-003] Event Loop Cleanup Warning** → Cosmetic but unprofessional

---

## Files by Issue

### 1. [FIX-001: DEBUG Logging](./01-debug-logging.md)
**File**: `bugtrace/core/database.py:376-379`
**Impact**: 🔴 CRITICAL - Logs are unreadable
**Time**: 15 minutes

---

### 2. [FIX-002: EventBus RuntimeWarnings](./02-eventbus-warnings.md)
**Files**: `bugtrace/core/event_bus.py` + 11 agent files
**Impact**: 🔴 HIGH - Unprofessional warnings
**Time**: 1 hour

---

### 3. [FIX-003: Event Loop Cleanup](./03-event-loop-cleanup.md)
**File**: `bugtrace/core/team.py`
**Impact**: 🟠 MEDIUM - Cosmetic warning at shutdown
**Time**: 1 hour

---

## How to Use This Directory

### For Developers

1. **Start with P0 fixes**: Read `01-debug-logging.md` first
2. **Work sequentially**: Fix-001 → Fix-002 → Fix-003
3. **Use code examples**: Each file has "Current Code" and "Fixed Code"
4. **Test after each fix**: Run `./bugtraceai-cli https://ginandjuice.shop` to verify

### Quick Start

```bash
# 1. Fix DEBUG logging (15 min)
cd bugtrace/core
# Edit database.py lines 376-379 (see 01-debug-logging.md)

# 2. Fix EventBus (1 hour)
# Edit event_bus.py line 52 (see 02-eventbus-warnings.md)

# 3. Fix Event Loop (1 hour)
# Edit team.py - add cleanup method (see 03-event-loop-cleanup.md)

# 4. Test
./bugtraceai-cli https://ginandjuice.shop
```

---

## Success Criteria

After all fixes:
- ✅ Logs should be <50 lines for a simple scan (currently 600+)
- ✅ No `RuntimeWarning: coroutine 'EventBus.subscribe' was never awaited`
- ✅ No `RuntimeError: Event loop is closed` at shutdown

---

## Timeline

**Day 1 (2 hours)**:
- Morning: FIX-001 DEBUG logging (15 min)
- Morning: FIX-002 EventBus warnings (1 hour)
- Test & commit

**Day 2-3 (1 hour)**:
- FIX-003 Event loop cleanup (1 hour)
- Final testing

---

## Related Documents

- [COMPREHENSIVE_AUDIT_REPORT.md](../../COMPREHENSIVE_AUDIT_REPORT.md) - Original audit
- [.ai-context/auditfix/](../auditfix/) - Long-term audit fixes (145 tasks)
- [.ai-context/roadmap/](../roadmap/) - Future features roadmap

---

## Summary Statistics

| Fix ID | File | Issue | Priority | Time | Impact |
|--------|------|-------|----------|------|--------|
| FIX-001 | database.py | DEBUG logging | 🔴 P0 | 15 min | Log pollution |
| FIX-002 | event_bus.py | RuntimeWarnings | 🔴 P0 | 1 hour | Code quality |
| FIX-003 | team.py | Event loop cleanup | 🟠 P1 | 1 hour | Shutdown warning |
| **TOTAL** | **3 files** | **3 issues** | - | **~3 hours** | **Professional code** |

---

**Last Updated**: 2026-01-26
**Analysis Version**: Critical Code Review (Post-Testing)
