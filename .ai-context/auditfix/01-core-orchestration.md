# Core Orchestration Layer - Audit Fix Tasks

## Feature Overview
The core orchestration layer handles job management, event routing, agent coordination, and state management. It includes:
- **Reactor V4**: Main event loop and job processor
- **JobManager**: SQLite-based job queue
- **EventBus**: Pub/sub for agent communication
- **TeamOrchestrator**: Agent lifecycle and coordination
- **StateManager**: Finding storage and persistence

---

## 🔴 CRITICAL Tasks (5)

### TASK-01: Fix Race Condition in Job Processing Loop
**Severity**: 🔴 CRITICAL
**File**: `bugtrace/core/reactor.py:49-72`
**Issue**: Non-atomic job fetch allows same job to be processed twice
**Impact**: Duplicate execution, incorrect scan results

**Current Code**:
```python
# Lines 49-72
while self.running:
    job = job_manager.get_next_job()
    if job:
        task = asyncio.create_task(self._process_job(job))
        # Race window here!
```

**Proposed Fix**:
```python
# Use BEGIN EXCLUSIVE TRANSACTION in SQLite
def get_next_job_atomic(self):
    with self.conn:
        cursor = self.conn.cursor()
        cursor.execute("BEGIN EXCLUSIVE")
        cursor.execute("SELECT * FROM jobs WHERE status='PENDING' LIMIT 1")
        job = cursor.fetchone()
        if job:
            cursor.execute("UPDATE jobs SET status='RUNNING' WHERE id=?", (job['id'],))
        cursor.execute("COMMIT")
        return job
```

**Verification**: Run 10 concurrent workers against 1 job, ensure single execution
**Priority**: P0 - Fix immediately

---

### TASK-02: Fix Task Tracking Memory Leak
**Severity**: 🔴 CRITICAL
**File**: `bugtrace/core/reactor.py:46,68-69`
**Issue**: `active_tasks` set grows unbounded, callbacks may not fire
**Impact**: Memory exhaustion in long-running scans

**Current Code**:
```python
self.active_tasks = set()
# ... later
self.active_tasks.add(task)
task.add_done_callback(lambda t: self.active_tasks.discard(t))
```

**Proposed Fix**:
```python
# Replace with asyncio.gather()
async def run(self):
    tasks = []
    while self.running:
        job = await self.get_next_job()
        if job:
            tasks.append(self._process_job(job))

        # Collect completed tasks
        if tasks:
            done, tasks = await asyncio.wait(tasks, timeout=0.1, return_when=asyncio.FIRST_COMPLETED)
```

**Verification**: Monitor memory usage during 1000-job scan
**Priority**: P0 - Fix immediately

---

### TASK-03: Fix Non-Atomic Job Lock in JobManager
**Severity**: 🔴 CRITICAL
**File**: `bugtrace/core/job_manager.py:72-95`
**Issue**: SELECT followed by UPDATE is not atomic (SQLite race)
**Impact**: Same job processed twice

**Current Code**:
```python
# Lines 78-92
job = cursor.execute("SELECT * FROM jobs WHERE status='PENDING'").fetchone()
# ... time gap here allows duplicate fetch
cursor.execute("UPDATE jobs SET status='RUNNING' WHERE id=?", (job_id,))
```

**Proposed Fix**:
```python
# Use UPDATE ... RETURNING (SQLite 3.35+)
cursor.execute("""
    UPDATE jobs
    SET status='RUNNING', updated_at=CURRENT_TIMESTAMP
    WHERE id = (
        SELECT id FROM jobs
        WHERE status='PENDING'
        ORDER BY priority DESC, created_at ASC
        LIMIT 1
    )
    RETURNING *
""")
job = cursor.fetchone()
```

**Verification**: Run concurrent worker stress test
**Priority**: P0 - Fix immediately

---

### TASK-04: Fix Event Bus Lock Not Used
**Severity**: 🔴 CRITICAL
**File**: `bugtrace/core/event_bus.py:41,52,132`
**Issue**: Lock created but never acquired during subscribe/emit
**Impact**: Iterator exhaustion, missed subscribers

**Current Code**:
```python
# Line 41
self._lock = asyncio.Lock()  # Created but never used!

# Line 52
async def subscribe(self, event_type, handler):
    # No lock here!
    if event_type not in self._subscribers:
        self._subscribers[event_type] = []
    self._subscribers[event_type].append(handler)
```

**Proposed Fix**:
```python
async def subscribe(self, event_type, handler):
    async with self._lock:
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        self._subscribers[event_type].append(handler)

async def emit(self, event_type, data):
    async with self._lock:
        handlers = self._subscribers.get(event_type, []).copy()

    # Emit outside lock to avoid deadlock
    for handler in handlers:
        await handler(data)
```

**Verification**: Concurrent subscribe/emit test with 100 threads
**Priority**: P0 - Fix immediately

---

### TASK-05: Fix State Manager Concurrent Access
**Severity**: 🔴 CRITICAL
**File**: `bugtrace/core/team.py:983-991`
**Issue**: Multiple agents call `state_manager.add_finding()` without locking
**Impact**: Lost findings, corrupted database state

**Current Code**:
```python
# Multiple agents calling simultaneously
await state_manager.add_finding(finding)  # No lock!
```

**Proposed Fix**:
```python
# In StateManager class
class StateManager:
    def __init__(self):
        self._finding_lock = asyncio.Lock()

    async def add_finding(self, finding):
        async with self._finding_lock:
            # Atomic database operation
            async with self.db.session() as session:
                session.add(finding)
                await session.commit()
```

**Verification**: Run 50 agents adding findings simultaneously
**Priority**: P0 - Fix immediately

---

## 🟠 HIGH Priority Tasks (7)

### TASK-06: Fix Unhandled Exception in Worker
**Severity**: 🟠 HIGH
**File**: `bugtrace/core/reactor.py:64-65`
**Issue**: Bare exception handler doesn't update job status
**Impact**: Jobs stuck in RUNNING state forever

**Current Code**:
```python
try:
    await self._process_job(job)
except Exception as e:
    logger.error(f"Job failed: {e}")
    # Missing: job status update!
```

**Proposed Fix**:
```python
try:
    await self._process_job(job)
except Exception as e:
    logger.error(f"Job failed: {e}")
finally:
    # Always update status
    await job_manager.update_status(job.id, "FAILED" if e else "COMPLETED")
```

**Priority**: P1 - Fix within 1 week

---

### TASK-07: Fix Browser Session Not Closed ✅ COMPLETED
**Severity**: 🟠 HIGH
**File**: `bugtrace/core/team.py:203`
**Issue**: `browser_manager.login()` lacks cleanup on error path
**Impact**: Stale sessions consume ports/memory
**Status**: ✅ COMPLETED (2026-01-26)

**Implementation**: Added try/finally block with `cleanup_auth_session()` call in Phase 0.5 authentication section of team.py.

**Priority**: P1 - Fix within 1 week

---

### TASK-08: Fix Connection Handle Leak
**Severity**: 🟠 HIGH
**File**: `bugtrace/core/job_manager.py:28,50,74,99,112`
**Issue**: Multiple `sqlite3.connect()` without connection pooling
**Impact**: File descriptor exhaustion

**Proposed Fix**:
```python
# Implement singleton connection pool
class JobManager:
    _instance = None
    _conn = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._conn = sqlite3.connect("jobs.db", check_same_thread=False)
        return cls._instance
```

**Priority**: P1 - Fix within 1 week

---

### TASK-09: Add Graceful Shutdown to Reactor
**Severity**: 🟠 HIGH
**File**: `bugtrace/core/reactor.py`
**Issue**: No graceful shutdown, tasks may be interrupted mid-execution

**Proposed Fix**:
```python
async def shutdown(self):
    self.running = False
    logger.info("Waiting for active tasks to complete...")
    await asyncio.gather(*self.active_tasks, return_exceptions=True)
    logger.info("Shutdown complete")
```

**Priority**: P1 - Fix within 1 week

---

### TASK-10: Add Timeout to Job Processing ✅ COMPLETED
**Severity**: 🟠 HIGH
**File**: `bugtrace/core/reactor.py`
**Issue**: Jobs can run forever, blocking queue
**Status**: ✅ COMPLETED (2026-01-26)

**Implementation**: Added `asyncio.wait_for()` wrapper around `_process_job()` in the worker function with configurable `JOB_PROCESSING_TIMEOUT` (default 3600s). Handles `asyncio.TimeoutError` and marks job as `JobStatus.TIMEOUT`.

**Priority**: P1 - Fix within 1 week

---

### TASK-11: Implement Job Priority Queue
**Severity**: 🟠 HIGH
**File**: `bugtrace/core/job_manager.py`
**Issue**: FIFO queue doesn't respect priority

**Proposed Fix**:
```python
# Add priority column to jobs table
# Update get_next_job to ORDER BY priority DESC
cursor.execute("""
    SELECT * FROM jobs
    WHERE status='PENDING'
    ORDER BY priority DESC, created_at ASC
    LIMIT 1
""")
```

**Priority**: P1 - Fix within 2 weeks

---

### TASK-12: Add Health Check Endpoint
**Severity**: 🟠 HIGH
**File**: `bugtrace/core/reactor.py`
**Issue**: No way to monitor reactor health

**Proposed Fix**:
```python
async def health_check(self):
    return {
        "status": "healthy" if self.running else "stopped",
        "active_jobs": len(self.active_tasks),
        "queue_size": job_manager.queue_size(),
        "uptime": time.time() - self.start_time
    }
```

**Priority**: P2 - Fix within 2 weeks

---

### TASK-13: Add Dead Letter Queue ✅ COMPLETED
**Severity**: 🟠 HIGH
**File**: `bugtrace/core/job_manager.py`
**Issue**: Failed jobs are lost forever
**Status**: ✅ COMPLETED (2026-01-26)

**Implementation**:
- Added `dead_letter_queue` table with `original_job_id`, `error_history`, `moved_at`
- Added `retry_count` column to jobs table (with migration for existing DBs)
- Added `MAX_RETRIES = 3` class constant
- Added `fail_job_with_retry()` method for retry logic
- Added `_move_to_dead_letter()` internal method
- Added `get_dead_letter_jobs()`, `requeue_dead_letter_job()`, `get_dead_letter_count()` methods

**Priority**: P2 - Fix within 2 weeks

---

## 🟡 MEDIUM Priority Tasks (9)

### TASK-14: Add Structured Logging
**Severity**: 🟡 MEDIUM
**File**: All core modules
**Issue**: Inconsistent logging format

**Proposed Fix**: Implement structured logging with context
```python
logger.info("job.started", job_id=job.id, type=job.type, priority=job.priority)
```

**Priority**: P2 - Fix before release

---

### TASK-15: Add Metrics Collection
**Severity**: 🟡 MEDIUM
**File**: `bugtrace/core/reactor.py`
**Issue**: No metrics for monitoring

**Proposed Fix**: Add Prometheus-compatible metrics
```python
from prometheus_client import Counter, Histogram

jobs_processed = Counter("jobs_processed_total", "Total jobs processed")
job_duration = Histogram("job_duration_seconds", "Job processing time")
```

**Priority**: P2 - Fix before release

---

### TASK-16: Add Job Cancellation Support
**Severity**: 🟡 MEDIUM
**File**: `bugtrace/core/reactor.py`, `bugtrace/core/job_manager.py`
**Issue**: No way to cancel running jobs

**Priority**: P3 - Next release

---

### TASK-17: Add Job Dependency Support
**Severity**: 🟡 MEDIUM
**File**: `bugtrace/core/job_manager.py`
**Issue**: Jobs can't depend on other jobs

**Priority**: P3 - Next release

---

### TASK-18: Add Circuit Breaker for Failing Jobs
**Severity**: 🟡 MEDIUM
**Issue**: Failed job types keep retrying

**Priority**: P3 - Next release

---

### TASK-19: Add Rate Limiting per Job Type
**Severity**: 🟡 MEDIUM
**Issue**: Expensive jobs can overwhelm system

**Priority**: P3 - Next release

---

### TASK-20: Add Event Replay Support
**Severity**: 🟡 MEDIUM
**File**: `bugtrace/core/event_bus.py`
**Issue**: Events are lost if no subscribers

**Priority**: P3 - Next release

---

### TASK-21: Add Job Progress Tracking
**Severity**: 🟡 MEDIUM
**Issue**: No visibility into long-running jobs

**Priority**: P3 - Next release

---

### TASK-22: Add Backpressure Mechanism
**Severity**: 🟡 MEDIUM
**Issue**: Queue can grow unbounded

**Priority**: P3 - Next release

---

## 🟢 LOW Priority Tasks (7)

### TASK-23: Refactor Hardcoded Timeouts
**Severity**: 🟢 LOW
**Issue**: Timeouts hardcoded instead of configurable

**Priority**: P4 - Technical debt

---

### TASK-24: Add Unit Tests for Reactor
**Severity**: 🟢 LOW
**Issue**: Core orchestration has ~40% test coverage

**Priority**: P4 - Technical debt

---

### TASK-25: Add Integration Tests
**Severity**: 🟢 LOW
**Issue**: No end-to-end orchestration tests

**Priority**: P4 - Technical debt

---

### TASK-26: Add Performance Benchmarks
**Severity**: 🟢 LOW
**Issue**: No baseline for job throughput

**Priority**: P4 - Technical debt

---

### TASK-27: Add Detailed Code Comments
**Severity**: 🟢 LOW
**Issue**: Complex orchestration logic under-documented

**Priority**: P4 - Technical debt

---

### TASK-28: Refactor TeamOrchestrator
**Severity**: 🟢 LOW
**Issue**: 983 lines, too large

**Priority**: P4 - Technical debt

---

### TASK-29: Add Type Hints
**Severity**: 🟢 LOW
**Issue**: Missing type hints in core modules

**Priority**: P4 - Technical debt

---

## Summary

**Total Tasks**: 29
- 🔴 Critical: 5 (Fix immediately)
- 🟠 High: 8 (Fix within 1-2 weeks)
- 🟡 Medium: 9 (Fix before release)
- 🟢 Low: 7 (Technical debt)

**Estimated Effort**: 3-4 weeks for P0-P1 tasks
