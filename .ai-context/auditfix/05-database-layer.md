# Database Layer - Audit Fix Tasks

## Feature Overview
The database layer handles persistent storage using:
- **SQLModel ORM**: Type-safe database operations
- **SQLAlchemy**: Core database engine
- **SQLite**: Default database for job queue
- **PostgreSQL**: Optional for production
- **LanceDB**: Vector database for semantic search

---

## 🔴 CRITICAL Tasks (2)

### TASK-81: Fix Race Condition in get_or_create_target
**Severity**: 🔴 CRITICAL
**File**: `bugtrace/core/database.py:144-165`
**Issue**: IntegrityError handling creates timing window
**Impact**: Duplicate targets or failed operations

**Current Code**:
```python
# Lines 144-165
try:
    target = TargetTable(url=url)
    session.add(target)
    await session.commit()
    return target
except IntegrityError:
    await session.rollback()
    # Race window here!
    target = await session.execute(
        select(TargetTable).where(TargetTable.url == url)
    ).scalar_one()
    return target
```

**Issue**: Between rollback and select, another process may delete the target

**Proposed Fix**:
```python
# Option 1: Use INSERT ... ON CONFLICT (PostgreSQL)
from sqlalchemy.dialects.postgresql import insert

stmt = insert(TargetTable).values(url=url).on_conflict_do_nothing(
    index_elements=['url']
).returning(TargetTable.id)

result = await session.execute(stmt)
target_id = result.scalar()

if target_id:
    return await session.get(TargetTable, target_id)
else:
    # Already exists, fetch it
    return await session.execute(
        select(TargetTable).where(TargetTable.url == url)
    ).scalar_one()

# Option 2: Use SELECT FOR UPDATE (locks row)
target = await session.execute(
    select(TargetTable).where(TargetTable.url == url).with_for_update()
).scalar_one_or_none()

if target:
    return target

# Create if not exists
target = TargetTable(url=url)
session.add(target)
try:
    await session.commit()
    return target
except IntegrityError:
    await session.rollback()
    # Retry once
    return await session.execute(
        select(TargetTable).where(TargetTable.url == url)
    ).scalar_one()

# Option 3: Use database-level UPSERT
from sqlalchemy import text

result = await session.execute(
    text("""
        INSERT INTO target (url, created_at)
        VALUES (:url, CURRENT_TIMESTAMP)
        ON CONFLICT (url) DO NOTHING
        RETURNING id
    """),
    {"url": url}
)

target_id = result.scalar()
if target_id:
    return await session.get(TargetTable, target_id)
else:
    return await session.execute(
        select(TargetTable).where(TargetTable.url == url)
    ).scalar_one()
```

**Verification**:
1. Run 100 concurrent get_or_create_target calls with same URL
2. Verify only 1 target created
3. Verify no IntegrityErrors propagate

**Priority**: P0 - Fix immediately

---

### TASK-82: Verify DetachedInstanceError Fix
**Severity**: 🔴 CRITICAL (Status: FIXED, needs verification)
**File**: `bugtrace/core/database.py:245-248`
**Issue**: Findings returned without expunge caused DetachedInstanceError
**Status**: Already fixed with expunge, but needs verification

**Current Code**:
```python
# Lines 246-247
for finding in findings:
    session.expunge(finding)  # ✅ Correctly implemented
```

**Verification Tasks**:
1. Run test with multiple agents accessing same finding
2. Verify no DetachedInstanceError occurs
3. Verify finding data is accessible after session closes
4. Add integration test:

```python
async def test_finding_access_after_session():
    """Verify findings can be accessed after session closes."""
    async with db.session() as session:
        finding = FindingTable(
            scan_id=1,
            type=VulnType.XSS,
            severity="HIGH"
        )
        session.add(finding)
        await session.commit()

        # Expunge and return
        session.expunge(finding)

    # Access after session closed
    assert finding.type == VulnType.XSS  # Should not raise
    assert finding.severity == "HIGH"
```

**Priority**: P0 - Verify within 1 week

---

## 🟡 MEDIUM Priority Tasks (4)

### TASK-83: Replace Status Strings with Enums
**Severity**: 🟡 MEDIUM
**File**: `bugtrace/schemas/db_models.py:20,40`
**Issue**: Status values as strings instead of enums
**Impact**: Typos cause logic errors, no type safety

**Current Code**:
```python
# Line 20
status: str = "PENDING"  # RUNNING, COMPLETED, STOPPED

# Line 40
status: str = "PENDING_VALIDATION"  # Magic strings
```

**Proposed Fix**:
```python
from enum import Enum

class ScanStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    STOPPED = "STOPPED"
    FAILED = "FAILED"

class FindingStatus(str, Enum):
    PENDING_VALIDATION = "PENDING_VALIDATION"
    VALIDATED_CONFIRMED = "VALIDATED_CONFIRMED"
    VALIDATED_FALSE_POSITIVE = "VALIDATED_FALSE_POSITIVE"
    MANUAL_REVIEW_RECOMMENDED = "MANUAL_REVIEW_RECOMMENDED"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"

# Update models
class ScanTable(SQLModel, table=True):
    status: ScanStatus = Field(default=ScanStatus.PENDING)

class FindingTable(SQLModel, table=True):
    status: FindingStatus = Field(default=FindingStatus.PENDING_VALIDATION)
```

**Migration**:
```python
# Alembic migration
def upgrade():
    # Add CHECK constraints for valid values
    op.execute("""
        ALTER TABLE scan ADD CONSTRAINT scan_status_check
        CHECK (status IN ('PENDING', 'RUNNING', 'COMPLETED', 'STOPPED', 'FAILED'))
    """)

    op.execute("""
        ALTER TABLE finding ADD CONSTRAINT finding_status_check
        CHECK (status IN ('PENDING_VALIDATION', 'VALIDATED_CONFIRMED', 'VALIDATED_FALSE_POSITIVE', 'MANUAL_REVIEW_RECOMMENDED', 'SKIPPED', 'ERROR'))
    """)
```

**Priority**: P2 - Fix before release

---

### TASK-84: Add Index on Finding Status
**Severity**: 🟡 MEDIUM
**File**: `bugtrace/schemas/db_models.py:40`
**Issue**: Frequent queries on `status` column without index
**Impact**: Slow queries when filtering findings by status

**Proposed Fix**:
```python
class FindingTable(SQLModel, table=True):
    status: str = Field(default="PENDING_VALIDATION", index=True)  # Add index

    # Alternative: Composite index
    __table_args__ = (
        Index('idx_scan_status', 'scan_id', 'status'),
    )
```

**Migration**:
```python
def upgrade():
    op.create_index('idx_finding_status', 'finding', ['status'])
    op.create_index('idx_finding_scan_status', 'finding', ['scan_id', 'status'])
```

**Verification**:
```sql
-- Test query performance
EXPLAIN QUERY PLAN
SELECT * FROM finding WHERE status = 'PENDING_VALIDATION';

-- Should show: SEARCH TABLE finding USING INDEX idx_finding_status
```

**Priority**: P2 - Fix before release

---

### TASK-85: Add Database Connection Pooling
**Severity**: 🟡 MEDIUM
**File**: `bugtrace/core/database.py`
**Issue**: No connection pooling configuration

**Proposed Fix**:
```python
from sqlalchemy.pool import QueuePool

# Configure pool
engine = create_async_engine(
    settings.DATABASE_URL,
    poolclass=QueuePool,
    pool_size=10,  # Max connections
    max_overflow=20,  # Additional connections when pool full
    pool_timeout=30,  # Wait time for connection
    pool_recycle=3600,  # Recycle connections after 1 hour
    pool_pre_ping=True,  # Verify connection before use
    echo=settings.DEBUG
)
```

**Priority**: P2 - Fix before release

---

### TASK-86: Add Database Migration System
**Severity**: 🟡 MEDIUM
**File**: New file needed
**Issue**: No schema migration management

**Proposed Fix**:
```bash
# Install Alembic
pip install alembic

# Initialize
alembic init alembic

# Configure alembic.ini
# Create initial migration
alembic revision --autogenerate -m "Initial schema"

# Apply migrations
alembic upgrade head
```

**Priority**: P2 - Fix before release

---

## 🟢 LOW Priority Tasks (3)

### TASK-87: Add Database Health Check
**Severity**: 🟢 LOW
**Issue**: No health check endpoint

**Proposed Fix**:
```python
async def health_check():
    try:
        async with db.session() as session:
            await session.execute(text("SELECT 1"))
        return {"status": "healthy"}
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}
```

**Priority**: P4 - Technical debt

---

### TASK-88: Add Database Metrics
**Severity**: 🟢 LOW
**Issue**: No monitoring of connection pool, query times

**Priority**: P4 - Technical debt

---

### TASK-89: Add Database Backup Automation
**Severity**: 🟢 LOW
**Issue**: No automated backups

**Priority**: P4 - Technical debt

---

## Summary

**Total Tasks**: 9
- 🔴 Critical: 2 (Race condition, verification) ✅ COMPLETED
- 🟠 High: 0
- 🟡 Medium: 4 (Enums, indexes, pooling, migrations) ✅ COMPLETED
- 🟢 Low: 3 (Technical debt) ✅ COMPLETED

**Status**: ALL 9 TASKS COMPLETED (2026-01-26)

### Implementation Details:

1. **TASK-81**: Race condition fixed with retry loop pattern in `get_or_create_target`
2. **TASK-82**: Test added in `tests/test_database.py` verifying expunge prevents DetachedInstanceError
3. **TASK-83**: `ScanStatus` and `FindingStatus` enums added to `db_models.py`
4. **TASK-84**: Index on `status` column and composite index `idx_finding_scan_status` added
5. **TASK-85**: Connection pooling with `StaticPool` (SQLite) / `QueuePool` (PostgreSQL) configured
6. **TASK-86**: Alembic migration system setup in `alembic/` with initial schema migration
7. **TASK-87**: `health_check()` method added to DatabaseManager
8. **TASK-88**: `get_metrics()` method added for pool stats and table counts
9. **TASK-89**: `backup_database()` method added with auto-cleanup of old backups
