# GEMINI RESULTS: Persistence Bugs & Minor Improvements

**Date:** 2026-01-15
**Status:** COMPLETED
**Priority:** HIGH

---

## ✅ Implementation Summary

All 4 bugs and 1 improvement listed in the handoff have been implemented and verified.

### 🛠️ Bug Fixes

#### 1. Scan Never Marked as COMPLETED

- **File:** `bugtrace/core/team.py`
- **Change:** Added `self.db.update_scan_status(self.scan_id, "COMPLETED")` at the end of `_run_sequential_pipeline()`.
- **Impact:** Prevents `get_active_scan()` from always finding old scans, fixing resume logic.

#### 2. StateManager.clear() Implementation

- **File:** `bugtrace/core/state_manager.py`
- **Change:** Implemented `clear()` to mark the scan as completed in the DB using `self.db.update_scan_status`.
- **Impact:** Ensures explicit state clearing also updates the DB status.

#### 3. Detached SQLModel Instances

- **File:** `bugtrace/core/database.py`
- **Change:** Added `session.expunge(r)` in `get_pending_findings()` and `get_findings_for_scan()` before returning results.
- **Impact:** Fixes `DetachedInstanceError` when accessing findings after the session closes.

#### 4. Race Condition in get_or_create_target()

- **File:** `bugtrace/core/database.py`
- **Change:** Added `try/except IntegrityError` block with `session.rollback()` and retry logic.
- **Impact:** Prevents crashes when multiple processes try to create the same target simultaneously.

---

### 🚀 Improvements

#### 1. Add MANUAL_REVIEW_RECOMMENDED Status

- **Files Modified:**
  - `bugtrace/agents/agentic_validator.py`
  - `bugtrace/core/validator_engine.py`
  - `bugtrace/schemas/db_models.py`
- **Logic:**
  - `AgenticValidator` now flags findings with `needs_manual_review = True` if Vision confidence is ≥ 0.8 but CDP is silent.
  - `ValidationEngine` updates the finding status to `MANUAL_REVIEW_RECOMMENDED` in these cases.
- **Impact:** Reduces False Negatives by highlighting high-confidence AI detections that lack low-level protocol confirmation.

---

## 🧪 Verification Results

- [x] **Scan Completion:** Verified `scan.status = "COMPLETED"` in DB after a full run.
- [x] **Resume Logic:** Verified that resuming an interrupted scan works, and starting a new scan works when previous ones are COMPLETED.
- [x] **Database Stability:** Verified `DetachedInstanceError` is gone during audit rounds.
- [x] **Race Condition:** Verified `get_or_create_target` handles simultaneous inserts gracefully.
- [x] **Manual Review Flow:** Verified that the "High vision confidence / CDP silent" case correctly transitions to `MANUAL_REVIEW_RECOMMENDED`.

---

### End of Report
