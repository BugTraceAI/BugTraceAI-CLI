# Phase 05: Conductor V3 Refactoring ("The Reactor Guardian")

**Status:** Pending
**Goal:** Transform Conductor from Centralized State Store (V2) to Decoupled Integrity Auditor (V3)
**Author:** Antigravity
**HLD Reference:** User-provided HLD document
**Review Status:** Approved with improvements (v1.1)

---

## Key Improvements (v1.1 - Post Review)

| Issue | Original Approach | Improved Approach |
|-------|-------------------|-------------------|
| ReportingAgent migration | RAM accumulation (volatile) | **File-Based Source of Truth** (`recon/urls.txt`) |
| Conductor dependency audit | Manual grep (error-prone) | **Automated gate test** that blocks Wave 4 |
| Integrity rules | Hard errors (breaks pipeline) | **Tolerance margins** + severity levels |

---

## Overview

The Conductor V3 refactoring eliminates the `shared_context` pattern that creates coupling between agents, replacing it with:
- **EventBus**: Hot path for real-time data transfer
- **StateManager**: Cold storage for persistent data
- **Passive Observer**: Conductor listens to events, validates integrity, never touches operational data

---

## Task Breakdown

### WAVE 1: Hardening & Deprecation (Non-Breaking)

#### Task 1.1: Add Fail-Fast Protocol Loading
**File:** `bugtrace/core/conductor.py`
**Lines:** 109-132
**Risk:** Low (startup only)

**Changes:**
1. Add `_CRITICAL_FILES` list for files that MUST exist
2. Modify `_load_file()` to `sys.exit(1)` if critical file missing
3. Add checksum validation for `security-rules.md`
4. Log CRITICAL error before exit

**Code:**
```python
# Add after line 48
CRITICAL_FILES = {"security_rules"}  # Files that MUST exist

def _load_file(self, key: str) -> str:
    """Load protocol file with Fail-Fast for critical files."""
    # ... existing path resolution ...

    if os.path.exists(path):
        # ... existing read logic ...
    else:
        if key in self.CRITICAL_FILES:
            logger.critical(f"FATAL: Critical protocol file missing: {path}")
            logger.critical("Cannot proceed without security rules. Aborting.")
            sys.exit(1)
        logger.warning(f"Protocol file not found: {path}")
        return ""
```

**Test:** `tests/unit/test_conductor_failfast.py`
- Test missing non-critical file → warning, returns ""
- Test missing critical file → sys.exit(1)

---

#### Task 1.2: Add Deprecation Warnings to shared_context Methods
**File:** `bugtrace/core/conductor.py`
**Lines:** 245-273
**Risk:** Low (warning only)

**Changes:**
1. Add `warnings.warn()` with DeprecationWarning to `share_context()`
2. Add `warnings.warn()` with DeprecationWarning to `get_shared_context()`
3. Log caller info for migration tracking

**Code:**
```python
import warnings

def share_context(self, key: str, value: Any) -> None:
    """DEPRECATED: Use EventBus.emit() instead."""
    warnings.warn(
        "share_context() is deprecated. Use EventBus.emit() for data transfer.",
        DeprecationWarning,
        stacklevel=2
    )
    logger.warning(f"DEPRECATED: share_context('{key}') called. Migrate to EventBus.")
    # ... existing logic ...

def get_shared_context(self, key: str = None) -> Any:
    """DEPRECATED: Use StateManager or EventBus subscriptions instead."""
    warnings.warn(
        "get_shared_context() is deprecated. Use StateManager for persistence.",
        DeprecationWarning,
        stacklevel=2
    )
    logger.warning(f"DEPRECATED: get_shared_context('{key}') called. Migrate to StateManager.")
    # ... existing logic ...
```

**Test:** `tests/unit/test_conductor_deprecation.py`
- Test `share_context()` emits DeprecationWarning
- Test `get_shared_context()` emits DeprecationWarning

---

#### Task 1.3: Add asyncio.Lock to Internal Structures
**File:** `bugtrace/core/conductor.py`
**Lines:** 77-82, 245-273
**Risk:** Low (thread-safety improvement)

**Changes:**
1. Add `self._context_lock = threading.Lock()` in `__init__`
2. Wrap `shared_context` mutations in lock context manager
3. Wrap `stats` mutations in lock context manager

**Code:**
```python
import threading

def __init__(self, ui_callback: Optional["UICallback"] = None):
    # ... existing init ...

    # Thread-safety locks
    self._context_lock = threading.Lock()
    self._stats_lock = threading.Lock()

def share_context(self, key: str, value: Any) -> None:
    # ... deprecation warning ...
    with self._context_lock:
        if key in self.shared_context and isinstance(self.shared_context[key], list):
            # ... existing logic ...

def verify_integrity(self, phase: str, expected: Dict, actual: Dict) -> bool:
    # ... existing logic ...
    with self._stats_lock:
        self.stats["integrity_failures"] += 1
```

**Test:** `tests/unit/test_conductor_threadsafety.py`
- Test concurrent `share_context()` calls don't corrupt data
- Test concurrent `verify_integrity()` calls update stats correctly

---

### WAVE 2: Agent Migration (Redirect Away from Conductor)

#### Task 2.1: Migrate ReportingAgent Away from shared_context
**File:** `bugtrace/agents/reporting.py`
**Line:** 530
**Risk:** Medium (behavior change)

**Current Code:**
```python
from bugtrace.core.conductor import conductor
urls = conductor.get_shared_context("discovered_urls") or []
```

**Migration Options:**
1. ~~Option A: Subscribe to `URL_CRAWLED` events, accumulate locally~~ ❌ Violates persistence (RAM is volatile)
2. Option B: Query StateManager for discovered URLs
3. **Option C (Recommended):** Read from `recon/urls.txt` file (File-Based Source of Truth)

**Why Option C:**
- Files are persistent across crashes
- Aligns with V3.2 architecture ("files are source of truth")
- No risk of data loss if agent restarts
- Already written by GoSpider/ReconAgent

**Implementation (Option C - File-Based):**
```python
class ReportingAgent(BaseAgent):
    def __init__(self, scan_id: int, target_url: str, output_dir: Path, ...):
        # ... existing init ...
        self.scan_dir = output_dir  # e.g., reports/target_20260206_120000/

    def _get_total_urls_discovered(self) -> int:
        """
        Get URL count from file-based source of truth.

        Reads from recon/urls.txt which is written by GoSpider/AssetDiscoveryAgent.
        This survives agent crashes and restarts.
        """
        urls_file = self.scan_dir / "recon" / "urls.txt"

        if not urls_file.exists():
            logger.debug(f"No URLs file found at {urls_file}")
            return 0

        try:
            with open(urls_file, "r") as f:
                urls = [line.strip() for line in f if line.strip()]
            return len(urls)
        except Exception as e:
            logger.warning(f"Failed to read URLs file: {e}")
            return 0
```

**Prerequisite:** Verify GoSpider/AssetDiscoveryAgent writes to `recon/urls.txt`

**Test:** `tests/unit/test_reporting_file_based.py`
- Test ReportingAgent reads URL count from file
- Test graceful handling when file missing
- Test count matches file content

---

#### Task 2.2: Add URL_CRAWLED Event Emission to GoSpiderAgent
**File:** `bugtrace/agents/gospider_agent.py`
**Risk:** Low (additive change)

**Changes:**
1. Emit `URL_CRAWLED` event when new URL discovered
2. Include URL and metadata in event payload

**Code:**
```python
async def _process_discovered_url(self, url: str, source: str):
    """Process a newly discovered URL."""
    # ... existing logic ...

    # Emit event for subscribers (ReportingAgent, etc.)
    await self._event_bus.emit(EventType.URL_CRAWLED.value, {
        "url": url,
        "source": source,
        "scan_context": self.scan_context
    })
```

**Test:** Integration test that GoSpider → URL_CRAWLED → ReportingAgent flow works

---

#### Task 2.3: Automated Conductor Dependency Gate
**Files:** New test file + all agent files
**Risk:** Low (CI gate, no production changes)

**Problem with Manual Grep:** Human error can miss references, especially dynamic ones.

**Solution:** Create automated test that FAILS if any `shared_context` references exist.

**Implementation:**
```python
# tests/unit/test_no_shared_context_usage.py
"""
Gate test: Blocks Wave 4 if shared_context still used anywhere.

This test should be GREEN before proceeding with The Purge.
Run: pytest tests/unit/test_no_shared_context_usage.py -v
"""
import subprocess
import pytest

FORBIDDEN_PATTERNS = [
    r"conductor\.share_context",
    r"conductor\.get_shared_context",
    r"\.shared_context\[",
    r"\.shared_context\.get",
]

ALLOWED_FILES = [
    "bugtrace/core/conductor.py",  # Definition is OK
    "tests/",  # Tests can reference for verification
    ".planning/",  # Documentation OK
]


def test_no_shared_context_usage_in_agents():
    """
    GATE TEST: Ensures no agent code uses shared_context.

    Must pass before Wave 4 (The Purge) can proceed.
    """
    for pattern in FORBIDDEN_PATTERNS:
        result = subprocess.run(
            ["grep", "-rn", "-E", pattern, "bugtrace/"],
            capture_output=True,
            text=True
        )

        if result.returncode == 0:  # Found matches
            # Filter out allowed files
            violations = []
            for line in result.stdout.strip().split("\n"):
                if not any(allowed in line for allowed in ALLOWED_FILES):
                    violations.append(line)

            if violations:
                pytest.fail(
                    f"shared_context still used! Pattern: {pattern}\n"
                    f"Violations:\n" + "\n".join(violations)
                )


def test_no_conductor_import_in_agents():
    """
    Verify agents don't import conductor (except for type hints).
    """
    result = subprocess.run(
        ["grep", "-rn", "from bugtrace.core.conductor import", "bugtrace/agents/"],
        capture_output=True,
        text=True
    )

    if result.returncode == 0:
        lines = result.stdout.strip().split("\n")
        # Filter: TYPE_CHECKING imports are OK
        violations = [l for l in lines if "TYPE_CHECKING" not in l]

        if violations:
            pytest.fail(
                f"Agents still import conductor!\n"
                f"Violations:\n" + "\n".join(violations)
            )
```

**Usage:**
```bash
# Run before Wave 4
pytest tests/unit/test_no_shared_context_usage.py -v

# Expected output after Wave 2 complete:
# test_no_shared_context_usage_in_agents PASSED
# test_no_conductor_import_in_agents PASSED
```

**Gate Rule:** Wave 4 CANNOT proceed until this test passes.

**Deliverable:**
- New test file `tests/unit/test_no_shared_context_usage.py`
- CI integration (optional: add to pre-commit hook)

---

### WAVE 3: Conductor Brain Upgrade (6-Phase Integrity)

#### Task 3.1: Define Integrity Rules for All 6 Phases
**File:** `bugtrace/core/conductor.py`
**Risk:** Low (additive)

**Design Principle:** Use **tolerance margins** and **severity levels** instead of hard errors.

**Why Tolerances?**
- Subdomains may be analyzed that weren't in the initial crawl list
- Some URLs may fail silently (timeouts, WAF blocks)
- Async processing can cause minor count mismatches
- Hard errors would halt pipeline unnecessarily

**New Integrity Rules with Tolerances:**

| Phase | Rule | Tolerance | Severity | Action |
|-------|------|-----------|----------|--------|
| 1. Recon | URLs found > 0 | None | ERROR | Abort if 0 URLs |
| 2. Discovery | Analyzed ≤ Crawled × 1.1 | +10% | WARN | Log warning, continue |
| 3. Strategy | Queued ≤ Analyzed × params × 1.2 | +20% | WARN | Log warning, continue |
| 4. Exploitation | Detected ≤ Queued | None | ERROR | Flag hallucination |
| 5. Validation | Validated + Rejected ≤ Detected × 1.05 | +5% | WARN | Log warning, continue |
| 6. Reporting | Report contains ≥ 95% of validated | -5% | WARN | Log missing findings |

**Code Structure:**
```python
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Tuple

class Severity(Enum):
    INFO = "info"
    WARN = "warn"
    ERROR = "error"
    CRITICAL = "critical"

@dataclass
class IntegrityRule:
    """Defines expected relationship between pipeline phases."""
    phase: str
    input_counter: str
    output_counter: str
    tolerance: float  # e.g., 1.1 means allow +10%
    severity: Severity
    validation_fn: Callable[[int, int, float], Tuple[bool, str]]
    error_message: str

def _validate_with_tolerance(input_count: int, output_count: int, tolerance: float) -> Tuple[bool, str]:
    """
    Generic validator with tolerance margin.

    Args:
        input_count: Expected input count
        output_count: Actual output count
        tolerance: Multiplier (1.1 = allow +10% deviation)

    Returns:
        (passed, detail_message)
    """
    max_allowed = int(input_count * tolerance)

    if output_count <= max_allowed:
        return True, f"OK: {output_count} ≤ {max_allowed} (tolerance: {tolerance})"
    else:
        deviation = ((output_count - input_count) / input_count * 100) if input_count > 0 else 0
        return False, f"DEVIATION: {output_count} > {max_allowed} ({deviation:.1f}% over tolerance)"

INTEGRITY_RULES = {
    "reconnaissance": IntegrityRule(
        phase="reconnaissance",
        input_counter="pipeline_started",
        output_counter="urls_crawled",
        tolerance=1.0,  # Must find at least 1 URL
        severity=Severity.ERROR,
        validation_fn=lambda i, o, t: (o > 0, f"Found {o} URLs"),
        error_message="No URLs discovered during reconnaissance"
    ),
    "discovery": IntegrityRule(
        phase="discovery",
        input_counter="urls_crawled",
        output_counter="urls_analyzed",
        tolerance=1.1,  # Allow +10% (subdomains, redirects)
        severity=Severity.WARN,
        validation_fn=_validate_with_tolerance,
        error_message="Analyzed {output} URLs but only crawled {input}"
    ),
    "strategy": IntegrityRule(
        phase="strategy",
        input_counter="urls_analyzed",
        output_counter="work_queued_total",
        tolerance=1.2,  # Allow +20% (multiple params per URL)
        severity=Severity.WARN,
        validation_fn=_validate_with_tolerance,
        error_message="Queued {output} items from {input} analyzed URLs"
    ),
    "exploitation": IntegrityRule(
        phase="exploitation",
        input_counter="work_queued_total",
        output_counter="vulnerabilities_detected",
        tolerance=1.0,  # Hard limit: can't find more vulns than tested
        severity=Severity.ERROR,
        validation_fn=_validate_with_tolerance,
        error_message="HALLUCINATION: {output} vulns from {input} tests"
    ),
    "validation": IntegrityRule(
        phase="validation",
        input_counter="vulnerabilities_detected",
        output_counter="findings_processed",  # validated + rejected
        tolerance=1.05,  # Allow +5% (race conditions)
        severity=Severity.WARN,
        validation_fn=_validate_with_tolerance,
        error_message="Processed {output} findings but only {input} detected"
    ),
    "reporting": IntegrityRule(
        phase="reporting",
        input_counter="findings_validated",
        output_counter="findings_in_report",
        tolerance=0.95,  # Must include at least 95%
        severity=Severity.WARN,
        validation_fn=lambda i, o, t: (o >= int(i * t), f"Report has {o}/{i} findings"),
        error_message="Report missing findings: {output}/{input}"
    ),
}
```

**Severity Actions:**
- `INFO`: Log only, continue
- `WARN`: Log + increment warning counter, continue
- `ERROR`: Log + emit `PIPELINE_ERROR` event, continue (let operators decide)
- `CRITICAL`: Log + abort pipeline (only for truly unrecoverable states)

---

#### Task 3.2: Implement Event Counter System
**File:** `bugtrace/core/conductor.py`
**Risk:** Medium (new subsystem)

**Changes:**
1. Add `_counters: Dict[str, int]` for tracking event counts
2. Subscribe to relevant EventBus events
3. Increment counters on each event
4. Thread-safe with `_counter_lock`

**Code:**
```python
class ConductorV3:
    def __init__(self, ...):
        # ... existing init ...

        # Event counters for integrity validation
        self._counters: Dict[str, int] = defaultdict(int)
        self._counter_lock = threading.Lock()

        # Subscribe to all tracked events
        self._subscribe_to_tracked_events()

    def _subscribe_to_tracked_events(self):
        """Subscribe to EventBus for counter tracking."""
        tracked_events = [
            EventType.URL_CRAWLED,
            EventType.URL_ANALYZED,
            EventType.VULNERABILITY_DETECTED,
            EventType.FINDING_VALIDATED,
            EventType.FINDING_REJECTED,
        ]
        # Add all WORK_QUEUED_* events
        tracked_events.extend([
            EventType.WORK_QUEUED_XSS,
            EventType.WORK_QUEUED_SQLI,
            # ... etc
        ])

        for event_type in tracked_events:
            event_bus.subscribe(event_type.value, self._increment_counter)

    async def _increment_counter(self, data: Dict):
        """Increment counter for received event."""
        event_type = data.get("_event_type")  # Injected by emit
        with self._counter_lock:
            self._counters[event_type] += 1
```

**Test:** `tests/unit/test_conductor_counters.py`
- Emit 5 URL_CRAWLED → counter shows 5
- Concurrent emissions don't lose counts

---

#### Task 3.3: Upgrade verify_integrity() to 6 Phases
**File:** `bugtrace/core/conductor.py`
**Lines:** 290-378
**Risk:** Medium (logic change)

**Changes:**
1. Replace current 3-phase logic with 6-phase rules
2. Use counter-based validation instead of passed dictionaries
3. Add anomaly detection and alerting

**Code:**
```python
def verify_integrity(self, phase: str) -> Tuple[bool, str]:
    """
    Verify coherence for a completed phase.

    Args:
        phase: Phase name (reconnaissance, discovery, strategy,
               exploitation, validation, reporting)

    Returns:
        (passed, message) tuple
    """
    rule = INTEGRITY_RULES.get(phase)
    if not rule:
        logger.warning(f"Unknown phase: {phase}")
        return True, "Unknown phase (skipped)"

    with self._counter_lock:
        input_count = self._counters.get(rule.input_counter, 0)
        output_count = self._counters.get(rule.output_counter, 0)

    if rule.validation_fn(input_count, output_count):
        self._increment_stat("integrity_passes")
        return True, f"{phase}: OK ({input_count} → {output_count})"
    else:
        self._increment_stat("integrity_failures")
        msg = rule.error_message.format(input=input_count, output=output_count)
        logger.error(f"[Conductor] INTEGRITY FAIL ({phase}): {msg}")
        return False, msg
```

---

#### Task 3.4: Add Phase Completion Hooks
**File:** `bugtrace/core/conductor.py`
**Risk:** Low (additive)

**Changes:**
1. Subscribe to `PHASE_COMPLETE_*` events
2. Auto-verify integrity when phase completes
3. Emit alert if integrity fails

**Code:**
```python
def _subscribe_to_phase_completions(self):
    """Subscribe to phase completion events for auto-verification."""
    phase_events = [
        (EventType.PHASE_COMPLETE_RECONNAISSANCE, "reconnaissance"),
        (EventType.PHASE_COMPLETE_DISCOVERY, "discovery"),
        (EventType.PHASE_COMPLETE_STRATEGY, "strategy"),
        (EventType.PHASE_COMPLETE_EXPLOITATION, "exploitation"),
        (EventType.PHASE_COMPLETE_VALIDATION, "validation"),
        (EventType.PHASE_COMPLETE_REPORTING, "reporting"),
    ]

    for event_type, phase_name in phase_events:
        handler = self._create_phase_handler(phase_name)
        event_bus.subscribe(event_type.value, handler)

def _create_phase_handler(self, phase_name: str):
    """Factory to create phase completion handler."""
    async def handler(data: Dict):
        passed, message = self.verify_integrity(phase_name)
        if not passed:
            # Emit anomaly alert
            await event_bus.emit(EventType.PIPELINE_ERROR.value, {
                "error_type": "INTEGRITY_FAILURE",
                "phase": phase_name,
                "message": message,
                "scan_context": data.get("scan_context")
            })
    return handler
```

---

### WAVE 4: The Purge (Remove shared_context)

#### Task 4.1: Remove shared_context Attributes and Methods
**File:** `bugtrace/core/conductor.py`
**Lines:** 74-82 (attribute), 245-284 (methods)
**Risk:** High (breaking change)

**Prerequisites:**
- Task 2.1 complete (ReportingAgent migrated)
- Task 2.3 confirms no other dependencies
- All deprecation warnings resolved

**Deletions:**
```python
# DELETE from __init__:
self.shared_context: Dict[str, Any] = {
    "discovered_urls": [],
    "confirmed_vulns": [],
    "tested_params": [],
    "scan_metadata": {}
}

# DELETE methods:
def share_context(self, key: str, value: Any) -> None: ...
def get_shared_context(self, key: str = None) -> Any: ...
def get_context_summary(self) -> str: ...
```

**Test:** `tests/unit/test_conductor_v3_no_shared_context.py`
- Verify `hasattr(conductor, 'shared_context')` is False
- Verify `hasattr(conductor, 'share_context')` is False
- Verify pipeline still works without shared_context

---

#### Task 4.2: Update Docstrings and Class Name
**File:** `bugtrace/core/conductor.py`
**Risk:** Low (cosmetic)

**Changes:**
1. Rename class from `ConductorV2` to `ConductorV3`
2. Update module docstring
3. Update class docstring
4. Keep backward-compatible singleton alias

**Code:**
```python
"""
Conductor V3: Pipeline Integrity Auditor ("The Reactor Guardian")

REFACTORED (2026-02-XX): Removed shared_context, now purely event-driven.
Conductor is a PASSIVE OBSERVER that:
- Listens to EventBus events
- Validates pipeline integrity (6 phases)
- Manages protocol files
- Routes UI callbacks

It does NOT:
- Store operational data
- Transfer data between agents
- Touch the hot path
"""

class ConductorV3:
    """
    Pipeline Integrity Auditor ("The Reactor Guardian").

    Passive observer that validates pipeline coherence without
    touching operational data. Agents communicate via EventBus
    and StateManager, not through Conductor.
    """
    ...

# Backward-compatible singleton
conductor = ConductorV3()
ConductorV2 = ConductorV3  # Alias for legacy imports
```

---

#### Task 4.3: Update Tests
**File:** `tests/test_conductor_v2.py` → rename to `tests/test_conductor_v3.py`
**Risk:** Low (test maintenance)

**Changes:**
1. Rename test file
2. Remove tests for `shared_context` methods
3. Add tests for 6-phase integrity
4. Add tests for event counter system
5. Add tests for Fail-Fast behavior

---

### WAVE 5: Documentation & Cleanup

#### Task 5.1: Update CLAUDE.md Architecture Section
**File:** `.claude/CLAUDE.md`
**Risk:** None (documentation)

**Add Section:**
```markdown
### Conductor V3 Architecture (2026-02-XX)

**Core Philosophy:** Conductor is a PASSIVE OBSERVER.

**Before (INCORRECT - V2):**
```
Agent A → conductor.share_context("key", data) → Agent B reads
```

**After (CORRECT - V3):**
```
Agent A → EventBus.emit(EVENT, data) → Agent B subscribes
Agent A → StateManager.save() → Agent B reads from files
Conductor → Listens to events → Validates integrity → Alerts if anomaly
```

**Key Changes:**
- `shared_context` removed entirely
- Integrity validation expanded to 6 phases
- Fail-Fast for missing security rules
- Event counter system for coherence checks
```

---

#### Task 5.2: Archive Old Refactor Plan
**File:** `.ai-context/CONDUCTOR_REFACTOR_PLAN.md`
**Risk:** None (cleanup)

**Changes:**
1. Move to `.ai-context/trash/` or delete
2. Update references to point to new V3 plan

---

## Execution Order Summary

```
┌─────────────────────────────────────────────────────────────────┐
│  WAVE 1: Hardening & Deprecation (Non-Breaking)                 │
│  ├─ Task 1.1: Fail-Fast Protocol Loading                        │
│  ├─ Task 1.2: Deprecation Warnings                              │
│  └─ Task 1.3: asyncio.Lock for Thread-Safety                    │
│                                                                 │
│  COMMIT: "feat(conductor): add Fail-Fast and deprecation prep"  │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  WAVE 2: Agent Migration                                        │
│  ├─ Task 2.1: Migrate ReportingAgent (file-based URL reading)   │
│  ├─ Task 2.2: Add URL_CRAWLED Emission                          │
│  └─ Task 2.3: Create automated gate test (blocks Wave 4)        │
│                                                                 │
│  COMMIT: "refactor(reporting): migrate from shared_context"     │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  WAVE 3: Conductor Brain Upgrade                                │
│  ├─ Task 3.1: Define 6-Phase Rules (with tolerance margins)     │
│  ├─ Task 3.2: Implement Event Counter System                    │
│  ├─ Task 3.3: Upgrade verify_integrity() (severity levels)      │
│  └─ Task 3.4: Add Phase Completion Hooks                        │
│                                                                 │
│  COMMIT: "feat(conductor): 6-phase integrity with tolerances"   │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  WAVE 4: The Purge                                              │
│  ├─ Task 4.1: Remove shared_context                             │
│  ├─ Task 4.2: Rename to ConductorV3                             │
│  └─ Task 4.3: Update Tests                                      │
│                                                                 │
│  COMMIT: "refactor(conductor): V3 - remove shared_context"      │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  WAVE 5: Documentation & Cleanup                                │
│  ├─ Task 5.1: Update CLAUDE.md                                  │
│  └─ Task 5.2: Archive Old Plan                                  │
│                                                                 │
│  COMMIT: "docs: update architecture for Conductor V3"           │
└─────────────────────────────────────────────────────────────────┘
```

---

## Risk Assessment

| Wave | Risk Level | Rollback Strategy |
|------|------------|-------------------|
| 1 | Low | Revert single commit |
| 2 | Low | Revert file read → restore conductor call (file approach is safer than RAM) |
| 3 | Medium | Feature flag for new integrity system; tolerances make it non-breaking |
| 4 | High | Must pass gate test first; no rollback path |
| 5 | None | Documentation only |

**Gate Condition for Wave 4:** `pytest tests/unit/test_no_shared_context_usage.py` must PASS

---

## Success Criteria

1. **No shared_context usage** - `test_no_shared_context_usage.py` passes (automated gate)
2. **6-phase integrity with tolerances** - All phases validated with margins, not hard errors
3. **Fail-Fast works** - Missing `security-rules.md` → exit(1)
4. **File-Based Source of Truth** - ReportingAgent reads from `recon/urls.txt`, not RAM
5. **Pipeline still works** - E2E scan completes successfully
6. **No data loss** - All findings reach reports
7. **Tests pass** - All unit and integration tests green

---

## Estimated Effort

| Wave | Tasks | Estimated Time |
|------|-------|----------------|
| 1 | 3 | 1-2 hours |
| 2 | 3 | 2-3 hours |
| 3 | 4 | 3-4 hours |
| 4 | 3 | 1-2 hours |
| 5 | 2 | 30 min |
| **Total** | **15** | **8-12 hours** |

---

## Files Modified Summary

| File | Wave | Change Type |
|------|------|-------------|
| `bugtrace/core/conductor.py` | 1,3,4 | Major refactor |
| `bugtrace/agents/reporting.py` | 2 | Read from file instead of conductor |
| `bugtrace/agents/gospider_agent.py` | 2 | Add event emission |
| `tests/test_conductor_v2.py` | 4 | Rename + update |
| `tests/unit/test_conductor_*.py` | 1,2,3 | New test files |
| `tests/unit/test_no_shared_context_usage.py` | 2 | **New: Automated gate test** |
| `tests/unit/test_reporting_file_based.py` | 2 | **New: File-based URL reading** |
| `.claude/CLAUDE.md` | 5 | Documentation |
