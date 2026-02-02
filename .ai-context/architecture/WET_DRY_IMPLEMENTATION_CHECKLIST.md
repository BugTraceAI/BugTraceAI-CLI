# WET→DRY Implementation Checklist

**Reference:** WET_DRY_IMPLEMENTATION_GUIDE.md
**Date:** 2026-02-02

---

## Progress Tracker

| # | Agent | Status | File | Notes |
|---|-------|--------|------|-------|
| 1 | SQLiAgent | ✅ COMPLETE | sqli_agent.py | Reference implementation |
| 2 | XXEAgent | ✅ COMPLETE | xxe_agent.py | Simple endpoint-based dedup |
| 3 | IDORAgent | ✅ COMPLETE | idor_agent.py | Similar to XXE |
| 4 | OpenRedirectAgent | ✅ COMPLETE | openredirect_agent.py | Simple param-based |
| 5 | LFIAgent | ✅ COMPLETE | lfi_agent.py | Simple param-based |
| 6 | RCEAgent | ✅ COMPLETE | rce_agent.py | Simple param-based |
| 7 | SSRFAgent | ✅ COMPLETE | ssrf_agent.py | Simple param-based |
| 8 | XSSAgent | ✅ COMPLETE | xss_agent.py | Context-aware (complex) |
| 9 | CSTIAgent | ✅ COMPLETE | csti_agent.py | Template engine detection |
| 10 | PrototypePollutionAgent | ✅ COMPLETE | prototype_pollution_agent.py | JavaScript-specific |
| 11 | JWTAgent | ✅ COMPLETE | jwt_agent.py | Token-based (global) |
| 12 | HeaderInjectionAgent | ✅ COMPLETE | header_injection_agent.py | Header-based (global) |

---

## Per-Agent Implementation Checklist

Copy this section for each agent:

### Agent: [NAME]

**File:** `bugtrace/agents/[name]_agent.py`
**Queue Name:** `"[queue_name]"`
**Fingerprint Method:** `_generate_[vuln]_fingerprint(...)`

#### Step 1: Add Attributes to `__init__`

- [ ] Add `self._dry_findings: List[Dict] = []` after `self._emitted_findings`
- [ ] Location: After line with `_emitted_findings: set = set()`
- [ ] Verify existing `_emitted_findings` and fingerprint method exist

**Code:**
```python
# WET → DRY transformation (Two-phase processing)
self._dry_findings: List[Dict] = []  # Dedup'd findings after Phase A
```

#### Step 2: Implement `analyze_and_dedup_queue()`

- [ ] Add method after existing methods, before `start_queue_consumer()`
- [ ] Update queue name: `queue_manager.get_queue("[queue_name]")`
- [ ] Update agent name in logs: `[{self.name}]`
- [ ] Verify timeout is 300s (matches team.py)
- [ ] Verify stable empty check (10 iterations, 5s total)

**Code Template:** See WET_DRY_IMPLEMENTATION_GUIDE.md Section "Step 2"

**Lines to customize:**
```python
queue = queue_manager.get_queue("[REPLACE_QUEUE_NAME]")  # Line ~10
```

#### Step 3: Implement `_llm_analyze_and_dedup()`

- [ ] Add method after `analyze_and_dedup_queue()`
- [ ] Update vulnerability type in prompt: `<VULN_TYPE>`
- [ ] Add agent-specific deduplication rules
- [ ] Update LLM client call (verify temperature=0.2)

**Agent-Specific Deduplication Rules:**

**[AGENT_NAME] Rules:**
```
[Copy rules from WET_DRY_IMPLEMENTATION_GUIDE.md "Agent-Specific Considerations"]
```

**Lines to customize:**
```python
prompt = f"""You are analyzing {len(wet_findings)} potential [VULN_TYPE] findings.

DEDUPLICATION RULES FOR [VULN_TYPE]:
[AGENT_SPECIFIC_RULES]
```

#### Step 4: Implement `_fallback_fingerprint_dedup()`

- [ ] Add method after `_llm_analyze_and_dedup()`
- [ ] Update fingerprint method call: `self._generate_[vuln]_fingerprint(...)`
- [ ] Verify parameters match existing fingerprint method signature

**Lines to customize:**
```python
fingerprint = self._generate_[VULN]_fingerprint(url, parameter)  # Update params
```

**Verify fingerprint method signature:**
```bash
grep "def _generate_.*_fingerprint" bugtrace/agents/[name]_agent.py
```

#### Step 5: Implement `exploit_dry_list()`

- [ ] Add method after dedup helpers
- [ ] Update vulnerability type: `<VULN_TYPE>`
- [ ] Update attack method call: `self._execute_[vuln]_attack(...)`
- [ ] Verify fingerprint dedup check before emit
- [ ] Update EventType.VULNERABILITY_DETECTED payload

**Lines to customize:**
```python
result = await self._execute_[VULN]_attack(finding)  # Update attack method

# Update event payload
{
    "type": "[VULN_TYPE]",  # e.g., "XSS", "CSTI"
    # ... other fields
}
```

**Find existing attack method:**
```bash
grep "async def.*attack\|async def.*exploit" bugtrace/agents/[name]_agent.py
```

#### Step 6: Implement `_generate_specialist_report()`

- [ ] Add method after `exploit_dry_list()`
- [ ] Update vulnerability type: `<vuln>`
- [ ] Update report path: `[vuln]_report.json`
- [ ] Verify `settings.BASE_DIR` import
- [ ] Verify `mkdir(parents=True, exist_ok=True)`

**Lines to customize:**
```python
from bugtrace.core.config import settings

report = {
    "agent": f"{self.name}",  # Auto-populated
    # ... rest of report
}

report_path = specialists_dir / "[VULN]_report.json"  # e.g., "xss_report.json"
```

#### Step 7: Refactor `start_queue_consumer()`

- [ ] **CRITICAL:** Remove `while not self._stop_requested` infinite loop
- [ ] Add Phase A section with logging
- [ ] Add Phase B section with logging
- [ ] Add early return if no DRY findings
- [ ] Add report generation at end
- [ ] Add termination comment

**Before (WRONG):**
```python
async def start_queue_consumer(self, scan_context: str) -> None:
    self._queue_mode = True
    self._scan_context = scan_context

    while not self._stop_requested:  # ❌ REMOVE THIS
        # ... queue processing ...
        await asyncio.sleep(1)
```

**After (CORRECT):**
```python
async def start_queue_consumer(self, scan_context: str) -> None:
    self._queue_mode = True
    self._scan_context = scan_context

    logger.info(f"[{self.name}] Starting TWO-PHASE queue consumer (WET → DRY)")

    # PHASE A
    logger.info(f"[{self.name}] ===== PHASE A: Analyzing WET list =====")
    dry_list = await self.analyze_and_dedup_queue()

    if not dry_list:
        logger.info(f"[{self.name}] No findings to exploit after deduplication")
        return  # ✅ Terminate

    # PHASE B
    logger.info(f"[{self.name}] ===== PHASE B: Exploiting DRY list =====")
    results = await self.exploit_dry_list()

    # REPORTING
    if results or self._dry_findings:
        await self._generate_specialist_report(results)

    # Method ends - agent terminates ✅
```

#### Step 8: Test Imports

- [ ] Verify all imports at top of file
- [ ] Add missing imports if needed

**Required imports:**
```python
import asyncio
import time
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
import aiofiles

from bugtrace.core.queue import queue_manager
from bugtrace.core.config import settings
from bugtrace.utils.logger import get_logger

logger = get_logger(__name__)
```

#### Step 9: Compile Check

- [ ] Run syntax check
- [ ] Fix any import errors
- [ ] Fix any syntax errors

**Command:**
```bash
python3 -m py_compile bugtrace/agents/[name]_agent.py
```

#### Step 10: Integration Test

- [ ] Run test scan
- [ ] Verify Phase A logs appear
- [ ] Verify Phase B logs appear
- [ ] Verify specialist report is generated
- [ ] Verify agent terminates (no hang)

**Command:**
```bash
.venv/bin/bugtrace scan https://ginandjuice.shop 2>&1 | tee scan_[agent]_test.log
```

**Expected logs:**
```
[AgentName] Starting TWO-PHASE queue consumer (WET → DRY)
[AgentName] ===== PHASE A: Analyzing WET list =====
[AgentName] Phase A: Queue has X items, starting drain...
[AgentName] Phase A: Drained X WET findings from queue
[AgentName] Phase A: Deduplication complete. X WET → Y DRY (Z duplicates removed)
[AgentName] ===== PHASE B: Exploiting DRY list =====
[AgentName] Phase B: Exploiting Y DRY findings...
[AgentName] Phase B: Exploitation complete. N validated findings
[AgentName] Specialist report saved: /path/to/report.json
[AgentName] Queue consumer complete: N validated findings
```

**Verify files:**
```bash
# Check specialist report was created
ls -lh reports/scan_*/specialists/[vuln]_report.json

# Check report content
cat reports/scan_*/specialists/[vuln]_report.json | jq .
```

---

## Batch Commands for Implementation

### Check all agents for infinite loops (MUST BE REMOVED)

```bash
for agent in xxe_agent.py idor_agent.py openredirect_agent.py lfi_agent.py rce_agent.py ssrf_agent.py xss_agent.py csti_agent.py prototype_pollution_agent.py jwt_agent.py header_injection_agent.py; do
    echo "=== $agent ==="
    grep -n "while not self._stop_requested" bugtrace/agents/$agent
done
```

**Expected:** NO MATCHES (infinite loops removed)

### Check all agents have WET→DRY methods

```bash
for agent in xxe_agent.py idor_agent.py openredirect_agent.py lfi_agent.py rce_agent.py ssrf_agent.py xss_agent.py csti_agent.py prototype_pollution_agent.py jwt_agent.py header_injection_agent.py; do
    echo "=== $agent ==="
    grep -c "async def analyze_and_dedup_queue" bugtrace/agents/$agent || echo "MISSING"
    grep -c "async def exploit_dry_list" bugtrace/agents/$agent || echo "MISSING"
    grep -c "async def _generate_specialist_report" bugtrace/agents/$agent || echo "MISSING"
done
```

**Expected:** Each method appears once per agent

### Compile check all agents

```bash
for agent in xxe_agent.py idor_agent.py openredirect_agent.py lfi_agent.py rce_agent.py ssrf_agent.py xss_agent.py csti_agent.py prototype_pollution_agent.py jwt_agent.py header_injection_agent.py; do
    echo "=== Compiling $agent ==="
    python3 -m py_compile bugtrace/agents/$agent && echo "✅ OK" || echo "❌ FAIL"
done
```

**Expected:** All show "✅ OK"

### Run test expert dedup fingerprints

```bash
python3 test_expert_dedup.py
```

**Expected:** All tests pass (fingerprint methods already implemented)

---

## Rollout Strategy

### Phase 1: Simple Agents (Days 1-2)

Implement WET→DRY in agents with simple parameter-based dedup:

- [ ] XXEAgent (endpoint-based)
- [ ] IDORAgent (endpoint-based)
- [ ] OpenRedirectAgent (param-based)
- [ ] LFIAgent (param-based)
- [ ] RCEAgent (param-based)
- [ ] SSRFAgent (param-based)

**Test after each:** Run scan and verify specialist report

### Phase 2: Complex Agents (Days 3-4)

Implement WET→DRY in agents with complex dedup logic:

- [ ] XSSAgent (context-aware)
- [ ] CSTIAgent (template engine detection)
- [ ] PrototypePollutionAgent (JavaScript-specific)

**Test after each:** Run scan and verify specialist report

### Phase 3: Global Dedup Agents (Day 5)

Implement WET→DRY in agents with global dedup:

- [ ] JWTAgent (token-based, netloc-only)
- [ ] HeaderInjectionAgent (header name-only)

**Test after each:** Run scan and verify specialist report

### Phase 4: System Integration Test (Day 6)

- [ ] Run full scan with all agents
- [ ] Verify all specialist reports generated
- [ ] Verify deduplication metrics correct
- [ ] Performance benchmark

---

## Quality Assurance

### Code Review Checklist

For each agent, verify:

- [ ] No `while not self._stop_requested` loops
- [ ] Phase A logging is clear and informative
- [ ] Phase B logging is clear and informative
- [ ] Fingerprint fallback works if LLM fails
- [ ] Specialist report uses absolute path
- [ ] Agent terminates (no infinite loops)
- [ ] Error handling is robust
- [ ] Type hints are correct

### Performance Checklist

- [ ] Phase A completes within 30s per agent
- [ ] Phase B doesn't timeout
- [ ] Total specialist phase < 5 minutes
- [ ] No memory leaks
- [ ] No file descriptor leaks

### Documentation Checklist

- [ ] Update DEDUP_IMPLEMENTATION_STATUS.md
- [ ] Update PIPELINE_FLOW_AND_FILES.md if needed
- [ ] Add agent-specific notes to guide

---

## Common Pitfalls

### ❌ WRONG: Using relative path for report

```python
# BAD
scan_dir = Path(self._scan_context)  # Relative path
```

### ✅ CORRECT: Using absolute path

```python
# GOOD
from bugtrace.core.config import settings
scan_id = self._scan_context.split("/")[-1]
scan_dir = settings.BASE_DIR / "reports" / scan_id  # Absolute path
```

---

### ❌ WRONG: Keeping infinite loop

```python
# BAD
async def start_queue_consumer(self, scan_context: str) -> None:
    while not self._stop_requested:  # ❌ NEVER TERMINATES
        # ... process queue ...
```

### ✅ CORRECT: Single execution

```python
# GOOD
async def start_queue_consumer(self, scan_context: str) -> None:
    # Phase A
    dry_list = await self.analyze_and_dedup_queue()
    if not dry_list:
        return  # ✅ Terminate

    # Phase B
    results = await self.exploit_dry_list()

    # Method ends - agent terminates ✅
```

---

### ❌ WRONG: Wrong fingerprint parameters

```python
# BAD - parameters don't match fingerprint method
fingerprint = self._generate_xss_fingerprint(url, parameter)  # Missing 'context'
```

### ✅ CORRECT: Match fingerprint signature

```python
# GOOD - all parameters provided
fingerprint = self._generate_xss_fingerprint(url, parameter, context)  # ✅ Correct
```

---

## Success Metrics

### Per Agent

- ✅ No compilation errors
- ✅ Phase A logs appear in scan
- ✅ Phase B logs appear in scan
- ✅ WET→DRY count is visible
- ✅ Specialist report generated at correct path
- ✅ Agent terminates successfully
- ✅ No timeout errors

### System-Wide

- ✅ All 12 agents have WET→DRY implementation
- ✅ Test scan completes without errors
- ✅ All specialist reports generated (12 total)
- ✅ Dispatcher activates only necessary agents
- ✅ Total runtime < 5 minutes for test scan
- ✅ Deduplication reduces findings (WET > DRY)
- ✅ Final report shows correct finding counts

---

**Last Updated:** 2026-02-02
**Completion Target:** 12/12 agents (100%)
**Current Status:** 12/12 complete (100%) ✅
