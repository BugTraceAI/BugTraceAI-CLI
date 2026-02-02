# WET→DRY Implementation Guide - Two-Phase Specialist Architecture

**Author:** BugTraceAI Team
**Date:** 2026-02-02
**Reference Implementation:** SQLiAgent (sqli_agent.py)
**Status:** ✅ SQLiAgent Complete, 11 agents pending

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Implementation Steps](#implementation-steps)
3. [Code Templates](#code-templates)
4. [Agent-Specific Considerations](#agent-specific-considerations)
5. [Testing & Validation](#testing--validation)
6. [Troubleshooting](#troubleshooting)

---

## Architecture Overview

### What is WET→DRY?

**WET (Write Everything Twice):**
- Queue files created by ThinkingConsolidationAgent
- May contain duplicates (e.g., same cookie SQLi on different URLs)
- Written to: `reports/scan_<id>/queues/<vuln_type>.queue`
- Format: XML with base64-encoded JSON findings

**DRY (Don't Repeat Yourself):**
- Deduplicated findings after expert analysis
- Only unique vulnerabilities (based on specialist knowledge)
- Emitted as `VULNERABILITY_DETECTED` events to event bus

### Two-Phase Processing

```
┌─────────────────────────────────────────────────────────────┐
│                    SPECIALIST AGENT LIFECYCLE               │
└─────────────────────────────────────────────────────────────┘

Phase A: ANALYSIS & DEDUPLICATION (WET → DRY)
├─ 1. Wait for queue to receive items (max 300s)
├─ 2. Drain ALL items from queue until stable empty
├─ 3. LLM-powered global analysis (with fallback)
├─ 4. Expert fingerprint deduplication
└─ 5. Store DRY list in memory

Phase B: EXPLOITATION (DRY → Validated)
├─ 1. Iterate through DRY list only
├─ 2. Execute specialized attack payloads
├─ 3. Validate each finding
├─ 4. Emit VULNERABILITY_DETECTED events
└─ 5. Generate specialist report

┌─────────────────────────────────────────────────────────────┐
│  KEY: Specialists process ONCE and TERMINATE (no loops)    │
└─────────────────────────────────────────────────────────────┘
```

### Why Two Phases?

1. **Efficiency:** Don't attack duplicate findings
2. **Expert Knowledge:** Only specialist understands what's a duplicate
   - SQLi: Cookie-based = global, URL param = endpoint-specific
   - XXE: Same endpoint = same vuln regardless of query params
   - XSS: Same param but different context = different vuln
3. **LLM Analysis:** Global view of all findings before attacking
4. **Clean Architecture:** Separation of concerns (analyze vs exploit)

---

## Implementation Steps

### Step 0: Prerequisites

✅ **Verify these exist in the agent:**
- `_emitted_findings: set = set()` in `__init__` (for expert dedup)
- `_generate_<vuln>_fingerprint()` method (for expert dedup)
- Fingerprint check before `VULNERABILITY_DETECTED` emit

📚 **Reference:** `.ai-context/audits/DEDUP_IMPLEMENTATION_STATUS.md`

---

### Step 1: Add Two-Phase Attributes to `__init__`

**Location:** Agent's `__init__` method

**Code to add:**
```python
# WET → DRY transformation (Two-phase processing)
self._dry_findings: List[Dict] = []  # Dedup'd findings after Phase A
```

**Example from SQLiAgent (line 317):**
```python
# Expert deduplication: Track emitted findings by fingerprint
self._emitted_findings: set = set()  # (param_type, param_name)

# WET → DRY transformation (Two-phase processing)
self._dry_findings: List[Dict] = []  # Dedup'd findings after Phase A
```

---

### Step 2: Implement `analyze_and_dedup_queue()` Method

**Location:** After existing methods, before `start_queue_consumer()`

**Purpose:** Phase A - Drain WET list and create DRY list

**Template:**
```python
async def analyze_and_dedup_queue(self) -> List[Dict]:
    """
    Phase A: Global analysis of WET list with LLM-powered deduplication.

    Process:
    1. Wait for queue to have items (max 300s - matches team.py timeout)
    2. Drain ALL items until queue is stable empty
    3. LLM analysis for global deduplication (with fallback)
    4. Expert fingerprint deduplication
    5. Return DRY list

    Returns:
        List[Dict]: Deduplicated findings (DRY list)
    """
    from bugtrace.core.queue import queue_manager
    import time

    queue = queue_manager.get_queue("<vuln_type>")  # e.g., "xss", "csti"
    wet_findings = []

    # 1. Wait for queue to have items (max 300s)
    wait_start = time.monotonic()
    max_wait = 300.0

    while (time.monotonic() - wait_start) < max_wait:
        depth = queue.depth() if hasattr(queue, 'depth') else 0
        if depth > 0:
            logger.info(f"[{self.name}] Phase A: Queue has {depth} items, starting drain...")
            break
        await asyncio.sleep(0.5)
    else:
        logger.info(f"[{self.name}] Phase A: No items received after {max_wait}s")
        return []

    # 2. Drain ALL items until queue is stable empty
    empty_count = 0
    max_empty_checks = 10

    while empty_count < max_empty_checks:
        item = await queue.dequeue(timeout=0.5)
        if item is None:
            empty_count += 1
            await asyncio.sleep(0.5)
            continue
        empty_count = 0

        finding = item.get("finding", {}) if isinstance(item, dict) else item
        wet_findings.append({
            "url": finding.get("url", ""),
            "parameter": finding.get("parameter", ""),
            "technique": finding.get("technique", ""),
            "priority": finding.get("priority", 0),
            "finding_data": finding
        })

    logger.info(f"[{self.name}] Phase A: Drained {len(wet_findings)} WET findings from queue")

    if not wet_findings:
        logger.info(f"[{self.name}] Phase A: No findings in WET list")
        return []

    # 3. LLM analysis and dedup (with fallback)
    try:
        dry_list = await self._llm_analyze_and_dedup(wet_findings, self._scan_context)
        logger.info(f"[{self.name}] LLM dedup: {len(wet_findings)} → {len(dry_list)}")
    except Exception as e:
        logger.error(f"[{self.name}] LLM deduplication failed: {e}. Falling back to fingerprint dedup.")
        dry_list = self._fallback_fingerprint_dedup(wet_findings)
        logger.info(f"[{self.name}] Fallback fingerprint dedup: {len(wet_findings)} → {len(dry_list)}")

    # 4. Store DRY list
    self._dry_findings = dry_list

    duplicates_removed = len(wet_findings) - len(dry_list)
    logger.info(f"[{self.name}] Phase A: Deduplication complete. {len(wet_findings)} WET → {len(dry_list)} DRY ({duplicates_removed} duplicates removed)")
    logger.info(f"[{self.name}] DRY list: {len(dry_list)} unique findings to attack")

    return dry_list
```

**Key Points:**
- **Timeout:** 300s matches `team.py:_wait_for_specialist_queues()`
- **Stable Empty:** Wait 10 consecutive empty dequeues (5s total) before considering queue drained
- **Fallback:** Always have fingerprint dedup as fallback if LLM fails
- **Logging:** Detailed logs for debugging WET→DRY process

---

### Step 3: Implement `_llm_analyze_and_dedup()` Helper Method

**Location:** After `analyze_and_dedup_queue()`

**Purpose:** Use LLM for intelligent global deduplication

**Template:**
```python
async def _llm_analyze_and_dedup(self, wet_findings: List[Dict], scan_context: str) -> List[Dict]:
    """
    Use LLM to analyze all WET findings globally and deduplicate intelligently.

    Args:
        wet_findings: All findings from queue (may contain duplicates)
        scan_context: Scan context identifier

    Returns:
        List[Dict]: Deduplicated findings based on LLM analysis
    """
    if not wet_findings:
        return []

    # Build LLM prompt with all findings
    findings_summary = "\n".join([
        f"{i+1}. {f['url']} - {f['parameter']} - {f.get('technique', 'N/A')}"
        for i, f in enumerate(wet_findings)
    ])

    prompt = f"""You are analyzing {len(wet_findings)} potential <VULN_TYPE> findings.

YOUR TASK: Identify which findings are DUPLICATES of the same underlying vulnerability.

FINDINGS:
{findings_summary}

DEDUPLICATION RULES FOR <VULN_TYPE>:
<AGENT_SPECIFIC_RULES>

OUTPUT FORMAT:
Return ONLY a JSON array of indices (1-based) to KEEP. Example: [1, 3, 5]

IMPORTANT:
- If unsure, KEEP the finding (prefer false negatives over false positives in dedup)
- Always keep at least one finding per distinct vulnerability

Your response (JSON array only):"""

    try:
        # Call LLM
        response = await self.llm_client.generate(
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            max_tokens=500
        )

        # Parse response
        import json
        keep_indices = json.loads(response.strip())

        # Filter findings
        dry_list = [wet_findings[i-1] for i in keep_indices if 0 < i <= len(wet_findings)]

        return dry_list

    except Exception as e:
        logger.warning(f"[{self.name}] LLM dedup failed: {e}")
        raise  # Will trigger fallback in caller
```

**Agent-Specific Rules Examples:**

**SQLiAgent:**
```
- Cookie-based SQLi: Same cookie name = DUPLICATE (cookies are global)
- URL parameter SQLi: Same param on different endpoints = DIFFERENT
- Example: "Cookie: TrackingId" on /blog and /catalog = DUPLICATE (keep 1)
```

**XXEAgent:**
```
- Same endpoint = DUPLICATE (regardless of query params)
- Example: /api/product?id=1 and /api/product?id=2 = DUPLICATE (keep 1)
```

**XSSAgent:**
```
- Same URL + param + context = DUPLICATE
- Different context = DIFFERENT (e.g., HTML vs JavaScript)
- Example: /search?q in <div> and /search?q in <script> = DIFFERENT (keep both)
```

---

### Step 4: Implement `_fallback_fingerprint_dedup()` Helper Method

**Location:** After `_llm_analyze_and_dedup()`

**Purpose:** Fingerprint-based dedup as fallback if LLM fails

**Template:**
```python
def _fallback_fingerprint_dedup(self, wet_findings: List[Dict]) -> List[Dict]:
    """
    Fallback fingerprint-based deduplication (no LLM).

    Uses existing `_generate_<vuln>_fingerprint()` method to identify duplicates.

    Args:
        wet_findings: All findings from queue

    Returns:
        List[Dict]: Deduplicated findings based on fingerprints
    """
    seen_fingerprints = set()
    dry_list = []

    for finding in wet_findings:
        url = finding.get("url", "")
        parameter = finding.get("parameter", "")

        # Generate fingerprint using existing method
        fingerprint = self._generate_<vuln>_fingerprint(url, parameter)

        if fingerprint not in seen_fingerprints:
            seen_fingerprints.add(fingerprint)
            dry_list.append(finding)

    return dry_list
```

**Note:** Replace `<vuln>` with actual vulnerability type (e.g., `xss`, `csti`, `xxe`)

---

### Step 5: Implement `exploit_dry_list()` Method

**Location:** After dedup helper methods

**Purpose:** Phase B - Attack only DRY findings

**Template:**
```python
async def exploit_dry_list(self) -> List[Dict]:
    """
    Phase B: Exploit DRY list (deduplicated findings only).

    Process:
    1. Iterate through DRY list
    2. Execute specialized attack payloads
    3. Validate each finding
    4. Emit VULNERABILITY_DETECTED events (with fingerprint check)
    5. Return validated findings

    Returns:
        List[Dict]: Validated findings after exploitation
    """
    if not self._dry_findings:
        logger.info(f"[{self.name}] Phase B: No DRY findings to exploit")
        return []

    logger.info(f"[{self.name}] Phase B: Exploiting {len(self._dry_findings)} DRY findings...")

    validated_findings = []

    for idx, finding in enumerate(self._dry_findings, 1):
        try:
            url = finding.get("url", "")
            parameter = finding.get("parameter", "")

            logger.info(f"[{self.name}] Phase B [{idx}/{len(self._dry_findings)}]: Attacking {url} - {parameter}")

            # Execute specialized attack
            result = await self._execute_<vuln>_attack(finding)

            if result and result.get("validated", False):
                validated_findings.append(result)

                # Emit event with fingerprint dedup check
                fingerprint = self._generate_<vuln>_fingerprint(url, parameter)

                if fingerprint not in self._emitted_findings:
                    self._emitted_findings.add(fingerprint)

                    # Emit VULNERABILITY_DETECTED event
                    await self.event_bus.emit(
                        EventType.VULNERABILITY_DETECTED,
                        {
                            "type": "<VULN_TYPE>",
                            "url": url,
                            "parameter": parameter,
                            "severity": result.get("severity", "High"),
                            "evidence": result.get("evidence", {}),
                            "status": "VALIDATED_CONFIRMED",
                            # ... other fields
                        }
                    )
                    logger.info(f"[{self.name}] ✅ Emitted unique finding: {parameter}")
                else:
                    logger.debug(f"[{self.name}] ⏭️  Skipped duplicate: {fingerprint}")

        except Exception as e:
            logger.error(f"[{self.name}] Phase B [{idx}/{len(self._dry_findings)}]: Attack failed: {e}")
            continue

    logger.info(f"[{self.name}] Phase B: Exploitation complete. {len(validated_findings)} validated findings")

    return validated_findings
```

**Key Points:**
- **NO Queue Draining:** Operates only on `self._dry_findings` (already loaded in Phase A)
- **Fingerprint Check:** Always check `_emitted_findings` before emitting event
- **Error Handling:** Continue on individual attack failures
- **Logging:** Clear progress indicators

---

### Step 6: Implement `_generate_specialist_report()` Method

**Location:** After `exploit_dry_list()`

**Purpose:** Generate JSON report for specialist phase

**Template:**
```python
async def _generate_specialist_report(self, findings: List[Dict]) -> str:
    """
    Generate specialist report after exploitation.

    Steps:
    1. Summarize findings (validated vs pending)
    2. Technical analysis per finding
    3. Save to: reports/scan_{id}/specialists/<vuln>_report.json

    Returns:
        Path to generated report
    """
    from datetime import datetime
    from bugtrace.core.config import settings

    # Create specialists directory (use absolute path)
    scan_id = self._scan_context.split("/")[-1]  # Extract scan ID
    scan_dir = settings.BASE_DIR / "reports" / scan_id
    specialists_dir = scan_dir / "specialists"
    specialists_dir.mkdir(parents=True, exist_ok=True)

    # Build report
    report = {
        "agent": f"{self.name}",
        "scan_id": scan_id,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "phase_a": {
            "wet_count": len(self._dry_findings) + len(findings),  # Estimate
            "dry_count": len(self._dry_findings),
            "duplicates_removed": max(0, len(self._dry_findings) - len(findings)),
            "analysis_duration_s": 0,  # TODO: Track timing
        },
        "phase_b": {
            "dry_exploited": len(self._dry_findings),
            "validated_count": len([f for f in findings if f.get("validated", False)]),
            "pending_count": len([f for f in findings if not f.get("validated", False)]),
            "exploitation_duration_s": 0,  # TODO: Track timing
        },
        "findings": findings,
        "summary": {
            "total_processed": len(self._dry_findings),
            "high_severity": len([f for f in findings if f.get("severity") == "High"]),
            "critical_severity": len([f for f in findings if f.get("severity") == "Critical"]),
        }
    }

    # Save report
    report_path = specialists_dir / f"<vuln>_report.json"
    async with aiofiles.open(report_path, 'w') as f:
        await f.write(json.dumps(report, indent=2))

    logger.info(f"[{self.name}] Specialist report saved: {report_path}")

    return str(report_path)
```

**Key Points:**
- **Absolute Path:** Use `settings.BASE_DIR` to construct full path
- **mkdir(parents=True):** Ensure directory exists
- **Metadata:** Include Phase A and Phase B statistics
- **Async I/O:** Use `aiofiles` for async file writing

---

### Step 7: Refactor `start_queue_consumer()` Method

**Location:** Existing method (refactor)

**Purpose:** Orchestrate Two-Phase processing

**Template:**
```python
async def start_queue_consumer(self, scan_context: str) -> None:
    """
    Start <VulnType>Agent in TWO-PHASE queue consumer mode (V3.1 architecture).

    Phase A: ANALYSIS & DEDUPLICATION
    - Drain WET list from queue
    - LLM-powered global analysis
    - Expert fingerprint deduplication
    - Create DRY list

    Phase B: EXPLOITATION
    - Attack only DRY findings
    - Validate each finding
    - Emit VULNERABILITY_DETECTED events
    - Generate specialist report

    IMPORTANT: This method runs ONCE and TERMINATES (no infinite loop).
    The asyncio.gather() in team.py waits for all specialists to complete.

    Args:
        scan_context: Scan context identifier
    """
    self._queue_mode = True
    self._scan_context = scan_context

    logger.info(f"[{self.name}] Starting TWO-PHASE queue consumer (WET → DRY)")

    # ===== PHASE A: ANALYSIS & DEDUPLICATION =====
    logger.info(f"[{self.name}] ===== PHASE A: Analyzing WET list =====")

    dry_list = await self.analyze_and_dedup_queue()

    if not dry_list:
        logger.info(f"[{self.name}] No findings to exploit after deduplication")
        return  # Terminate, not loop

    # ===== PHASE B: EXPLOITATION =====
    logger.info(f"[{self.name}] ===== PHASE B: Exploiting DRY list =====")

    results = await self.exploit_dry_list()

    # ===== REPORTING =====
    if results or self._dry_findings:
        await self._generate_specialist_report(results)
        logger.info(f"[{self.name}] Queue consumer complete: {len(results)} validated findings")

        # Print specialist report path for user visibility
        scan_id = self._scan_context.split("/")[-1]
        report_path = f"{scan_id}/specialists/<vuln>_report.json"
        logger.info(f"[{self.name}] Specialist report saved to: {report_path}")

    # Method ends here - specialist terminates (asyncio.gather continues)
```

**Key Changes from Original:**
1. ❌ **Remove:** `while not self._stop_requested` infinite loop
2. ✅ **Add:** Two clear phases with logging
3. ✅ **Add:** Early return if no findings
4. ✅ **Add:** Report generation at end
5. ✅ **Add:** Comment explaining termination behavior

---

## Code Templates

### Complete Method Signature Summary

```python
class XSSAgent(BaseAgent):  # Example
    def __init__(self, ...):
        # ... existing code ...
        self._dry_findings: List[Dict] = []  # Add this

    async def analyze_and_dedup_queue(self) -> List[Dict]:
        """Phase A: Drain WET, deduplicate, return DRY"""

    async def _llm_analyze_and_dedup(self, wet_findings: List[Dict], scan_context: str) -> List[Dict]:
        """LLM-powered global analysis"""

    def _fallback_fingerprint_dedup(self, wet_findings: List[Dict]) -> List[Dict]:
        """Fingerprint fallback if LLM fails"""

    async def exploit_dry_list(self) -> List[Dict]:
        """Phase B: Attack DRY findings only"""

    async def _generate_specialist_report(self, findings: List[Dict]) -> str:
        """Generate JSON report"""

    async def start_queue_consumer(self, scan_context: str) -> None:
        """Refactored: Two-phase orchestration (NO infinite loop)"""
```

---

## Agent-Specific Considerations

### XSSAgent (xss_agent.py)

**Queue Name:** `"xss"`

**Fingerprint Method:** `_generate_xss_fingerprint(url, parameter, context)`

**Deduplication Rules:**
```python
# Same URL + param + context = DUPLICATE
# Different context (html, js, attr) = DIFFERENT
```

**Attack Method:** Use existing XSS validation methods

**Special Notes:**
- Context-aware: HTML context ≠ JavaScript context
- Must preserve context information through Phase A → Phase B

---

### XXEAgent (xxe_agent.py)

**Queue Name:** `"xxe"`

**Fingerprint Method:** `_generate_xxe_fingerprint(url)`

**Deduplication Rules:**
```python
# Same endpoint (ignore query params) = DUPLICATE
# Example: /api/product?id=1 and /api/product?id=2 = DUPLICATE
```

**Attack Method:** XML payload injection

**Special Notes:**
- Endpoint-based deduplication (most aggressive)
- Query parameters don't matter for XXE

---

### CSTIAgent (csti_agent.py)

**Queue Name:** `"csti"`

**Fingerprint Method:** `_generate_csti_fingerprint(url, parameter, template_engine)`

**Deduplication Rules:**
```python
# Same URL + param + template engine = DUPLICATE
# Different template engine = DIFFERENT
```

**Attack Method:** Template injection payloads

**Special Notes:**
- Template engine detection is key
- Jinja2 ≠ Mako ≠ Twig (different vulns)

---

### IDORAgent (idor_agent.py)

**Queue Name:** `"idor"`

**Fingerprint Method:** `_generate_idor_fingerprint(url, resource_type)`

**Deduplication Rules:**
```python
# Same endpoint + resource type = DUPLICATE
# Example: /api/users?id=123 and /api/users?id=456 = DUPLICATE
```

**Attack Method:** ID manipulation tests

**Special Notes:**
- Resource type matters (/users vs /orders)
- Similar to XXE (endpoint-based)

---

### OpenRedirectAgent (openredirect_agent.py)

**Queue Name:** `"openredirect"`

**Fingerprint Method:** `_generate_openredirect_fingerprint(url, parameter)`

**Deduplication Rules:**
```python
# Same URL + redirect parameter = DUPLICATE
# Different parameter = DIFFERENT
```

**Attack Method:** URL manipulation

**Special Notes:**
- Parameter-specific (url, redirect, next, etc.)

---

### RCEAgent (rce_agent.py)

**Queue Name:** `"rce"`

**Fingerprint Method:** `_generate_rce_fingerprint(url, parameter)`

**Deduplication Rules:**
```python
# Same URL + parameter = DUPLICATE
```

**Attack Method:** Command injection payloads

**Special Notes:**
- High severity - careful validation required

---

### LFIAgent (lfi_agent.py)

**Queue Name:** `"lfi"`

**Fingerprint Method:** `_generate_lfi_fingerprint(url, parameter)`

**Deduplication Rules:**
```python
# Same URL + parameter = DUPLICATE
```

**Attack Method:** Path traversal tests

**Special Notes:**
- Parameter-specific deduplication

---

### SSRFAgent (ssrf_agent.py)

**Queue Name:** `"ssrf"`

**Fingerprint Method:** `_generate_ssrf_fingerprint(url, parameter)`

**Deduplication Rules:**
```python
# Same URL + parameter = DUPLICATE
```

**Attack Method:** OOB callbacks via Interactsh

**Special Notes:**
- Requires Interactsh for validation

---

### JWTAgent (jwt_agent.py)

**Queue Name:** `"jwt"`

**Fingerprint Method:** `_generate_jwt_fingerprint(url, vuln_type)`

**Deduplication Rules:**
```python
# Same netloc + vuln type = DUPLICATE (JWT is token-specific, not URL-specific)
# Example: /api/auth and /api/profile with "none_alg" = DUPLICATE
```

**Attack Method:** JWT manipulation

**Special Notes:**
- Token-based vulnerabilities are global (not URL-specific)
- Most aggressive deduplication (netloc-based)

---

### PrototypePollutionAgent (prototype_pollution_agent.py)

**Queue Name:** `"prototype_pollution"`

**Fingerprint Method:** `_generate_protopollution_fingerprint(url, parameter)`

**Deduplication Rules:**
```python
# Same URL + parameter = DUPLICATE
```

**Attack Method:** Prototype chain manipulation

**Special Notes:**
- JavaScript-specific vulnerability

---

### HeaderInjectionAgent (header_injection_agent.py)

**Queue Name:** `"header_injection"`

**Fingerprint Method:** `_generate_headerinjection_fingerprint(header_name)`

**Deduplication Rules:**
```python
# Same header name = DUPLICATE (headers are global, not URL-specific)
# Example: "X-Forwarded-Host" on /page1 and /page2 = DUPLICATE
```

**Attack Method:** Header manipulation

**Special Notes:**
- Most aggressive deduplication (header name only)
- Similar to Cookie SQLi (global vulnerability)

---

## Testing & Validation

### Unit Tests

Create tests in `tests/unit/test_<agent>_wet_dry.py`:

```python
def test_phase_a_deduplication():
    """Test Phase A drains queue and deduplicates correctly"""

def test_phase_b_exploitation():
    """Test Phase B attacks only DRY findings"""

def test_llm_dedup_fallback():
    """Test fallback to fingerprint dedup if LLM fails"""

def test_report_generation():
    """Test specialist report is generated with correct path"""
```

### Integration Test

Run full scan:
```bash
.venv/bin/bugtrace scan https://ginandjuice.shop
```

**Expected Behavior:**
1. ✅ PHASE 3: ThinkingConsolidation creates WET lists
2. ✅ PHASE 4: Dispatcher starts only necessary specialists
3. ✅ Agent Phase A: Drains queue, shows "X WET → Y DRY"
4. ✅ Agent Phase B: Attacks Y DRY findings
5. ✅ Report: `reports/scan_<id>/specialists/<vuln>_report.json` exists
6. ✅ Pipeline: All specialists complete and terminate

### Validation Checklist

- [ ] No infinite loops (`while not self._stop_requested`)
- [ ] Phase A logs show WET→DRY count
- [ ] Phase B logs show exploitation progress
- [ ] Specialist report is generated at correct path
- [ ] Agent terminates (doesn't hang)
- [ ] Dispatcher completes successfully
- [ ] No "Queue has 6 items but drained 0" errors
- [ ] Fingerprint dedup fallback works if LLM fails

---

## Troubleshooting

### Issue: "Phase A: Drained 0 WET findings from queue"

**Cause:** Race condition - queue file not loaded yet

**Fix:** Increase wait time or check queue file format

**Verify:**
```bash
# Check queue file exists and has content
cat reports/scan_<id>/queues/<vuln>.queue | head -20
```

---

### Issue: "LLM deduplication failed: TypeError"

**Cause:** LLM response parsing error

**Fix:** Fallback should trigger automatically

**Verify:**
```bash
# Check logs show fallback message
grep "Falling back to fingerprint dedup" scan_test.log
```

---

### Issue: "FileNotFoundError: scan_xxx/specialists"

**Cause:** Relative path used instead of absolute

**Fix:** Use `settings.BASE_DIR / "reports" / scan_id`

**Code:**
```python
from bugtrace.core.config import settings
scan_dir = settings.BASE_DIR / "reports" / scan_id  # Absolute path
```

---

### Issue: Agent hangs forever

**Cause:** Infinite loop in `start_queue_consumer()`

**Fix:** Remove `while not self._stop_requested` loop

**Expected Flow:**
```python
async def start_queue_consumer(self, scan_context: str) -> None:
    # Phase A
    dry_list = await self.analyze_and_dedup_queue()
    if not dry_list:
        return  # ✅ Terminate here

    # Phase B
    results = await self.exploit_dry_list()

    # Report
    await self._generate_specialist_report(results)

    # ✅ Method ends - agent terminates
```

---

## Implementation Order

**Recommended order (based on complexity):**

1. ✅ **SQLiAgent** - Reference implementation (DONE)
2. **XXEAgent** - Simple endpoint-based dedup
3. **IDORAgent** - Similar to XXE
4. **OpenRedirectAgent** - Simple param-based dedup
5. **LFIAgent** - Simple param-based dedup
6. **RCEAgent** - Simple param-based dedup
7. **SSRFAgent** - Simple param-based dedup
8. **XSSAgent** - Context-aware (moderate complexity)
9. **CSTIAgent** - Template engine detection (moderate complexity)
10. **PrototypePollutionAgent** - JavaScript-specific
11. **JWTAgent** - Token-based (global dedup)
12. **HeaderInjectionAgent** - Header-based (global dedup)

---

## Success Criteria

### Per Agent

- [ ] `_dry_findings` attribute added to `__init__`
- [ ] `analyze_and_dedup_queue()` method implemented
- [ ] `_llm_analyze_and_dedup()` helper method implemented
- [ ] `_fallback_fingerprint_dedup()` helper method implemented
- [ ] `exploit_dry_list()` method implemented
- [ ] `_generate_specialist_report()` method implemented
- [ ] `start_queue_consumer()` refactored (no infinite loop)
- [ ] Unit tests created
- [ ] Integration test passes

### System-Wide

- [ ] All 12 agents have WET→DRY implementation
- [ ] Test scan completes without errors
- [ ] All specialist reports generated
- [ ] Dispatcher shows correct agent activation
- [ ] No agents hang or timeout
- [ ] Deduplication metrics visible in logs

---

**Last Updated:** 2026-02-02
**Reference Implementation:** SQLiAgent (bugtrace/agents/sqli_agent.py:2024-2366)
**Status:** Documentation complete, ready for rollout to 11 remaining agents
