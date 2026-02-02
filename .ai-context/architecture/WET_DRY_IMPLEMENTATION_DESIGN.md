# WET → DRY Implementation Design
**Architecture Change: Incremental Processing → Global Analysis**

**Date:** 2026-02-02
**Status:** DESIGN PHASE - Awaiting Approval

---

## 0. Pipeline Context (CRITICAL)

### Phase 2: DAST Discovery (pipeline.py:1735)

**Pipeline code:**
```python
self.vulnerabilities_by_url = await self._phase_2_batch_dast(dashboard, analysis_dir)
```

**What happens:**
1. **DASTySASTAgent analyzes ALL URLs** (batch mode)
2. **Saves JSON files in:** `scan_dir/dastysast/` (NOT in analysis_dir)
3. **Creates:** `{url}.json` for each analyzed URL
4. **IMPORTANT:** NO deduplication at this stage
5. **IMPORTANT:** NO specialist agents started yet

**File structure created:**
```
reports/scan_<id>/
├── dastysast/
│   ├── https___ginandjuice_shop_blog_post_id_3.json
│   ├── https___ginandjuice_shop_catalog_product_id_1.json
│   ├── https___ginandjuice_shop_about.json
│   └── https___ginandjuice_shop_product_id_5.json
```

**Key principle: Fases conducidas pero desacopladas**
- Pipeline orchestrates phases (conducidas)
- Each phase produces artifacts independently (desacopladas)
- DAST → Raw findings → ThinkingConsolidation → WET lists → Specialists → DRY results

**Flow:**
```
Phase 2 (DAST)          Phase 3 (Thinking)       Phase 19-20 (Specialists)
    ↓                          ↓                          ↓
dastysast/*.json  →  URL_ANALYZED events  →  queues/sqli/*.json (WET)
(raw findings)       (no dedup yet)           (potential duplicates)
                                                      ↓
                                              analyze_and_dedup_queue()
                                              (THIS DESIGN DOC)
```

---

## 1. Executive Summary

### Current Architecture (INCREMENTAL)
```
WorkerPool → Read WET item → Attack immediately → Dedup check → Emit
```

### Target Architecture (GLOBAL ANALYSIS)
```
Phase A: Read ALL WET → LLM Analysis → Generate DRY list
Phase B: Attack each DRY item → Emit findings → Generate specialist report
```

**Impact:** All 12 specialist agents need refactoring.

---

## 2. Detailed Comparison

### 2.1 Current Flow (INCREMENTAL)

```python
# start_queue_consumer()
WorkerPool.start() → Spawns 5 workers

# Worker loop (parallel)
for item in queue:
    result = _process_queue_item(item)     # Attack immediately
    _handle_queue_result(item, result)     # Dedup check
    if not duplicate:
        event_bus.emit(VULNERABILITY_DETECTED)
```

**Problems:**
- No global context analysis
- Attacks potentially duplicate findings
- No specialist report generation
- Wastes time/resources on duplicates

### 2.2 Target Flow (GLOBAL ANALYSIS)

```python
# PHASE A: ANALYSIS (NEW)
async def analyze_and_dedup_queue(self):
    # 1. Read ALL WET files
    wet_findings = load_all_queue_files(queue_dir)

    # 2. LLM Analysis with context
    context = {
        "nuclei_tech": tech_profile.json,
        "urls_scanned": discovered_urls.txt,
        "findings": wet_findings
    }

    # 3. LLM generates DRY list
    dry_list = await self._llm_analyze_and_dedup(wet_findings, context)

    # 4. Save DRY list for Phase B
    self._dry_findings = dry_list
    return dry_list

# PHASE B: EXPLOITATION
async def exploit_dry_list(self):
    results = []
    for dry_item in self._dry_findings:
        result = await self._attack(dry_item)
        if result:
            await self.event_bus.emit(VULNERABILITY_DETECTED, result)
            results.append(result)

    # 5. Generate specialist report
    await self._generate_specialist_report(results)
    return results
```

---

## 3. Implementation Details

### 3.1 New Methods per Agent

Each specialist agent (SQLiAgent, XXEAgent, etc.) needs:

#### Method 1: `analyze_and_dedup_queue()`
```python
async def analyze_and_dedup_queue(self) -> List[Dict]:
    """
    Phase A: Global analysis of WET list.

    Steps:
    1. Read ALL JSON files from queue directory
    2. Load global context (Nuclei, tech stack, URLs)
    3. Call LLM with expert system prompt
    4. LLM returns DRY list (deduplicated findings)
    5. Save DRY list to self._dry_findings

    Returns:
        List of unique findings (DRY list)
    """
```

**LLM System Prompt Template:**
```
You are an expert {VULN_TYPE} security analyst.

Context:
- Target: {target_url}
- Tech Stack: {nuclei_findings}
- URLs Scanned: {url_count}

WET List ({wet_count} findings):
{wet_findings_json}

Task:
1. Analyze each finding for real exploitability
2. Identify attack paths worth testing
3. Apply expert deduplication rules:
   - {agent_specific_rules}
4. Return DRY list in JSON format

Output format:
{
  "dry_findings": [
    {
      "url": "...",
      "parameter": "...",
      "rationale": "why unique",
      "attack_priority": 1-5
    }
  ],
  "duplicates_removed": 10,
  "reasoning": "..."
}
```

#### Method 2: `exploit_dry_list()`
```python
async def exploit_dry_list(self) -> List[Dict]:
    """
    Phase B: Attack each DRY finding.

    Steps:
    1. For each DRY item:
       a. Execute specialized attack
       b. Validate result
       c. Emit VULNERABILITY_DETECTED event
    2. Generate specialist report

    Returns:
        List of validated findings
    """
```

#### Method 3: `_generate_specialist_report()`
```python
async def _generate_specialist_report(self, findings: List[Dict]) -> str:
    """
    Generate specialist report after exploitation.

    Steps:
    1. Summarize findings (validated vs pending)
    2. Technical analysis per finding
    3. Save to: reports/scan_{id}/specialists/{agent_name}_report.json

    Returns:
        Path to generated report
    """
```

### 3.2 Modified Methods

#### `start_queue_consumer()` - Refactored
```python
async def start_queue_consumer(self, scan_context: str) -> None:
    """
    Start specialist agent in TWO-PHASE mode.

    OLD: Start WorkerPool for parallel item processing
    NEW: Execute PHASE A → PHASE B sequentially
    """
    self._queue_mode = True
    self._scan_context = scan_context

    logger.info(f"[{self.name}] PHASE A: Analyzing WET list...")
    dry_list = await self.analyze_and_dedup_queue()
    logger.info(f"[{self.name}] DRY list: {len(dry_list)} unique findings")

    logger.info(f"[{self.name}] PHASE B: Exploiting DRY list...")
    results = await self.exploit_dry_list()
    logger.info(f"[{self.name}] Validated: {len(results)} findings")

    logger.info(f"[{self.name}] Queue consumer complete")
```

### 3.3 Removed/Deprecated Methods

- `_process_queue_item()` - Replaced by `exploit_dry_list()`
- `_handle_queue_result()` - No longer needed (dedup in Phase A)
- WorkerPool usage - No longer needed (sequential Phase A → B)

---

## 4. Agent-Specific Deduplication Rules

### SQLiAgent
```
Rules:
- Cookie-based SQLi: Global (ignore URL)
- Header-based SQLi: Global (ignore URL)
- URL param SQLi: Per-endpoint
- POST param SQLi: Per-endpoint
```

### XXEAgent
```
Rules:
- Same XML endpoint: Duplicate (ignore query params)
- Different endpoint: Unique
```

### XSSAgent
```
Rules:
- Same URL + param + context: Duplicate
- Different context (HTML vs JS): Unique
```

### CSTIAgent
```
Rules:
- Same URL + param + template engine: Duplicate
- Different engine: Unique
```

### IDORAgent
```
Rules:
- Same endpoint + resource type: Duplicate
- Different endpoint: Unique
```

### JWTAgent
```
Rules:
- Same netloc + vuln type: Duplicate (token-level)
- Different vuln type: Unique
```

### Other Agents (SSRF, RCE, LFI, OpenRedirect, PrototypePollution, HeaderInjection)
```
Rules: Similar endpoint-based deduplication
```

---

## 5. File Structure Changes

### 5.1 Current Files (NO CHANGE)
```
reports/scan_<id>/
├── queues/                  # ThinkingConsolidation creates WET lists
│   ├── sqli/*.json
│   ├── xss/*.json
│   └── xxe/*.json
```

### 5.2 New Files (CREATED BY AGENTS)
```
reports/scan_<id>/
├── specialists/             # NEW: Specialist reports directory
│   ├── sqli_report.json    # SQLiAgent report
│   ├── xxe_report.json     # XXEAgent report
│   ├── xss_report.json     # XSSAgent report
│   └── ...
```

### 5.3 Report Format
```json
{
  "agent": "SQLiAgent",
  "scan_id": "scan_123",
  "timestamp": "2026-02-02T10:30:00Z",
  "phase_a": {
    "wet_count": 4,
    "dry_count": 1,
    "duplicates_removed": 3,
    "analysis_duration_s": 5.2
  },
  "phase_b": {
    "attacks_executed": 1,
    "validated_confirmed": 1,
    "validated_likely": 0,
    "pending_validation": 0,
    "exploitation_duration_s": 12.3
  },
  "findings": [
    {
      "type": "SQL Injection",
      "url": "https://shop.com/product",
      "parameter": "Cookie: TrackingId",
      "status": "VALIDATED_CONFIRMED",
      "technique": "error_based",
      "payload": "...",
      "evidence": "..."
    }
  ]
}
```

---

## 6. Integration with Reporting Phase

### 6.1 ReportingAgent Changes

```python
# bugtrace/agents/reporting.py

async def _phase_4_reporting(self, dashboard, scan_dir):
    """
    Phase 6: Generate final reports.

    NEW: Read specialist reports from specialists/ directory
    """
    # 1. Load data
    urls_scanned = self._load_urls(scan_dir / "discovered_urls.txt")
    nuclei_tech = self._load_json(scan_dir / "tech_profile.json")

    # 2. Load specialist reports (NEW)
    specialist_reports = self._load_specialist_reports(scan_dir / "specialists")

    # 3. Load AgenticValidator report
    validator_report = self._load_validator_report(scan_dir / "validation")

    # 4. Aggregate all findings
    all_findings = self._aggregate_findings(
        specialist_reports=specialist_reports,
        validator_report=validator_report
    )

    # 5. Generate final reports
    await self._generate_final_report(
        urls_scanned=urls_scanned,
        nuclei_tech=nuclei_tech,
        specialist_reports=specialist_reports,
        validator_report=validator_report,
        all_findings=all_findings
    )
```

---

## 7. AgenticValidator Scope

**IMPORTANT:** AgenticValidator processes ONLY XSS and CSTI with CDP.

```python
# bugtrace/agents/agentic_validator.py

VALIDATABLE_TYPES = ["XSS", "CSTI"]

async def process_findings(self, findings: List[Dict]):
    """
    Validate findings using CDP (Chrome DevTools Protocol).

    Filters:
    - ONLY XSS and CSTI types
    - Status: PENDING_VALIDATION

    Other types (SQLi, XXE, SSRF, etc.) are NOT validated by this agent.
    """
    for finding in findings:
        if finding["type"] not in VALIDATABLE_TYPES:
            continue  # Skip non-XSS/CSTI

        if finding["status"] != "PENDING_VALIDATION":
            continue  # Skip already validated

        # CDP validation
        result = await self._validate_with_cdp(finding)
        await self._update_finding_status(finding, result)
```

---

## 8. Affected Files

### Core Files to Modify

1. **bugtrace/agents/sqli_agent.py**
   - Add: `analyze_and_dedup_queue()`
   - Add: `exploit_dry_list()`
   - Add: `_generate_specialist_report()`
   - Modify: `start_queue_consumer()`
   - Remove: WorkerPool usage

2. **bugtrace/agents/xxe_agent.py** (same changes)

3. **bugtrace/agents/xss_agent.py** (same changes)

4. **bugtrace/agents/csti_agent.py** (same changes)

5. **bugtrace/agents/ssrf_agent.py** (same changes)

6. **bugtrace/agents/rce_agent.py** (same changes)

7. **bugtrace/agents/lfi_agent.py** (same changes)

8. **bugtrace/agents/idor_agent.py** (same changes)

9. **bugtrace/agents/jwt_agent.py** (same changes)

10. **bugtrace/agents/openredirect_agent.py** (same changes)

11. **bugtrace/agents/prototype_pollution_agent.py** (same changes)

12. **bugtrace/agents/header_injection_agent.py** (same changes)

13. **bugtrace/agents/reporting.py**
    - Add: `_load_specialist_reports()`
    - Modify: `_phase_4_reporting()` to include specialist reports

14. **bugtrace/agents/agentic_validator.py**
    - Verify: ONLY processes XSS and CSTI
    - Document: Other types skip validation

---

## 9. LLM Client Integration

### 9.1 LLM Call per Agent

Each agent makes ONE LLM call in Phase A:

```python
# bugtrace/agents/sqli_agent.py

async def _llm_analyze_and_dedup(
    self,
    wet_findings: List[Dict],
    context: Dict
) -> List[Dict]:
    """
    Call LLM to analyze WET list and generate DRY list.

    Uses: llm_client from bugtrace.core.llm_client
    """
    from bugtrace.core.llm_client import llm_client

    system_prompt = self._build_analysis_prompt(context)
    user_prompt = self._format_wet_findings(wet_findings)

    response = await llm_client.generate(
        system=system_prompt,
        user=user_prompt,
        response_format="json"
    )

    dry_list = self._parse_llm_response(response)
    return dry_list
```

---

## 10. Performance Considerations

### 10.1 Current Performance
```
WorkerPool (5 parallel workers)
- Process items concurrently
- Fast for small queues
- Wastes resources on duplicates
```

### 10.2 New Performance
```
Sequential: Phase A (LLM) → Phase B (Attacks)
- Phase A: ~5-10s (LLM analysis)
- Phase B: Only unique attacks
- Overall: Slower per agent, but:
  - Fewer total attacks (dedup first)
  - Better quality (LLM analysis)
  - Specialist reports generated
```

### 10.3 Mitigation
- Phase A: Use fast model (Haiku) for analysis
- Phase B: Parallel attacks still possible (asyncio.gather)
- Overall pipeline: Multiple agents run in parallel

---

## 11. Testing Strategy

### 11.1 Unit Tests

Create test file: `tests/unit/test_wet_dry_flow.py`

```python
def test_sqli_phase_a_analysis():
    """Test SQLiAgent Phase A: WET → DRY"""
    wet_findings = [
        {"url": "/blog", "parameter": "Cookie: TrackingId"},
        {"url": "/catalog", "parameter": "Cookie: TrackingId"},
        {"url": "/about", "parameter": "Cookie: TrackingId"},
    ]

    agent = SQLiAgent("https://example.com")
    dry_list = await agent.analyze_and_dedup_queue()

    assert len(dry_list) == 1  # Deduplicated
    assert dry_list[0]["parameter"] == "Cookie: TrackingId"

def test_sqli_phase_b_exploitation():
    """Test SQLiAgent Phase B: DRY → Attack"""
    dry_list = [{"url": "...", "parameter": "..."}]

    agent = SQLiAgent("https://example.com")
    agent._dry_findings = dry_list
    results = await agent.exploit_dry_list()

    assert len(results) >= 0  # May be 0 if no validation
```

### 11.2 Integration Tests

Test full pipeline with ginandjuice.shop scan:

```bash
# Expected behavior:
# - SQLi: 4 WET → 1 DRY → 1 validated
# - XXE: 2 WET → 1 DRY → 1 validated
# - XSS: 3 WET → 2 DRY → 2 validated (different contexts)
```

---

## 12. Risks and Mitigation

### Risk 1: LLM Hallucination
**Impact:** LLM might remove valid findings or keep duplicates
**Mitigation:**
- Detailed system prompts with examples
- Validate LLM output format
- Log LLM reasoning for debugging
- Keep WET list as backup

### Risk 2: Slower per Agent
**Impact:** Phase A adds LLM latency (~5-10s)
**Mitigation:**
- Use fast model (Haiku) for Phase A
- Agents still run in parallel
- Overall time saved by avoiding duplicate attacks

### Risk 3: LLM API Failures
**Impact:** Phase A fails, no DRY list generated
**Mitigation:**
- Retry logic with exponential backoff
- Fallback: Use fingerprint dedup (current approach)
- Log errors clearly

### Risk 4: Breaking Existing Functionality
**Impact:** Changes to 12 agents, high risk of bugs
**Mitigation:**
- Implement one agent first (SQLiAgent)
- Test thoroughly
- Roll out to other agents incrementally

---

## 13. Implementation Plan

### Phase 1: Prototype (1 agent)
1. Implement new flow in SQLiAgent only
2. Test with ginandjuice.shop scan
3. Verify deduplication works (4 → 1)
4. Verify specialist report generated

### Phase 2: Core Agents (3 agents)
5. Implement in XXEAgent
6. Implement in XSSAgent
7. Implement in CSTIAgent
8. Test all 4 agents together

### Phase 3: Remaining Agents (8 agents)
9. Implement in remaining agents (SSRF, RCE, LFI, IDOR, JWT, OpenRedirect, PrototypePollution, HeaderInjection)
10. Test full pipeline

### Phase 4: Reporting Integration
11. Modify ReportingAgent to read specialist reports
12. Update final_report.md generation
13. Test end-to-end

### Phase 5: Validation
14. Full scan of ginandjuice.shop
15. Compare results with current implementation
16. Verify deduplication effectiveness
17. Document final metrics

---

## 14. Success Criteria

- ✅ SQLi: 4 WET → 1 DRY (Cookie global dedup)
- ✅ XXE: 2 WET → 1 DRY (Endpoint dedup)
- ✅ XSS: Correct context-based dedup
- ✅ All 12 agents generate specialist reports
- ✅ ReportingAgent reads specialist reports
- ✅ AgenticValidator processes ONLY XSS/CSTI
- ✅ Final report includes all specialist data
- ✅ Overall scan time ≤ current implementation

---

## 15. Rollback Plan

If implementation fails:

1. **Revert commits** to last working state
2. **Keep fingerprint dedup** (already implemented)
3. **Document issues** for future attempt

Git branches:
- `main` - Current working code
- `feat/wet-dry-flow` - New implementation
- Merge only after full validation

---

**NEXT STEP:** Review this design and approve before implementation begins.
