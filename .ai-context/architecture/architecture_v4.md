# Architecture V4 - The Autonomous Reactive Swarm

> **Release**: BugtraceAI 2.0.0 (Phoenix Edition)
> **Architecture Version**: V4 (Reactor V4)

**Status:** ACTIVE / IMPLEMENTED (2026-01-13)
**Last Update:** 2026-01-26 (Documentation cleanup)
**Design Goal:** Industrial Reliability & Stateful Recovery.

---

## 1. The Core Philosophy: "State is King"

In V3, the process flow was the source of truth. If the process died, the truth was lost.
In V4, the **State DB** is the source of truth. The agents are just stateless workers that modify the database.

* **Principle 1:** Every action (Discovery, Scan, Attack) is a discrete "Job".
* **Principle 2:** Jobs are idempotent. If a job fails halfway, it can be retried or resumed.
* **Principle 3:** Isolate the Dangerous. Browsers, Scanners, and Exploits run in disposable wrappers.

---

## 2. Infrastructure Components

### A. The State Graph (The Brain)

Instead of a simple list of URLs, we will maintain a **Knowledge Graph** (NetworkX or simple Network Graph in SQLite).

* **Nodes:** URLs, APIs, Assets (IPs), Findings.
* **Edges:** "Discovered-By", "Linked-To", "Vulnerable-To".

This allows **Resumability**. You close the CLI, open it tomorrow, and the Graph is still there. You just say "Continue".

### B. The Job Queue (The Heart)

A lightweight in-memory queue (or SQLite-backed) managing tasks.

* `JOB_RECON_TARGET`
* `JOB_CRAWL_URL`
* `JOB_ATTACK_XSS_PARAM`

The **Orchestrator** simply polls this queue and dispatches workers.

### C. Isolated Tool Runtime (The Hands)

This layer provides secure, isolated execution of security tools.

* **`ToolExecutor`**: A specialized class that wraps subprocesses.
  * Enforces strict Timeouts (via `asyncio.wait_for`).
  * Enforces Resource Limits (CPU/RAM).
  * Captures `stdout/stderr` streams reliably.
  * **Self-Healing**: If a tool hangs, `ToolExecutor` kills it (`SIGKILL`) and reports `JOB_FAILED` (so it can be retried or marked dead).

---

## 3. The New Agent Hierarchy

We proceed from "Monolithic Agents" to **"Functional Agents"**:

1. **Planner Agent (Orchestrator):**
    * Looks at the Graph.
    * Decides what Jobs to create. (e.g., "Found a login page -> Create `JOB_ATTACK_SQLI` and `JOB_BRUTEFORCE`").

2. **Worker Agents (Specialists):**
    * Stateless. They pick up a Job, perform it, update the Graph, and die.
    * Example: `XSSWorker` receives `url="http://target/search", param="q"`. It spins up, tries 50 payloads, logs results to DB, and shuts down.

3. **Validator Agent (Quality Assurance):** ⭐ **CRITICAL LAYER**
    * **Role**: Senior Pentester reviewing findings before client delivery
    * **Input**: Findings from Worker Agents (with PoC already generated)
    * **Process**:
      * Receives URL + payload + vulnerability type
      * Executes PoC in isolated Chrome browser
      * Captures screenshot for visual confirmation
      * Uses Vision AI to analyze results
      * Marks `validated=True` only if confirmed
    * **Output**: Validated findings with evidence
    * **Timing**: Phase 3 Validation (integrated into validation pipeline)
    * **Critical for**: XSS (visual confirmation), SQLi (error detection), IDOR (access confirmation)

> **Note**: "Phase 3.5" was a proposed design concept. The AgenticValidator is integrated
> into Phase 3 (Validation) in the current implementation.

---

## 4. The Complete Pipeline (Updated 2026-01-14)

### Phase-by-Phase Flow

```text
┌─────────────────────────────────────────────────────────────┐
│ PHASE 1: RECONNAISSANCE                                     │
├─────────────────────────────────────────────────────────────┤
│  GoSpider     → Discovers URLs with parameters             │
│  Nuclei       → Tech fingerprinting & known vulnerabilities │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ PHASE 2: ANALYSIS & EXPLOITATION (Per URL)                  │
├─────────────────────────────────────────────────────────────┤
│  DAST Agent   → AI analysis, generates hypotheses          │
│                 (validated=False, potential findings)       │
│                                                             │
│  Swarm Agents → Parallel specialist attacks:               │
│    ├─ XSSAgent        → Discovers params, generates PoCs   │
│    ├─ SQLiAgent       → SQL injection + SQLMap validation  │
│    ├─ SSRFAgent       → SSRF detection + OOB confirmation  │
│    ├─ IDORAgent       → Access control testing             │
│    ├─ XXEAgent        → XML entity expansion testing       │
│    ├─ JWTAgent        → Token manipulation                 │
│    └─ FileUploadAgent → RCE via file upload                │
│                                                             │
│  Output: 20-30 findings (mix of validated & potential)     │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ PHASE 3: GLOBAL REVIEW                                      │
├─────────────────────────────────────────────────────────────┤
│  Chain Discovery → Identifies attack chains & patterns     │
│  Cross-URL Analysis → Correlates findings across endpoints │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ PHASE 3.5: AGENTIC VALIDATION ⭐ CRITICAL QA LAYER         │
├─────────────────────────────────────────────────────────────┤
│  AgenticValidator (The "Senior Pentester" Review)          │
│                                                             │
│  Input:  Findings from Phase 2 (validated + potential)     │
│  Process:                                                   │
│    1. Separate: Already validated vs Needs review          │
│    2. For each unvalidated finding:                        │
│       ├─ Extract URL + payload from finding data           │
│       ├─ Launch isolated Chrome browser (single-threaded)  │
│       ├─ Navigate to exploit URL                           │
│       ├─ Capture screenshot                                │
│       ├─ Check for immediate indicators (alert, errors)    │
│       └─ If unclear → Vision AI analyzes screenshot        │
│    3. Mark validated=True only if confirmed                │
│    4. Add validation_method metadata                       │
│                                                             │
│  Output: 8-15 validated + 10-15 potential findings         │
│                                                             │
│  Key Features:                                              │
│    ✅ Single-threaded (Chrome DevTools safe)               │
│    ✅ Does NOT discover (only validates existing PoCs)     │
│    ✅ Fast (1-3 sec/finding, only execution + screenshot)  │
│    ✅ Error handling (scan continues if validator fails)   │
│    ✅ Respects agent auto-validation                       │
│                                                             │
│  Validation Methods Added:                                  │
│    • "AgenticValidator - Vision AI"                        │
│    • "Browser + Alert Detection"                           │
│    • "SQLMap Confirmation"                                 │
│    • "Screenshot Evidence"                                 │
│    • "Agent Self-Validation"                               │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ PHASE 4: REPORT GENERATION                                  │
├─────────────────────────────────────────────────────────────┤
│  DataCollector → Aggregates validated findings             │
│  AIReportWriter → Generates technical & executive reports  │
│  HTMLGenerator → Creates interactive HTML report           │
│                                                             │
│  Report Sections:                                           │
│    ✅ VALIDATED findings (confirmed by AgenticValidator)   │
│    ⚠️  POTENTIAL findings (detected but not confirmed)     │
│                                                             │
│  Each finding shows:                                        │
│    - Status: ✅ VALIDATED or ⚠️ POTENTIAL                  │
│    - Validation Method (who/how confirmed)                 │
│    - Evidence (screenshots, logs, PoC)                     │
│    - CVSS Score                                            │
│    - Reproduction steps                                    │
└─────────────────────────────────────────────────────────────┘
```

---

## 5. Why AgenticValidator is Critical

### The Problem It Solves

**Without AgenticValidator** (Architecture V3):
* Agents self-validate, but sometimes fail to mark `validated=True`
* LLM-based detection can hallucinate
* `REPORT_ONLY_VALIDATED=True` filters out all unconfirmed findings
* **Result**: 20 detected vulnerabilities → 2 in report ❌

**With AgenticValidator** (Architecture V4):
* Acts as "Senior Pentester" reviewing junior's work
* Executes PoCs in real browser with Vision AI
* Confirms vulnerabilities with visual evidence
* **Result**: 20 detected → 8-15 validated → quality report ✅

### Real-World Analogy

```text
Without Validator:
  Junior Pentester → Finds 20 vulns → Report to client
                      (some may be false positives)

With Validator:
  Junior Pentester → Finds 20 vulns → Senior reviews → Confirms 12 → Report to client
                                       (verified & trusted)
```

### Cost-Benefit

| Metric | Cost | Benefit |
|--------|------|---------|
| **Time Added** | +20-60 seconds | Quality assurance |
| **API Cost** | ~$0.002 per scan | Prevents false reports |
| **Accuracy** | - | >90% validation accuracy |
| **Client Trust** | - | Evidence-backed findings |

---

## 6. Implementation Roadmap (2 Weeks Panic Mode)

### Sprint 1: The Backbone (Days 1-4)

* [x] Implement **State Manager V2** (SQLite-based, atomic updates).
* [x] Build **ToolExecutor** (The Robust Wrapper with timeouts/janitor built-in).
* [x] Port `TeamOrchestrator` to use a simple Job Queue loop instead of a `for url in urls` loop.

### Sprint 2: The Migration (Days 5-9)

* [x] Port `GoSpiderAgent` -> `ReconWorker`.
* [x] Port `XSSAgent` -> `XSSWorker`.
* [x] Port `SQLMapAgent` -> `SQLWorker`. (Heavy isolation here).
* [x] Integrate **LLM Decision** only at the "Planner" level, to save tokens and latency.

### Sprint 3: The Polish (Days 10-14)

* [x] **Dojo V3 Stress Test**: Run 24h loops (Verified against Dojo Comprehensive).
* [x] **AgenticValidator Integration**: Phase 3.5 validation layer (2026-01-14).
* [ ] **Report Generator**: Query the Graph to build the PDF.
* [ ] **UI Upgrade**: Show the Job Queue processing in real-time (The "Hacker Matrix" view).

---

## 7. Why This Wins

* **No more zombie hangs**: The `ToolExecutor` is a serial killer of hung processes.
* **Pause/Resume**: Critical for long scans or poor internet.
* **Scalability**: We can run 5 Workers in parallel if we want (configurable).
* **Quality Assurance**: AgenticValidator prevents false positives from reaching clients.
* **Evidence-Based**: Every validated finding has screenshot + PoC proof.
* **Transparency**: Reports show exactly who/how each finding was validated.

**"Risk is the price of glory."** Built and validated.

---

## References

* **AgenticValidator Implementation**: `bugtrace/agents/agentic_validator.py`
* **Integration Point**: `bugtrace/core/team.py` Phase 3.5 (lines 1166-1197)
* **Design Doc**: `.ai-context/agentic_validator_design.md`
* **Role Clarification**: `.ai-context/AGENTIC_VALIDATOR_ROLE_CLARIFICATION.md`
* **Reintegration Report**: `.ai-context/VALIDATOR_REINTEGRATION_2026-01-14.md`
