# Agent Pipeline Architecture v3.0 Proposal

**Status:** Under Discussion
**Date:** 2026-01-29
**Authors:** BugTraceAI Team

---

## Executive Summary

This document proposes a reorganization of the BugTraceAI agent pipeline from the current 4-phase model to a 5-phase model. The primary goals are:

1. **Better multi-threading utilization** - Specialists work in true parallel
2. **Reduced resource consumption** - HTTP-first validation before browser
3. **Earlier false positive elimination** - SkepticalAgent integrated in Discovery
4. **Intelligent work distribution** - ThinkingConsolidationAgent as central coordinator

---

## Current Architecture (4-Phase Model)

```
┌─────────────────────────────────────────────────────────────────┐
│ PHASE 1: RECONNAISSANCE                                         │
│ ├── GoSpiderAgent (URL Discovery)                               │
│ ├── NucleiAgent (Tech Discovery)                                │
│ ├── AssetDiscoveryAgent (Attack Surface Mapping)                │
│ └── ReconAgent (Visual Intelligence)                            │
├─────────────────────────────────────────────────────────────────┤
│ PHASE 2: URL-BY-URL ANALYSIS                                    │
│ ├── DASTySASTAgent (5 approaches)                               │
│ └── Per-URL specialist deployment                               │
├─────────────────────────────────────────────────────────────────┤
│ PHASE 3: GLOBAL REVIEW & CHAINING                               │
│ ├── ChainDiscoveryAgent                                         │
│ └── APISecurityAgent                                            │
├─────────────────────────────────────────────────────────────────┤
│ PHASE 4: REPORTING & VALIDATION                                 │
│ ├── SkepticalAgent (FP elimination)                             │
│ ├── AgenticValidator (CDP validation)                           │
│ └── ReportingAgent (Final report)                               │
└─────────────────────────────────────────────────────────────────┘
```

### Current Problems

1. **Sequential bottleneck** - Specialists wait for each URL to complete
2. **Browser overuse** - XSSAgent uses Playwright for 100% of candidates
3. **Late FP elimination** - SkepticalAgent runs in Phase 4 (too late)
4. **No deduplication** - Same vulnerability tested multiple times
5. **CDP saturation** - AgenticValidator overwhelmed with edge cases + normal cases

---

## Proposed Architecture (5-Phase Model)

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  FASE 1: DISCOVERY                                              │
│  ════════════════                                               │
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │  GoSpider   │  │ NucleiAgent │  │     SASTDASTAgent       │  │
│  │             │  │             │  │  ┌─────────────────┐    │  │
│  │  URLs List  │  │    Tech     │  │  │ 5 Approaches:   │    │  │
│  │             │  │ Fingerprint │  │  │ 1. Pentester    │    │  │
│  └──────┬──────┘  └──────┬──────┘  │  │ 2. Bug Bounty   │    │  │
│         │                │         │  │ 3. Code Auditor │    │  │
│         │                │         │  │ 4. Red Team     │    │  │
│         │                │         │  │ 5. Researcher   │    │  │
│         │                │         │  │ 6. SKEPTICAL ←──┼────┤  │
│         │                │         │  └─────────────────┘    │  │
│         │                │         └─────────────┬───────────┘  │
│         │                │                       │              │
│         └────────────────┴───────────────────────┘              │
│                          │                                      │
│                          ▼                                      │
│              URL Reports con Análisis Inicial                   │
│              (FPs eliminados temprano)                          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  FASE 2: EVALUACIÓN                                             │
│  ══════════════════                                             │
│                                                                 │
│  ┌─────────────────┐    ┌───────────────────────────────────┐   │
│  │  AnalysisAgent  │───▶│   ThinkingConsolidationAgent      │   │
│  │                 │    │                                   │   │
│  │   Evaluación    │    │   ┌─────────────────────────┐     │   │
│  │   Inteligente   │    │   │ 1. Deduplica findings   │     │   │
│  │                 │    │   │ 2. Clasifica por tipo   │     │   │
│  └─────────────────┘    │   │ 3. Prioriza por prob.   │     │   │
│                         │   │ 4. Distribuye a colas   │     │   │
│                         │   └─────────────────────────┘     │   │
│                         │                                   │   │
│                         │   Output: Colas por especialista  │   │
│                         └───────────────────────────────────┘   │
│                                        │                        │
│         ┌──────────┬──────────┬────────┼────────┬──────────┐    │
│         ▼          ▼          ▼        ▼        ▼          ▼    │
│      [XSS]     [SQLi]     [CSTI]   [LFI]    [SSRF]    [...]    │
│      Queue     Queue      Queue    Queue    Queue     Queues   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  FASE 3: EXPLOITATION (PARALELO MASIVO)                         │
│  ══════════════════════════════════════                         │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                   SPECIALIST AGENTS                      │    │
│  │                   (Todos en paralelo)                    │    │
│  │                                                          │    │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────────────┐│    │
│  │  │   XSS   │ │  SQLi   │ │  CSTI   │ │ OpenRedirect    ││    │
│  │  │ Agent   │ │ Agent   │ │ Agent   │ │ Agent      NEW  ││    │
│  │  │(workers)│ │         │ │         │ │                 ││    │
│  │  └────┬────┘ └────┬────┘ └────┬────┘ └────────┬────────┘│    │
│  │       │           │           │               │         │    │
│  │  ┌────┴────┐ ┌────┴────┐ ┌────┴────┐ ┌───────┴───────┐ │    │
│  │  │   LFI   │ │  IDOR   │ │   RCE   │ │PrototypePoll. │ │    │
│  │  │  Agent  │ │  Agent  │ │  Agent  │ │ Agent    NEW  │ │    │
│  │  └────┬────┘ └────┬────┘ └────┬────┘ └───────┬───────┘ │    │
│  │       │           │           │               │         │    │
│  │  ┌────┴────┐ ┌────┴────┐ ┌────┴────┐ ┌───────┴───────┐ │    │
│  │  │  SSRF   │ │   XXE   │ │   JWT   │ │  FileUpload   │ │    │
│  │  │  Agent  │ │  Agent  │ │  Agent  │ │    Agent      │ │    │
│  │  └────┬────┘ └────┬────┘ └────┬────┘ └───────┬───────┘ │    │
│  │       │           │           │               │         │    │
│  │       └───────────┴───────────┴───────────────┘         │    │
│  │                           │                              │    │
│  │  ┌────────────────────────┴────────────────────────┐    │    │
│  │  │              ADVANCED ANALYSIS                   │    │    │
│  │  │  ┌──────────────────┐  ┌──────────────────────┐ │    │    │
│  │  │  │ChainDiscoveryAgent│  │  APISecurityAgent    │ │    │    │
│  │  │  │(consume findings) │  │  (GraphQL, REST, WS) │ │    │    │
│  │  │  └──────────────────┘  └──────────────────────┘ │    │    │
│  │  └─────────────────────────────────────────────────┘    │    │
│  └─────────────────────────────────────────────────────────┘    │
│                           │                                     │
│           ┌───────────────┴───────────────┐                     │
│           ▼                               ▼                     │
│   ┌───────────────┐               ┌───────────────┐             │
│   │   VALIDATED   │               │    PENDING    │             │
│   │   CONFIRMED   │               │  VALIDATION   │             │
│   └───────┬───────┘               └───────┬───────┘             │
│           │                               │                     │
│           ▼                               ▼                     │
│      Directo a                       A Fase 4                   │
│       Fase 5                                                    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  FASE 4: VALIDATION                                             │
│  ══════════════════                                             │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                  AgenticValidator                        │    │
│  │                                                          │    │
│  │  Input: SOLO findings con status PENDING_VALIDATION      │    │
│  │                                                          │    │
│  │  ┌─────────────────────────────────────────────────┐    │    │
│  │  │  CDP Chrome (single-threaded, exclusive access)  │    │    │
│  │  │                                                  │    │    │
│  │  │  • DOM-based XSS requiring JS execution          │    │    │
│  │  │  • Complex event handlers (autofocus, etc.)      │    │    │
│  │  │  • Sink analysis validation                      │    │    │
│  │  │  • Edge cases from specialists                   │    │    │
│  │  └─────────────────────────────────────────────────┘    │    │
│  │                                                          │    │
│  │  Expected load: ~1% of total candidates (down from 100%)│    │
│  └─────────────────────────────────────────────────────────┘    │
│                           │                                     │
│                           ▼                                     │
│                   VALIDATED or REJECTED                         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  FASE 5: REPORTING                                              │
│  ═════════════════                                              │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                   ReportingAgent                         │    │
│  │                                                          │    │
│  │  Inputs:                                                 │    │
│  │  • VALIDATED_CONFIRMED from Phase 3 (direct)            │    │
│  │  • VALIDATED from Phase 4 (after AgenticValidator)      │    │
│  │                                                          │    │
│  │  Outputs:                                                │    │
│  │  ├── raw_findings.json                                  │    │
│  │  ├── validated_findings.json                            │    │
│  │  ├── final_report.md                                    │    │
│  │  ├── engagement_data.json                               │    │
│  │  └── report.html                                        │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Key Components

### 1. ThinkingConsolidationAgent (NEW)

**Purpose:** Central coordinator that enables true parallel exploitation.

**Responsibilities:**
1. **Deduplication** - Prevents testing same vulnerability multiple times
2. **Classification** - Categorizes findings by vulnerability type
3. **Prioritization** - Ranks by probability of successful exploitation
4. **Distribution** - Routes work to appropriate specialist queues

**Implementation Options:**

```python
# Option A: Batch processing
class ThinkingConsolidationAgent:
    async def process_all_findings(self, findings: List[Finding]) -> Dict[str, Queue]:
        deduplicated = self._deduplicate(findings)
        classified = self._classify_by_type(deduplicated)
        prioritized = self._prioritize(classified)
        return self._distribute_to_queues(prioritized)

# Option B: Streaming (better for large targets)
class ThinkingConsolidationAgent:
    async def process_stream(self, findings_stream: AsyncIterator[Finding]):
        async for finding in findings_stream:
            if not self._is_duplicate(finding):
                queue = self._get_queue_for_type(finding.vuln_type)
                await queue.put(finding)  # Specialists start immediately
```

**Deduplication Keys:**
```python
# Example deduplication logic
def _get_dedup_key(finding: Finding) -> str:
    return f"{finding.vuln_type}:{finding.parameter}:{finding.url_path}"
```

### 2. SkepticalAgent Integration in SASTDASTAgent

**Current:** SkepticalAgent runs in Phase 4 (too late)
**Proposed:** SkepticalAgent as "6th approach" inside SASTDASTAgent

**Benefits:**
- Context is fresh (no need to re-read)
- Immediate FP elimination
- Reduces work for downstream phases

```python
class SASTDASTAgent:
    APPROACHES = [
        "pentester",
        "bug_bounty",
        "code_auditor",
        "red_team",
        "researcher",
        "skeptical"  # NEW: 6th approach for FP elimination
    ]

    async def analyze_url(self, url: str) -> List[Finding]:
        findings = []
        for approach in self.APPROACHES[:5]:
            findings.extend(await self._run_approach(approach, url))

        # 6th approach: Skeptical review
        return await self._skeptical_filter(findings)
```

### 3. XSS HTTP-First Validation

**Current Problem:** XSSAgent uses Playwright for 100% of candidates.

**Proposed Solution:** Three-tier validation hierarchy:

```
┌─────────────────────────────────────────────────────────────┐
│                    XSS VALIDATION FLOW                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Tier 1: HTTP Response Analysis (~90% resolved here)        │
│  ═══════════════════════════════════════════════════        │
│  • Interactsh OOB callback (fastest, definitive)            │
│  • HTTP Manipulator context detection:                      │
│    - Payload inside <script>...</script>                    │
│    - Event handlers (onclick, onerror, onload)              │
│    - javascript: URI scheme                                 │
│    - Template expressions ({{payload}})                     │
│                                                             │
│  If confirmed → VALIDATED_CONFIRMED (skip browser)          │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Tier 2: Playwright Browser (~9% of cases)                  │
│  ═════════════════════════════════════════                  │
│  Only when Tier 1 cannot confirm:                           │
│  • DOM-based XSS (location.hash, postMessage)               │
│  • Payloads requiring JS execution                          │
│  • Autofocus/onfocus handlers                               │
│  • Complex sink analysis                                    │
│                                                             │
│  Uses worker pool for parallelization.                      │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Tier 3: AgenticValidator CDP (~1% of cases)                │
│  ═══════════════════════════════════════════                │
│  Edge cases only:                                           │
│  • Vision AI validation needed                              │
│  • Complex JS execution contexts                            │
│  • Cases where Tier 1+2 are inconclusive                    │
│                                                             │
│  Single-threaded (CDP limitation), but rarely reached.      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Implementation:**

```python
async def _validate(self, param, payload, response_html, screenshots_dir):
    evidence = {"payload": payload}

    # Tier 1: Interactsh OOB (fastest)
    if await self._check_interactsh_hit(param, evidence):
        return True, evidence

    # Tier 1: HTTP Response Analysis (NEW - before browser)
    if self._can_confirm_from_http_response(payload, response_html, evidence):
        evidence["status"] = "VALIDATED_CONFIRMED"
        evidence["method"] = "http_response_analysis"
        return True, evidence

    # Tier 2: Playwright (only if necessary)
    if self._requires_browser_validation(payload, response_html):
        result = await self._run_playwright_validation(...)
        if result.success:
            return True, evidence

    # Tier 3: Mark for AgenticValidator (edge cases)
    if self._check_reflection(payload, response_html, evidence):
        evidence["status"] = "PENDING_CDP_VALIDATION"
        return True, evidence

    return False, evidence

def _can_confirm_from_http_response(self, payload, response_html, evidence) -> bool:
    """Confirm XSS without browser by analyzing HTTP response."""
    context = self._detect_execution_context(payload, response_html)

    if context in ["script_block", "event_handler", "javascript_uri"]:
        evidence["http_confirmed"] = True
        evidence["execution_context"] = context
        return True

    return False

def _requires_browser_validation(self, payload, response_html) -> bool:
    """Determine if Playwright is needed."""
    # DOM-based contexts
    if self._is_dom_based_context():
        return True

    # Event handlers requiring interaction
    if any(x in payload for x in ["autofocus", "onfocus", "onblur"]):
        return True

    # Sink analysis needed
    if self._requires_sink_analysis(response_html):
        return True

    return False
```

---

## Event Bus Communication

```
┌─────────────────────────────────────────────────────────────────┐
│                       EVENT BUS FLOW                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Phase 1 (Discovery):                                           │
│  ────────────────────                                           │
│  GoSpider ──emit──▶ url_discovered                              │
│  NucleiAgent ──emit──▶ tech_fingerprint_ready                   │
│  SASTDASTAgent ──emit──▶ url_analyzed (with findings)           │
│                                                                 │
│  Phase 2 (Evaluation):                                          │
│  ─────────────────────                                          │
│  ThinkingAgent ──subscribe──▶ url_analyzed                      │
│  ThinkingAgent ──emit──▶ work_queued_{specialist}               │
│                                                                 │
│  Phase 3 (Exploitation):                                        │
│  ───────────────────────                                        │
│  Specialists ──subscribe──▶ work_queued_{self}                  │
│  Specialists ──emit──▶ vulnerability_detected                   │
│  Specialists ──emit──▶ finding_validated (direct confirm)       │
│  Specialists ──emit──▶ finding_pending (needs CDP)              │
│                                                                 │
│  Phase 4 (Validation):                                          │
│  ─────────────────────                                          │
│  AgenticValidator ──subscribe──▶ finding_pending                │
│  AgenticValidator ──emit──▶ finding_validated                   │
│                                                                 │
│  Phase 5 (Reporting):                                           │
│  ─────────────────────                                          │
│  ReportingAgent ──subscribe──▶ finding_validated                │
│  ReportingAgent ──emit──▶ report_generated                      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Benefits Summary

| Aspect | Current (4-Phase) | Proposed (5-Phase) |
|--------|-------------------|-------------------|
| **Specialist parallelism** | Sequential per-URL | True parallel via queues |
| **XSS browser usage** | 100% use Playwright | ~10% use Playwright |
| **FP elimination** | Phase 4 (late) | Phase 1 (early) |
| **Deduplication** | None | ThinkingAgent handles |
| **CDP load** | High (all edge cases) | Low (~1% of findings) |
| **Multi-threading** | Limited | Fully utilized |

---

## Implementation Phases

### Phase A: XSS HTTP-First Validation (Phase 15 in v2.2)
- Implement `_can_confirm_from_http_response()`
- Implement `_requires_browser_validation()`
- Reorder validation in `_validate()` method
- Estimated: 3-5 plans

### Phase B: ThinkingConsolidationAgent (v3.0)
- Design queue architecture
- Implement deduplication logic
- Add distribution routing
- Estimated: 5-7 plans

### Phase C: SkepticalAgent Integration (v3.0)
- Move SkepticalAgent logic into SASTDASTAgent
- Add as 6th approach
- Update Phase 1 flow
- Estimated: 2-3 plans

### Phase D: Specialist Queue Consumption (v3.0)
- Modify specialists to consume from queues
- Add worker pools where beneficial (XSS, SQLi)
- Update event bus subscriptions
- Estimated: 5-7 plans

---

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Queue backpressure | Specialists overwhelmed | Implement backpressure handling, rate limiting |
| Deduplication misses | False negatives | Conservative dedup keys, allow user override |
| HTTP analysis FP | False confirmations | Strict context detection, confidence thresholds |
| Migration complexity | Breaking changes | Feature flags, gradual rollout |

---

## Open Questions

1. **Queue persistence:** Should queues be in-memory or persistent (Redis)?
2. **Streaming vs batch:** Which approach for ThinkingAgent?
3. **Worker pool sizing:** How many workers per specialist?
4. **Fallback behavior:** What if ThinkingAgent fails?

---

## References

- Current agent implementations: `bugtrace/agents/`
- Event bus: `bugtrace/core/event_bus.py`
- Team orchestrator: `bugtrace/core/team.py`
- XSS agent: `bugtrace/agents/xss_agent.py` (lines 2401-2438)

---

*Document created: 2026-01-29*
*Last updated: 2026-01-29*
