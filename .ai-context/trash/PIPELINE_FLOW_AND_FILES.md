# BugTraceAI Pipeline Flow & File Generation

## Pipeline Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                    BUGTRACE PIPELINE v3.1                           │
│                    Sequential Architecture                          │
└─────────────────────────────────────────────────────────────────────┘

Phase 1: RECONNAISSANCE
├─ GoSpider crawling
├─ Tech stack detection
└─ URL discovery
   ├─ Output: discovered_urls.txt
   └─ Output: tech_profile.json

Phase 2-18: DAST ANALYSIS
├─ Cookie SQLi Probe
├─ Parameter Discovery
├─ DASTySASTAgent (LLM-powered analysis)
└─ Vulnerability detection per URL
   └─ Output: URL_ANALYZED events (15 findings detected)

Phase 3: THINKING CONSOLIDATION (Strategy)
├─ Receives URL_ANALYZED events from DAST
├─ LRU cache prevents reprocessing same finding
├─ FP filtering & prioritization
└─ Creates specialist queues (WET lists)
   ├─ Output: Queue files in reports/scan_<id>/queues/
   └─ Distribution: 15 findings → 9 queued (40% cache hits)

Phase 19-20: SPECIALIST AGENTS (Queue Consumer Mode)
├─ SQLiAgent processes SQLi findings
│  └─ Expert deduplication: 4 Cookie SQLi → 1 finding
├─ XSSAgent processes XSS findings
│  └─ Expert deduplication by URL + param + context
├─ XXEAgent processes XXE findings
│  └─ Expert deduplication by endpoint
├─ CSTIAgent processes CSTI findings
│  └─ Expert deduplication by URL + param + template
├─ SSRFAgent, RCEAgent, LFIAgent, IDORAgent, etc.
│  └─ Each with expert-level deduplication
└─ Output: Findings emitted to event bus
   └─ Status: VALIDATED_CONFIRMED / PENDING_VALIDATION

Phase 21: VALIDATION (AgenticValidator)
├─ Playwright validation (L3)
├─ CDP deep validation (L4)
└─ Vision API analysis (optional)
   ├─ Input: 9 findings to validate
   ├─ Output: 2 CDP confirmed
   └─ Average time: 30s per finding

Phase 22: REPORTING
├─ DataCollector aggregation
├─ CVSS/Severity analysis
├─ PoC generation
└─ Report generation
   ├─ raw_findings.json (17 findings - all detections)
   ├─ validated_findings.json (8 findings - validated only)
   ├─ engagement_data.json (5 findings - deduplicated final)
   ├─ final_report.md (professional report)
   ├─ raw_findings.md
   └─ validated_findings.md
```

---

## Detailed Phase Breakdown

### Phase 1: Reconnaissance (Discovery)

**Tools:**
- GoSpider (web crawler)
- Nuclei (tech detection)
- Parameter extractor

**Files Created:**
```
reports/scan_<id>/
├── discovered_urls.txt          # All discovered URLs
├── tech_profile.json            # Detected technologies
├── parameters.json              # Extracted parameters
└── cookies.json                 # Discovered cookies
```

**Duration:** ~10-15s

---

### Phase 2-18: DAST Analysis (Vulnerability Discovery)

**Code:** `pipeline.py:1735` - `self.vulnerabilities_by_url = await self._phase_2_batch_dast()`

**Tools:**
- Cookie SQLi Probe
- DASTySASTAgent (LLM-based, analyzes ALL URLs)
- NucleiAgent
- Multiple vulnerability detectors

**Files Created:**
```
reports/scan_<id>/
└── dastysast/                   # DASTySASTAgent output
    ├── {url1}.json             # Raw findings per URL
    ├── {url2}.json             # NO deduplication yet
    └── {url3}.json             # NO specialist agents started
```

**Events Emitted:**
- `URL_ANALYZED` events per URL analyzed
- Contains findings, parameters, cookies, tech stack

**Important:**
- Raw findings saved to `scan_dir/dastysast/*.json` (NOT in analysis_dir)
- NO deduplication at this stage
- NO specialist agents started yet
- Phases are **conducted but decoupled** (orchestrated by pipeline, independent artifacts)

**Output:**
- 15 findings detected across analyzed URLs
- Findings passed as `URL_ANALYZED` events to Phase 3

**Duration:** ~120-150s

---

### Phase 3: ThinkingConsolidationAgent (Strategy & Queue Creation)

**Process:**
1. Subscribes to `URL_ANALYZED` events from DAST agents
2. Applies LRU cache to prevent reprocessing (max_size=1000)
3. Performs FP filtering (fp_confidence < threshold)
4. Classifies findings by vulnerability type
5. **Creates and populates specialist queues (WET lists)**
6. Emits `work_queued_*` events to trigger specialist agents

**Queue Files Created (WET lists - may contain duplicates):**
```
reports/scan_<id>/queues/
├── sqli/                        # SQLi findings queue (WET)
│   ├── cookie_tracking_id_1.json  # Cookie: TrackingId @ /blog
│   ├── cookie_tracking_id_2.json  # Cookie: TrackingId @ /catalog
│   ├── cookie_tracking_id_3.json  # Cookie: TrackingId @ /about
│   └── cookie_tracking_id_4.json  # Cookie: TrackingId @ /product
├── xss/                         # XSS findings queue (WET)
│   ├── blog_search_param.json
│   └── catalog_search_param.json
├── xxe/                         # XXE findings queue (WET)
│   ├── product_xml_body.json    # /catalog/product?id=2
│   └── stock_check_xml.json     # /catalog/product?id=10
├── csti/                        # CSTI findings queue (WET)
└── [other vulnerability types]/
```

**Cache Behavior:**
- LRU cache prevents reprocessing the exact same finding
- **Not a fixed percentage reduction** - depends on duplicate rate
- Example: 15 findings from DAST → 9 queued (40% were cache hits)

**Duration:** ~5-10s

---

### Phase 19-20: Specialist Agents (Expert Processing - WET → DRY)

**Process (WET list → DRY list transformation):**
Each specialist agent runs as a queue consumer:
1. **Reads WET list:** All findings from queue directory (may contain duplicates)
2. **Validates:** Tests each finding with specialized payloads
3. **Expert deduplication:** Generates fingerprints, checks `_emitted_findings` set
4. **Emits DRY list:** Only unique `VULNERABILITY_DETECTED` events

**WET → DRY Example (SQLiAgent):**
```python
# WET list (4 files in sqli/ queue):
cookie_tracking_id_1.json  # Cookie: TrackingId @ /blog
cookie_tracking_id_2.json  # Cookie: TrackingId @ /catalog
cookie_tracking_id_3.json  # Cookie: TrackingId @ /about
cookie_tracking_id_4.json  # Cookie: TrackingId @ /product

# Expert deduplication fingerprints:
fingerprint_1 = ("SQLI", "cookie", "trackingid")  # ALL SAME
fingerprint_2 = ("SQLI", "cookie", "trackingid")  # DUPLICATE
fingerprint_3 = ("SQLI", "cookie", "trackingid")  # DUPLICATE
fingerprint_4 = ("SQLI", "cookie", "trackingid")  # DUPLICATE

# DRY list (1 event emitted):
VULNERABILITY_DETECTED: Cookie: TrackingId (global cookie vulnerability)
```

**Expert Deduplication Logic:**

```python
# SQLiAgent - Cookie Intelligence
Cookie: TrackingId @ /blog      → ("SQLI", "cookie", "trackingid")
Cookie: TrackingId @ /catalog   → ("SQLI", "cookie", "trackingid")  # DUPLICATE
Cookie: TrackingId @ /about     → ("SQLI", "cookie", "trackingid")  # DUPLICATE
Cookie: TrackingId @ /product   → ("SQLI", "cookie", "trackingid")  # DUPLICATE
Result: 4 findings → 1 finding ✅

# XXEAgent - Endpoint Deduplication
/catalog/product?id=2  → ("https", "shop.com", "/catalog/product", "XXE")
/catalog/product?id=10 → ("https", "shop.com", "/catalog/product", "XXE")  # DUPLICATE
Result: 2 findings → 1 finding ✅

# XSSAgent - Context-Aware
/blog?search=payload (HTML context)   → ("XSS", "shop.com", "/blog", "search", "html")
/blog?search=payload (JS context)     → ("XSS", "shop.com", "/blog", "search", "js")  # DIFFERENT
Result: Both kept (different contexts) ✅
```

**Agents:**
- SQLiAgent (sqli/)
- XSSAgent (xss/)
- XXEAgent (xxe/)
- SSRFAgent (ssrf/)
- RCEAgent (rce/)
- LFIAgent (lfi/)
- CSTIAgent (csti/)
- IDORAgent (idor/)
- JWTAgent (jwt/)
- OpenRedirectAgent (openredirect/)
- PrototypePollutionAgent (prototype_pollution/)
- HeaderInjectionAgent (header_injection/)

**Files Created:**
```
reports/scan_<id>/
└── events/                      # Event bus logs
    └── vulnerability_detected_*.json
```

**Duration:** ~5-10s (queue drain)

---

### Phase 21: Validation (AgenticValidator)

**Process:**
1. Receives findings from event bus
2. Level 3 validation: Playwright browser automation
3. Level 4 validation: CDP (Chrome DevTools Protocol)
4. Vision API: Screenshot analysis (optional)

**Validation Tiers:**
```
VALIDATED_CONFIRMED         # Definitive proof (file exfil, OOB hit)
VALIDATED_LIKELY           # Strong evidence (error messages)
PENDING_VALIDATION         # Needs human verification
REJECTED                   # False positive
```

**Files Created:**
```
reports/scan_<id>/validation/
├── screenshots/             # Visual evidence
│   ├── xss_blog_search.png
│   └── csti_product_page.png
├── cdp_logs/               # Chrome DevTools logs
│   ├── console_output.json
│   └── network_traffic.json
└── validation_cache.json   # Validation results cache
```

**Duration:** ~30s per finding (avg)

---

### Phase 22: Reporting (Final Output)

**Process:**
1. Collect all validated findings from DB
2. Enrich with CVSS scores (LLM-powered)
3. Generate professional PoCs (LLM-powered)
4. **Apply final deduplication** at report level
5. Generate multiple report formats

**Files Created:**
```
reports/scan_<id>/
├── raw_findings.json            # All 17 findings (unvalidated)
├── validated_findings.json      # 8 validated findings
├── engagement_data.json         # 5 unique findings (deduplicated)
├── engagement_data.js           # JavaScript format for UI
├── final_report.md              # Professional markdown report
├── raw_findings.md              # Markdown: all findings
├── validated_findings.md        # Markdown: validated only
└── summary.json                 # Executive summary
```

**Deduplication Messages:**
```
✅ [ReportingAgent] Deduplicated 4 SQLI findings on parameter 'Cookie: TrackingId'
✅ Dedup effectiveness: 40.0%
```

**Duration:** ~15-20s

---

## Complete File Structure

```
reports/scan_<id>/
├── discovered_urls.txt          # Phase 1: Reconnaissance
├── tech_profile.json            # Phase 1: Tech detection
├── parameters.json              # Phase 1: Parameter discovery
├── cookies.json                 # Phase 1: Cookie discovery
│
├── dastysast/                   # Phase 2: DASTySASTAgent raw findings
│   ├── {url1}.json             # Raw findings per URL (NO dedup)
│   ├── {url2}.json             # Analyzed by DASTySASTAgent
│   └── {url3}.json             # Saved before ThinkingConsolidation
│
├── queues/                      # Phase 3: ThinkingConsolidationAgent queues
│   ├── sqli/
│   │   └── *.json              (4 files → expert dedup → 1 finding)
│   ├── xss/
│   │   └── *.json              (3 files)
│   ├── xxe/
│   │   └── *.json              (3 files)
│   └── csti/
│       └── *.json              (2 files)
│
├── events/                      # Phase 19-20: Agent emissions
│   └── vulnerability_detected_*.json
│
├── validation/                  # Phase 21: Validation artifacts
│   ├── screenshots/
│   ├── cdp_logs/
│   └── validation_cache.json
│
├── raw_findings.json            # Phase 22: 17 findings (all)
├── validated_findings.json      # Phase 22: 8 findings (validated)
├── engagement_data.json         # Phase 22: 5 findings (final dedup)
├── engagement_data.js           # Phase 22: UI format
├── final_report.md              # Phase 22: Professional report
├── raw_findings.md              # Phase 22: Markdown all
├── validated_findings.md        # Phase 22: Markdown validated
└── summary.json                 # Phase 22: Executive summary
```

---

## Deduplication Cascade (WET → DRY)

```
Phase 2: DAST Analysis (pipeline.py:1735)
    ↓
  dastysast/*.json (raw findings, NO dedup)
    ↓
  15 findings → URL_ANALYZED events
    ↓
Phase 3: ThinkingConsolidationAgent
    ↓ [LRU cache: Prevent reprocessing]
    ↓ [FP filtering: fp_confidence < threshold]
    ↓
  9 findings → WET lists in queues (sqli/, xss/, xxe/)
    ↓ (WET lists may contain similar findings on different URLs)
    ↓
Phase 19-20: Specialist Agents (WET → DRY transformation)
    ↓ [Read WET list from queue]
    ↓ [Validate each finding]
    ↓ [Expert fingerprint deduplication]
    ↓  - SQLi: 4 files → fingerprint check → 1 unique (Cookie global)
    ↓  - XXE: 2 files → fingerprint check → 1 unique (Endpoint-based)
    ↓  - XSS: Context-aware fingerprints
    ↓ [Emit DRY list: Only unique findings]
    ↓
  DRY: 5-8 unique findings emitted to event bus
    ↓
Phase 21: Validation
    ↓ [CDP/Playwright validation]
    ↓
  8 validated findings → Database
    ↓
Phase 22: Reporting
    ↓ [Final aggregation deduplication]
    ↓
  5 unique findings in engagement_data.json (FINAL)
```

---

## Performance Metrics (ginandjuice.shop scan)

```
URLs analyzed:              4
DAST batch duration:        126.3s
Queue drain duration:       0.0s
Total duration:             140.2s
Estimated sequential time:  360.0s
TIME SAVED:                 61.1% ⚡

Findings pipeline:
  Raw detections:           15 (DAST phase)
  WET lists (queues):       9  (LRU cache hit rate: 40%)
  DRY list (validated):     8  (Expert deduplication applied)
  Final deduplicated:       5  (67% reduction from raw)
```

---

## Key Insights

### 1. WET → DRY Deduplication Flow
- **Layer 1 (ThinkingConsolidation):** LRU cache prevents reprocessing → Creates WET lists
  - WET lists: Queue files may contain similar findings (e.g., same cookie on different URLs)
  - Example: 15 findings → 9 queued (cache hit rate varies per scan)
- **Layer 2 (Expert Agents - WET → DRY):** Fingerprint-based deduplication
  - Reads WET list from queue
  - Validates each finding
  - Applies expert fingerprints: SQLi (cookie intelligence), XXE (endpoint normalization)
  - Emits DRY list: Only unique findings
  - Example: SQLi 4 files (WET) → 1 finding (DRY)
- **Layer 3 (Reporting):** Final aggregation (8 → 5)

### 2. Expert Deduplication Authority
Only specialist agents have the authority to deduplicate because they understand:
- **SQLi:** Cookie-based = global, URL param = endpoint-specific
- **XXE:** Same endpoint with different query params = same vuln
- **XSS:** Same param but different context = different vuln

### 3. File Lifecycle
```
DAST Events (Phase 2-18)  →  Queue Files (Phase 3)  →  Event Bus (Phase 19-20)  →  Database (Phase 21)  →  Report Files (Phase 22)
   URL_ANALYZED events    →  ThinkingConsolidation  →  Specialist Agents emit  →  AgenticValidator     →  DataCollector
```

### 4. Concurrency
- **DAST Phase:** 5 concurrent workers per URL
- **Agent Phase:** 5 workers per agent (parallel processing)
- **Validation Phase:** 3 concurrent validators

---

**Last Updated:** 2026-02-02
**Scan Example:** ginandjuice.shop (scan_id=1)
**Architecture:** V3.1 Sequential Pipeline with Expert Deduplication
