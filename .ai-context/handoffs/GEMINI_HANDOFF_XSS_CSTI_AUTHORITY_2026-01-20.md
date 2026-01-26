# GEMINI HANDOFF: XSS/CSTI Agent Separation Complete

**Date:** 2026-01-20  
**Priority:** COMPLETED ✅  
**Scope:** Separated CSTI into independent agent from XSS

---

## ✅ CHANGES IMPLEMENTED

### 1. Created CSTIAgent V1 (`bugtrace/agents/csti_agent.py`)

A fully independent agent for Client-Side Template Injection detection with:

- **Multi-tier validation:**
  - TIER 1: Arithmetic probes (HTTP-only, no browser) - `{{7*7}}` → `49`
  - TIER 2: Sandbox escape payloads
  - TIER 3: LLM-driven bypass generation

- **Framework support:**
  - Angular (all versions, including sandbox bypasses)
  - Vue.js
  - Handlebars/Mustache
  - ES6 Template Literals
  - ERB/EJS
  - Polymer

- **Authority to confirm:**
  - When arithmetic executes (e.g., `49` appears without literal payload), returns `VALIDATED_CONFIRMED`
  - No browser validation needed for arithmetic checks

### 2. Updated Reactor (`bugtrace/core/reactor.py`)

- Added import for `CSTIAgent`
- Changed CSTI routing: `"CSTI"` or `"TEMPLATE"` vulnerabilities now route to `ATTACK_CSTI` instead of `ATTACK_XSS`
- Added full `ATTACK_CSTI` handler with state persistence

### 3. Cleaned XSSAgent (`bugtrace/agents/xss_agent.py`)

- **Removed** `_check_csti_arithmetic()` method (now in CSTIAgent)
- **Removed** CSTI payloads from `GOLDEN_PAYLOADS`:
  - `{{7*7}}`
  - `{{constructor.constructor(...)}}`
- **Removed** `{}` from `PROBE_STRING` (CSTI characters)
- Updated comments to indicate CSTI is handled by dedicated agent

---

## 📊 ARCHITECTURE IMPACT

| Component | Before | After |
|-----------|--------|-------|
| XSSAgent | Handled XSS + CSTI | Only XSS |
| CSTIAgent | Did not exist | Fully independent specialist |
| Reactor | CSTI → ATTACK_XSS | CSTI → ATTACK_CSTI |

---

## 🎯 EXPECTED BEHAVIOR

### When DASTySASTAgent detects CSTI

1. Creates `ATTACK_CSTI` job
2. Reactor dispatches to `CSTIAgent`
3. CSTIAgent runs:
   - Framework detection (Angular, Vue, etc.)
   - Arithmetic probes (fastest confirmation)
   - Sandbox escape tests
   - LLM bypass generation (if needed)
4. Findings persisted with `type="Confirmed CSTI"`

### When DASTySASTAgent detects XSS

1. Creates `ATTACK_XSS` job
2. Reactor dispatches to `XSSAgent`
3. XSSAgent runs pure XSS tests (no CSTI)

---

## 🔧 FILES MODIFIED

| File | Change |
|------|--------|
| `bugtrace/agents/csti_agent.py` | **NEW** - Full CSTI specialist |
| `bugtrace/core/reactor.py` | Added CSTI import, routing, and handler |
| `bugtrace/agents/xss_agent.py` | Removed CSTI logic and payloads |

---

## ✅ VERIFICATION

```bash
# All imports successful:
python3 -c "from bugtrace.agents.csti_agent import CSTIAgent; from bugtrace.agents.xss_agent import XSSAgent; from bugtrace.core.reactor import Reactor; print('✅ All OK')"
```

---

## 🚀 NEXT STEPS (Optional)

1. **Add Go CSTI Fuzzer** - For even faster arithmetic detection
2. **Browser validation** - Add Playwright validation for sandbox escape confirmation
3. **Interactsh integration** - For OOB CSTI validation (constructor.constructor with fetch)
