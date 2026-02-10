# Tech Detection Integration - Agent Architecture Updates

**Date:** 2026-02-02
**Version:** v3.1
**Scope:** Architecture documentation updates for tech detection integration

---

## Overview

This document contains the architectural changes to be integrated into individual agent documentation files following the Tech Detection v3.1 implementation.

**Affected Agents:**
1. ✅ NucleiAgent - 2-phase scan implementation
2. ✅ ThinkingConsolidationAgent - Queue directory fix + XXE dedup
3. ✅ CSTIAgent - Tech-aware Angular prioritization
4. ✅ XSSAgent - Tech profile loading
5. ✅ SQLiAgent - Tech profile loading
6. ✅ DASTySASTAgent (AnalysisAgent) - LLM context enhancement
7. ✅ ReportingAgent - Technology Stack section

---

## 1. NucleiAgent Architecture Update

**Location:** `.ai-context/architecture/agents/nuclei_agent.md`

### Changes Required

#### Section: "Arquitectura de Template-Based Scanning"
**Add NEW subsection after existing workflow:**

```markdown
### 🆕 v3.1: Two-Phase Scanning Architecture (Tech Detection + Vulnerability Discovery)

Starting in v3.1, NucleiAgent executes a **two-phase scan** to provide technology context for specialist agents:

```
┌─────────────────────────────────────────────────────────────────┐
│            NUCLEI AGENT v3.1 - TWO-PHASE WORKFLOW               │
└─────────────────────────────────────────────────────────────────┘

Input: Target URL (from TeamOrchestrator)
│
▼
┌────────────────────────────────────────────────────────────────┐
│ PHASE 1: TECHNOLOGY DETECTION (15-20s)                         │
├────────────────────────────────────────────────────────────────┤
│  🔍 Tech Stack Fingerprinting                                  │
│  • Command: nuclei -u <URL> -tags tech -silent -jsonl         │
│  • Templates: ~500 tech detection templates                    │
│  • Detects: Frameworks, servers, infrastructure, WAF, CDN      │
│                                                                 │
│  Example Output:                                                │
│  {                                                              │
│    "template-id": "angular-detect",                            │
│    "info": {                                                    │
│      "name": "AngularJS 1.7.7 Detected",                       │
│      "tags": ["tech", "angular", "detect"]                     │
│    }                                                            │
│  }                                                              │
│                                                                 │
│  Output: tech_findings[] → Parse & Categorize                  │
└────────────┬───────────────────────────────────────────────────┘
             │
             ▼
┌────────────────────────────────────────────────────────────────┐
│ CATEGORIZATION: Technology Profile Builder                     │
├────────────────────────────────────────────────────────────────┤
│  🏗️ Parse tech_findings and categorize into:                  │
│                                                                 │
│  tech_profile = {                                              │
│    "infrastructure": ["AWS ALB", "Cloudflare"],                │
│    "frameworks": ["AngularJS 1.7.7"],                          │
│    "languages": ["PHP 7.4"],                                   │
│    "servers": ["Nginx 1.18"],                                  │
│    "cms": ["WordPress 5.8"],                                   │
│    "waf": ["Cloudflare WAF"],                                  │
│    "cdn": ["Cloudflare"],                                      │
│    "tech_tags": ["angular-detect", "nginx-version", ...]       │
│  }                                                              │
│                                                                 │
│  Save to: {scan_dir}/recon/tech_profile.json                   │
└────────────┬───────────────────────────────────────────────────┘
             │
             ▼
┌────────────────────────────────────────────────────────────────┐
│ PHASE 2: VULNERABILITY SCAN (45-60s)                           │
├────────────────────────────────────────────────────────────────┤
│  ⚡ Automatic Scan Mode                                        │
│  • Command: nuclei -u <URL> -as -silent -jsonl                │
│  • Templates: ~6000+ vulnerability templates                   │
│  • Auto-selects relevant templates based on response           │
│  • Detects: CVEs, misconfigs, exposures                        │
│                                                                 │
│  Output: vuln_findings[] → Vulnerability discoveries           │
└────────────┬───────────────────────────────────────────────────┘
             │
             ▼
┌────────────────────────────────────────────────────────────────┐
│ RETURN: Complete tech_profile to TeamOrchestrator              │
│                                                                 │
│ return {                                                        │
│   "url": target,                                               │
│   "infrastructure": [...],                                     │
│   "frameworks": [...],                                         │
│   ... (all categories),                                        │
│   "raw_tech_findings": tech_findings,                          │
│   "raw_vuln_findings": vuln_findings                           │
│ }                                                               │
└────────────────────────────────────────────────────────────────┘
```

**Key Benefits:**

1. **Specialist Context:** Agents know what tech they're attacking (Angular, React, WordPress)
2. **Smarter Payloads:** CSTI prioritizes Angular-specific exploits if AngularJS detected
3. **WAF Awareness:** Agents adapt techniques when WAF/CDN detected
4. **Better Reports:** Final report includes Technology Stack section

**Performance Impact:**
- Phase 1 (tech): ~15-20 seconds
- Phase 2 (vulns): ~45-60 seconds
- **Total:** ~60-80 seconds (+33% vs old single-phase)
- **Trade-off:** Acceptable for context-aware exploitation

**File Persistence:**
```
{scan_dir}/recon/
├── tech_profile.json          ← Main tech profile (consumed by specialists)
├── nuclei_tech_raw.json       ← Raw Phase 1 output (debugging)
└── nuclei_vulns_raw.json      ← Raw Phase 2 output (debugging)
```

**Error Handling:**
If Phase 1 fails, returns empty tech_profile with all arrays empty. Specialists gracefully degrade to generic payloads.
```

---

## 2. ThinkingConsolidationAgent Architecture Update

**Location:** `.ai-context/architecture/agents/thinking_consolidation_agent.md`

### Changes Required

#### Section: Add NEW subsection "v3.1 Improvements"

```markdown
## 🆕 v3.1 Improvements

### 1. Queue Directory Location Fix

**Problem (v3.0):**
Queue files were created in wrong directory due to directory name pattern matching:
```python
# OLD CODE (BROKEN)
def _get_queues_dir(self) -> Path:
    # Search for directory containing scan_context
    for candidate in self.report_dir.parent.iterdir():
        if self.scan_context in candidate.name:
            return candidate / "queues"
```

**Issue:** TeamOrchestrator uses `{domain}_{timestamp}` format, not `scan_{scan_context}`. This caused queue files to be created in directories like:
```
BugtraceAI-CLI_scan_scan_20260202/queues/  ❌ WRONG
```

**Solution (v3.1):**
Pass `scan_dir` directly from TeamOrchestrator:
```python
# NEW CODE (FIXED)
def __init__(self, scan_context: str = None, scan_dir: Path = None):
    self.scan_dir = scan_dir  # Direct path from orchestrator

def _get_queues_dir(self) -> Path:
    return self.scan_dir / "queues"  # No more searching
```

**Result:**
```
example_com_20260202/queues/xss.queue  ✅ CORRECT
```

**Code Location:** [bugtrace/agents/thinking_consolidation_agent.py:45-50](../../bugtrace/agents/thinking_consolidation_agent.py#L45-L50)

---

### 2. Enhanced XXE Parameter Normalization

**Problem (v3.0):**
LLM generated inconsistent XXE parameter names:
- "POST Body"
- "POST Body (Stock Check)"
- "XML Body (stockCheckForm)"
- "Request Body (XML)"

These bypassed deduplication, causing 6-12 duplicate XXE findings per endpoint.

**Solution (v3.1):**
Enhanced `_normalize_parameter()` to detect ANY XXE-related keyword:
```python
def _normalize_parameter(self, param: str, vuln_type: str) -> str:
    param_lower = param.lower()

    # XXE: Normalize all POST body variations
    if vuln_type == "xxe":
        xxe_indicators = ["post", "body", "xml", "stock", "form"]
        if any(indicator in param_lower for indicator in xxe_indicators):
            return "post_body"  # All variations → same fingerprint

    # SQLi: Normalize query parameters
    if vuln_type == "sqli":
        if any(x in param_lower for x in ["id", "product", "item", "user"]):
            return re.sub(r'\d+', 'N', param)

    return param
```

**Result:**
- Before: 6-12 XXE duplicates per endpoint
- After: 1-2 XXE duplicates per endpoint (only legitimate variations)

**Code Location:** [bugtrace/agents/thinking_consolidation_agent.py:380-395](../../bugtrace/agents/thinking_consolidation_agent.py#L380-L395)
```

---

## 3. CSTIAgent Architecture Update

**Location:** `.ai-context/architecture/agents/csti_agent.md`

### Changes Required

#### Section: Add NEW subsection "Tech-Aware Payload Prioritization"

```markdown
## 🆕 v3.1: Tech-Aware Payload Prioritization

### Technology Profile Integration

CSTIAgent now loads `tech_profile.json` (created by NucleiAgent) to prioritize framework-specific exploits:

```python
from bugtrace.utils.tech_loader import load_tech_profile

class CSTIAgent(BaseAgent):
    def __init__(self, target, report_dir, ...):
        super().__init__(...)
        self.tech_profile = load_tech_profile(self.report_dir)
```

**Tech Profile Structure:**
```json
{
  "frameworks": ["AngularJS 1.7.7", "jQuery 3.6"],
  "servers": ["Nginx 1.18"],
  "waf": ["Cloudflare WAF"]
}
```

---

### AngularJS Detection & Prioritization

When AngularJS is detected in `tech_profile["frameworks"]`, CSTIAgent **prioritizes Angular-specific CSTI payloads**:

**Implementation:**
```python
async def _targeted_probe(self, session, param, engines) -> Optional[Dict]:
    # Enhance engine detection with tech_profile data
    tech_engines = []

    if self.tech_profile and self.tech_profile.get("frameworks"):
        for framework in self.tech_profile["frameworks"]:
            fw_lower = framework.lower()

            # Detect AngularJS
            if "angular" in fw_lower:
                tech_engines.append("angular")
                logger.info(f"[{self.name}] Tech-aware: Prioritizing Angular CSTI (detected: {framework})")

            # Future: React, Vue, etc.
            elif "vue" in fw_lower:
                tech_engines.append("vue")

    # Merge: tech_engines FIRST, then regular detected engines
    prioritized_engines = list(dict.fromkeys(tech_engines + engines))

    # Now try payloads in priority order
    for engine in prioritized_engines:
        payloads = self._get_payloads_for_engine(engine)
        # ... exploitation logic
```

**Example Scenario:**

1. **NucleiAgent detects:** "AngularJS 1.7.7"
2. **CSTIAgent loads tech_profile:** `{"frameworks": ["AngularJS 1.7.7"]}`
3. **Payload order changes:**

**Before (v3.0 - Generic):**
```python
payloads = [
    "{{7*7}}",                      # Generic template injection
    "${7*7}",                       # Generic EL injection
    "{{constructor.constructor('alert(1)')()}}"  # Angular (but tried late)
]
```

**After (v3.1 - Tech-Aware):**
```python
payloads = [
    "{{constructor.constructor('alert(1)')()}}",  # Angular 1.x sandbox escape (PRIORITY)
    "{{$eval.constructor('alert(1)')()}}",        # Angular $eval bypass (PRIORITY)
    "{{7*7}}",                                     # Generic detection
    "${7*7}",                                      # Other templates
]
```

**Result:** Angular-specific bypasses are tried **first**, increasing success rate and reducing scan time.

---

### Graceful Degradation

If `tech_profile.json` doesn't exist or is empty:
- `load_tech_profile()` returns empty dict with all categories as `[]`
- CSTIAgent continues with generic payload ordering
- No errors, no crashes - fully backward compatible

**Code Location:** [bugtrace/agents/csti_agent.py:185-205](../../bugtrace/agents/csti_agent.py#L185-L205)
```

---

## 4. XSSAgent / SQLiAgent Architecture Update

**Location:** `.ai-context/architecture/agents/xss_agent.md` and `sqli_agent.md`

### Changes Required

#### Section: Add to "Initialization" section

```markdown
### Tech Profile Loading (v3.1)

All specialist agents now load the technology profile on initialization:

```python
from bugtrace.utils.tech_loader import load_tech_profile

class XSSAgent(BaseAgent):
    def __init__(self, target: str, report_dir: Path, ...):
        super().__init__(...)

        # Load tech profile for context-aware exploitation
        self.tech_profile = load_tech_profile(self.report_dir)

        # Tech profile contains:
        # - frameworks: ["React 18.2", "AngularJS 1.7"]
        # - servers: ["Nginx 1.18"]
        # - waf: ["Cloudflare WAF"]
        # - infrastructure: ["AWS ALB", "Cloudflare"]
```

**Use Cases:**

1. **WAF-Aware Testing:**
   ```python
   if self.tech_profile.get("waf"):
       # Adapt payload encoding when WAF detected
       payloads = self._get_waf_bypass_payloads()
   ```

2. **Framework-Specific Escaping:**
   ```python
   if "react" in str(self.tech_profile.get("frameworks")).lower():
       # React uses JSX - standard XSS payloads work
       payloads = self._get_standard_xss_payloads()
   elif "angular" in str(self.tech_profile.get("frameworks")).lower():
       # AngularJS has sanitization - need context-specific bypasses
       payloads = self._get_angular_xss_bypasses()
   ```

3. **Infrastructure Optimization:**
   ```python
   if "cloudflare" in str(self.tech_profile.get("cdn")).lower():
       # Cloudflare has request size limits
       payloads = self._filter_large_payloads(payloads, max_size=8KB)
   ```

**File Location:** `{scan_dir}/recon/tech_profile.json`

**Backward Compatibility:** If file doesn't exist, returns empty dict - no impact on functionality.
```

---

## 5. DASTySASTAgent (AnalysisAgent) Architecture Update

**Location:** `.ai-context/architecture/agents/dastysast_agent.md`

### Changes Required

#### Section: Add to "LLM Prompt Engineering" section

```markdown
### Tech Profile Context Enhancement (v3.1)

The LLM system prompt now includes **Technology Stack context** from `tech_profile.json`:

```python
from bugtrace.utils.tech_loader import format_tech_context

async def _build_system_prompt(self, url: str) -> str:
    # Format tech stack for LLM consumption
    tech_stack_summary = format_tech_context(self.tech_profile)

    return f"""Analyze this URL for security vulnerabilities.

=== TECHNOLOGY STACK (Use this to craft precise exploits) ===
{tech_stack_summary}

NOTE: Use detected technologies to:
- Generate version-specific exploits (e.g., AngularJS 1.7.7 CSTI bypasses)
- Identify infrastructure-specific attack vectors (e.g., AWS ALB header manipulation)
- Adapt payloads to framework constraints (e.g., React escaping, Vue template syntax)
- Account for WAF/CDN filtering when crafting bypasses

URL to analyze: {url}
...
"""
```

**Example Tech Stack Summary:**
```
Technology Stack:
  - Infrastructure: AWS ALB, Cloudflare
  - Frameworks: AngularJS 1.7.7
  - Servers: Nginx 1.18
  - WAF: Cloudflare WAF ⚠️
  - Languages: PHP 7.4
```

**LLM Benefits:**

1. **Version-Specific Exploits:**
   - LLM knows AngularJS 1.7.7 → suggests 1.7.x-specific sandbox escapes
   - LLM knows WordPress 5.8 → suggests CVE-2021-* exploits

2. **Infrastructure Context:**
   - AWS ALB detected → test for AWS-specific header injection
   - Cloudflare CDN → avoid payloads that trigger CDN caching

3. **WAF Evasion:**
   - WAF detected → LLM suggests encoding, case variation, fragmentation

**Code Location:** [bugtrace/agents/analysis_agent.py:125-145](../../bugtrace/agents/analysis_agent.py#L125-L145)
```

---

## 6. ReportingAgent Architecture Update

**Location:** Not currently documented, but should be added to `.ai-context/architecture/agents/`

### Create New Section

```markdown
## Technology Stack Section (v3.1)

The final report now includes a **Technology Stack** section based on `tech_profile.json`:

```markdown
## Technology Stack

### Infrastructure
- AWS ALB
- Cloudflare

### Frameworks
- AngularJS 1.7.7
- jQuery 3.6

### Web Servers
- Nginx 1.18.0

### Languages
- PHP 7.4.3

### Security Controls
- ⚠️ WAF: Cloudflare WAF
- CDN: Cloudflare

### CMS
- WordPress 5.8.1
```

**Implementation:**
```python
class ReportingAgent:
    def __init__(self, scan_id, target_url, output_dir, tech_profile: Dict = None):
        self.tech_profile = tech_profile or {}

    def _md_build_header(self) -> List[str]:
        lines = []
        # ... existing header content

        # Add Technology Stack section
        if self.tech_profile:
            lines.append("\n## Technology Stack\n")

            if self.tech_profile.get("infrastructure"):
                lines.append("### Infrastructure")
                for tech in self.tech_profile["infrastructure"]:
                    lines.append(f"- {tech}")

            if self.tech_profile.get("frameworks"):
                lines.append("\n### Frameworks")
                for tech in self.tech_profile["frameworks"]:
                    lines.append(f"- {tech}")

            # ... all categories
```

**Pentester Value:**
- Quick overview of target stack
- Informs manual testing approach
- Helps identify missing attack surface

**Code Location:** [bugtrace/agents/reporting.py:85-120](../../bugtrace/agents/reporting.py#L85-L120)
```

---

## 7. Architecture Diagram Updates

**Location:** `.ai-context/architecture/architecture_now.md`

### Add to "Phase 1: Reconnaissance" Section

```markdown
### Phase 1: Reconnaissance (Enhanced v3.1)

**NucleiAgent** now performs **two-phase scanning**:

```
┌─────────────────────────────────────────────────────────────────┐
│                   PHASE 1: RECONNAISSANCE                        │
└─────────────────────────────────────────────────────────────────┘

TeamOrchestrator
│
├─→ GoSpiderAgent
│   └─→ URLs discovered
│
└─→ NucleiAgent (v3.1: TWO-PHASE)
    │
    ├─→ Phase 1: Tech Detection (nuclei -tags tech)
    │   ├─→ Frameworks (Angular, React, Vue)
    │   ├─→ Servers (Nginx, Apache)
    │   ├─→ Infrastructure (AWS, GCP, Azure)
    │   ├─→ Security (WAF, CDN)
    │   └─→ Save: tech_profile.json
    │
    └─→ Phase 2: Vuln Scan (nuclei -as)
        └─→ CVEs, misconfigs, exposures

tech_profile.json consumed by:
├─→ SpecialistAgents (XSS, SQLi, CSTI, etc.)
│   └─→ Tech-aware payload prioritization
│
├─→ AnalysisAgent (DASTySAST)
│   └─→ LLM context enhancement
│
└─→ ReportingAgent
    └─→ Technology Stack section in final_report.md
```

**Key Integration Point:**
`tech_profile.json` is the **shared knowledge artifact** that makes all subsequent phases tech-aware.
```

---

## Implementation Checklist

For each agent documentation file, add the relevant sections above:

- [ ] `.ai-context/architecture/agents/nuclei_agent.md` - Two-phase workflow
- [ ] `.ai-context/architecture/agents/thinking_consolidation_agent.md` - v3.1 improvements
- [ ] `.ai-context/architecture/agents/csti_agent.md` - Tech-aware prioritization
- [ ] `.ai-context/architecture/agents/xss_agent.md` - Tech profile loading
- [ ] `.ai-context/architecture/agents/sqli_agent.md` - Tech profile loading
- [ ] `.ai-context/architecture/agents/dastysast_agent.md` - LLM context enhancement
- [ ] `.ai-context/architecture/` - Create `reporting_agent.md` with Tech Stack section
- [ ] `.ai-context/architecture/architecture_now.md` - Update Phase 1 diagram

---

## Cross-References

All agent updates should reference:
- **Specification:** [specs/TECH_DETECTION_AND_CONTEXT_AWARE_EXPLOITATION.md](../specs/TECH_DETECTION_AND_CONTEXT_AWARE_EXPLOITATION.md)
- **Audit Report:** [audits/IMPLEMENTATION_AUDIT_2026_02_02.md](../audits/IMPLEMENTATION_AUDIT_2026_02_02.md)
- **Utility:** [bugtrace/utils/tech_loader.py](../../bugtrace/utils/tech_loader.py)
- **Tech Profile Format:** See spec for JSON schema

---

**Next Step:** Integrate these sections into individual agent documentation files to complete the architecture documentation update.
