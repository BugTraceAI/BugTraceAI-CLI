# BugtraceAI Phase Architecture

> **Version**: 2.0.0 (Phoenix Edition)
> **Architecture**: Reactor V4

## Phase Naming Convention

BugtraceAI uses a 4-phase sequential pipeline. This document standardizes naming across code and documentation.

### Formal Names (Code Constants)

Used in `bugtrace/core/team.py` and dashboard status:

| Code Constant | Description |
|---------------|-------------|
| `PHASE_1_RECON` | URL discovery and tech detection |
| `PHASE_2_ANALYSIS` | Per-URL vulnerability analysis |
| `PHASE_3_REVIEW` | Cross-URL pattern analysis |
| `PHASE_4_REPORTING` | Report generation |

### Friendly Names (Documentation)

Used in user-facing documentation and logs:

| Phase | Friendly Name | Emoji | Purpose |
|-------|---------------|-------|---------|
| Phase 1 | **Hunter** | 🔍 | Discovers attack surface via GoSpider/Nuclei |
| Phase 2 | **Researcher** | 🧪 | Analyzes vulnerabilities per-URL with 5-approach DAST |
| Phase 3 | **Validator** | ✅ | Confirms findings via browser/vision validation |
| Phase 4 | **Reporter** | 📊 | Generates HTML/JSON reports |

### Phase Details

#### Phase 1: Hunter (PHASE_1_RECON)

**Executor**: `TeamOrchestrator`
**Duration**: ~2-5 minutes depending on target size

1. **Tech Detection**: Nuclei identifies frameworks/CMS
2. **URL Discovery**: GoSpider crawls with authenticated session
3. **Fallback**: VisualCrawler for JS-heavy sites
4. **Deduplication**: Filter duplicate/invalid URLs

**Output**: List of unique URLs with tech context

---

#### Phase 2: Researcher (PHASE_2_ANALYSIS)

**Executor**: `URLMasterAgent` (one per URL)
**Duration**: ~1-3 minutes per URL (parallelized)

1. **Context Assembly**: Extract params, headers, cookies
2. **5-Approach Analysis**: Multiple AI personas analyze risk
3. **Skill Routing**: Activate appropriate exploit skills
4. **Initial Validation**: Payload execution and confirmation

**Output**: Raw findings with exploit evidence

---

#### Phase 3: Validator (PHASE_3_REVIEW)

**Executor**: `TeamOrchestrator`
**Duration**: ~1-2 minutes

1. **Cross-URL Analysis**: Find attack chains (IDOR + Info Leak)
2. **Deduplication**: Normalize by (Type + URL + Parameter)
3. **Impact Scoring**: Assess real-world severity
4. **Browser Verification**: CDP/Playwright confirmation
5. **Vision AI**: Screenshot analysis for visual proof

**Output**: Validated findings with confidence scores

---

#### Phase 4: Reporter (PHASE_4_REPORTING)

**Executor**: `ReportingAgent`
**Duration**: ~30 seconds

1. **AI Enrichment**: Add CWE/CVSS/Remediation context
2. **Evidence Linking**: Attach screenshots and HTTP logs
3. **Reproduction Steps**: Include exact commands used
4. **Format Generation**: HTML, JSON, Markdown output

**Output**: Final vulnerability report

---

## Historical Note

Earlier documentation may reference:
- **"Auditor"**: Now standardized as "Researcher" (Phase 2)
- **"Phase 3.5"**: Was a proposed design for AgenticValidator; now integrated into Phase 3

## Code Reference

```python
# bugtrace/core/team.py - Phase constants
dashboard.set_phase("PHASE_1_RECON")      # Hunter
dashboard.set_phase("PHASE_2_ANALYSIS")   # Researcher
dashboard.set_phase("PHASE_3_REVIEW")     # Validator
dashboard.set_phase("PHASE_4_REPORTING")  # Reporter
```

---

*Last Updated: 2026-01-26*
