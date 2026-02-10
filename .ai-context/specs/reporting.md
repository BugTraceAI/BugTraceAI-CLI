# BugTraceAI V5: Reporting Architecture Specification ("Report-as-Software")

## 1. Philosophy

Decouple the "Working State" (Markdown) from the "Delivery State" (JSON/HTML).

- **Markdown**: For humans (hackers/auditors) and LLMs to read/debug/refine during the process.
- **JSON**: The single source of truth for delivery and integration.
- **HTML**: A stateless Single-Page Application (SPA) viewer that renders the JSON. "Print to PDF" relies on browser rendering.

## 2. Artifact Flow

### Phase 1: Hunter (Discovery)

- **Input**: Target URL
- **Process**: Agents swarm the target.
- **Output**: `raw_findings.md`
  - **Content**: Unfiltered findings, raw payloads, initial observations.
  - **Consumer**: AgenticValidator (Auditor).

### Phase 2: Auditor (Validation)

- **Input**: `raw_findings.md` (or DB equivalent)
- **Process**: AgenticValidator verifies findings via Browser/Vision.
- **Output**: `validated_findings.md`
  - **Content**: Confirmed vulnerabilities + Manual Review items.
  - **Extras**: "Validator Notes" explaining the verdict.
  - **Consumer**: ReportingAgent.

### Phase 3: Reporting (Delivery)

- **Input**: `validated_findings.md` + Capture Images
- **Process**: ReportingAgent aggregates and formats data.
- **Output**:
    1. **`final_report.json`**:
        - Structured data (Schema V5).
        - Embedded Base64 images or relative paths.
        - Pre-formatted "Triager-Ready" Markdown blocks (steps to reproduce, PoC) stored as string fields.
    2. **`report.html`**:
        - Static Viewer (SPA).
        - Loads `final_report.json` (renamed/aliased as `engagement_data.json` for loading).
        - Features: Interactive filtering, Copy-to-Clipboard (Markdown), Print-friendly CSS.

## 3. JSON Schema (Simplified)

```json
{
  "meta": {
    "tool": "BugTraceAI V5",
    "scan_id": "123",
    "date": "2026-01-01"
  },
  "findings": [
    {
      "id": 1,
      "title": "Reflected XSS on 'q'",
      "severity": "HIGH",
      "status": "CONFIRMED",
      "triager_ready_markdown": "### Steps to Reproduce\n1. Go to...\n\n### PoC\n`curl...`",
      "assets": {
        "screenshot": "captures/vuln_1.png"
      }
    }
  ]
}
```

## 4. Automation & Integration

- **Client Delivery**: Ship the folder containing `report.html`, `final_report.json`, and `captures/`.
- **Integrations**: Third-party tools ingest `final_report.json`.

---

## 5. DASTySAST Numbered Reports System with Dual Format (v1.4.0)

### Overview

A partir de la versión 1.4.0, los reportes de análisis DASTySAST (Fase 2: Discovery) se organizan con numeración secuencial que mapea directamente a las URLs descubiertas, y se generan en **formato dual** (JSON + Markdown) para garantizar 100% de preservación de payloads críticos.

### Directory Structure

```
reports/scan_example_com_20260202_153045/
├── urls.txt                    # Master index: ordered list of discovered URLs
├── dastysast/                  # DASTySAST analysis reports (numbered, dual format)
│   ├── 1.json                  # Structured data for URL line 1 (100% robust)
│   ├── 1.md                    # Human-readable report for URL line 1
│   ├── 2.json                  # Structured data for URL line 2
│   ├── 2.md                    # Human-readable report for URL line 2
│   ├── 3.json
│   ├── 3.md
│   └── N.json + N.md           # Analysis for URL line N of urls.txt
├── specialists/                # Specialist validation reports
│   ├── xss_findings.json
│   ├── sqli_findings.json
│   └── ...
└── final_report.{json,html,md} # Consolidated final report
```

### Dual Format Rationale

**Why JSON + Markdown?**

Reports contain **critical exploitation payloads** (XSS scripts, SQL injection strings, etc.) that must be preserved with 100% fidelity for reproduction. The dual format approach provides:

| Format | Purpose | Robustness | Use Case |
|--------|---------|-----------|----------|
| **`.json`** | Structured data | ⭐⭐⭐⭐⭐ (100%) | Automated processing, scripts, integrations |
| **`.md`** | Human-readable | ⭐⭐⭐⭐ (code blocks) | Manual review, debugging, documentation |

### URL ↔ Report Mapping

The report number **exactly matches** the URL line number in `urls.txt`:

```bash
# Example workflow - Human reading
head -n 1 reports/scan_*/urls.txt   # Get URL at line 1
cat reports/scan_*/dastysast/1.md   # Read its human-readable analysis

# Example workflow - Script processing
head -n 5 reports/scan_*/urls.txt   # Get URL at line 5
jq '.vulnerabilities' reports/scan_*/dastysast/5.json  # Parse structured data

# Validate URL correspondence
sed -n '1p' urls.txt                          # URL line 1
jq '.metadata.url' dastysast/1.json           # Verify it matches
```

### JSON Report Format

Each JSON report (`N.json`) contains complete structured data:

```json
{
  "metadata": {
    "url": "https://example.com/page",
    "url_index": 1,
    "scan_context": "scan_123",
    "timestamp": 1738454400.0,
    "tech_profile": {
      "frameworks": ["React", "Express"],
      "libraries": ["axios"],
      "server": "nginx",
      "language": "JavaScript"
    }
  },
  "statistics": {
    "total_vulnerabilities": 3,
    "high_confidence": 2,
    "medium_confidence": 1,
    "low_confidence": 0,
    "by_type": {
      "XSS": 2,
      "SQL Injection": 1
    }
  },
  "vulnerabilities": [
    {
      "type": "XSS",
      "parameter": "user_input",
      "fp_confidence": 0.85,
      "skeptical_score": 7,
      "votes": 4,
      "severity": "High",
      "confidence_score": 8,
      "reasoning": "Parameter reflects in response without encoding",
      "payload": "<script>alert(document.domain)</script>",
      "evidence": "Response contains: <script>alert(document.domain)</script>",
      "fp_reason": "Direct reflection with HTML context",
      "validation_result": null,
      "http_method": "POST",
      "url": "https://example.com/page"
    }
  ]
}
```

**Key Features**:
- ✅ **100% payload preservation** (no character escaping or interpretation)
- ✅ **Complete metadata** (tech profile, timestamps, indices)
- ✅ **Aggregated statistics** (totals, confidence levels, type distribution)
- ✅ **UTF-8 without escaping** (`ensure_ascii=False`)
- ✅ **Sorted by confidence** (highest first)

### Markdown Report Format

Each Markdown report (`N.md`) contains human-readable visualization:

```markdown
# Potential Vulnerabilities for {URL}

| Type | Parameter | FP Confidence | Skeptical Score | Votes |
|------|-----------|---------------|-----------------|-------|
| XSS  | search    | 0.85 ++       | 8/10            | 4/5   |
| SQLi | id        | 0.72 +        | 7/10            | 5/5   |

## Details

### XSS on `search`
- **FP Confidence**: 0.85
- **Skeptical Score**: 8/10
- **Votes**: 4/5 approaches
- **Reasoning**: Parameter reflects in input value attribute...
- **FP Analysis**: High confidence based on reflection evidence
```

### Implementation Details

**Constructor Parameter**:
```python
DASTySASTAgent(
    url, tech_profile, report_dir,
    state_manager, scan_context,
    url_index=N  # Sequential index (1-based)
)
```

**Orchestrator Integration** (`bugtrace/core/team.py`):
```python
# Enumerate URLs to pass index
tasks = [
    analyze_url(url, idx + 1)  # Index starts at 1
    for idx, url in enumerate(self.urls_to_scan)
]
```

**Report Generation** (`bugtrace/agents/analysis_agent.py`):
```python
async def _run_save_results(self, vulnerabilities: List[Dict]):
    # Determine base filename
    if self.url_index is not None:
        base_filename = str(self.url_index)
    else:
        base_filename = f"vulnerabilities_{self._get_safe_name()}"

    # Save JSON report (structured data - 100% robust)
    json_path = self.report_dir / f"{base_filename}.json"
    self._save_json_report(json_path, vulnerabilities)

    # Save Markdown report (human-readable)
    md_path = self.report_dir / f"{base_filename}.md"
    self._save_markdown_report(md_path, vulnerabilities)
```

**Return Value**:
```python
return {
    "url": self.url,
    "vulnerabilities": vulnerabilities,
    "report_file": str(self.report_dir / f"{base_filename}.md"),
    "json_report_file": str(self.report_dir / f"{base_filename}.json"),
    "url_index": self.url_index,
    ...
}
```

### Benefits

1. **Direct Navigation**: `dastysast/5.md` always corresponds to line 5 of `urls.txt`
2. **Reproducibility**: Order is preserved and documented
3. **Scalability**: Works equally well with 10 or 10,000 URLs
4. **Correlation**: Easy to cross-reference findings numerically
5. **Backward Compatibility**: Legacy calls without `url_index` use long filenames
6. **100% Payload Preservation**: JSON format guarantees exact payload fidelity
7. **Automated Processing**: Scripts can parse JSON without Markdown interpretation issues
8. **Human-Readable Fallback**: Markdown provides quick visual inspection

### Usage Examples

**For Human Review**:
```bash
# Quick scan of findings
less dastysast/1.md

# View summary table
head -20 dastysast/1.md
```

**For Automated Processing**:
```python
import json

# Load structured data
with open("dastysast/1.json") as f:
    report = json.load(f)

# Extract high-confidence findings
high_conf = [
    v for v in report["vulnerabilities"]
    if v["fp_confidence"] >= 0.7
]

# Reproduce exploit
for vuln in high_conf:
    exploit(
        url=vuln["url"],
        parameter=vuln["parameter"],
        payload=vuln["payload"]  # 100% exact payload
    )
```

**For CI/CD Integration**:
```bash
# Count high-confidence vulnerabilities across all reports
jq -r '.statistics.high_confidence' dastysast/*.json | \
    awk '{sum+=$1} END {print sum}'

# Extract all XSS payloads
jq -r '.vulnerabilities[] | select(.type=="XSS") | .payload' \
    dastysast/*.json
```

### Migration Notes

- **Old format**: `vulnerabilities_https___example_com_page_abc123.md` (hash-based, MD only)
- **New format**: `1.json` + `1.md`, `2.json` + `2.md`, etc. (index-based, dual format)
- **Coexistence**: Both formats work; `url_index=None` uses old format

---

**Last Updated**: 2026-02-02
**Version**: 1.4.0 (Dual Format JSON+MD)
