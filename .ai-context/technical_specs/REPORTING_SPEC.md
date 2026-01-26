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
