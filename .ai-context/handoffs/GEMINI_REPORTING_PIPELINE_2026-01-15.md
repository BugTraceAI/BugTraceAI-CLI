# HANDOFF: Reporting Pipeline Refactor

**Date:** 2026-01-15
**Priority:** HIGH
**Assignee:** Gemini
**Reviewer:** Claude (Tech Lead)

---

## OVERVIEW

The reporting system is broken. Reports are generated BEFORE AgenticValidator runs, so validated findings never appear in the final reports. We need to fix the pipeline order and generate 4 deliverables.

---

## PART 1: BUG FIXES (Do these FIRST)

### Bug 1.1: Missing "Critical" in severity_order

**File:** `bugtrace/reporting/markdown_generator.py`
**Line:** 66

**CURRENT CODE (WRONG):**
```python
severity_order = {"High": 0, "Medium": 1, "Low": 2, "Information": 3}
```

**NEW CODE (CORRECT):**
```python
severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Information": 4}
```

**Why:** Critical findings appear LAST in reports instead of FIRST.

---

### Bug 1.2: validation_method not read from Finding object

**File:** `bugtrace/reporting/markdown_generator.py`
**Line:** 81

**CURRENT CODE (WRONG):**
```python
ftype = vuln.metadata.get('validation_method', 'Automated Check')
```

**NEW CODE (CORRECT):**
```python
ftype = vuln.validation_method or vuln.metadata.get('validation_method', 'Automated Check')
```

**Why:** The Finding object has `validation_method` attribute but code only checks metadata.

---

### Bug 1.3: datetime assigned as string

**File:** `bugtrace/core/team.py`
**Line:** 1242

**CURRENT CODE (WRONG):**
```python
collector.context.stats.start_time = start_time.isoformat() if isinstance(start_time, datetime) else start_time
```

**NEW CODE (CORRECT):**
```python
collector.context.stats.start_time = start_time if isinstance(start_time, datetime) else datetime.fromisoformat(start_time)
```

**Line:** 1244 - same fix for end_time:
```python
collector.context.stats.end_time = end_time
```

**Why:** ScanStats model expects datetime objects, not strings.

---

## PART 2: ADD scan_id TO REPORTING MODELS

### Task 2.1: Update ReportContext model

**File:** `bugtrace/reporting/models.py`

**ADD this field to ReportContext class (after line 66):**
```python
class ReportContext(BaseModel):
    scan_id: Optional[int] = None  # ADD THIS LINE
    target_url: str
    scan_date: datetime = Field(default_factory=datetime.now)
    # ... rest stays the same
```

**ADD import at top of file:**
```python
from typing import List, Dict, Optional, Any  # Optional already there, just confirm
```

---

### Task 2.2: Update DataCollector to accept scan_id

**File:** `bugtrace/reporting/collector.py`

**CHANGE the __init__ method (line 10):**

**CURRENT:**
```python
def __init__(self, target_url: str):
    self.context = ReportContext(target_url=target_url)
```

**NEW:**
```python
def __init__(self, target_url: str, scan_id: Optional[int] = None):
    self.context = ReportContext(target_url=target_url, scan_id=scan_id)
```

**ADD import at top:**
```python
from typing import List, Dict, Any, Optional  # Optional already there, just confirm
```

---

### Task 2.3: Update team.py to pass scan_id

**File:** `bugtrace/core/team.py`
**Line:** 1207

**CURRENT:**
```python
collector = DataCollector(self.target)
```

**NEW:**
```python
collector = DataCollector(self.target, scan_id=self.scan_id)
```

---

## PART 3: REFACTOR ReportingAgent

**File:** `bugtrace/agents/reporting.py`

**REPLACE the entire file with this new implementation:**

```python
"""
ReportingAgent: Generates all 4 deliverables for a scan.

Deliverables:
1. raw_findings.json - Pre-AgenticValidator findings (for manual review)
2. validated_findings.json - Only VALIDATED_CONFIRMED findings
3. final_report.md - Triager-ready markdown with all findings
4. engagement_data.json - Structured JSON for HTML viewer
5. report.html - Static HTML that loads engagement_data.json
"""

import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from bugtrace.agents.base import BaseAgent
from bugtrace.core.config import settings
from bugtrace.core.database import get_db_manager
from bugtrace.core.ui import dashboard
from bugtrace.utils.logger import get_logger

logger = get_logger("agents.reporting")


class ReportingAgent(BaseAgent):
    """
    Final Agent responsible for generating all report deliverables.
    """

    def __init__(self, scan_id: int, target_url: str, output_dir: Path):
        super().__init__("ReportingAgent", "Reporting Specialist", agent_id="reporting_agent")
        self.scan_id = scan_id
        self.target_url = target_url
        self.output_dir = Path(output_dir)
        self.db = get_db_manager()

    async def run_loop(self):
        """Not used - call generate_all_deliverables() directly."""
        pass

    async def generate_all_deliverables(self) -> Dict[str, Path]:
        """
        Main entry point. Generates all 4 deliverables.

        Returns dict with paths to each deliverable.
        """
        dashboard.update_task("reporting", name="Reporting Agent", status="Generating deliverables...")
        logger.info(f"[{self.name}] Starting report generation for scan {self.scan_id}")

        # Ensure output directory exists
        self.output_dir.mkdir(parents=True, exist_ok=True)
        captures_dir = self.output_dir / "captures"
        captures_dir.mkdir(exist_ok=True)

        # 1. Pull ALL findings from DB for this scan
        all_findings = self._get_findings_from_db()
        logger.info(f"[{self.name}] Retrieved {len(all_findings)} findings from DB")

        # 2. Separate by validation status
        raw_findings = [f for f in all_findings]  # All findings
        validated_findings = [f for f in all_findings if f.get("status") == "VALIDATED_CONFIRMED"]
        manual_review = [f for f in all_findings if f.get("status") == "MANUAL_REVIEW_RECOMMENDED"]
        false_positives = [f for f in all_findings if f.get("status") == "VALIDATED_FALSE_POSITIVE"]
        pending = [f for f in all_findings if f.get("status") == "PENDING_VALIDATION"]

        # 3. Generate each deliverable
        paths = {}

        # Deliverable 1: raw_findings.json
        paths["raw_findings"] = self._write_json(
            raw_findings,
            "raw_findings.json",
            "All findings before/after AgenticValidator"
        )

        # Deliverable 2: validated_findings.json
        paths["validated_findings"] = self._write_json(
            validated_findings,
            "validated_findings.json",
            "Only VALIDATED_CONFIRMED findings"
        )

        # Deliverable 3: final_report.md
        paths["final_report"] = self._write_markdown_report(
            validated=validated_findings,
            manual_review=manual_review,
            pending=pending
        )

        # Deliverable 4: engagement_data.json (structured for HTML)
        paths["engagement_data"] = self._write_engagement_json(
            all_findings=all_findings,
            validated=validated_findings,
            false_positives=false_positives,
            manual_review=manual_review
        )

        # Deliverable 5: report.html (copy static template)
        paths["report_html"] = self._copy_html_template()

        # Copy screenshots to captures folder
        self._copy_screenshots(all_findings, captures_dir)

        dashboard.log(f"[{self.name}] Generated {len(paths)} deliverables in {self.output_dir}", "SUCCESS")

        return paths

    def _get_findings_from_db(self) -> List[Dict]:
        """Pull findings from database for this scan_id."""
        db_findings = self.db.get_findings_for_scan(self.scan_id)

        findings = []
        for f in db_findings:
            findings.append({
                "id": f.id,
                "type": str(f.type.value if hasattr(f.type, 'value') else f.type),
                "severity": f.severity,
                "url": f.attack_url,
                "parameter": f.vuln_parameter,
                "payload": f.payload_used,
                "description": f.details,
                "status": f.status,
                "validator_notes": f.validator_notes,
                "screenshot_path": f.proof_screenshot_path,
                "created_at": f.created_at.isoformat() if f.created_at else None
            })

        return findings

    def _write_json(self, findings: List[Dict], filename: str, description: str) -> Path:
        """Write findings to a JSON file."""
        path = self.output_dir / filename

        output = {
            "meta": {
                "scan_id": self.scan_id,
                "target": self.target_url,
                "generated_at": datetime.now().isoformat(),
                "description": description,
                "count": len(findings)
            },
            "findings": findings
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, default=str)

        logger.info(f"[{self.name}] Wrote {filename} ({len(findings)} findings)")
        return path

    def _write_engagement_json(
        self,
        all_findings: List[Dict],
        validated: List[Dict],
        false_positives: List[Dict],
        manual_review: List[Dict]
    ) -> Path:
        """Write the structured engagement_data.json for HTML viewer."""
        path = self.output_dir / "engagement_data.json"

        # Count by severity
        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in validated:
            sev = (f.get("severity") or "medium").lower()
            if sev in by_severity:
                by_severity[sev] += 1

        # Build triager-ready findings
        triager_findings = []
        for i, f in enumerate(validated, 1):
            triager_findings.append({
                "id": f"F-{i:03d}",
                "type": f.get("type", "Unknown"),
                "severity": f.get("severity", "MEDIUM"),
                "confidence": "CERTAIN",
                "status": "VALIDATED_CONFIRMED",
                "url": f.get("url", ""),
                "parameter": f.get("parameter", ""),
                "payload": f.get("payload", ""),
                "validation": {
                    "method": "CDP + Vision AI",
                    "screenshot": f"captures/{Path(f.get('screenshot_path', '')).name}" if f.get("screenshot_path") else None,
                    "notes": f.get("validator_notes", "")
                },
                "reproduction": {
                    "steps": [
                        f"1. Navigate to: {f.get('url', '')}",
                        f"2. Locate parameter: {f.get('parameter', '')}",
                        f"3. Inject payload: {f.get('payload', '')}",
                        f"4. Observe the vulnerability trigger"
                    ],
                    "curl": self._generate_curl(f)
                },
                "description": f.get("description", ""),
                "impact": self._get_impact_for_type(f.get("type", "")),
                "remediation": self._get_remediation_for_type(f.get("type", ""))
            })

        output = {
            "meta": {
                "scan_id": self.scan_id,
                "target": self.target_url,
                "scan_date": datetime.now().isoformat(),
                "tool_version": settings.VERSION,
                "validation_engine": "AgenticValidator + CDP + Vision AI"
            },
            "summary": {
                "total_findings": len(all_findings),
                "validated": len(validated),
                "false_positives": len(false_positives),
                "manual_review": len(manual_review),
                "by_severity": by_severity
            },
            "findings": triager_findings
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, default=str)

        logger.info(f"[{self.name}] Wrote engagement_data.json ({len(triager_findings)} triager-ready findings)")
        return path

    def _write_markdown_report(
        self,
        validated: List[Dict],
        manual_review: List[Dict],
        pending: List[Dict]
    ) -> Path:
        """Write the triager-ready markdown report."""
        path = self.output_dir / "final_report.md"

        lines = []
        lines.append(f"# Security Assessment: {self.target_url}\n")
        lines.append(f"**Scan ID:** {self.scan_id}")
        lines.append(f"**Date:** {datetime.now().strftime('%d %b %Y %H:%M')}")
        lines.append(f"**Tool:** BugTraceAI v{settings.VERSION}\n")

        # Summary
        lines.append("## Executive Summary\n")
        lines.append(f"| Category | Count |")
        lines.append(f"|----------|-------|")
        lines.append(f"| **Confirmed Vulnerabilities** | {len(validated)} |")
        lines.append(f"| **Needs Manual Review** | {len(manual_review)} |")
        lines.append(f"| **Pending Validation** | {len(pending)} |")
        lines.append("")

        # Section 1: Confirmed Findings (Triager Ready)
        lines.append("---\n")
        lines.append("## Confirmed Vulnerabilities (Triager Ready)\n")

        if not validated:
            lines.append("*No confirmed vulnerabilities found.*\n")
        else:
            # Sort by severity
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
            validated_sorted = sorted(validated, key=lambda x: severity_order.get((x.get("severity") or "MEDIUM").upper(), 5))

            for i, f in enumerate(validated_sorted, 1):
                lines.append(f"### {i}. {f.get('type', 'Unknown Vulnerability')}\n")
                lines.append(f"| Field | Value |")
                lines.append(f"|-------|-------|")
                lines.append(f"| **Severity** | {f.get('severity', 'MEDIUM')} |")
                lines.append(f"| **Status** | ✅ CONFIRMED |")
                lines.append(f"| **URL** | `{f.get('url', '')}` |")
                lines.append(f"| **Parameter** | `{f.get('parameter', '')}` |")
                lines.append("")

                # Steps to Reproduce
                lines.append("#### Steps to Reproduce\n")
                lines.append(f"1. Navigate to: `{f.get('url', '')}`")
                lines.append(f"2. Locate the parameter: `{f.get('parameter', '')}`")
                lines.append(f"3. Inject the payload: `{f.get('payload', '')}`")
                lines.append(f"4. Observe the vulnerability trigger\n")

                # PoC
                lines.append("#### Proof of Concept\n")
                lines.append("```bash")
                lines.append(self._generate_curl(f))
                lines.append("```\n")

                # Validator Notes
                if f.get("validator_notes"):
                    lines.append("#### Validation Notes\n")
                    lines.append(f"> {f.get('validator_notes')}\n")

                # Screenshot
                if f.get("screenshot_path"):
                    img_name = Path(f.get("screenshot_path")).name
                    lines.append(f"#### Screenshot\n")
                    lines.append(f"![Evidence](captures/{img_name})\n")

                lines.append("---\n")

        # Section 2: Manual Review Needed
        if manual_review:
            lines.append("## Needs Manual Review\n")
            lines.append("> These findings have high AI confidence but could not be confirmed via browser automation.\n")

            for i, f in enumerate(manual_review, 1):
                lines.append(f"### MR-{i}. {f.get('type', 'Unknown')}\n")
                lines.append(f"- **URL:** `{f.get('url', '')}`")
                lines.append(f"- **Parameter:** `{f.get('parameter', '')}`")
                lines.append(f"- **Payload:** `{f.get('payload', '')}`")
                if f.get("validator_notes"):
                    lines.append(f"- **AI Notes:** {f.get('validator_notes')}")
                lines.append("")

        # Write file
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        logger.info(f"[{self.name}] Wrote final_report.md")
        return path

    def _copy_html_template(self) -> Path:
        """Copy the static HTML template that loads engagement_data.json."""
        # The HTML template location
        template_src = Path(__file__).parent.parent / "reporting" / "templates" / "report_dynamic.html"
        dest = self.output_dir / "report.html"

        if template_src.exists():
            shutil.copy(template_src, dest)
        else:
            # Create a minimal HTML if template doesn't exist
            self._create_minimal_html(dest)

        logger.info(f"[{self.name}] Copied report.html")
        return dest

    def _create_minimal_html(self, path: Path):
        """Create minimal HTML that loads JSON dynamically."""
        html = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BugTraceAI Report</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body { font-family: system-ui, sans-serif; background: #f8fafc; }
        .severity-critical { background: #991b1b; color: white; }
        .severity-high { background: #dc2626; color: white; }
        .severity-medium { background: #d97706; color: white; }
        .severity-low { background: #2563eb; color: white; }
        .severity-info { background: #059669; color: white; }
        pre { background: #1e293b; color: #e2e8f0; padding: 1rem; border-radius: 0.5rem; overflow-x: auto; }
    </style>
</head>
<body class="p-8">
    <div id="app" class="max-w-6xl mx-auto">
        <div class="text-center py-8">
            <p class="text-gray-500">Loading report...</p>
        </div>
    </div>

    <script>
        async function loadReport() {
            try {
                const response = await fetch('./engagement_data.json');
                const data = await response.json();
                renderReport(data);
            } catch (e) {
                document.getElementById('app').innerHTML =
                    '<p class="text-red-500">Error loading report: ' + e.message + '</p>';
            }
        }

        function renderReport(data) {
            const app = document.getElementById('app');

            let html = `
                <header class="mb-8">
                    <h1 class="text-3xl font-bold text-gray-900">Security Assessment Report</h1>
                    <p class="text-gray-600 mt-2">Target: ${data.meta.target}</p>
                    <p class="text-gray-500 text-sm">Scan ID: ${data.meta.scan_id} | Date: ${data.meta.scan_date}</p>
                </header>

                <section class="grid grid-cols-4 gap-4 mb-8">
                    <div class="bg-white p-4 rounded-lg shadow">
                        <p class="text-3xl font-bold text-green-600">${data.summary.validated}</p>
                        <p class="text-gray-600">Confirmed</p>
                    </div>
                    <div class="bg-white p-4 rounded-lg shadow">
                        <p class="text-3xl font-bold text-yellow-600">${data.summary.manual_review}</p>
                        <p class="text-gray-600">Manual Review</p>
                    </div>
                    <div class="bg-white p-4 rounded-lg shadow">
                        <p class="text-3xl font-bold text-red-600">${data.summary.false_positives}</p>
                        <p class="text-gray-600">False Positives</p>
                    </div>
                    <div class="bg-white p-4 rounded-lg shadow">
                        <p class="text-3xl font-bold text-gray-600">${data.summary.total_findings}</p>
                        <p class="text-gray-600">Total</p>
                    </div>
                </section>

                <section>
                    <h2 class="text-2xl font-bold mb-4">Confirmed Vulnerabilities</h2>
            `;

            if (data.findings.length === 0) {
                html += '<p class="text-gray-500">No confirmed vulnerabilities found.</p>';
            } else {
                data.findings.forEach((f, i) => {
                    const sevClass = 'severity-' + f.severity.toLowerCase();
                    html += `
                        <div class="bg-white rounded-lg shadow mb-4 overflow-hidden">
                            <div class="flex items-center justify-between p-4 border-b">
                                <h3 class="text-xl font-bold">${f.id}. ${f.type}</h3>
                                <span class="px-3 py-1 rounded text-sm font-bold ${sevClass}">${f.severity}</span>
                            </div>
                            <div class="p-4">
                                <p class="mb-2"><strong>URL:</strong> <code class="bg-gray-100 px-2 py-1 rounded">${f.url}</code></p>
                                <p class="mb-2"><strong>Parameter:</strong> <code class="bg-gray-100 px-2 py-1 rounded">${f.parameter}</code></p>
                                <p class="mb-4"><strong>Payload:</strong> <code class="bg-gray-100 px-2 py-1 rounded">${f.payload}</code></p>

                                <h4 class="font-bold mt-4 mb-2">Steps to Reproduce</h4>
                                <ol class="list-decimal list-inside mb-4">
                                    ${f.reproduction.steps.map(s => '<li>' + s + '</li>').join('')}
                                </ol>

                                <h4 class="font-bold mt-4 mb-2">PoC (cURL)</h4>
                                <pre>${f.reproduction.curl}</pre>

                                ${f.validation.notes ? '<p class="mt-4 text-gray-600"><strong>Validator Notes:</strong> ' + f.validation.notes + '</p>' : ''}
                                ${f.validation.screenshot ? '<img src="' + f.validation.screenshot + '" class="mt-4 rounded border" />' : ''}
                            </div>
                        </div>
                    `;
                });
            }

            html += '</section>';
            app.innerHTML = html;
        }

        loadReport();
    </script>
</body>
</html>''';

        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

    def _copy_screenshots(self, findings: List[Dict], captures_dir: Path):
        """Copy all screenshots to the captures folder."""
        for f in findings:
            src = f.get("screenshot_path")
            if src and Path(src).exists():
                try:
                    shutil.copy(src, captures_dir / Path(src).name)
                except Exception as e:
                    logger.debug(f"Could not copy screenshot {src}: {e}")

    def _generate_curl(self, finding: Dict) -> str:
        """Generate a curl command for the finding."""
        url = finding.get("url", "")
        param = finding.get("parameter", "")
        payload = finding.get("payload", "")

        if not url:
            return "# No URL available"

        # URL encode the payload for curl
        import urllib.parse
        encoded_payload = urllib.parse.quote(payload, safe='')

        if '?' in url:
            return f'curl "{url}"'
        else:
            return f'curl "{url}?{param}={encoded_payload}"'

    def _get_impact_for_type(self, vuln_type: str) -> str:
        """Get standard impact description for vulnerability type."""
        impacts = {
            "XSS": "Cross-Site Scripting can lead to session hijacking, credential theft, defacement, and malware distribution.",
            "SQLI": "SQL Injection can lead to unauthorized data access, data manipulation, and complete database compromise.",
            "SQLi": "SQL Injection can lead to unauthorized data access, data manipulation, and complete database compromise.",
            "LFI": "Local File Inclusion can expose sensitive files and potentially lead to remote code execution.",
            "RCE": "Remote Code Execution allows attackers to run arbitrary commands on the server.",
            "SSRF": "Server-Side Request Forgery can expose internal services and sensitive data.",
            "IDOR": "Insecure Direct Object Reference can lead to unauthorized access to other users' data.",
        }
        return impacts.get(vuln_type.upper(), "This vulnerability may compromise the security of the application.")

    def _get_remediation_for_type(self, vuln_type: str) -> str:
        """Get standard remediation for vulnerability type."""
        remediations = {
            "XSS": "Implement proper output encoding and Content Security Policy (CSP). Use context-aware escaping.",
            "SQLI": "Use parameterized queries or prepared statements. Never concatenate user input into SQL queries.",
            "SQLi": "Use parameterized queries or prepared statements. Never concatenate user input into SQL queries.",
            "LFI": "Validate and sanitize file paths. Use allowlists for permitted files. Avoid user input in file operations.",
            "RCE": "Never execute user-controlled input. Use allowlists for permitted commands. Implement strict input validation.",
            "SSRF": "Validate and sanitize URLs. Use allowlists for permitted domains. Block internal IP ranges.",
            "IDOR": "Implement proper authorization checks. Use indirect references. Validate user permissions for each request.",
        }
        return remediations.get(vuln_type.upper(), "Follow security best practices for this vulnerability type.")
```

---

## PART 4: UPDATE VALIDATOR ENGINE TO CALL REPORTING AGENT

**File:** `bugtrace/core/validator_engine.py`

**ADD import at top of file (after line 9):**
```python
from bugtrace.agents.reporting import ReportingAgent
```

**ADD new method to ValidationEngine class (after line 97, before `def stop`):**

```python
    async def generate_final_reports(self, output_dir: Path):
        """Generate all report deliverables after validation is complete."""
        if not self.scan_id:
            logger.error("Cannot generate reports: no scan_id")
            return

        # Get target URL from DB
        target_url = self._get_target_url()
        if not target_url:
            logger.error("Cannot generate reports: target URL not found")
            return

        reporter = ReportingAgent(
            scan_id=self.scan_id,
            target_url=target_url,
            output_dir=output_dir
        )

        return await reporter.generate_all_deliverables()

    def _get_target_url(self) -> Optional[str]:
        """Get target URL for this scan from DB."""
        from sqlmodel import select
        from bugtrace.schemas.db_models import ScanTable, TargetTable

        with self.db.get_session() as session:
            scan = session.get(ScanTable, self.scan_id)
            if scan and scan.target_id:
                target = session.get(TargetTable, scan.target_id)
                if target:
                    return target.url
        return None
```

**MODIFY the `run` method (around line 40) to generate reports after validation:**

Find this block (around line 85-86):
```python
            if not continuous:
                break
```

**CHANGE to:**
```python
            if not continuous:
                break

        # After validation completes, generate final reports
        if not continuous:
            dashboard.log("📊 Generating final reports...", "INFO")
            # Determine output directory
            from bugtrace.core.config import settings
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = settings.LOG_DIR / f"scan_{self.scan_id}_{timestamp}"
            await self.generate_final_reports(output_dir)
            dashboard.log(f"✅ Reports generated in {output_dir}", "SUCCESS")
```

---

## PART 5: UPDATE team.py TO NOT GENERATE REPORTS

The Hunter phase should NOT generate final reports. Remove or comment out the report generation.

**File:** `bugtrace/core/team.py`

**Find line 1034 (the call to _generate_v2_report):**
```python
await self._generate_v2_report(all_findings, urls_to_scan, tech_profile, scan_dir, start_time)
```

**REPLACE with:**
```python
# V5: Reports are now generated by ValidationEngine after validation
# Just save raw findings for AgenticValidator to process
raw_findings_path = scan_dir / "raw_findings.json"
import json
with open(raw_findings_path, "w") as f:
    json.dump({
        "meta": {"scan_id": self.scan_id, "target": self.target, "phase": "hunter"},
        "findings": all_findings
    }, f, indent=2, default=str)
logger.info(f"Saved {len(all_findings)} raw findings to {raw_findings_path}")
```

---

## PART 6: ADD IMPORT FOR Path IN VALIDATOR ENGINE

**File:** `bugtrace/core/validator_engine.py`

**Verify this import exists at top (add if missing):**
```python
from pathlib import Path
```

---

## VERIFICATION CHECKLIST

After implementing all changes, verify:

1. [ ] Run a scan with `bugtrace scan <target> --phase all`
2. [ ] Check that `raw_findings.json` is created BEFORE AgenticValidator runs
3. [ ] Check that after AgenticValidator completes, these files exist:
   - `raw_findings.json`
   - `validated_findings.json`
   - `final_report.md`
   - `engagement_data.json`
   - `report.html`
4. [ ] Open `report.html` in browser - it should load `engagement_data.json` dynamically
5. [ ] Verify that `final_report.md` has separate sections for Confirmed vs Manual Review
6. [ ] Verify Critical severity findings appear FIRST in reports

---

## FILES MODIFIED (Summary)

| File | Change Type |
|------|-------------|
| `bugtrace/reporting/markdown_generator.py` | Bug fix (severity_order, validation_method) |
| `bugtrace/reporting/models.py` | Add scan_id field |
| `bugtrace/reporting/collector.py` | Accept scan_id in constructor |
| `bugtrace/core/team.py` | Remove report generation, save raw_findings.json |
| `bugtrace/core/validator_engine.py` | Add report generation after validation |
| `bugtrace/agents/reporting.py` | FULL REWRITE - new ReportingAgent |

---

## DO NOT

- Do NOT modify `bugtrace/__main__.py`
- Do NOT modify `bugtrace/agents/agentic_validator.py`
- Do NOT change the database schema
- Do NOT add new dependencies

---

**END OF HANDOFF**
