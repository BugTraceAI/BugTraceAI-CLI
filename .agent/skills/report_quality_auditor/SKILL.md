---
name: report_quality_auditor
description: Expert auditor for validating the quality, accuracy, and visual integrity of BugTraceAI reports. Use this to ensure reports are "Triager-Ready" and professional.
---

# Report Quality Auditor Skill

This skill provides the intelligence to audit generated reports (Markdown and HTML) to ensure they meet the "Pentagon-Grade" and "Triager-Ready" standards of the project.

## 1. Compliance Checklist (Bug Bounty Grade)

### A. Document Integrity (Markdown/HTML)

- **Triager-Ready Sections**: Every finding MUST have:
  - `🕵️ Steps to Reproduce`: Clear, numbered list.
  - `💥 Proof of Concept (Curl)`: A functional, copy-pasteable curl command.
  - `Classification`: Correct Severity and Confidence levels.
- **No Placeholders**: Search for generic terms like `[TARGET]`, `example.com`, or any non-contextual data.
- **AI Validator Comments**: Ensure comments from the `AgenticValidator` are clear and explain WHY the issue was confirmed.

### B. Visual Validation (HTML Report)

- **Live Review**: Use the browser tool to open the local `report.html` file.
- **Screenshot Integrity**:
  - Verify that images load correctly.
  - Audit the image content: Does the screenshot actually show the vulnerability execution (e.g., an alert box, a SQL error dump, or a leaked file)?
- **Aesthetics & UX**: The report must look premium. Check for broken layouts, overlapping text, or poor contrast.

## 2. Investigative Workflow

1. **Locate Artifacts**: Find the latest `report.html` and `final_report.md` in the `reports/` directory.
2. **Structural Audit**: Parse the Markdown file to ensure all mandatory sections from `.ai-context/technical_specs/REPORTING_AND_VALIDATION_SPEC.md` are present.
3. **Visual Audit (MANDATORY)**:
   - Use the browser agent to open the HTML report.
   - Navigate through the findings.
   - Zoom in on screenshots to confirm they are authentic and high-quality.
4. **Final Verdict**:
   - **APPROVED**: The report is ready for the CEO/Client.
   - **REJECTED**: List specific failures (e.g., "Finding #3 has a broken PoC", "Screenshot in XSS section is a generic homepage, not an exploit").

## 3. Instructions for the Agent

- Be **highly critical**. You are the final shield before the user sees the output.
- If a PoC looks like it was "guessed" rather than "verified", flag it for re-testing.
- If you find deficiencies, DO NOT fix them silently. Inform the CEO (USER) and propose a fix for the report generator code.

**REMEMBER**: A bad report wastes the Triager's time and hurts our reputation. Quality over quantity.
