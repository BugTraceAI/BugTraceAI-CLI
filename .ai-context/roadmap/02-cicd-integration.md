# CI/CD Integration - Feature Tasks

## Feature Overview
Integrate BugTraceAI-CLI into developer CI/CD workflows for automated security testing.

**Why**: Developers want security in their workflow (shift-left security)
**Competitor Gap**: Strix (GitHub Actions), Shannon (Temporal workflows)
**Phase**: 2 - Competitive Parity
**Duration**: 1 week
**Effort**: $10k

---

## 🟣 QUICK Tasks

### FEATURE-013: Add Exit Codes for CI/CD
**Complexity**: 🟣 QUICK (1 day)
**Priority**: P1

**Implementation**:
```python
# bugtrace/cli/main.py
import sys

def main():
    scan = run_scan(url)

    # Exit codes
    if scan.critical_findings > 0:
        print(f"FAILED: {scan.critical_findings} critical vulnerabilities found")
        sys.exit(1)  # CI/CD will fail the build

    elif scan.high_findings > 0:
        print(f"WARNING: {scan.high_findings} high severity findings")
        sys.exit(0)  # Warning only, don't fail

    else:
        print("PASSED: No critical vulnerabilities")
        sys.exit(0)
```

**Configuration**:
```ini
[CI_CD]
FAIL_ON_CRITICAL=true
FAIL_ON_HIGH=false
FAIL_ON_MEDIUM=false
```

---

### FEATURE-014: Add Quick Scan Mode
**Complexity**: 🟣 QUICK (2 days)
**Priority**: P1

**Description**: 5-minute max scan for CI/CD

**Implementation**:
```python
# bugtrace/core/scan_modes.py
SCAN_MODES = {
    "quick": {
        "max_depth": 1,
        "max_urls": 5,
        "max_duration_seconds": 300,  # 5 minutes
        "agents": ["xss", "sqli", "idor"],  # Top 3 only
        "parallel": True,
        "skip_validation": False  # Still validate!
    },
    "thorough": {
        "max_depth": 3,
        "max_urls": 50,
        "max_duration_seconds": 3600,  # 1 hour
        "agents": "all",
        "parallel": True
    },
    "bug-bounty": {
        "max_depth": 5,
        "max_urls": 200,
        "max_duration_seconds": 7200,  # 2 hours
        "agents": "all",
        "parallel": True,
        "enable_waf_bypass": True,
        "enable_vision_ai": True
    }
}

# Usage
./bugtraceai-cli scan --mode quick https://target.com
```

---

## 🔵 MEDIUM Tasks

### FEATURE-015: Create GitHub Actions Workflow
**Complexity**: 🔵 MEDIUM (3 days)
**Priority**: P1

**Implementation**:
```yaml
# .github/workflows/bugtrace-scan.yml
name: BugTraceAI Security Scan
on:
  pull_request:
    branches: [main]
  push:
    branches: [staging, production]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write  # For SARIF upload

    steps:
      - name: Checkout code
        uses: actions/checkout@v3

      - name: Install BugTraceAI
        run: |
          pip install bugtraceai-cli

      - name: Configure API Keys
        env:
          OPENROUTER_API_KEY: ${{ secrets.OPENROUTER_API_KEY }}
        run: |
          echo "OPENROUTER_API_KEY=$OPENROUTER_API_KEY" > .env

      - name: Run Security Scan
        run: |
          bugtraceai-cli scan \
            --target ${{ github.event.pull_request.html_url || github.repository_url }} \
            --mode quick \
            --output-format sarif \
            --output-file bugtrace-results.sarif
        continue-on-error: true

      - name: Upload SARIF Results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: bugtrace-results.sarif
          category: bugtrace-cli

      - name: Comment on PR
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v6
        with:
          script: |
            const fs = require('fs');
            const results = JSON.parse(fs.readFileSync('bugtrace-results.json'));

            const comment = `## 🔒 BugTraceAI Security Scan Results

            **Status:** ${results.critical_count > 0 ? '❌ FAILED' : '✅ PASSED'}

            | Severity | Count |
            |----------|-------|
            | 🔴 Critical | ${results.critical_count} |
            | 🟠 High | ${results.high_count} |
            | 🟡 Medium | ${results.medium_count} |

            View detailed results in the Security tab.`;

            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: comment
            });
```

---

### FEATURE-016: Add SARIF Output Format
**Complexity**: 🔵 MEDIUM (2 days)
**Priority**: P1

**Description**: Generate SARIF for GitHub Security tab

**Implementation**:
```python
# bugtrace/output/sarif.py
import json

def generate_sarif(findings, scan_info):
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "BugTraceAI-CLI",
                    "version": scan_info["version"],
                    "informationUri": "https://bugtraceai.com",
                    "rules": _generate_rules()
                }
            },
            "results": [
                {
                    "ruleId": f"BT-{finding.type}",
                    "level": _severity_to_sarif(finding.severity),
                    "message": {
                        "text": finding.details
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.url
                            },
                            "region": {
                                "startLine": 1,
                                "snippet": {
                                    "text": finding.payload_used
                                }
                            }
                        }
                    }],
                    "properties": {
                        "confidence": finding.confidence_score,
                        "validated": finding.visual_validated,
                        "attack_url": finding.attack_url,
                        "parameter": finding.vuln_parameter
                    }
                }
                for finding in findings
            ]
        }]
    }

def _severity_to_sarif(severity):
    return {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note"
    }.get(severity, "warning")
```

**Usage**:
```bash
bugtraceai-cli scan --output-format sarif https://target.com
```

---

### FEATURE-017: Add JSON Summary Output
**Complexity**: 🟣 QUICK (1 day)
**Priority**: P1

**Description**: Machine-readable scan results

**Implementation**:
```python
# bugtrace/output/json_summary.py
def generate_json_summary(scan):
    return {
        "scan_id": scan.id,
        "target": scan.target_url,
        "started_at": scan.started_at.isoformat(),
        "completed_at": scan.completed_at.isoformat(),
        "duration_seconds": (scan.completed_at - scan.started_at).total_seconds(),
        "status": scan.status,
        "summary": {
            "critical_count": scan.critical_findings,
            "high_count": scan.high_findings,
            "medium_count": scan.medium_findings,
            "low_count": scan.low_findings,
            "total_findings": scan.total_findings
        },
        "findings": [
            {
                "id": f.id,
                "type": f.type,
                "severity": f.severity,
                "confidence": f.confidence_score,
                "validated": f.visual_validated,
                "url": f.attack_url,
                "parameter": f.vuln_parameter,
                "payload": f.payload_used,
                "proof": f.proof_screenshot_path
            }
            for f in scan.findings
        ],
        "cost_analysis": {
            "llm_cost_usd": scan.llm_cost,
            "tokens_used": scan.tokens_used
        }
    }
```

---

### FEATURE-018: Add GitLab CI Integration
**Complexity**: 🔵 MEDIUM (2 days)
**Priority**: P2

**Implementation**:
```yaml
# .gitlab-ci.yml
security-scan:
  image: python:3.11
  stage: test
  script:
    - pip install bugtraceai-cli
    - bugtraceai-cli scan --mode quick --output-format gitlab $CI_PROJECT_URL
  artifacts:
    reports:
      sast: bugtrace-gl-sast-report.json
  only:
    - merge_requests
```

---

## 🟠 COMPLEX Tasks

### FEATURE-019: Add IDE Integration (VS Code)
**Complexity**: 🟠 COMPLEX (1 week)
**Priority**: P2

**Description**: VS Code extension for inline security scanning

**Implementation**: Create VS Code extension package
- Right-click file → "Scan with BugTraceAI"
- Shows results in Problems panel
- Inline annotations for vulnerabilities

---

### FEATURE-020: Add Pre-Commit Hook
**Complexity**: 🟣 QUICK (1 day)
**Priority**: P2

**Implementation**:
```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: bugtrace-scan
        name: BugTraceAI Quick Scan
        entry: bugtraceai-cli scan --mode quick
        language: system
        pass_filenames: false
```

---

## 🟢 NICE-TO-HAVE Tasks

### FEATURE-021: Add Jenkins Plugin
**Complexity**: 🟠 COMPLEX (1 week)
**Priority**: P3

---

### FEATURE-022: Add CircleCI Orb
**Complexity**: 🔵 MEDIUM (3 days)
**Priority**: P3

---

## Summary

**Total Tasks**: 10
- 🟣 Quick: 4 (5 days)
- 🔵 Medium: 4 (9 days)
- 🟠 Complex: 2 (optional)

**Estimated Effort**: 1 week for P1 tasks
**Investment**: ~$10k

**Competitive Gap Closed**:
- Strix (GitHub Actions integration)
- Shannon (Workflow orchestration)

**Deliverables**:
- GitHub Actions workflow
- SARIF output format
- Quick scan mode
- Exit codes for CI/CD
- JSON summary output
- GitLab CI integration (bonus)
