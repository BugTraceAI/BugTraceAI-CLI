"""
SQLMap Core

PURE functions for SQLMap command building, result parsing,
security validation, data structures, DB fingerprinting,
and WAF bypass strategy.

Extracted from sqlmap_agent.py for modularity.
"""

import re
import json
import hashlib
import base64
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bugtrace.agents.sqlmap.core_types import SQLiEvidence, SQLMapConfig, DBType


# =============================================================================
# SECURITY VALIDATION PATTERNS
# =============================================================================

# Regex for safe cookie values (alphanumeric, dash, underscore, equals, dot, slash)
def build_report_header(
    url: str,
    stats: Dict,
    detected_waf: Optional[str],
    detected_db_type: DBType,
    agent_name: str,
) -> str:  # PURE
    """Build report header with summary.

    Args:
        url: Target URL
        stats: Agent statistics
        detected_waf: Detected WAF name
        detected_db_type: Detected database type
        agent_name: Agent name

    Returns:
        Markdown report header string
    """
    import datetime
    return f"""# SQL Injection Report
## Target: {url}
## Date: {datetime.datetime.now().isoformat()}
## Agent: {agent_name}

---

## Summary
- **Parameters Tested:** {stats['params_tested']}
- **Vulnerabilities Found:** {stats['vulns_found']}
- **WAF Bypasses:** {stats['waf_bypassed']}
- **Data Extractions:** {stats['data_extracted']}
- **Detected WAF:** {detected_waf or 'None'}
- **Detected DB Type:** {detected_db_type.value}

---

## Findings

"""

def build_single_finding_report(index: int, finding: Dict) -> str:  # PURE
    """Build markdown for a single finding.

    Args:
        index: Finding number
        finding: Finding dictionary

    Returns:
        Markdown string for finding
    """
    content = f"""### Finding #{index}: {finding['type']} CONFIRMED

| Field | Value |
|-------|-------|
| **URL** | `{finding.get('url', 'N/A')}` |
| **Parameter** | `{finding.get('parameter', 'N/A')}` |
| **Injection Type** | {finding.get('payload', 'N/A')} |
| **DB Type** | {finding.get('db_type', 'unknown')} |
| **Validation Method** | {finding.get('validation_method', 'N/A')} |
| **Confidence** | {finding.get('confidence', 1.0):.0%} |
| **Tamper Used** | {finding.get('tamper_used', 'None')} |

**Reproduction Command:**
```bash
{finding.get('reproduction', 'N/A')}
```

"""
    if finding.get('extracted_data'):
        content += f"""**Extracted Data:**
```json
{json.dumps(finding['extracted_data'], indent=2)}
```

"""

    content += f"""**Evidence:**
```
{finding.get('evidence', 'N/A')[:1000]}
```

---

"""
    return content

def build_report_findings(findings: List[Dict]) -> str:  # PURE
    """Build findings section of report.

    Args:
        findings: List of finding dictionaries

    Returns:
        Combined markdown findings string
    """
    content = ""
    for i, f in enumerate(findings, 1):
        content += build_single_finding_report(i, f)
    return content

