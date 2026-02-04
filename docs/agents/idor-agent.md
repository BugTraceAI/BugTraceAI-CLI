# IDOR Agent Documentation

## Overview

The IDOR Agent (Insecure Direct Object Reference) is a specialist agent in BugTraceAI that detects and exploits IDOR vulnerabilities. It uses a WET→DRY two-phase pipeline with LLM-powered deduplication and optional deep exploitation analysis.

## Pipeline Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  PHASE A: WET → DRY (Deduplication)                             │
│  • Go fuzzer generates findings (WET)                            │
│  • LLM deduplicates using semantic analysis                     │
│  • Output: DRY list (unique findings only)                      │
└────────────────────────────┬────────────────────────────────────┘
                             ↓
┌─────────────────────────────────────────────────────────────────┐
│  PHASE B: Exploit DRY List                                      │
│  • Test each DRY finding                                        │
│  • Create IDOR finding if validated                             │
│  • → Phase 4b: Deep Exploitation (optional) ← NEW               │
│  • Emit to ValidationEngine                                     │
└─────────────────────────────────────────────────────────────────┘
```

## Deep Exploitation (Phase 4b)

IDORAgent includes optional deep exploitation analysis for CRITICAL/HIGH findings.

### Configuration

```python
# Enable/disable deep exploitation
IDOR_ENABLE_DEEP_EXPLOITATION = True

# Exploitation mode
IDOR_EXPLOITER_MODE = "full"  # Options: "full", "quick", "safe"

# Destructive tests (disabled by default for safety)
IDOR_EXPLOITER_ENABLE_WRITE_TESTS = False  # ⚠️ DANGEROUS: Allow PUT/PATCH
IDOR_EXPLOITER_ENABLE_DELETE_TESTS = False  # ⚠️ DANGEROUS: Allow DELETE

# Enumeration limits
IDOR_EXPLOITER_MAX_HORIZONTAL_ENUM = 50  # Max IDs to enumerate

# Severity threshold
IDOR_EXPLOITER_SEVERITY_THRESHOLD = "HIGH"  # Minimum severity to trigger exploitation

# Rate limiting (avoid WAF triggers)
IDOR_EXPLOITER_RATE_LIMIT = 0.5  # Seconds between requests

# Timeouts
IDOR_EXPLOITER_TIMEOUT = 10.0  # HTTP request timeout in seconds
```

### Exploitation Modes

| Mode | Phases Executed | Description |
|------|----------------|-------------|
| `safe` | Phase 1 only | Re-test confirmation (no enumeration) |
| `quick` | Phases 1-3 | Re-test + HTTP methods + impact analysis |
| `full` | Phases 1-6 | Complete analysis including escalation and LLM report |

### Exploitation Phases

#### Phase 1: Re-test Confirmation
- Re-fetch baseline (authorized) and exploit (unauthorized) URLs
- Confirm vulnerability still exists
- Analyze response differences (user_id, email extraction)
- Return confirmation status and differential summary

**Output:**
```python
{
    "confirmed": True,
    "baseline_status": 200,
    "exploit_status": 200,
    "baseline_length": 1234,
    "exploit_length": 1456,
    "response_diff": "user_id: {'123'} → {'456'}; email: {'alice@example.com'} → {'bob@example.com'}",
    "timestamp": "2026-02-04T10:30:00"
}
```

#### Phase 2: HTTP Methods Testing
- Test GET, POST, PUT, PATCH, DELETE methods
- Skip destructive tests if disabled via config
- Rate limiting to avoid WAF triggers
- Auto-detect severity upgrades

**Output:**
```python
{
    "methods_tested": ["GET", "POST", "PUT", "PATCH", "DELETE"],
    "vulnerable_methods": {
        "GET": {"status": 200, "accessible": True},
        "POST": {"status": 200, "accessible": True},
        "PUT": {"skipped": True, "reason": "write_tests_disabled"},
        "DELETE": {"skipped": True, "reason": "delete_tests_disabled"}
    },
    "accessible_methods": ["GET", "POST"],
    "severity_upgrade": "HIGH - Write methods accessible"
}
```

#### Phase 3: Impact Analysis
- Calculate read/write/delete capabilities
- Generate impact score (0-10)
- Build human-readable impact description

**Impact Score Calculation:**
- Read capability: +4.0 points
- Write capability: +3.0 points
- Delete capability: +3.0 points

**Output:**
```python
{
    "read_capability": True,
    "write_capability": True,
    "delete_capability": False,
    "impact_score": 7.0,
    "impact_description": "Attacker can: read unauthorized data, modify data"
}
```

#### Phase 4: Horizontal Escalation (mode=full only)
- Enumerate other accessible IDs
- Detect ID format (numeric, UUID, etc.)
- Generate test IDs based on format
- Identify special accounts (admin, root, system)
- Calculate severity multiplier based on exposure

**Output:**
```python
{
    "enumerated_ids": ["1", "2", "3", ...],  # First 20
    "total_accessible": 42,
    "id_pattern": "numeric",
    "special_accounts": ["1", "admin"],
    "severity_multiplier": 1.42
}
```

#### Phase 5: Vertical Escalation (mode=full only)
- Test admin ID candidates (0, 1, -1, admin, root, etc.)
- Detect privilege indicators in responses
- Categories: admin_panel, user_management, system_config
- Return confirmed vertical escalation status

**Output:**
```python
{
    "admin_accessible": True,
    "admin_ids": ["1", "admin"],
    "privilege_indicators": ["admin_panel", "user_management"],
    "vertical_confirmed": True
}
```

#### Phase 6: LLM Report Generation (mode=full only)
- Generate comprehensive exploitation report using LLM
- Professional Markdown format
- Includes: executive summary, technical analysis, PoC, remediation
- Falls back to basic report if LLM fails

**Output:** Full Markdown report (see Output Structure below)

### Output Structure

When deep exploitation is enabled, the finding is enhanced with an `exploitation` key:

```python
{
    "type": "IDOR",
    "url": "https://example.com/api/user?id=123",
    "parameter": "id",
    "payload": "456",
    "original_value": "123",
    "severity": "HIGH",  # May be upgraded to CRITICAL if delete_capability=True
    "evidence": {...},

    # Deep exploitation data (NEW)
    "exploitation": {
        "retest": {
            "confirmed": True,
            "baseline_status": 200,
            "exploit_status": 200,
            "response_diff": "user_id: {'123'} → {'456'}"
        },
        "http_methods": {
            "accessible_methods": ["GET", "POST"],
            "severity_upgrade": "HIGH - Write methods accessible"
        },
        "impact": {
            "read_capability": True,
            "write_capability": True,
            "delete_capability": False,
            "impact_score": 7.0,
            "impact_description": "Attacker can: read unauthorized data, modify data"
        },
        "horizontal": {
            "total_accessible": 42,
            "special_accounts": ["admin"]
        },
        "vertical": {
            "admin_accessible": True,
            "vertical_confirmed": True
        },
        "llm_report": "# IDOR Exploitation Report\n...",
        "timeline": [...]  # Execution log
    },

    "deep_exploitation_completed": True
}
```

### LLM Report Structure

The LLM-generated report includes:

```markdown
# IDOR Exploitation Report

## Executive Summary
[1-2 paragraphs explaining business impact]

## Vulnerability Details
- **Type:** Insecure Direct Object Reference (IDOR)
- **Severity:** HIGH/CRITICAL
- **CWE:** CWE-639
- **CVSS Score:** [Estimate based on impact]

## Technical Analysis

### 1. Re-test Confirmation
[Explain re-test results]

### 2. HTTP Methods Analysis
[Which methods are vulnerable?]

### 3. Impact Assessment
- **Read Access:** Yes/No + details
- **Write Access:** Yes/No + details
- **Delete Access:** Yes/No + details
- **Impact Score:** 0-10

### 4. Horizontal Escalation
[How many users can be accessed?]

### 5. Vertical Escalation
[Can admin accounts be accessed?]

## Proof of Concept

```bash
# Baseline (authorized)
curl 'https://example.com/api/user?id=123' -H 'Cookie: session=...'

# IDOR exploit (unauthorized)
curl 'https://example.com/api/user?id=456' -H 'Cookie: session=...'
```

## Business Impact
[Real-world consequences]

## Remediation

### Immediate Actions
1. [First step]
2. [Second step]

### Long-term Fixes
1. Implement proper authorization checks
2. Use indirect references (tokens instead of sequential IDs)
3. Add access control logging

## References
- OWASP: https://owasp.org/www-community/attacks/Insecure_Direct_Object_References
- CWE-639: https://cwe.mitre.org/data/definitions/639.html

---
**Report Generated:** 2026-02-04 10:30:00
**Tool:** BugTraceAI IDORAgent Deep Exploitation
```

## Safety Features

### Destructive Test Protection

By default, destructive tests are **DISABLED** to prevent accidental data modification:

- `IDOR_EXPLOITER_ENABLE_WRITE_TESTS = False` → Skips PUT/PATCH tests
- `IDOR_EXPLOITER_ENABLE_DELETE_TESTS = False` → Skips DELETE tests

Enable these **ONLY** in authorized testing environments where you have explicit permission.

### Rate Limiting

To avoid WAF triggers and respect server resources:

- `IDOR_EXPLOITER_RATE_LIMIT = 0.5` → Wait 0.5 seconds between requests
- Concurrent requests limited via asyncio.Semaphore (max 5 parallel)

### Severity Threshold

Deep exploitation is resource-intensive. Only run it on high-value findings:

- `IDOR_EXPLOITER_SEVERITY_THRESHOLD = "HIGH"` → Only CRITICAL/HIGH findings
- Configurable to "CRITICAL", "HIGH", "MEDIUM", or "LOW"

## Example Usage

### Basic IDOR Detection (without deep exploitation)

```python
from bugtrace.agents.idor_agent import IDORAgent

agent = IDORAgent(
    url="https://example.com/api/user?id=123",
    params=[{"parameter": "id", "original_value": "123"}]
)

findings = await agent.run()
# Returns basic IDOR findings with differential analysis
```

### With Deep Exploitation

```python
from bugtrace.core.config import settings

# Enable deep exploitation
settings.IDOR_ENABLE_DEEP_EXPLOITATION = True
settings.IDOR_EXPLOITER_MODE = "full"
settings.IDOR_EXPLOITER_SEVERITY_THRESHOLD = "HIGH"

agent = IDORAgent(
    url="https://example.com/api/user?id=123",
    params=[{"parameter": "id", "original_value": "123"}]
)

findings = await agent.run()
# Returns IDOR findings with deep exploitation data
# Check finding["exploitation"] for detailed analysis
```

### Safe Mode (Re-test Only)

```python
settings.IDOR_ENABLE_DEEP_EXPLOITATION = True
settings.IDOR_EXPLOITER_MODE = "safe"

# Only runs Phase 1 (re-test confirmation)
# No enumeration, no HTTP method testing
```

## Integration with ValidationEngine

IDOR findings are emitted to the ValidationEngine with `validation_requires_cdp=False` because:

- IDOR validation is HTTP-deterministic (no browser execution needed)
- CDP (Chrome DevTools Protocol) is only used for XSS/CSTI
- IDOR findings are validated via semantic differential analysis

## Performance Considerations

### Full Mode Impact

- **Phase 1-3:** ~3-5 seconds per finding (safe, fast)
- **Phase 4 (Horizontal):** ~10-30 seconds (depends on IDOR_EXPLOITER_MAX_HORIZONTAL_ENUM)
- **Phase 5 (Vertical):** ~5-10 seconds (8 admin candidates)
- **Phase 6 (LLM):** ~3-5 seconds (LLM generation)

**Total:** ~20-50 seconds per HIGH/CRITICAL finding in full mode

### Optimization Tips

1. Use `mode="quick"` for faster analysis (skips Phases 4-5)
2. Reduce `IDOR_EXPLOITER_MAX_HORIZONTAL_ENUM` for faster horizontal testing
3. Increase `IDOR_EXPLOITER_RATE_LIMIT` if server has strict rate limiting
4. Use `IDOR_EXPLOITER_SEVERITY_THRESHOLD="CRITICAL"` to only exploit highest-severity findings

## Troubleshooting

### "Re-test failed" in exploitation log

**Cause:** The IDOR was a false positive, or the vulnerability was patched between detection and exploitation.

**Solution:** This is expected behavior. The finding is still reported but marked as `exploitation_failed="retest_failed"`.

### All HTTP methods show "skipped"

**Cause:** Destructive tests are disabled by default.

**Solution:** If authorized, enable write/delete tests:
```python
settings.IDOR_EXPLOITER_ENABLE_WRITE_TESTS = True  # Enable PUT/PATCH
settings.IDOR_EXPLOITER_ENABLE_DELETE_TESTS = True  # Enable DELETE
```

### LLM report is very short

**Cause:** LLM generation failed, fallback report was used.

**Solution:** Check LLM configuration and logs. The basic fallback report still contains key information.

### Horizontal enumeration finds 0 IDs

**Cause:**
- ID format detection failed
- Server has proper authorization checks (good!)
- Rate limiting or WAF blocking requests

**Solution:** This is normal if the server is properly secured. Check logs for HTTP errors.

## References

- [OWASP IDOR](https://owasp.org/www-community/attacks/Insecure_Direct_Object_References)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- [OWASP API Security Top 10 - Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
