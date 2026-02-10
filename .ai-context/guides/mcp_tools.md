# BugTraceAI MCP Tool Reference

## Overview

BugTraceAI exposes its security scanning capabilities through the Model Context Protocol (MCP), allowing AI assistants like Claude to run scans, query findings, and explain vulnerabilities directly in conversation.

**Transport:** STDIO (local process communication)

### Starting the MCP Server

```bash
bugtraceai-cli mcp
```

### Claude Desktop Configuration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "bugtrace": {
      "command": "bugtraceai-cli",
      "args": ["mcp"]
    }
  }
}
```

## Tools

BugTraceAI registers 6 MCP tools across two modules.

### start_scan

Start a new security scan on a target URL. The scan runs in the background.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `target_url` | `str` | required | URL to scan (HTTP/HTTPS) |
| `scan_type` | `str` | `"full"` | Scan type: `full`, `hunter`, `manager`, or specific agent name |
| `max_depth` | `int` | `2` | Maximum crawl depth (1-5) |
| `max_urls` | `int` | `20` | Maximum URLs to scan (1-100) |

**Returns:** `{"scan_id": int, "status": "created", "message": str}`

**Example:**
```
Scan https://example.com with full scan type and max depth of 3
```

---

### get_scan_status

Get the current status and progress of a scan.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `scan_id` | `int` | required | The scan ID to check |

**Returns:** `{"scan_id": int, "target": str, "status": str, "progress": int, "findings_count": int, "active_agent": str, "phase": str, "uptime_seconds": float}`

Status values: `initializing`, `running`, `completed`, `failed`, `stopped`

**Example:**
```
Check the status of scan 1
```

---

### query_findings

Retrieve vulnerability findings from a scan with optional filtering and pagination.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `scan_id` | `int` | required | The scan ID to query |
| `severity` | `str` | `None` | Filter: `critical`, `high`, `medium`, `low`, `info` |
| `vuln_type` | `str` | `None` | Filter: `xss`, `sqli`, `csrf`, etc. |
| `page` | `int` | `1` | Page number (min: 1) |
| `per_page` | `int` | `20` | Results per page (1-100) |

**Returns:** `{"scan_id": int, "findings": list, "total": int, "page": int, "per_page": int, "total_pages": int}`

**Example:**
```
Show me all high severity findings from scan 1
```

---

### stop_scan

Stop a running scan gracefully. The scan completes current tasks before stopping.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `scan_id` | `int` | required | The scan ID to stop |

**Returns:** `{"scan_id": int, "status": str, "message": str}`

**Example:**
```
Stop scan 1
```

---

### explain_vulnerability

Explain a vulnerability finding in business terms. Returns structured explanation with business impact, technical details, and risk rating. Does not call external LLMs.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `vuln_type` | `str` | required | Vulnerability type (see supported types below) |
| `severity` | `str` | `"HIGH"` | Severity level: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` |
| `details` | `str` | `""` | Optional additional context about the finding |

Supported vulnerability types: `XSS`, `SQLI`, `RCE`, `XXE`, `CSTI`, `PROTOTYPE_POLLUTION`, `OPEN_REDIRECT`, `HEADER_INJECTION`, `SENSITIVE_DATA_EXPOSURE`, `IDOR`, `LFI`, `SSRF`, `SECURITY_MISCONFIGURATION`

**Returns:** `{"vuln_type": str, "severity": str, "business_impact": str, "technical_explanation": str, "risk_rating": int, "affected_area": str, "additional_context": str}`

**Example:**
```
Explain the XSS vulnerability found with critical severity
```

---

### suggest_remediation

Suggest remediation steps for a vulnerability. Returns prioritized fix steps, code examples, and OWASP reference links.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `vuln_type` | `str` | required | Vulnerability type (same values as explain_vulnerability) |
| `severity` | `str` | `"HIGH"` | Severity level |
| `url` | `str` | `""` | Optional URL where vulnerability was found |
| `parameter` | `str` | `""` | Optional vulnerable parameter name |

**Returns:** `{"vuln_type": str, "severity": str, "priority": str, "remediation_steps": list, "code_example": str, "references": list, "context": str}`

Priority values: `Immediate` (critical), `High`, `Planned` (medium), `Low`, `Optional` (info)

**Example:**
```
How do I fix the SQL injection on the login page's username parameter?
```

## Resources

BugTraceAI exposes 3 read-only MCP resources for contextual data.

### scan-results://{scan_id}

Combined scan status and findings for a specific scan.

**URI pattern:** `scan-results://1`, `scan-results://42`

**Returns:** `{"status": {...}, "findings": {...}}`

---

### bugtrace://vulnerability_types

List of all 13 detectable vulnerability categories with descriptions.

**URI:** `bugtrace://vulnerability_types`

**Returns:** `{"vulnerability_types": [{"id": str, "name": str, "description": str}, ...]}`

---

### bugtrace://configuration_schema

JSON schema of ScanOptions and runtime configuration fields.

**URI:** `bugtrace://configuration_schema`

**Returns:** `{"scan_options_schema": {...}, "runtime_config_fields": {...}}`

Runtime config fields: MAX_DEPTH, MAX_URLS, MAX_CONCURRENT_URL_AGENTS, SAFE_MODE, DEFAULT_MODEL

## Example Workflow

A typical AI assistant conversation using BugTraceAI MCP tools:

1. **Start a scan:** Assistant calls `start_scan` with the target URL and receives a `scan_id`
2. **Monitor progress:** Assistant polls `get_scan_status` to track completion percentage
3. **Review findings:** Once complete, assistant calls `query_findings` to list vulnerabilities
4. **Explain results:** For each finding, assistant calls `explain_vulnerability` for business context
5. **Get fixes:** Assistant calls `suggest_remediation` for actionable remediation steps with code examples
6. **Access resources:** Assistant reads `scan-results://{scan_id}` for the full combined report

### Sample Conversation

> **User:** Scan my app at https://testapp.example.com
>
> **Assistant:** *(calls start_scan)* Started scan 1 on https://testapp.example.com. I will monitor progress.
>
> **Assistant:** *(calls get_scan_status)* Scan is 45% complete, currently running the XSS detection agent.
>
> **Assistant:** *(calls get_scan_status)* Scan complete. Found 3 vulnerabilities.
>
> **Assistant:** *(calls query_findings)* Here are the findings:
> - HIGH: SQL Injection on /api/login (username parameter)
> - MEDIUM: XSS on /search (query parameter)
> - LOW: Missing security headers
>
> **User:** Tell me more about the SQL injection
>
> **Assistant:** *(calls explain_vulnerability + suggest_remediation)* This SQL injection allows attackers to manipulate database queries. Use parameterized queries to fix it. Here is an example...
