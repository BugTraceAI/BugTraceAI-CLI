---
name: REPORT_VALIDATOR
version: 1.0
description: "Post-scan report verification agent"
---

# REPORT_VALIDATOR

Analyze the provided screenshot of the URL: {url}
Current payload being tested: {payload}

XSS SUCCESS indicators:
✅ Text containing "HACKED BY BUGTRACEAI", "FRAGMENT XSS", "MXSS DETECTED" or similar
✅ Any banner/div with "HACKED", "BUGTRACEAI", "BUGTRACE", "PWNED", or "XSS" text
✅ Alert/confirm/prompt dialog box showing injected content
✅ Visible `<script>` tags rendered as HTML elements (not escaped)
✅ DOM manipulation evidence (unusual banners, floating divs)

XSS FAILURE indicators:
❌ Normal page with no abnormalities
❌ "Invalid input" or error message
❌ Payload visible as escaped text (e.g., `&lt;script&gt;`)
❌ WAF/security block page

Respond in JSON ONLY:

```json
{{
  "success": true/false,
  "confidence": 0.0-1.0,
  "evidence": "detailed description of what you see that proves or disproves XSS"
}}
```

## SQLi Vision Analysis Prompt

Analyze the provided screenshot for SQL Injection validation.
URL: {url}
Payload: {payload}

SQL INJECTION SUCCESS indicators:
✅ SQL syntax error message (MySQL, PostgreSQL, etc.)
✅ Database version disclosure
✅ Unexpected data displayed
✅ Table/column names in error

SQL INJECTION FAILURE indicators:
❌ Normal page content
❌ Generic "Invalid input" (type validation, not SQLi)
❌ WAF block page
❌ 404/500 without SQL hints

Respond in JSON ONLY:

```json
{{
  "success": true/false,
  "confidence": 0.0-1.0,
  "evidence": "detailed description of what you see",
  "db_type": "MySQL/PostgreSQL/None"
}}
```

## General Vision Analysis Prompt

Analyze the provided screenshot for security vulnerability validation.
URL: {url}
Payload: {payload}

Look for any signs of:

- Security vulnerability exploitation
- Error messages revealing sensitive info
- Unexpected behavior indicating a bug
- Evidence the payload affected the application

Respond in JSON ONLY:

```json
{{
  "success": true/false,
  "confidence": 0.0-1.0,
  "evidence": "description of what you observe"
}}
```
