# GEMINI HANDOFF: DASTySAST Code Challenge Dojo

**Date:** 2026-01-19  
**Priority:** 🔴 HIGH  
**Type:** Testing Infrastructure - DASTySAST Calibration  
**Prepared by:** Antigravity AI Assistant

---

## Executive Summary

Create a specialized **Code Challenge Dojo** to benchmark and calibrate the `DASTySASTAgent` and its `_skeptical_review()` function. Unlike traditional security dojos that test exploitation, this Dojo tests the **analysis and filtering accuracy** of the DASTySAST pipeline.

### The Core Problem

The DASTySAST + Skeptical Review needs to find the perfect balance:

```
┌─────────────────────────────────────────────────────────────────┐
│                     THE BALANCE PROBLEM                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   Too Aggressive Skeptical    ←──────→    Too Permissive        │
│   (Rejects real vulns)                    (Passes garbage)      │
│                                                                 │
│   ❌ False Negatives                      ❌ False Positives    │
│   = Missed vulnerabilities                = Wasted agent time   │
│                                                                 │
│                        ▼ GOAL ▼                                 │
│                                                                 │
│              ✅ Approve REAL vulnerabilities                    │
│              ✅ Reject FALSE positives                          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Objective

Create `dojo_dastysast_challenges.py` that:

1. Presents **10 Code Challenges** with increasing difficulty (L1-L10)
2. Each challenge has a **known correct answer** (vulnerable or safe)
3. Allows measurement of DASTySAST + Skeptical accuracy
4. Enables rapid iteration and calibration

---

## File Location

```
/home/ubuntu/Dev/Projects/BugTraceAI/BugTraceAI-CLI/testing/dojos/dojo_dastysast_challenges.py
```

**Port:** `5250`

---

## How DASTySAST Works (Context for Gemini)

The DASTySAST analyzes **rendered HTML** (not source code) to detect vulnerabilities:

```python
# In analysis_agent.py
async def run(self):
    # 1. Fetch page HTML
    html_content = await self._fetch_html(self.url)
    
    # 2. LLM analyzes HTML for vulnerability patterns
    # 3. 5 voting rounds for consensus
    # 4. Skeptical Review filters false positives
    
    return approved_candidates  # Goes to specialist agents
```

**Key insight:** The Dojo must return realistic HTML that simulates vulnerable/safe patterns.

---

## Challenge Design

### Structure Per Challenge

Each challenge endpoint returns HTML that:

1. Contains parameters reflected in different contexts
2. Shows clear indicators of vulnerability (or safety)
3. Has metadata in comments for verification

### The 10 Levels

| Level | Name | Type | Expected DASTySAST | Expected Skeptical | Why |
|-------|------|------|-------------------|-------------------|-----|
| L1 | Obvious XSS | VULN | Detect ✅ | Approve ✅ | Direct `<p>{input}</p>` reflection |
| L2 | Attribute XSS | VULN | Detect ✅ | Approve ✅ | `<input value="{input}">` |
| L3 | Escaped Safe | SAFE | Maybe detect | Reject ✅ | Uses `html.escape()` properly |
| L4 | Misleading Param Name | SAFE | Detect SQLi? | Reject ✅ | Param called "id" but just text |
| L5 | Webhook Display Only | SAFE | Detect SSRF? | Reject ✅ | Shows "webhook" but no request |
| L6 | Error-Based SQLi | VULN | Detect ✅ | Approve ✅ | Shows SQL error in response |
| L7 | XML Comment | SAFE | Detect XXE? | Reject ✅ | "XML" mentioned but safe |
| L8 | Subtle Reflection | VULN | Detect ✅ | Approve ✅ | Hidden in JS context |
| L9 | Complex Filter Bypass | VULN | Detect ✅ | Approve ✅ | Filter but bypassable |
| L10 | Level God | VULN | Detect? | Approve? | Near-impossible subtle vuln |

---

## Implementation Specification

### Base Flask Structure

```python
#!/usr/bin/env python3
"""
DASTySAST Code Challenge Dojo
Port: 5250

PURPOSE: Calibrate DASTySAST + Skeptical Review accuracy
Each endpoint is a "challenge" with known correct answer.
"""

from flask import Flask, request
import html as html_module

app = Flask(__name__)
PORT = 5250

# Challenge metadata for automated testing
CHALLENGES = {
    "L1": {"type": "xss", "expected_vuln": True, "difficulty": "easy"},
    "L2": {"type": "xss", "expected_vuln": True, "difficulty": "easy"},
    "L3": {"type": "xss", "expected_vuln": False, "difficulty": "medium"},
    "L4": {"type": "sqli", "expected_vuln": False, "difficulty": "medium"},
    "L5": {"type": "ssrf", "expected_vuln": False, "difficulty": "medium"},
    "L6": {"type": "sqli", "expected_vuln": True, "difficulty": "hard"},
    "L7": {"type": "xxe", "expected_vuln": False, "difficulty": "hard"},
    "L8": {"type": "xss", "expected_vuln": True, "difficulty": "expert"},
    "L9": {"type": "xss", "expected_vuln": True, "difficulty": "expert"},
    "L10": {"type": "mixed", "expected_vuln": True, "difficulty": "god"},
}


@app.route('/')
def index():
    """Index page with all challenges listed."""
    challenges_html = ""
    for level, meta in CHALLENGES.items():
        vuln_status = "🔴 VULNERABLE" if meta["expected_vuln"] else "🟢 SAFE"
        challenges_html += f'''
        <tr>
            <td><a href="/challenge/{level}?input=test">{level}</a></td>
            <td>{meta["type"].upper()}</td>
            <td>{meta["difficulty"]}</td>
            <td>{vuln_status}</td>
        </tr>
        '''
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head><title>DASTySAST Code Challenge Dojo</title></head>
    <body>
        <h1>🧪 DASTySAST Calibration Challenges</h1>
        <p>Each challenge tests DASTySAST + Skeptical Review accuracy.</p>
        <table border="1" cellpadding="10">
            <tr><th>Level</th><th>Type</th><th>Difficulty</th><th>Expected</th></tr>
            {challenges_html}
        </table>
        
        <h2>API Endpoint</h2>
        <p>GET <code>/api/challenges</code> - Returns JSON with all challenge metadata</p>
    </body>
    </html>
    """


@app.route('/api/challenges')
def api_challenges():
    """Return challenge metadata for automated testing."""
    from flask import jsonify
    return jsonify(CHALLENGES)
```

### Challenge Implementations

```python
# ============================================================
# LEVEL 1: Obvious XSS (VULNERABLE)
# Expected: DASTySAST detects, Skeptical approves
# ============================================================
@app.route('/challenge/L1')
def challenge_l1():
    """
    VULNERABLE: Direct reflection without any escaping.
    This is the most basic XSS - if DASTySAST misses this, something is broken.
    """
    user_input = request.args.get('input', 'default')
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head><title>Challenge L1 - Obvious XSS</title></head>
    <body>
        <h1>Search Results</h1>
        <!-- CHALLENGE: L1 | TYPE: XSS | EXPECTED: VULNERABLE -->
        <p>You searched for: {user_input}</p>
        <p>No results found.</p>
    </body>
    </html>
    """


# ============================================================
# LEVEL 2: Attribute XSS (VULNERABLE)
# Expected: DASTySAST detects, Skeptical approves
# ============================================================
@app.route('/challenge/L2')
def challenge_l2():
    """
    VULNERABLE: Reflection inside HTML attribute.
    Requires breaking out of attribute context.
    """
    user_input = request.args.get('input', 'default')
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head><title>Challenge L2 - Attribute XSS</title></head>
    <body>
        <h1>Profile Settings</h1>
        <!-- CHALLENGE: L2 | TYPE: XSS | EXPECTED: VULNERABLE -->
        <form>
            <label>Display Name:</label>
            <input type="text" name="name" value="{user_input}">
            <button type="submit">Save</button>
        </form>
    </body>
    </html>
    """


# ============================================================
# LEVEL 3: Escaped Safe (NOT VULNERABLE)
# Expected: DASTySAST might flag, Skeptical MUST reject
# ============================================================
@app.route('/challenge/L3')
def challenge_l3():
    """
    SAFE: Properly escaped output.
    DASTySAST might see reflection, but Skeptical should recognize safety.
    """
    user_input = request.args.get('input', 'default')
    safe_input = html_module.escape(user_input)
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head><title>Challenge L3 - Safe Display</title></head>
    <body>
        <h1>Message Board</h1>
        <!-- CHALLENGE: L3 | TYPE: XSS | EXPECTED: SAFE -->
        <p>Your message: {safe_input}</p>
        <p><small>All inputs are properly sanitized.</small></p>
    </body>
    </html>
    """


# ============================================================
# LEVEL 4: Misleading Param Name (NOT VULNERABLE)
# Expected: DASTySAST might flag SQLi, Skeptical MUST reject
# ============================================================
@app.route('/challenge/L4')
def challenge_l4():
    """
    SAFE: Parameter named 'id' but just displayed as text.
    No database interaction whatsoever.
    """
    user_id = request.args.get('id', '1')
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head><title>Challenge L4 - Misleading Param</title></head>
    <body>
        <h1>User Profile</h1>
        <!-- CHALLENGE: L4 | TYPE: SQLI | EXPECTED: SAFE -->
        <p>Viewing profile ID: {html_module.escape(user_id)}</p>
        <p>Username: test_user</p>
        <p>Status: Active</p>
        <p><small>Note: This is a static page, no database.</small></p>
    </body>
    </html>
    """


# ============================================================
# LEVEL 5: Webhook Display Only (NOT VULNERABLE)
# Expected: DASTySAST might flag SSRF, Skeptical MUST reject
# ============================================================
@app.route('/challenge/L5')
def challenge_l5():
    """
    SAFE: Parameter named 'webhook' but only displayed.
    No outbound requests are made.
    """
    webhook_url = request.args.get('webhook', 'https://example.com/hook')
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head><title>Challenge L5 - Webhook Config</title></head>
    <body>
        <h1>Webhook Configuration</h1>
        <!-- CHALLENGE: L5 | TYPE: SSRF | EXPECTED: SAFE -->
        <p>Current webhook URL: {html_module.escape(webhook_url)}</p>
        <p>Status: Configured (display only)</p>
        <p><small>Webhooks are processed by external service, not this server.</small></p>
    </body>
    </html>
    """


# ============================================================
# LEVEL 6: Error-Based SQLi (VULNERABLE)
# Expected: DASTySAST detects SQL error, Skeptical approves
# ============================================================
@app.route('/challenge/L6')
def challenge_l6():
    """
    VULNERABLE: SQL error message exposed in response.
    Clear indicator of SQL injection possibility.
    """
    user_id = request.args.get('id', '1')
    
    # Simulate SQL error if special chars present
    if "'" in user_id or '"' in user_id:
        error_html = f"""
        <div class="error">
            <h2>Database Error</h2>
            <pre>MySQL Error: You have an error in your SQL syntax near '{user_id}'</pre>
            <p>Query: SELECT * FROM users WHERE id = {user_id}</p>
        </div>
        """
    else:
        error_html = "<p>User: admin</p>"
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head><title>Challenge L6 - SQL Error</title></head>
    <body>
        <h1>User Lookup</h1>
        <!-- CHALLENGE: L6 | TYPE: SQLI | EXPECTED: VULNERABLE -->
        {error_html}
    </body>
    </html>
    """


# ============================================================
# LEVEL 7: XML Comment Misleading (NOT VULNERABLE)
# Expected: DASTySAST might flag XXE, Skeptical MUST reject
# ============================================================
@app.route('/challenge/L7')
def challenge_l7():
    """
    SAFE: References XML but doesn't process it.
    The word "XML" appears but no parser is used.
    """
    data = request.args.get('data', 'sample')
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head><title>Challenge L7 - XML Mention</title></head>
    <body>
        <h1>Data Export</h1>
        <!-- CHALLENGE: L7 | TYPE: XXE | EXPECTED: SAFE -->
        <p>Export format: XML, JSON, CSV</p>
        <p>Your data: {html_module.escape(data)}</p>
        <p><small>Note: Export happens client-side, no server XML parsing.</small></p>
    </body>
    </html>
    """


# ============================================================
# LEVEL 8: Subtle JS Context (VULNERABLE)
# Expected: DASTySAST should detect, Skeptical should approve
# ============================================================
@app.route('/challenge/L8')
def challenge_l8():
    """
    VULNERABLE: Reflection inside JavaScript string.
    Requires understanding of execution context.
    """
    user_input = request.args.get('input', 'default')
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head><title>Challenge L8 - JS Context</title></head>
    <body>
        <h1>Dashboard</h1>
        <!-- CHALLENGE: L8 | TYPE: XSS | EXPECTED: VULNERABLE -->
        <div id="greeting"></div>
        <script>
            var username = '{user_input}';
            document.getElementById('greeting').innerText = 'Hello, ' + username;
        </script>
    </body>
    </html>
    """


# ============================================================
# LEVEL 9: Filter Bypass (VULNERABLE)
# Expected: DASTySAST should detect despite filter, Skeptical approves
# ============================================================
@app.route('/challenge/L9')
def challenge_l9():
    """
    VULNERABLE: Has a filter but it's bypassable.
    Blocks <script> but not other vectors.
    """
    user_input = request.args.get('input', 'default')
    
    # Weak filter - only blocks <script>
    filtered = user_input.replace('<script', '').replace('</script>', '')
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head><title>Challenge L9 - Filter Bypass</title></head>
    <body>
        <h1>Filtered Search</h1>
        <!-- CHALLENGE: L9 | TYPE: XSS | EXPECTED: VULNERABLE (filter bypassable) -->
        <p>Results for: {filtered}</p>
        <p><small>Protected by security filter v1.0</small></p>
    </body>
    </html>
    """


# ============================================================
# LEVEL 10: God Level (VULNERABLE)
# Expected: Very subtle, tests limits of DASTySAST
# ============================================================
@app.route('/challenge/L10')
def challenge_l10():
    """
    VULNERABLE: Extremely subtle vulnerability.
    Requires deep reasoning to identify.
    """
    callback = request.args.get('callback', 'handleData')
    data = request.args.get('data', '{}')
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head><title>Challenge L10 - God Level</title></head>
    <body>
        <h1>JSONP API</h1>
        <!-- CHALLENGE: L10 | TYPE: MIXED | EXPECTED: VULNERABLE (JSONP callback injection) -->
        <script>
            function handleData(d) {{ console.log(d); }}
        </script>
        <script src="/api/data?callback={callback}&data={data}"></script>
    </body>
    </html>
    """


# ============================================================
# MAIN
# ============================================================
if __name__ == '__main__':
    print(f"🧪 DASTySAST Code Challenge Dojo - Port {PORT}")
    print("=" * 50)
    for level, meta in CHALLENGES.items():
        status = "🔴 VULN" if meta["expected_vuln"] else "🟢 SAFE"
        print(f"  {level}: {meta['type'].upper():5} | {meta['difficulty']:6} | {status}")
    print("=" * 50)
    app.run(host='0.0.0.0', port=PORT, debug=False)
```

---

## Testing Protocol

### 1. Manual Test (Quick)

```bash
# Start dojo
python3 testing/dojos/dojo_dastysast_challenges.py

# Run scan
./bugtraceai-cli --clean http://127.0.0.1:5250

# Check logs for Skeptical decisions
grep -i "skeptical" logs/execution.log
```

### 2. Automated Benchmark (Recommended)

Create `testing/benchmark_dastysast.py`:

```python
#!/usr/bin/env python3
"""
Benchmark DASTySAST accuracy against Code Challenge Dojo.
"""

import requests
import json

DOJO_URL = "http://127.0.0.1:5250"

def get_expected_results():
    """Fetch expected results from Dojo API."""
    resp = requests.get(f"{DOJO_URL}/api/challenges")
    return resp.json()

def parse_scan_results():
    """Parse DASTySAST results from raw_findings.json."""
    # Implementation depends on scan output structure
    pass

def calculate_accuracy():
    """
    Compare expected vs actual results.
    
    Metrics:
    - True Positive: Expected VULN, Detected + Approved
    - True Negative: Expected SAFE, Not detected OR Rejected
    - False Positive: Expected SAFE, Detected + Approved
    - False Negative: Expected VULN, Not detected OR Rejected
    """
    pass

if __name__ == '__main__':
    # Run benchmark
    pass
```

---

## Success Metrics

| Metric | Target | Description |
|--------|--------|-------------|
| True Positive Rate | ≥90% | Real vulns detected AND approved |
| True Negative Rate | ≥90% | False positives correctly rejected |
| L1-L3 Accuracy | 100% | Easy challenges must be perfect |
| L4-L7 Accuracy | ≥80% | Medium challenges |
| L8-L10 Accuracy | ≥50% | Hard challenges (stretch goal) |

---

## Current Configuration

```ini
# bugtraceaicli.conf
SKEPTICAL_MODEL = google/gemini-3-flash-preview   # Changed from Claude Haiku
MAX_URLS = 1  # Increase to 10+ for full challenge coverage
```

---

## Files to Reference

- `bugtrace/agents/analysis_agent.py` - DASTySASTAgent + `_skeptical_review()`
- `testing/dojos/dojo_basic.py` - Example Flask dojo structure
- `logs/llm_audit.jsonl` - LLM request/response logs for debugging

---

## Priority Notes

1. **Start with L1-L5** - Get the basics working first
2. **Decoys are critical** - L3, L4, L5, L7 test false positive filtering
3. **Include HTML comments** - Helps debugging which challenge failed
4. **API endpoint for automation** - `/api/challenges` returns JSON metadata

---

**END OF HANDOFF**
