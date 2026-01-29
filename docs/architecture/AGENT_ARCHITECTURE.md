# Agent Architecture Guide

**Purpose:** This guide documents how to develop new vulnerability detection agents for BugTraceAI.

**Target Audience:** Contributors adding new agent types to expand BugTraceAI's detection capabilities.

**Last Updated:** 2026-01-29

---

## Table of Contents

1. [Overview](#overview)
2. [Agent Architecture](#agent-architecture)
3. [Hunter-Auditor Pattern](#hunter-auditor-pattern)
4. [Integration Points](#integration-points)
5. [Queue-Based Agent Pattern](#queue-based-agent-pattern)
6. [Reporting Standards](#reporting-standards)
7. [Step-by-Step: Creating a New Agent](#step-by-step-creating-a-new-agent)
8. [Best Practices](#best-practices)

---

## Overview

### What Are Agents in BugTraceAI?

Agents are specialized vulnerability detection modules that focus on a single vulnerability class. Each agent operates independently within the BugTraceAI scanning pipeline, applying domain-specific knowledge to discover and validate security issues.

**Current Agents:**
- `XSSAgent` - Cross-Site Scripting detection
- `SQLMapAgent` - SQL Injection validation
- `JWTAgent` - JWT security testing
- `OpenRedirectAgent` - Open Redirect detection (CWE-601)
- `PrototypePollutionAgent` - Prototype Pollution detection (CWE-1321)
- `IDORAgent` - Insecure Direct Object Reference
- `SSRFAgent` - Server-Side Request Forgery
- `LFIAgent` - Local File Inclusion
- `RCEAgent` - Remote Code Execution
- `XXEAgent` - XML External Entity injection

### Hunter-Auditor Pattern Overview

All modern agents follow the **Hunter-Auditor** pattern, a two-phase approach:

1. **Hunter Phase:** Discover all potential attack vectors (parameters, paths, patterns)
2. **Auditor Phase:** Validate vectors with exploitation payloads (ranked by severity)

This separation enables:
- **Efficiency:** Hunters quickly identify promising targets
- **Precision:** Auditors focus exploitation on high-confidence vectors
- **Scalability:** Parallel hunting across multiple endpoints
- **Clarity:** Clean separation between discovery and validation logic

### When to Create a New Agent vs Extend Existing

**Create a new agent when:**
- Targeting a distinct CWE/vulnerability class (e.g., SSRF, XXE, CSRF)
- Requiring specialized detection logic (e.g., JWT parsing, prototype chain inspection)
- Needing unique payload libraries (e.g., SQL injection syntax vs XSS contexts)

**Extend an existing agent when:**
- Adding new payloads to an existing vulnerability class
- Improving detection heuristics for the same CWE
- Adding support for new encoding/bypass techniques within the same vulnerability type

---

## Agent Architecture

### BaseAgent Class

All agents inherit from `BaseAgent` (located at `bugtrace/agents/base.py`):

```python
from bugtrace.agents.base import BaseAgent

class YourAgent(BaseAgent):
    def __init__(self, url: str, params: List[str] = None, report_dir: Path = None):
        super().__init__(
            name="YourAgent",
            role="Your Agent Role",
            agent_id="your_agent_id"
        )
        self.url = url
        self.params = params or []
        self.report_dir = report_dir or Path("./reports")
```

**Key attributes:**
- `name`: Display name for logging/UI
- `role`: Agent description
- `agent_id`: Unique identifier for prompt loading
- `url`: Target URL for testing
- `params`: Optional parameter hints from upstream detection
- `report_dir`: Output directory for findings

### Required Methods

#### 1. `run_loop()` - Main Execution Entry Point

The orchestrator calls this method to execute the agent. It coordinates Hunter and Auditor phases:

```python
async def run_loop(self) -> Dict:
    """Main execution loop for vulnerability testing."""
    dashboard.current_agent = self.name
    dashboard.log(f"[{self.name}] Starting analysis on {self.url}", "INFO")

    # Phase 1: Hunter - Discover attack vectors
    vectors = await self._hunter_phase()

    if not vectors:
        dashboard.log(f"[{self.name}] No vectors found", "INFO")
        return {
            "status": JobStatus.COMPLETED,
            "vulnerable": False,
            "findings": [],
            "findings_count": 0
        }

    # Phase 2: Auditor - Validate vectors
    findings = await self._auditor_phase(vectors)

    # Report findings
    for finding in findings:
        await self._create_finding(finding)

    return {
        "status": JobStatus.COMPLETED,
        "vulnerable": len(findings) > 0,
        "findings": findings,
        "findings_count": len(findings)
    }
```

**Return structure:**
- `status`: `JobStatus.COMPLETED` or `JobStatus.FAILED`
- `vulnerable`: Boolean indicating if vulnerabilities were found
- `findings`: List of finding dictionaries
- `findings_count`: Total findings count

#### 2. `_hunter_phase()` - Vector Discovery

Discovers all potential attack vectors without validation:

```python
async def _hunter_phase(self) -> List[Dict]:
    """
    Hunter Phase: Discover all potential attack vectors.

    Returns:
        List of vectors with type, source, and confidence
    """
    vectors = []

    # Example: Check query parameters
    param_vectors = self._discover_param_vectors()
    vectors.extend(param_vectors)

    # Example: Analyze response content
    content_vectors = await self._discover_content_vectors()
    vectors.extend(content_vectors)

    dashboard.log(f"[{self.name}] Hunter found {len(vectors)} vectors", "INFO")
    return vectors
```

**Vector structure:**
```python
{
    "type": "QUERY_PARAM",          # Vector type
    "param": "redirect_url",         # Parameter name
    "value": "https://google.com",   # Current value (if any)
    "source": "URL_EXISTING",        # Where vector was found
    "confidence": "HIGH"             # Confidence level (HIGH/MEDIUM/LOW)
}
```

#### 3. `_auditor_phase()` - Validation

Tests vectors with exploitation payloads:

```python
async def _auditor_phase(self, vectors: List[Dict]) -> List[Dict]:
    """
    Auditor Phase: Validate vectors with exploitation payloads.

    Returns:
        List of confirmed findings with exploitation details
    """
    findings = []

    for vector in vectors:
        # Test based on vector type
        if vector["type"] == "QUERY_PARAM":
            result = await self._test_param_vector(vector)
        elif vector["type"] == "PATH":
            result = await self._test_path_vector(vector)

        if result and result.get("exploitable"):
            findings.append(result)
            dashboard.log(
                f"[{self.name}] CONFIRMED: {vector['type']}",
                "CRITICAL"
            )

    return findings
```

#### 4. `_create_finding()` - Report Generation

Generates standardized finding reports:

```python
async def _create_finding(self, result: Dict):
    """Reports a confirmed finding using standardized format."""
    finding = {
        "type": "YOUR_VULN_TYPE",
        "severity": result.get("severity", "MEDIUM"),
        "url": self.url,
        "parameter": result.get("param"),
        "payload": result.get("payload"),
        "description": f"Description of vulnerability",
        "validated": True,
        "status": "VALIDATED_CONFIRMED",
        "reproduction": f"curl '{result.get('test_url')}'",
        "cwe_id": get_cwe_for_vuln("YOUR_VULN_TYPE"),
        "remediation": get_remediation_for_vuln("YOUR_VULN_TYPE"),
        "cve_id": "N/A",
        "http_request": result.get("http_request"),
        "http_response": result.get("http_response"),
    }
    logger.info(f"[{self.name}] VULNERABILITY CONFIRMED: {result.get('payload')}")
```

### Event Bus Integration

Agents use the Event Bus for asynchronous communication:

```python
from bugtrace.core.event_bus import event_bus

class YourAgent(BaseAgent):
    def __init__(self, url: str, ...):
        super().__init__(
            name="YourAgent",
            role="Your Role",
            agent_id="your_agent",
            event_bus=event_bus
        )

    def _setup_event_subscriptions(self):
        """Subscribe to relevant events."""
        self.event_bus.subscribe("FINDING_DISCOVERED", self._on_finding)

    async def _on_finding(self, event_data: dict):
        """Handle finding events from other agents."""
        pass
```

### System Prompt Loading

Agents can load external system prompts from Markdown files:

**File:** `bugtrace/agents/system_prompts/your_agent.md`

```markdown
---
name: Your Agent
description: Brief description
skills:
  - skill_name: "Exploitation Technique"
    skill_file: "skills/technique.md"
---

# System Prompt

Your agent's instructions and context go here.
```

The `BaseAgent.__init__()` automatically loads this if `agent_id` is provided.

### Agent Lifecycle Diagram

```
┌─────────────────────────────────────────────────┐
│         TeamOrchestrator Dispatch               │
│  (Fast-path or LLM-based classification)        │
└─────────────────┬───────────────────────────────┘
                  │
                  ▼
         ┌────────────────┐
         │  Agent.init()  │
         │  - Set URL     │
         │  - Set params  │
         └────────┬───────┘
                  │
                  ▼
        ┌──────────────────┐
        │  run_loop()      │
        └────────┬─────────┘
                 │
                 ▼
       ┌─────────────────────┐
       │  _hunter_phase()    │◄─── Discovery Phase
       │  - Find vectors     │
       │  - Return candidates│
       └──────────┬──────────┘
                  │
                  ▼
       ┌─────────────────────┐
       │  _auditor_phase()   │◄─── Validation Phase
       │  - Test payloads    │
       │  - Validate exploit │
       └──────────┬──────────┘
                  │
                  ▼
       ┌─────────────────────┐
       │  _create_finding()  │◄─── Reporting Phase
       │  - Format finding   │
       │  - Log to DB        │
       └─────────────────────┘
```

---

## Hunter-Auditor Pattern

### Hunter Phase: Discovery of Attack Vectors

The Hunter phase focuses on **breadth over depth** - quickly identifying all potential attack surfaces.

**Goals:**
1. Enumerate parameters, paths, headers that could be vulnerable
2. Analyze response content for patterns indicating vulnerability
3. Build a ranked list of vectors for the Auditor to test
4. Return metadata (confidence, type, source) for prioritization

**Example: OpenRedirectAgent Hunter Phase**

```python
async def _hunter_phase(self) -> List[Dict]:
    """Discover all potential redirect vectors."""
    vectors = []

    # 1. Check existing query parameters
    param_vectors = self._discover_param_vectors()
    vectors.extend(param_vectors)

    # 2. Check URL path patterns
    path_vectors = self._discover_path_vectors()
    vectors.extend(path_vectors)

    # 3. Fetch page and analyze content
    try:
        content_vectors = await self._discover_content_vectors()
        vectors.extend(content_vectors)
    except Exception as e:
        logger.warning(f"Content analysis failed: {e}")

    return vectors

def _discover_param_vectors(self) -> List[Dict]:
    """Discover redirect vectors in query parameters."""
    vectors = []
    parsed = urlparse(self.url)
    existing_params = parse_qs(parsed.query)

    # Check if any existing params match redirect parameter names
    for param in existing_params.keys():
        param_lower = param.lower()

        # Check against known redirect parameter list
        for redirect_param in REDIRECT_PARAMS:
            if param_lower == redirect_param.lower():
                vectors.append({
                    "type": "QUERY_PARAM",
                    "param": param,
                    "value": existing_params[param][0],
                    "source": "URL_EXISTING",
                    "confidence": "HIGH"
                })
                break

    return vectors
```

**Hunter Best Practices:**
- Use **synchronous methods** for fast parameter/path detection
- Use **async methods** for HTTP content fetching
- Return **confidence levels** (HIGH/MEDIUM/LOW) for Auditor prioritization
- **Deduplicate** vectors before returning (same param tested multiple ways)
- **Log progress** to dashboard for user visibility

### Auditor Phase: Validation with Exploitation Payloads

The Auditor phase focuses on **depth over breadth** - rigorously validating promising vectors.

**Goals:**
1. Test each vector with ranked payloads (basic → advanced)
2. Confirm exploitation with evidence (HTTP response, timing, etc.)
3. Assign accurate severity based on exploitation level
4. Stop on first success (early termination for efficiency)

**Example: OpenRedirectAgent Auditor Phase**

```python
async def _auditor_phase(self, vectors: List[Dict]) -> List[Dict]:
    """Validate redirect vectors with exploitation payloads."""
    findings = []

    for vector in vectors:
        # Skip already tested params (deduplication)
        key = f"{self.url}#{vector.get('param')}"
        if key in self._tested_params:
            continue
        self._tested_params.add(key)

        # Test based on vector type
        if vector["type"] == "QUERY_PARAM":
            result = await self._test_param_vector(vector)
        elif vector["type"] == "PATH":
            result = await self._test_path_vector(vector)

        if result and result.get("exploitable"):
            findings.append(result)
            dashboard.log(
                f"[{self.name}] CONFIRMED: {result.get('technique')}",
                "CRITICAL"
            )

    return findings

async def _test_param_vector(self, vector: Dict) -> Optional[Dict]:
    """Test a query parameter vector with ranked payloads."""
    param = vector["param"]
    parsed = urlparse(self.url)

    # Get trusted domain for whitelist bypass payloads
    trusted_domain = parsed.netloc

    # Test payloads in tier order (stop on first success)
    for tier in ["basic", "encoding", "whitelist", "advanced"]:
        payloads = get_payloads_for_tier(tier, ATTACKER_DOMAIN, trusted_domain)

        for payload in payloads:
            result = await self._test_single_payload(param, payload, tier)
            if result and result.get("exploitable"):
                return result  # Early termination

    return None
```

### Ranked Payload Approach

Organize payloads in tiers from least to most sophisticated:

**Example: OpenRedirect Payloads**

```python
RANKED_PAYLOADS = {
    "basic": [
        "//evil.com",                    # Protocol-relative
        "https://evil.com",              # Direct URL
        "http://evil.com",
    ],
    "encoding": [
        "//evil%2ecom",                  # Dot encoding
        "https%3A%2F%2Fevil.com",        # Full URL encoding
        "/%09/evil.com",                 # Tab character
    ],
    "whitelist": [
        "https://evil.com@trusted.com",  # User info bypass
        "https://trusted.com.evil.com",  # Domain suffix
        "https://trusted.com%2f@evil.com",
    ],
    "advanced": [
        "javascript:alert(document.domain)",  # JavaScript protocol
        "data:text/html,<script>alert(1)</script>",  # Data URI
    ]
}
```

**Rationale:**
- **Basic tier:** Test common patterns first (fastest, most likely)
- **Encoding tier:** Test bypass techniques if basic fails
- **Whitelist tier:** Test domain validation bypasses
- **Advanced tier:** Test protocol-based redirects

**Early termination:** Stop testing once a payload succeeds in any tier. This minimizes testing impact on production systems.

### Confidence Scoring

Assign confidence to vectors based on evidence strength:

**HIGH Confidence:**
- Parameter name exactly matches known vulnerable patterns (`redirect`, `url`, `next`)
- Response contains direct evidence (HTTP 302 with Location header)
- JSON body accepted by POST endpoint

**MEDIUM Confidence:**
- Parameter name contains redirect-related keywords
- URL path matches redirect patterns (`/redirect/`, `/goto/`)
- Response contains suspicious JavaScript patterns

**LOW Confidence:**
- Generic parameter names that might be used for redirects
- Response contains merge/extend library references
- Error messages suggesting object manipulation

**Example: PrototypePollutionAgent Confidence**

```python
def _discover_param_vectors(self) -> List[Dict]:
    """Discover pollution vectors in existing query parameters."""
    vectors = []

    for param in existing_params.keys():
        param_lower = param.lower()

        # HIGH confidence: Known vulnerable parameter names
        if any(vuln_param in param_lower for vuln_param in VULNERABLE_PARAMS):
            vectors.append({
                "type": "QUERY_PARAM",
                "param": param,
                "confidence": "HIGH",
                "reason": "Parameter name suggests object merging",
            })

    return vectors

async def _discover_json_body_vector(self) -> Optional[Dict]:
    """Check if endpoint accepts JSON POST requests."""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                self.url,
                json={"test": "probe"},
                timeout=aiohttp.ClientTimeout(total=5)
            ) as response:
                # HIGH confidence: Endpoint accepts JSON
                if response.status not in (415, 405):
                    return {
                        "type": "JSON_BODY",
                        "method": "POST",
                        "confidence": "HIGH",
                        "status_code": response.status,
                    }
    except Exception as e:
        logger.debug(f"JSON probe failed: {e}")

    return None
```

---

## Integration Points

### TeamOrchestrator Dispatch

The `TeamOrchestrator` class (located at `bugtrace/core/team.py`) orchestrates all agents. It uses two dispatch mechanisms:

1. **Fast-path classification** - Pattern matching on vulnerability type
2. **LLM dispatcher fallback** - GPT-based classification for ambiguous cases

### Fast-Path Classification

Fast-path uses simple string matching for performance:

**File:** `bugtrace/core/team.py`

```python
def _try_fast_path_classification(self, vuln: dict) -> Optional[str]:
    """Try fast-path classification for obvious vulnerability types."""
    v_type = str(vuln.get("type", "")).upper()

    if "XSS" in v_type: return "XSS_AGENT"
    if "SQL" in v_type: return "SQL_AGENT"
    if "SSRF" in v_type: return "SSRF_AGENT"
    if "IDOR" in v_type or "INSECURE DIRECT" in v_type: return "IDOR_AGENT"
    if "XXE" in v_type or "XML" in v_type: return "XXE_AGENT"
    if "LFI" in v_type or "PATH TRAVERSAL" in v_type: return "LFI_AGENT"
    if "RCE" in v_type or "COMMAND" in v_type: return "RCE_AGENT"
    if "JWT" in v_type or "TOKEN" in v_type: return "JWT_AGENT"
    if "REDIRECT" in v_type or "OPEN REDIRECT" in v_type: return "OPENREDIRECT_AGENT"
    if "PROTOTYPE" in v_type or "POLLUTION" in v_type or "__PROTO__" in v_type: return "PROTOTYPE_POLLUTION_AGENT"

    return None
```

**To add your agent to fast-path:**
1. Add pattern matching for your vulnerability type
2. Return your agent's constant name (e.g., `YOUR_AGENT`)

### LLM Dispatcher Fallback

When fast-path fails, the LLM dispatcher classifies vulnerabilities:

```python
async def _decide_specialist(self, vuln: dict) -> str:
    """Uses LLM to classify vulnerability and select best specialist agent."""
    from bugtrace.core.llm_client import llm_client

    # Fast path for obvious classifications
    fast_path_result = self._try_fast_path_classification(vuln)
    if fast_path_result:
        return fast_path_result

    # LLM-based classification
    prompt = self._build_dispatcher_prompt(vuln)
    try:
        response = await llm_client.simple_generate(prompt)
        chosen_agent = self._extract_agent_from_response(response)
        return chosen_agent
    except Exception as e:
        logger.error(f"Dispatcher LLM failed: {e}")
        return self._fallback_classification(vuln)
```

**Dispatcher Prompt Template:**

```python
def _build_dispatcher_prompt(self, vuln: dict) -> str:
    return f"""Vulnerability Classification Task:

Vulnerability Data:
{json.dumps(vuln, indent=2)}

Available Agents:
- XSS_AGENT (Cross-Site Scripting, HTML injection)
- SQL_AGENT (SQL Injection, database attacks)
- JWT_AGENT (JWT token validation, signature bypass)
- OPENREDIRECT_AGENT (Open Redirect, URL redirection)
- PROTOTYPE_POLLUTION_AGENT (Prototype Pollution, __proto__ injection)
- IGNORE (If low confidence or not relevant)

Return ONLY the Agent Name using XML format:
<thought>Reasoning for selection</thought>
<agent>AGENT_NAME</agent>
"""
```

**To add your agent to LLM dispatcher:**
1. Add your agent to the "Available Agents" list in the prompt
2. Add your agent constant to `valid_agents` list in `_extract_agent_from_response()`

### Agent Imports in team.py

Agents are imported conditionally to avoid loading unnecessary dependencies:

**File:** `bugtrace/core/team.py`

```python
if "OPENREDIRECT_AGENT" in specialist_dispatches:
    from bugtrace.agents.openredirect_agent import OpenRedirectAgent
    p_list = list(params_map.get("OPENREDIRECT_AGENT", [])) or None
    openredirect_agent = OpenRedirectAgent(url, p_list, url_dir)
    tasks.append(run_agent_with_semaphore(self.url_semaphore, openredirect_agent, process_result))

if "PROTOTYPE_POLLUTION_AGENT" in specialist_dispatches:
    from bugtrace.agents.prototype_pollution_agent import PrototypePollutionAgent
    p_list = list(params_map.get("PROTOTYPE_POLLUTION_AGENT", [])) or None
    pp_agent = PrototypePollutionAgent(url, p_list, url_dir)
    tasks.append(run_agent_with_semaphore(self.url_semaphore, pp_agent, process_result))
```

**Pattern:**
1. Check if agent dispatch was requested
2. Import agent class (deferred import)
3. Extract parameters from `params_map` if available
4. Instantiate agent with URL, params, and report directory
5. Add to task list with semaphore for concurrency control

### Adding Agent to Scan Pipeline

**Step 1:** Add import block in `_create_specialist_tasks()` method

```python
if "YOUR_AGENT" in specialist_dispatches:
    from bugtrace.agents.your_agent import YourAgent
    p_list = list(params_map.get("YOUR_AGENT", [])) or None
    your_agent = YourAgent(url, p_list, url_dir)
    tasks.append(run_agent_with_semaphore(self.url_semaphore, your_agent, process_result))
```

**Step 2:** Add to fast-path classification

```python
def _try_fast_path_classification(self, vuln: dict) -> Optional[str]:
    v_type = str(vuln.get("type", "")).upper()

    # ... existing patterns ...

    if "YOUR_PATTERN" in v_type: return "YOUR_AGENT"

    return None
```

**Step 3:** Add to LLM dispatcher prompt and valid agents list

```python
def _build_dispatcher_prompt(self, vuln: dict) -> str:
    return f"""...
Available Agents:
- YOUR_AGENT (Your vulnerability description)
...
"""

def _extract_agent_from_response(self, response: str) -> str:
    valid_agents = [
        "XSS_AGENT", "SQL_AGENT", ..., "YOUR_AGENT", "IGNORE"
    ]
    ...
```

---

## Queue-Based Agent Pattern

> **New in v2.3:** Specialist agents now receive work from queues for parallel processing.

In v2.3, agents consume findings from specialist queues rather than receiving work via direct dispatch. The `ThinkingConsolidationAgent` classifies and prioritizes findings, then distributes them to per-specialist queues. Agents consume from their queue via a `WorkerPool` for parallel processing.

For full queue infrastructure details, see [QUEUE_PATTERNS.md](./QUEUE_PATTERNS.md).

### Queue Consumption Overview

The v2.3 pipeline flow:

```
Discovery Phase          Evaluation Phase              Exploitation Phase
+---------------+       +------------------------+     +------------------+
| SASTDASTAgent | --->  | ThinkingConsolidation  | --> | XSS Specialist   |
| + Skeptical   |       | Agent                  |     | SQLi Specialist  |
+---------------+       | - Deduplication        |     | CSTI Specialist  |
       |                | - Classification       |     | ... 8 more       |
  url_analyzed          | - Prioritization       |     +------------------+
    events              +------------------------+            ^
                               |                              |
                        specialist queues                     |
                          (work_queued_*)                     |
```

**Key Concepts:**

1. **Agents receive work from queues** - Not direct dispatch from orchestrator
2. **ThinkingConsolidationAgent** distributes findings to specialist queues
3. **WorkerPool** enables parallel processing of queue items
4. **Events** signal finding status (vulnerability_detected)

### WorkerPool Integration

The `WorkerPool` class manages concurrent workers that consume from a specialist queue:

```python
from bugtrace.agents.worker_pool import WorkerPool, WorkerConfig
from bugtrace.core.queue import queue_manager
from bugtrace.core.config import settings

class YourAgent(BaseAgent):
    def __init__(self, url: str, ...):
        super().__init__(
            name="YourAgent",
            role="Your Specialist",
            agent_id="your_agent"
        )
        self.url = url
        self._worker_pool: Optional[WorkerPool] = None

    async def start_queue_consumer(self) -> None:
        """Start consuming from the specialist queue."""
        config = WorkerConfig(
            specialist="your_specialist",  # Queue name
            pool_size=settings.WORKER_POOL_DEFAULT_SIZE,  # Default: 5
            process_func=self._process_queue_item,
            on_result=self._handle_result,  # Optional callback
        )
        self._worker_pool = WorkerPool(config)
        await self._worker_pool.start()

    async def stop_queue_consumer(self) -> None:
        """Stop the worker pool gracefully."""
        if self._worker_pool:
            await self._worker_pool.drain()  # Wait for queue to empty
            await self._worker_pool.stop()

    async def _process_queue_item(self, item: dict) -> dict:
        """Process a single queue item."""
        finding = item.get("finding", {})
        scan_context = item.get("scan_context", "")
        priority = item.get("priority", 0)

        # Your validation logic here
        result = await self._test_finding(finding)
        return result
```

**WorkerConfig Parameters:**

| Parameter | Default | Description |
|-----------|---------|-------------|
| `specialist` | (required) | Queue name (e.g., "xss", "sqli") |
| `pool_size` | 5 | Number of concurrent workers |
| `process_func` | (required) | Async function to process each item |
| `on_result` | None | Optional callback(item, result) |
| `shutdown_timeout` | 30s | Max wait for graceful shutdown |
| `dequeue_timeout` | 5s | Timeout between dequeue attempts |

### Event Emission Pattern

After processing a queue item, emit a `vulnerability_detected` event:

```python
from bugtrace.core.event_bus import event_bus, EventType
from bugtrace.core.validation_status import ValidationStatus

async def _process_queue_item(self, item: dict) -> dict:
    """Process queue item and emit event."""
    finding = item.get("finding", {})
    scan_context = item.get("scan_context", "")

    # Validate the finding
    result = await self._validate_finding(finding)

    # Determine validation status
    if result.get("confirmed"):
        status = ValidationStatus.VALIDATED_CONFIRMED
        validation_requires_cdp = False
    else:
        status = ValidationStatus.PENDING_VALIDATION
        validation_requires_cdp = True

    # Emit vulnerability_detected event
    if self.event_bus:
        await self.event_bus.emit(EventType.VULNERABILITY_DETECTED, {
            "specialist": "your_agent",
            "finding": finding,
            "status": status.value,
            "validation_requires_cdp": validation_requires_cdp,
            "scan_context": scan_context,
        })

    return result
```

**Event Payload Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `specialist` | str | Agent identifier (e.g., "xss", "sqli") |
| `finding` | dict | Original finding with validation results |
| `status` | str | ValidationStatus value |
| `validation_requires_cdp` | bool | True if CDP validation needed |
| `scan_context` | str | Scan context identifier |

### ValidationStatus Usage

The `ValidationStatus` enum tracks finding validation state:

```python
from bugtrace.core.validation_status import (
    ValidationStatus,
    EDGE_CASE_PATTERNS,
    requires_cdp_validation,
    get_validation_status
)

# ValidationStatus values:
# - VALIDATED_CONFIRMED: High confidence, skip CDP validation
# - PENDING_VALIDATION: Needs CDP browser validation
# - VALIDATION_ERROR: Validation process failed
# - FINDING_VALIDATED: CDP confirmed as real vulnerability
# - FINDING_REJECTED: CDP rejected as false positive
```

**When to use each status:**

| Status | Use When |
|--------|----------|
| `VALIDATED_CONFIRMED` | HTTP evidence confirms (OOB callback, SQL error, file content) |
| `PENDING_VALIDATION` | Needs browser context (DOM XSS, event handlers) |
| `VALIDATION_ERROR` | Validation failed (timeout, network error) |

**Edge case patterns that require CDP validation:**

```python
EDGE_CASE_PATTERNS = {
    # DOM-based XSS - needs JavaScript execution
    "dom_based_xss": [
        "location.hash",      # Fragment-based XSS
        "document.URL",       # Full URL access
        "postMessage",        # Cross-origin messaging
    ],

    # Complex event handlers - need visual confirmation
    "complex_event_handlers": [
        "autofocus",          # Auto-triggers onfocus
        "onfocus",            # Focus-based execution
        "onanimationend",     # CSS animation triggers
    ],

    # Sink analysis - dangerous sinks need execution
    "sink_analysis": [
        "eval(",              # Direct code execution
        "innerHTML",          # DOM injection
        "document.write",     # Document rewriting
        "setTimeout(",        # Delayed execution
    ],
}
```

**Helper function:**

```python
# Check if finding needs CDP validation
if requires_cdp_validation(finding):
    status = ValidationStatus.PENDING_VALIDATION
    validation_requires_cdp = True
else:
    status = ValidationStatus.VALIDATED_CONFIRMED
    validation_requires_cdp = False
```

### Complete Queue Consumer Example

Minimal working example of a queue-consuming agent:

```python
from typing import Dict, Any, Optional
from bugtrace.agents.base import BaseAgent
from bugtrace.agents.worker_pool import WorkerPool, WorkerConfig
from bugtrace.core.queue import queue_manager
from bugtrace.core.event_bus import event_bus, EventType
from bugtrace.core.validation_status import (
    ValidationStatus,
    requires_cdp_validation
)
from bugtrace.core.config import settings
from bugtrace.utils.logger import get_logger

logger = get_logger("agents.your_agent")


class YourQueueAgent(BaseAgent):
    """Queue-consuming specialist agent template."""

    def __init__(self, url: str = None, event_bus: Any = None):
        super().__init__(
            name="YourQueueAgent",
            role="Your Specialist",
            event_bus=event_bus,
            agent_id="your_queue_agent"
        )
        self.url = url
        self._worker_pool: Optional[WorkerPool] = None

    async def start_queue_consumer(self) -> None:
        """Start consuming from the specialist queue."""
        config = WorkerConfig(
            specialist="your_specialist",
            pool_size=settings.WORKER_POOL_DEFAULT_SIZE,
            process_func=self._process_queue_item,
        )
        self._worker_pool = WorkerPool(config)
        await self._worker_pool.start()
        logger.info(f"[{self.name}] Queue consumer started")

    async def stop_queue_consumer(self) -> None:
        """Stop the worker pool gracefully."""
        if self._worker_pool:
            await self._worker_pool.drain()
            await self._worker_pool.stop()
            logger.info(f"[{self.name}] Queue consumer stopped")

    async def _process_queue_item(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Process a single queue item."""
        finding = item.get("finding", {})
        scan_context = item.get("scan_context", "")

        logger.debug(f"Processing: {finding.get('url')} / {finding.get('parameter')}")

        # Validate the finding
        result = await self._validate(finding)

        # Determine status based on evidence
        if result.get("confirmed"):
            status = ValidationStatus.VALIDATED_CONFIRMED
            validation_requires_cdp = False
        elif requires_cdp_validation(finding):
            status = ValidationStatus.PENDING_VALIDATION
            validation_requires_cdp = True
        else:
            status = ValidationStatus.PENDING_VALIDATION
            validation_requires_cdp = True

        # Emit event for downstream agents
        if self.event_bus:
            await self.event_bus.emit(EventType.VULNERABILITY_DETECTED, {
                "specialist": "your_specialist",
                "finding": {**finding, **result},
                "status": status.value,
                "validation_requires_cdp": validation_requires_cdp,
                "scan_context": scan_context,
            })

        return result

    async def _validate(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Validate the finding. Override with specialist logic."""
        # Your validation implementation here
        return {"confirmed": False}
```

**Key Methods:**

| Method | Purpose |
|--------|---------|
| `start_queue_consumer()` | Initialize and start WorkerPool |
| `stop_queue_consumer()` | Drain queue and stop workers |
| `_process_queue_item()` | Process single item from queue |
| `_validate()` | Specialist-specific validation logic |

### Related Documentation

- [QUEUE_PATTERNS.md](./QUEUE_PATTERNS.md) - Queue infrastructure details
- [THINKING_AGENT.md](./THINKING_AGENT.md) - ThinkingConsolidationAgent algorithms
- [Worker Pool Implementation](../../bugtrace/agents/worker_pool.py) - Source code

---

## Reporting Standards

BugTraceAI uses a standardized reporting system to ensure consistency across all agents.

**Module:** `bugtrace/reporting/standards.py`

### Using normalize_severity()

Always normalize severity values to the standard enum:

```python
from bugtrace.reporting.standards import normalize_severity

# Input: any case variant
severity = normalize_severity("critical")  # Returns: "CRITICAL"
severity = normalize_severity("Medium")    # Returns: "MEDIUM"
severity = normalize_severity("low")       # Returns: "LOW"
```

**Valid Severity Values:**
- `CRITICAL` - Remote Code Execution, Authentication Bypass
- `HIGH` - SQL Injection, XXE with data exfiltration
- `MEDIUM` - XSS, Open Redirect, CSRF
- `LOW` - Information Disclosure, Missing Headers

### Using get_cwe_for_vuln()

Retrieve standardized CWE IDs for vulnerability types:

```python
from bugtrace.reporting.standards import get_cwe_for_vuln

cwe_id = get_cwe_for_vuln("OPEN_REDIRECT")         # Returns: "CWE-601"
cwe_id = get_cwe_for_vuln("PROTOTYPE_POLLUTION")   # Returns: "CWE-1321"
cwe_id = get_cwe_for_vuln("XSS")                   # Returns: "CWE-79"
```

### Using get_remediation_for_vuln()

Retrieve comprehensive remediation guidance:

```python
from bugtrace.reporting.standards import get_remediation_for_vuln

remediation = get_remediation_for_vuln("OPEN_REDIRECT")
# Returns multi-line remediation with:
# - Validation approaches
# - Code examples
# - Security best practices
```

### Finding Structure

All findings must follow this standardized structure:

```python
finding = {
    # Core identification
    "type": "OPEN_REDIRECT",              # Vulnerability type (uppercase)
    "severity": "MEDIUM",                  # Normalized severity
    "url": "https://target.com/redirect",  # Target URL
    "parameter": "next",                   # Vulnerable parameter
    "payload": "//evil.com",               # Exploitation payload

    # Validation status
    "validated": True,                     # Whether exploitation was confirmed
    "status": "VALIDATED_CONFIRMED",       # Validation status

    # Reproduction
    "reproduction": "curl -I 'https://...'",  # Reproduction command

    # Standards compliance
    "cwe_id": get_cwe_for_vuln("OPEN_REDIRECT"),        # CWE-601
    "remediation": get_remediation_for_vuln("OPEN_REDIRECT"),
    "cve_id": "N/A",                       # CVE if applicable (or "N/A")

    # HTTP evidence (REQUIRED for all findings)
    "http_request": "GET /redirect?next=//evil.com HTTP/1.1",
    "http_response": "HTTP/1.1 302 Found\nLocation: //evil.com",

    # Optional metadata
    "description": "Human-readable description",
    "technique": "protocol_relative",       # Technique used
    "tier": "basic",                        # Payload tier
}
```

### HTTP Evidence Fields

**CRITICAL:** All findings MUST include HTTP request/response evidence.

```python
# During payload testing
async def _test_single_payload(self, param: str, payload: str) -> Optional[Dict]:
    test_url = f"{self.url}?{param}={payload}"

    async with aiohttp.ClientSession() as session:
        async with session.get(test_url, allow_redirects=False) as response:
            # Capture full HTTP exchange
            http_request = f"GET {test_url} HTTP/1.1"
            http_response = f"HTTP/{response.version.major}.{response.version.minor} {response.status}\n"
            http_response += f"Location: {response.headers.get('Location', '')}"

            if self._is_vulnerable(response):
                return {
                    "exploitable": True,
                    "http_request": http_request,
                    "http_response": http_response,
                    # ... other fields
                }
```

**Why HTTP evidence is required:**
- Enables **reproduction** by security teams
- Provides **proof** for bug bounty reports
- Allows **validation** by third-party tools
- Supports **offline analysis** without re-running scans

### Example Finding from OpenRedirectAgent

```python
{
    "type": "OPEN_REDIRECT",
    "severity": "MEDIUM",
    "url": "https://example.com/auth/login",
    "parameter": "next",
    "payload": "//evil.com",
    "description": "Open Redirect via HTTP_HEADER in 'next'",
    "validated": True,
    "status": "VALIDATED_CONFIRMED",
    "reproduction": "curl -I 'https://example.com/auth/login?next=//evil.com'",
    "cwe_id": "CWE-601",
    "remediation": "**Validation:** Use allowlist of trusted domains...",
    "cve_id": "N/A",
    "http_request": "GET /auth/login?next=//evil.com HTTP/1.1",
    "http_response": "HTTP/1.1 302 Found\nLocation: //evil.com",
    "technique": "protocol_relative",
    "tier": "basic",
    "method": "HTTP_HEADER"
}
```

---

## Step-by-Step: Creating a New Agent

This walkthrough demonstrates creating a **CSRFAgent** from scratch.

### Step 1: Create Agent File

**File:** `bugtrace/agents/csrf_agent.py`

```python
import asyncio
from typing import Dict, List, Optional
from pathlib import Path
from urllib.parse import urlparse
import aiohttp
from bugtrace.agents.base import BaseAgent
from bugtrace.core.job_manager import JobStatus
from bugtrace.core.ui import dashboard
from bugtrace.utils.logger import get_logger
from bugtrace.reporting.standards import (
    get_cwe_for_vuln,
    get_remediation_for_vuln,
    normalize_severity,
)

logger = get_logger("agents.csrf")


class CSRFAgent(BaseAgent):
    """
    Specialist Agent for CSRF vulnerabilities (CWE-352).
    Target: State-changing operations without CSRF tokens.
    """

    def __init__(self, url: str, params: List[str] = None, report_dir: Path = None):
        super().__init__(
            name="CSRFAgent",
            role="CSRF Specialist",
            agent_id="csrf_specialist"
        )
        self.url = url
        self.params = params or []
        self.report_dir = report_dir or Path("./reports")
        self._tested_endpoints = set()

    async def run_loop(self) -> Dict:
        """Main execution loop for CSRF testing."""
        dashboard.current_agent = self.name
        dashboard.log(f"[{self.name}] Starting CSRF analysis on {self.url}", "INFO")

        # Phase 1: Hunter - Discover CSRF vectors
        vectors = await self._hunter_phase()

        if not vectors:
            dashboard.log(f"[{self.name}] No CSRF vectors found", "INFO")
            return {
                "status": JobStatus.COMPLETED,
                "vulnerable": False,
                "findings": [],
                "findings_count": 0
            }

        # Phase 2: Auditor - Validate CSRF vulnerabilities
        findings = await self._auditor_phase(vectors)

        # Report findings
        for finding in findings:
            await self._create_finding(finding)

        return {
            "status": JobStatus.COMPLETED,
            "vulnerable": len(findings) > 0,
            "findings": findings,
            "findings_count": len(findings)
        }

    async def _hunter_phase(self) -> List[Dict]:
        """
        Hunter Phase: Discover endpoints vulnerable to CSRF.

        Checks for:
        - State-changing endpoints (POST/PUT/DELETE)
        - Missing CSRF tokens in forms
        - Missing SameSite cookie attributes
        """
        dashboard.log(f"[{self.name}] Hunter: Scanning for CSRF vectors", "INFO")
        vectors = []

        # 1. Check if endpoint accepts state-changing methods
        method_vectors = await self._discover_state_changing_methods()
        vectors.extend(method_vectors)

        # 2. Analyze forms for CSRF tokens
        form_vectors = await self._discover_form_vectors()
        vectors.extend(form_vectors)

        dashboard.log(f"[{self.name}] Hunter found {len(vectors)} vectors", "INFO")
        return vectors

    async def _auditor_phase(self, vectors: List[Dict]) -> List[Dict]:
        """
        Auditor Phase: Validate CSRF vectors.

        Tests:
        - Submit requests without CSRF token
        - Test with modified/missing Origin/Referer headers
        - Validate SameSite cookie enforcement
        """
        dashboard.log(f"[{self.name}] Auditor: Validating {len(vectors)} vectors", "INFO")
        findings = []

        for vector in vectors:
            key = f"{self.url}#{vector.get('method', 'POST')}"
            if key in self._tested_endpoints:
                continue
            self._tested_endpoints.add(key)

            result = await self._test_csrf_vector(vector)

            if result and result.get("exploitable"):
                findings.append(result)
                dashboard.log(
                    f"[{self.name}] CONFIRMED: CSRF on {vector.get('method')} {self.url}",
                    "WARNING"
                )

        return findings

    async def _create_finding(self, result: Dict):
        """Reports a confirmed CSRF finding."""
        finding = {
            "type": "CSRF",
            "severity": result.get("severity", "MEDIUM"),
            "url": self.url,
            "parameter": None,
            "payload": result.get("payload"),
            "description": f"CSRF vulnerability on {result.get('method', 'POST')} endpoint",
            "validated": True,
            "status": "VALIDATED_CONFIRMED",
            "reproduction": result.get("reproduction"),
            "cwe_id": get_cwe_for_vuln("CSRF"),
            "remediation": get_remediation_for_vuln("CSRF"),
            "cve_id": "N/A",
            "http_request": result.get("http_request"),
            "http_response": result.get("http_response"),
        }
        logger.info(f"[{self.name}] CSRF CONFIRMED on {self.url}")
```

### Step 2: Define Payload Library

**File:** `bugtrace/agents/csrf_payloads.py`

```python
"""
CSRF payload library.
"""

# State-changing HTTP methods
STATE_CHANGING_METHODS = ["POST", "PUT", "DELETE", "PATCH"]

# Common CSRF token parameter names
CSRF_TOKEN_NAMES = [
    "csrf_token", "csrf", "token", "_token", "authenticity_token",
    "csrfmiddlewaretoken", "anti-csrf", "xsrf-token", "_csrf"
]

# Test headers for CSRF validation bypass
BYPASS_HEADERS = {
    "missing_origin": {},  # No Origin header
    "null_origin": {"Origin": "null"},
    "malicious_origin": {"Origin": "https://evil.com"},
    "missing_referer": {},  # No Referer header
}

def get_csrf_test_payload(method: str = "POST") -> str:
    """Generate HTML form for CSRF PoC."""
    return f"""
    <html>
      <body>
        <form action="{{target_url}}" method="{method}">
          <input type="hidden" name="email" value="attacker@evil.com" />
          <input type="submit" value="Submit" />
        </form>
        <script>document.forms[0].submit();</script>
      </body>
    </html>
    """
```

### Step 3: Implement Hunter Phase

Add vector discovery methods to `CSRFAgent`:

```python
async def _discover_state_changing_methods(self) -> List[Dict]:
    """Check if endpoint accepts state-changing methods."""
    vectors = []

    for method in STATE_CHANGING_METHODS:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.request(
                    method,
                    self.url,
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as response:
                    # If method is accepted (not 405 Method Not Allowed)
                    if response.status != 405:
                        vectors.append({
                            "type": "STATE_CHANGING",
                            "method": method,
                            "source": "METHOD_PROBE",
                            "confidence": "HIGH",
                            "status_code": response.status,
                        })
        except Exception as e:
            logger.debug(f"Method probe failed for {method}: {e}")

    return vectors

async def _discover_form_vectors(self) -> List[Dict]:
    """Analyze HTML forms for CSRF tokens."""
    vectors = []

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(self.url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                html_content = await response.text()

                # Check for forms with state-changing methods
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(html_content, 'html.parser')
                forms = soup.find_all('form', method=lambda m: m and m.upper() in STATE_CHANGING_METHODS)

                for form in forms:
                    # Check if form has CSRF token
                    has_csrf_token = any(
                        input_tag.get('name', '').lower() in CSRF_TOKEN_NAMES
                        for input_tag in form.find_all('input')
                    )

                    if not has_csrf_token:
                        vectors.append({
                            "type": "FORM_NO_TOKEN",
                            "method": form.get('method', 'POST').upper(),
                            "action": form.get('action', ''),
                            "source": "FORM_ANALYSIS",
                            "confidence": "HIGH",
                        })
    except Exception as e:
        logger.debug(f"Form analysis failed: {e}")

    return vectors
```

### Step 4: Implement Auditor Phase

Add validation methods to `CSRFAgent`:

```python
async def _test_csrf_vector(self, vector: Dict) -> Optional[Dict]:
    """Test CSRF vector with header bypass techniques."""
    method = vector.get("method", "POST")

    # Test each bypass technique
    for technique, headers in BYPASS_HEADERS.items():
        try:
            async with aiohttp.ClientSession() as session:
                async with session.request(
                    method,
                    self.url,
                    headers=headers,
                    data={"test": "csrf_probe"},
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as response:
                    # If request succeeds without CSRF token (200/201/204)
                    if response.status in (200, 201, 204):
                        resp_text = await response.text()

                        return {
                            "exploitable": True,
                            "type": "CSRF",
                            "method": method,
                            "technique": technique,
                            "severity": "MEDIUM",
                            "payload": get_csrf_test_payload(method),
                            "reproduction": self._build_curl_command(method, headers),
                            "http_request": f"{method} {self.url}\n{headers}",
                            "http_response": f"HTTP/1.1 {response.status}\n\n{resp_text[:200]}",
                        }
        except Exception as e:
            logger.debug(f"CSRF test failed for {technique}: {e}")

    return None

def _build_curl_command(self, method: str, headers: Dict) -> str:
    """Build curl reproduction command."""
    header_args = " ".join([f"-H '{k}: {v}'" for k, v in headers.items()])
    return f"curl -X {method} {header_args} '{self.url}' -d 'test=csrf_probe'"
```

### Step 5: Add to TeamOrchestrator Fast-Path

**File:** `bugtrace/core/team.py`

```python
def _try_fast_path_classification(self, vuln: dict) -> Optional[str]:
    """Try fast-path classification for obvious vulnerability types."""
    v_type = str(vuln.get("type", "")).upper()

    # ... existing patterns ...

    if "CSRF" in v_type or "CROSS-SITE REQUEST" in v_type: return "CSRF_AGENT"

    return None
```

Add agent dispatch in `_create_specialist_tasks()`:

```python
if "CSRF_AGENT" in specialist_dispatches:
    from bugtrace.agents.csrf_agent import CSRFAgent
    csrf_agent = CSRFAgent(url, None, url_dir)
    tasks.append(run_agent_with_semaphore(self.url_semaphore, csrf_agent, process_result))
```

### Step 6: Create System Prompt (Optional)

**File:** `bugtrace/agents/system_prompts/csrf_specialist.md`

```markdown
---
name: CSRF Specialist
description: Detects Cross-Site Request Forgery vulnerabilities
---

# CSRF Agent System Prompt

You are a CSRF (Cross-Site Request Forgery) detection specialist.

## Your Mission

Identify state-changing operations that can be executed by attackers without user consent.

## Detection Strategy

1. **Hunter Phase:**
   - Find endpoints accepting POST/PUT/DELETE/PATCH
   - Analyze forms for CSRF token presence
   - Check SameSite cookie attributes

2. **Auditor Phase:**
   - Submit requests without CSRF tokens
   - Test Origin/Referer header bypasses
   - Validate SameSite enforcement

## Validation Criteria

A CSRF vulnerability is confirmed when:
- State-changing request succeeds without CSRF token
- Request succeeds with malicious Origin header
- Request succeeds without Referer header
```

### Step 7: Add Unit Tests

**File:** `bugtrace/agents/tests/test_csrf_agent.py`

```python
import pytest
import aiohttp
from aiohttp import web
from bugtrace.agents.csrf_agent import CSRFAgent
from bugtrace.core.job_manager import JobStatus


@pytest.fixture
async def csrf_mock_server():
    """Mock server with CSRF vulnerable endpoint."""
    async def handle_vulnerable_post(request):
        # No CSRF token validation
        return web.Response(text="Action executed", status=200)

    async def handle_protected_post(request):
        # Validates CSRF token
        csrf_token = request.headers.get('X-CSRF-Token')
        if not csrf_token:
            return web.Response(text="CSRF token missing", status=403)
        return web.Response(text="Action executed", status=200)

    app = web.Application()
    app.router.add_post('/vulnerable', handle_vulnerable_post)
    app.router.add_post('/protected', handle_protected_post)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, 'localhost', 8765)
    await site.start()

    yield 'http://localhost:8765'

    await runner.cleanup()


@pytest.mark.asyncio
async def test_csrf_hunter_phase(csrf_mock_server):
    """Test CSRF Hunter phase vector discovery."""
    agent = CSRFAgent(url=f"{csrf_mock_server}/vulnerable")
    vectors = await agent._hunter_phase()

    assert len(vectors) > 0
    assert any(v["type"] == "STATE_CHANGING" for v in vectors)


@pytest.mark.asyncio
async def test_csrf_auditor_confirms_vulnerability(csrf_mock_server):
    """Test CSRF Auditor confirms vulnerable endpoint."""
    agent = CSRFAgent(url=f"{csrf_mock_server}/vulnerable")

    result = await agent.run_loop()

    assert result["status"] == JobStatus.COMPLETED
    assert result["vulnerable"] is True
    assert result["findings_count"] > 0

    finding = result["findings"][0]
    assert finding["type"] == "CSRF"
    assert finding["severity"] == "MEDIUM"


@pytest.mark.asyncio
async def test_csrf_auditor_respects_protection(csrf_mock_server):
    """Test CSRF Auditor does not flag protected endpoint."""
    agent = CSRFAgent(url=f"{csrf_mock_server}/protected")

    result = await agent.run_loop()

    assert result["status"] == JobStatus.COMPLETED
    assert result["vulnerable"] is False
```

---

## Best Practices

### 1. Async/Await for HTTP Requests

Always use async HTTP libraries for performance:

```python
# GOOD: Async HTTP with aiohttp
async def _test_vector(self, url: str) -> bool:
    async with aiohttp.ClientSession() as session:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as response:
            return response.status == 200

# BAD: Blocking HTTP with requests
def _test_vector(self, url: str) -> bool:
    import requests
    response = requests.get(url)  # Blocks event loop
    return response.status_code == 200
```

### 2. Deduplication with _tested_params Set

Prevent redundant testing:

```python
class YourAgent(BaseAgent):
    def __init__(self, url: str, ...):
        super().__init__(...)
        self._tested_params = set()  # Deduplication tracking

    async def _auditor_phase(self, vectors: List[Dict]) -> List[Dict]:
        findings = []

        for vector in vectors:
            # Create unique key for this test
            key = f"{self.url}#{vector.get('param')}"

            # Skip if already tested
            if key in self._tested_params:
                continue
            self._tested_params.add(key)

            # Test vector...
```

### 3. Dashboard Logging for Progress

Keep users informed of scan progress:

```python
from bugtrace.core.ui import dashboard

async def run_loop(self) -> Dict:
    dashboard.current_agent = self.name
    dashboard.log(f"[{self.name}] Starting analysis", "INFO")

    vectors = await self._hunter_phase()
    dashboard.log(f"[{self.name}] Found {len(vectors)} vectors", "INFO")

    for i, vector in enumerate(vectors, 1):
        dashboard.log(f"[{self.name}] Testing vector {i}/{len(vectors)}", "INFO")
        # ...

    dashboard.log(f"[{self.name}] Scan complete: {len(findings)} findings", "SUCCESS")
```

**Log Levels:**
- `INFO` - Normal progress updates
- `WARNING` - Suspicious findings (needs validation)
- `CRITICAL` - Confirmed vulnerabilities
- `SUCCESS` - Completion messages
- `ERROR` - Errors/failures

### 4. Error Handling Patterns

Fail gracefully and log appropriately:

```python
async def _hunter_phase(self) -> List[Dict]:
    vectors = []

    # Sync operations: use try/except for each discovery method
    try:
        param_vectors = self._discover_param_vectors()
        vectors.extend(param_vectors)
    except Exception as e:
        logger.warning(f"[{self.name}] Param discovery failed: {e}")

    # Async operations: catch specific exceptions
    try:
        content_vectors = await self._discover_content_vectors()
        vectors.extend(content_vectors)
    except aiohttp.ClientError as e:
        logger.warning(f"[{self.name}] HTTP request failed: {e}")
    except asyncio.TimeoutError:
        logger.warning(f"[{self.name}] Request timeout")

    return vectors
```

**Guidelines:**
- Catch specific exceptions when possible
- Log warnings (not errors) for expected failures
- Continue execution even if one discovery method fails
- Return partial results rather than failing entirely

### 5. Respect SAFE_MODE Setting

When BugTraceAI runs in safe mode, avoid destructive payloads:

```python
from bugtrace.core.config import settings

async def _auditor_phase(self, vectors: List[Dict]) -> List[Dict]:
    findings = []

    for vector in vectors:
        # In safe mode, skip RCE payload tier
        if settings.SAFE_MODE and vector.get("tier") == "rce_exploitation":
            logger.info(f"[{self.name}] Skipping RCE tier (SAFE_MODE enabled)")
            continue

        result = await self._test_vector(vector)
        # ...
```

**SAFE_MODE restrictions:**
- No destructive file operations (`rm`, `format`, `dd`)
- No RCE payloads with side effects
- No database modification commands (`DROP`, `DELETE`, `UPDATE`)
- Read-only validation techniques only

---

## Complete Agent Skeleton

Here's a minimal agent template to get started:

```python
import asyncio
from typing import Dict, List, Optional
from pathlib import Path
import aiohttp
from bugtrace.agents.base import BaseAgent
from bugtrace.core.job_manager import JobStatus
from bugtrace.core.ui import dashboard
from bugtrace.utils.logger import get_logger
from bugtrace.reporting.standards import (
    get_cwe_for_vuln,
    get_remediation_for_vuln,
    normalize_severity,
)

logger = get_logger("agents.your_agent")


class YourAgent(BaseAgent):
    """
    Specialist Agent for [VULNERABILITY_TYPE] (CWE-XXXX).
    Target: [DESCRIPTION OF WHAT THIS AGENT TARGETS]
    """

    def __init__(self, url: str, params: List[str] = None, report_dir: Path = None):
        super().__init__(
            name="YourAgent",
            role="Your Agent Role",
            agent_id="your_agent_id"
        )
        self.url = url
        self.params = params or []
        self.report_dir = report_dir or Path("./reports")
        self._tested_vectors = set()

    async def run_loop(self) -> Dict:
        """Main execution loop."""
        dashboard.current_agent = self.name
        dashboard.log(f"[{self.name}] Starting analysis on {self.url}", "INFO")

        # Phase 1: Hunter
        vectors = await self._hunter_phase()

        if not vectors:
            dashboard.log(f"[{self.name}] No vectors found", "INFO")
            return {
                "status": JobStatus.COMPLETED,
                "vulnerable": False,
                "findings": [],
                "findings_count": 0
            }

        # Phase 2: Auditor
        findings = await self._auditor_phase(vectors)

        # Report findings
        for finding in findings:
            await self._create_finding(finding)

        return {
            "status": JobStatus.COMPLETED,
            "vulnerable": len(findings) > 0,
            "findings": findings,
            "findings_count": len(findings)
        }

    async def _hunter_phase(self) -> List[Dict]:
        """Hunter Phase: Discover attack vectors."""
        dashboard.log(f"[{self.name}] Hunter: Scanning for vectors", "INFO")
        vectors = []

        # TODO: Implement vector discovery
        # - Check parameters
        # - Analyze content
        # - Detect patterns

        return vectors

    async def _auditor_phase(self, vectors: List[Dict]) -> List[Dict]:
        """Auditor Phase: Validate vectors with payloads."""
        dashboard.log(f"[{self.name}] Auditor: Validating {len(vectors)} vectors", "INFO")
        findings = []

        for vector in vectors:
            # Deduplication
            key = f"{self.url}#{vector.get('param')}"
            if key in self._tested_vectors:
                continue
            self._tested_vectors.add(key)

            # TODO: Test vector with payloads
            result = await self._test_vector(vector)

            if result and result.get("exploitable"):
                findings.append(result)
                dashboard.log(
                    f"[{self.name}] CONFIRMED: {vector['type']}",
                    "CRITICAL"
                )

        return findings

    async def _test_vector(self, vector: Dict) -> Optional[Dict]:
        """Test a single vector."""
        # TODO: Implement validation logic
        return None

    async def _create_finding(self, result: Dict):
        """Reports a confirmed finding."""
        finding = {
            "type": "YOUR_VULN_TYPE",
            "severity": result.get("severity", "MEDIUM"),
            "url": self.url,
            "parameter": result.get("param"),
            "payload": result.get("payload"),
            "description": f"[Description of vulnerability]",
            "validated": True,
            "status": "VALIDATED_CONFIRMED",
            "reproduction": result.get("reproduction"),
            "cwe_id": get_cwe_for_vuln("YOUR_VULN_TYPE"),
            "remediation": get_remediation_for_vuln("YOUR_VULN_TYPE"),
            "cve_id": "N/A",
            "http_request": result.get("http_request"),
            "http_response": result.get("http_response"),
        }
        logger.info(f"[{self.name}] VULNERABILITY CONFIRMED")
```

---

## References

- **OpenRedirectAgent:** `bugtrace/agents/openredirect_agent.py` - Canonical example of Hunter-Auditor pattern
- **PrototypePollutionAgent:** `bugtrace/agents/prototype_pollution_agent.py` - Tiered payload escalation example
- **TeamOrchestrator:** `bugtrace/core/team.py` - Integration point for new agents
- **Reporting Standards:** `bugtrace/reporting/standards.py` - Finding format requirements
- **BaseAgent:** `bugtrace/agents/base.py` - Abstract base class

---

**Last Updated:** 2026-01-29
**Maintainer:** BugTraceAI Core Team
