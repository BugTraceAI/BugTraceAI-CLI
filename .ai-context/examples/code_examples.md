# BugtraceAI Code Examples

> **Version**: 2.0.0 (Phoenix Edition)
> **Note**: These examples demonstrate internal APIs for development reference.

## Table of Contents

1. [Basic Scan Execution](#1-basic-scan-execution)
2. [JobManager Usage](#2-jobmanager-usage)
3. [EventBus Pub/Sub](#3-eventbus-pubsub)
4. [LLM Client](#4-llm-client)
5. [Browser Automation](#5-browser-automation)
6. [Custom Agent Creation](#6-custom-agent-creation)
7. [Skill System](#7-skill-system)
8. [Validation Pipeline](#8-validation-pipeline)

---

## 1. Basic Scan Execution

### Running a scan programmatically

```python
import asyncio
from bugtrace.core.team import TeamOrchestrator
from bugtrace.core.config import settings

async def run_scan():
    # Initialize orchestrator
    orchestrator = TeamOrchestrator("https://target.example.com")

    # Optional: Configure settings
    settings.SAFE_MODE = True
    settings.MAX_URLS = 50

    # Start the scan
    try:
        await orchestrator.start()
    except KeyboardInterrupt:
        print("Scan interrupted by user")
    finally:
        # Cleanup
        await orchestrator.cleanup()

if __name__ == "__main__":
    asyncio.run(run_scan())
```

### With authentication

```python
async def run_authenticated_scan():
    orchestrator = TeamOrchestrator(
        target="https://target.example.com",
        auth_config={
            "type": "form",
            "login_url": "https://target.example.com/login",
            "username_field": "email",
            "password_field": "password",
            "credentials": {
                "username": "test@example.com",
                "password": "password123"
            }
        }
    )
    await orchestrator.start()
```

---

## 2. JobManager Usage

### Adding and processing jobs

```python
from bugtrace.core.job_manager import JobManager, JobStatus

# Initialize manager
job_manager = JobManager(db_path="state/jobs.db")

# Add a job
job_id = job_manager.add_job(
    job_type="XSS_SCAN",
    target="https://example.com/search?q=test",
    params={"param": "q", "context": "html"},
    priority=20  # Higher = processed first
)
print(f"Created job: {job_id}")

# Fetch next job atomically
job = job_manager.get_next_job()
if job:
    print(f"Processing: {job['type']} - {job['target']}")

    try:
        # Do work...
        result = {"status": "exploited", "payload": "<script>alert(1)</script>"}
        job_manager.complete_job(job['id'], result, JobStatus.COMPLETED)
    except Exception as e:
        # Use retry logic
        moved_to_dlq = job_manager.fail_job_with_retry(job['id'], str(e))
        if moved_to_dlq:
            print("Job moved to dead letter queue after 3 failures")
```

### Dead letter queue operations

```python
# Check DLQ count
dlq_count = job_manager.get_dead_letter_count()
print(f"Jobs in DLQ: {dlq_count}")

# Retrieve failed jobs
dead_jobs = job_manager.get_dead_letter_jobs(limit=10)
for job in dead_jobs:
    print(f"Failed job: {job['type']} - Errors: {job['error_history']}")

# Requeue a job for retry
if dead_jobs:
    new_id = job_manager.requeue_dead_letter_job(dead_jobs[0]['id'])
    print(f"Requeued as job {new_id}")
```

---

## 3. EventBus Pub/Sub

### Publishing and subscribing to events

```python
import asyncio
from bugtrace.core.event_bus import EventBus

async def main():
    bus = EventBus()

    # Subscribe to events
    async def on_finding(data):
        print(f"New finding: {data['type']} at {data['url']}")

    async def on_scan_complete(data):
        print(f"Scan completed with {data['total_findings']} findings")

    await bus.subscribe("finding.created", on_finding)
    await bus.subscribe("scan.complete", on_scan_complete)

    # Publish events
    await bus.emit("finding.created", {
        "type": "XSS",
        "url": "https://example.com/page",
        "severity": "HIGH"
    })

    await bus.emit("scan.complete", {
        "target": "https://example.com",
        "total_findings": 5,
        "duration": 120.5
    })

asyncio.run(main())
```

---

## 4. LLM Client

### Basic generation

```python
import asyncio
from bugtrace.core.llm_client import llm_client

async def analyze_response():
    prompt = """
    Analyze this HTTP response for vulnerabilities:

    HTTP/1.1 200 OK
    Content-Type: text/html

    <html>
    <script>var user = 'admin'; var token = 'abc123';</script>
    </html>
    """

    # Basic generation
    response = await llm_client.generate(prompt, calling_module="analysis")
    print(response)

asyncio.run(analyze_response())
```

### With caching and metrics

```python
async def cached_generation():
    prompt = "Explain XSS vulnerabilities in 2 sentences."

    # Use cache (1 hour TTL)
    response = await llm_client.generate_with_cache(
        prompt,
        calling_module="xss_agent",
        cache_ttl=3600
    )

    # Check token usage
    summary = llm_client.get_token_summary()
    print(f"Total tokens: {summary['total']}")
    print(f"Estimated cost: ${summary['estimated_cost']:.4f}")

    # Check model metrics
    metrics = llm_client.get_model_metrics()
    for model, stats in metrics.items():
        print(f"{model}: {stats['success_rate']} success, {stats['avg_latency_ms']}ms avg")
```

### Streaming responses

```python
async def stream_analysis():
    prompt = "Generate a detailed security report for SQLi vulnerability."

    async for chunk in llm_client.generate_stream(prompt, "reporting"):
        print(chunk, end="", flush=True)
    print()  # Newline after stream completes
```

### JSON response validation

```python
from bugtrace.core.llm_client import llm_client, VULNERABILITY_SCHEMA

async def get_structured_response():
    prompt = """
    Return JSON with vulnerability details:
    {
        "type": "XSS",
        "severity": "HIGH",
        "parameter": "q",
        "confidence": 0.95
    }
    """

    response = await llm_client.generate(prompt, "analysis")

    # Validate against schema
    data = llm_client.validate_json_response(response, VULNERABILITY_SCHEMA)
    if data:
        print(f"Valid finding: {data['type']} ({data['severity']})")
    else:
        print("Invalid response format")
```

---

## 5. Browser Automation

### CDP Client usage

```python
import asyncio
from bugtrace.core.cdp_client import CDPClient

async def browser_verification():
    cdp = CDPClient(port=9222)

    try:
        # Start Chrome
        await cdp.start()

        # Navigate to target
        await cdp.navigate("https://example.com/vulnerable?xss=<script>alert(1)</script>")

        # Check for alert
        if cdp.was_alert_detected():
            print(f"XSS confirmed! Alert message: {cdp.get_last_alert()}")

        # Take screenshot
        screenshot = await cdp.screenshot()
        with open("evidence.png", "wb") as f:
            f.write(screenshot)

        # Get console logs
        logs = cdp.get_console_logs()
        print(f"Console errors: {[l for l in logs if l['level'] == 'error']}")

        # Get network requests
        requests = cdp.get_network_requests()
        print(f"Total requests: {len(requests)}")

    finally:
        await cdp.stop()

asyncio.run(browser_verification())
```

### Browser Manager for sessions

```python
from bugtrace.tools.visual.browser import BrowserManager

async def authenticated_browser():
    browser = BrowserManager()

    # Login and capture session
    session = await browser.login(
        url="https://example.com/login",
        username="test@example.com",
        password="password123"
    )

    # Use authenticated session
    cookies = session.get_cookies()
    print(f"Session cookies: {len(cookies)}")

    # Cleanup
    await browser.cleanup_auth_session()
```

---

## 6. Custom Agent Creation

### Creating a new specialized agent

```python
from bugtrace.agents.base import BaseAgent
from bugtrace.core.llm_client import llm_client

class CustomVulnAgent(BaseAgent):
    """Agent specialized for detecting custom vulnerability type."""

    AGENT_NAME = "CustomVulnAgent"
    PROMPT_FILE = "custom_vuln.md"  # In system_prompts/

    async def analyze(self, url: str, params: dict) -> list:
        """Analyze URL for custom vulnerability."""
        findings = []

        # Build context
        context = self.build_context(url, params)

        # Ask LLM for analysis
        prompt = f"""
        {self.system_prompt}

        TARGET: {url}
        PARAMETERS: {params}

        Analyze for custom vulnerability patterns.
        Return JSON with findings.
        """

        response = await llm_client.generate(prompt, self.AGENT_NAME)

        # Parse response
        parsed = self.parse_response(response)
        if parsed.get("vulnerable"):
            findings.append({
                "type": "CUSTOM_VULN",
                "url": url,
                "parameter": parsed["parameter"],
                "evidence": parsed["evidence"],
                "confidence": parsed["confidence"]
            })

        return findings

    def build_context(self, url: str, params: dict) -> dict:
        """Build analysis context."""
        return {
            "url": url,
            "params": params,
            "tech_stack": self.detect_tech(url)
        }
```

---

## 7. Skill System

### Using existing skills

```python
from bugtrace.skills import SKILL_REGISTRY
from bugtrace.skills.injection import XSSSkill

async def use_xss_skill():
    # Get skill from registry
    skill = SKILL_REGISTRY.get("xss")

    # Or instantiate directly
    xss = XSSSkill()

    # Execute skill
    result = await xss.execute(
        url="https://example.com/search",
        params={"q": "test"},
        context={"tech_stack": ["PHP", "Apache"]}
    )

    if result.success:
        print(f"XSS found: {result.payload}")
        print(f"Evidence: {result.evidence}")
```

### Creating a custom skill

```python
from bugtrace.skills.base import BaseSkill, SkillResult

class CustomSkill(BaseSkill):
    """Custom exploitation skill."""

    SKILL_NAME = "custom_exploit"
    REQUIRED_CONTEXT = ["url", "params"]

    async def execute(self, url: str, params: dict, context: dict = None) -> SkillResult:
        """Execute custom exploitation logic."""

        # Validate inputs
        if not self.validate_context(context):
            return SkillResult(success=False, error="Missing required context")

        # Generate payloads
        payloads = self.generate_payloads(params)

        # Test each payload
        for payload in payloads:
            result = await self.test_payload(url, params, payload)
            if result.vulnerable:
                return SkillResult(
                    success=True,
                    payload=payload,
                    evidence=result.response,
                    confidence=result.confidence
                )

        return SkillResult(success=False)

    def generate_payloads(self, params: dict) -> list:
        """Generate test payloads."""
        return [
            "{{7*7}}",
            "${7*7}",
            "#{7*7}"
        ]
```

---

## 8. Validation Pipeline

### Complete validation flow

```python
from bugtrace.core.conductor import ConductorV2
from bugtrace.core.cdp_client import CDPClient
from bugtrace.core.llm_client import llm_client

async def validate_xss_finding(finding: dict) -> dict:
    """
    Complete 3-layer validation:
    1. Payload verification
    2. Browser verification
    3. Vision AI validation
    """

    conductor = ConductorV2()
    validated = finding.copy()
    validated["validation_layers"] = []

    # Layer 1: Payload Verification
    syntax_valid = conductor.verify_payload_syntax(
        finding["payload"],
        finding["type"]
    )
    validated["validation_layers"].append({
        "layer": "payload_syntax",
        "passed": syntax_valid
    })

    if not syntax_valid:
        validated["confidence"] = 0.3
        return validated

    # Layer 2: Browser Verification
    cdp = CDPClient()
    try:
        await cdp.start()
        await cdp.navigate(finding["exploit_url"])

        browser_confirmed = cdp.was_alert_detected()
        validated["validation_layers"].append({
            "layer": "browser_verify",
            "passed": browser_confirmed,
            "alert_message": cdp.get_last_alert() if browser_confirmed else None
        })

        if not browser_confirmed:
            validated["confidence"] = 0.5
            return validated

        # Layer 3: Vision AI Validation
        screenshot = await cdp.screenshot()

        vision_prompt = """
        Analyze this screenshot for XSS evidence:
        1. Is there a JavaScript alert box visible?
        2. Does the alert contain our test payload?
        3. Rate your confidence (0.0-1.0)

        Return JSON: {"confirmed": bool, "confidence": float, "reasoning": string}
        """

        # Call vision model
        vision_response = await llm_client.generate(
            vision_prompt,
            calling_module="vision_validator",
            image_data=screenshot
        )

        vision_result = llm_client.validate_json_response(vision_response)
        validated["validation_layers"].append({
            "layer": "vision_ai",
            "passed": vision_result.get("confirmed", False),
            "confidence": vision_result.get("confidence", 0.0),
            "reasoning": vision_result.get("reasoning", "")
        })

        # Calculate final confidence
        if vision_result.get("confirmed"):
            validated["confidence"] = 0.95
        else:
            validated["confidence"] = 0.6

    finally:
        await cdp.stop()

    return validated
```

---

## Usage Notes

1. **Import paths**: All imports assume running from the project root
2. **Async/Await**: Most operations are async - use `asyncio.run()` for scripts
3. **Configuration**: Settings can be overridden via `bugtraceaicli.conf`
4. **Error handling**: Always wrap browser operations in try/finally for cleanup
5. **Token limits**: Be mindful of LLM token usage for large scans

---

*Last Updated: 2026-01-26*
