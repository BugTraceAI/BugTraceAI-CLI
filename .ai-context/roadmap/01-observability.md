# Observability & Monitoring - Feature Tasks (Local-First)

## Feature Overview
Add comprehensive observability stack to track LLM calls, agent performance, and system health.

**Why**: Professional teams need visibility into what AI is doing
**Competitor Gap**: PentAGI, CAI, Cyber Napoleon have full observability
**Phase**: 2 - Competitive Parity
**Duration**: 2 weeks
**Effort**: $15k

**⚠️ PRIVACY REQUIREMENT**: All observability runs **100% locally** on bug hunter's machine/VPC. No cloud services.

---

## 🟣 QUICK Tasks (1-2 days each)

### FEATURE-001: Add Structured JSON Logging
**Complexity**: 🟣 QUICK (1 day)
**Priority**: P1

**Description**: Replace print statements with structured logging (LOCAL ONLY)

**Implementation**:
```python
# Install: pip install structlog
# bugtrace/utils/logger.py
import structlog
import logging

def setup_structured_logging():
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer()
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Write to local file
    handler = logging.FileHandler("~/.bugtrace/logs/bugtrace.jsonl")
    handler.setLevel(logging.INFO)
    logging.root.addHandler(handler)

# Usage
logger = structlog.get_logger()
logger.info("scan.started", target_url=url, scan_id=scan_id, agents=31)
logger.warning("waf.detected", waf_type="cloudflare", confidence=0.85)
logger.error("agent.failed", agent="sqli", error=str(e), target=url)
```

**Benefits**:
- Machine-readable logs (stored locally in `~/.bugtrace/logs/`)
- Easy filtering and search with `jq`
- Correlation IDs for tracing
- Zero external dependencies

**Example Query**:
```bash
# Find all XSS findings today
cat ~/.bugtrace/logs/bugtrace.jsonl | jq 'select(.event=="finding.detected" and .type=="xss")'

# Calculate average scan duration
cat ~/.bugtrace/logs/bugtrace.jsonl | jq -s 'map(select(.event=="scan.completed")) | map(.duration_seconds) | add/length'
```

---

### FEATURE-002: Add Correlation IDs
**Complexity**: 🟣 QUICK (1 day)
**Priority**: P1

**Description**: Add correlation IDs to track requests across agents

**Implementation**:
```python
import uuid
from contextvars import ContextVar

# Global context variable
correlation_id: ContextVar[str] = ContextVar("correlation_id", default=None)

# Set at scan start
async def start_scan(url):
    cid = str(uuid.uuid4())
    correlation_id.set(cid)

    logger.info("scan.started", correlation_id=cid, url=url)

# Use in agents
async def xss_agent_scan(url):
    cid = correlation_id.get()
    logger.info("agent.started", correlation_id=cid, agent="xss", url=url)
```

**Query by correlation ID**:
```bash
# Get all logs for a specific scan
cat ~/.bugtrace/logs/bugtrace.jsonl | jq 'select(.correlation_id=="abc-123")'
```

---

### FEATURE-003: Add Local Performance Metrics
**Complexity**: 🟣 QUICK (2 days)
**Priority**: P1

**Description**: Track scan metrics locally (no external services)

**Implementation**:
```python
# bugtrace/core/local_metrics.py
import json
from pathlib import Path
from datetime import datetime

class LocalMetrics:
    def __init__(self):
        self.metrics_file = Path.home() / ".bugtrace" / "metrics" / "daily.jsonl"
        self.metrics_file.parent.mkdir(parents=True, exist_ok=True)

    def record_scan(self, scan_data):
        """Record scan metrics to local JSONL file"""
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "scan_id": scan_data["scan_id"],
            "duration_seconds": scan_data["duration"],
            "findings": {
                "critical": scan_data["critical_count"],
                "high": scan_data["high_count"],
                "medium": scan_data["medium_count"],
                "low": scan_data["low_count"]
            },
            "llm_cost_usd": scan_data["llm_cost"],
            "tokens_used": scan_data["tokens_used"],
            "agents_run": scan_data["agents"]
        }

        with open(self.metrics_file, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def get_summary(self, days=7):
        """Get metrics summary for last N days"""
        # Read and analyze local metrics file
        pass

# Usage
metrics = LocalMetrics()
metrics.record_scan({
    "scan_id": "abc-123",
    "duration": 450.2,
    "critical_count": 2,
    "high_count": 5,
    "medium_count": 8,
    "low_count": 3,
    "llm_cost": 0.15,
    "tokens_used": 45000,
    "agents": 31
})
```

**Query local metrics**:
```bash
# Total cost last 7 days
cat ~/.bugtrace/metrics/daily.jsonl | jq -s 'map(.llm_cost_usd) | add'

# Average findings per scan
cat ~/.bugtrace/metrics/daily.jsonl | jq -s 'map(.findings | .critical + .high + .medium + .low) | add/length'
```

---

## 🔵 MEDIUM Tasks (3-5 days each)

### FEATURE-004: Add Prometheus Metrics Export (LOCAL)
**Complexity**: 🔵 MEDIUM (3 days)
**Priority**: P1

**Description**: Export metrics for Prometheus scraping (localhost only)

**Implementation**:
```python
# Install: pip install prometheus-client
# bugtrace/core/metrics.py
from prometheus_client import Counter, Histogram, Gauge, start_http_server

# Define metrics
scans_total = Counter('bugtrace_scans_total', 'Total scans', ['status'])
scan_duration = Histogram('bugtrace_scan_duration_seconds', 'Scan duration')
findings_total = Counter('bugtrace_findings_total', 'Findings', ['type', 'severity'])
agent_success_rate = Gauge('bugtrace_agent_success_rate', 'Success rate', ['agent'])
waf_bypass_rate = Gauge('bugtrace_waf_bypass_rate', 'WAF bypass rate', ['waf_type'])
llm_tokens_used = Counter('bugtrace_llm_tokens_total', 'LLM tokens', ['model', 'type'])
llm_cost_total = Counter('bugtrace_llm_cost_usd', 'LLM cost in USD', ['model'])

# Start server on LOCALHOST ONLY
start_http_server(8000, addr='127.0.0.1')  # ⚠️ localhost only!

# Usage
scans_total.labels(status='completed').inc()
scan_duration.observe(elapsed_seconds)
findings_total.labels(type='xss', severity='high').inc()
agent_success_rate.labels(agent='sqli').set(0.85)
waf_bypass_rate.labels(waf_type='cloudflare').set(0.78)
llm_tokens_used.labels(model='gemini', type='input').inc(1234)
llm_cost_total.labels(model='gemini').inc(0.0012)
```

**Prometheus Config** (localhost only):
```yaml
# ~/.bugtrace/prometheus/prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'bugtrace'
    static_configs:
      - targets: ['127.0.0.1:8000']  # localhost only
```

**Docker Compose** (see 00-privacy-principles.md):
```yaml
# All services bind to 127.0.0.1 only
services:
  prometheus:
    image: prom/prometheus:latest
    ports:
      - "127.0.0.1:9090:9090"  # ⚠️ localhost only
    volumes:
      - ~/.bugtrace/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml
      - ~/.bugtrace/prometheus/data:/prometheus
```

**Dashboard Queries**:
```promql
# Scan success rate
rate(bugtrace_scans_total{status="completed"}[5m])

# Average scan duration
rate(bugtrace_scan_duration_seconds_sum[5m]) / rate(bugtrace_scan_duration_seconds_count[5m])

# Total LLM cost today
bugtrace_llm_cost_usd - (bugtrace_llm_cost_usd offset 24h)

# Findings per hour
rate(bugtrace_findings_total[1h]) * 3600
```

---

### FEATURE-005: Add LLM Cost Tracking
**Complexity**: 🔵 MEDIUM (2 days)
**Priority**: P1

**Description**: Track and report LLM API costs (stored locally)

**Implementation**:
```python
# bugtrace/core/cost_tracker.py
class CostTracker:
    # OpenRouter pricing (per 1M tokens)
    PRICING = {
        "google/gemini-3-flash-preview": {"input": 0.05, "output": 0.15},
        "qwen/qwen-2.5-coder-32b-instruct": {"input": 0.20, "output": 0.60},
        "deepseek/deepseek-chat": {"input": 0.14, "output": 0.28},
        "x-ai/grok-code-fast-1": {"input": 0.50, "output": 1.50}
    }

    def __init__(self):
        self.costs_by_model = {}
        self.costs_by_agent = {}
        self.total_cost = 0.0
        self.cost_file = Path.home() / ".bugtrace" / "costs.jsonl"

    def record_usage(self, model, agent, input_tokens, output_tokens):
        if model not in self.PRICING:
            return

        input_cost = (input_tokens / 1_000_000) * self.PRICING[model]["input"]
        output_cost = (output_tokens / 1_000_000) * self.PRICING[model]["output"]
        total = input_cost + output_cost

        self.total_cost += total

        # Track by model
        if model not in self.costs_by_model:
            self.costs_by_model[model] = 0.0
        self.costs_by_model[model] += total

        # Track by agent
        if agent not in self.costs_by_agent:
            self.costs_by_agent[agent] = 0.0
        self.costs_by_agent[agent] += total

        # Save to local file
        with open(self.cost_file, "a") as f:
            f.write(json.dumps({
                "timestamp": datetime.utcnow().isoformat(),
                "model": model,
                "agent": agent,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "cost_usd": total
            }) + "\n")

    def get_report(self):
        return {
            "total_cost_usd": round(self.total_cost, 4),
            "by_model": {
                model: round(cost, 4)
                for model, cost in self.costs_by_model.items()
            },
            "by_agent": {
                agent: round(cost, 4)
                for agent, cost in self.costs_by_agent.items()
            }
        }

# Usage
cost_tracker = CostTracker()

# After each LLM call
cost_tracker.record_usage(
    model="google/gemini-3-flash-preview",
    agent="xss_agent",
    input_tokens=1500,
    output_tokens=500
)

# At end of scan
report = cost_tracker.get_report()
logger.info("scan.completed", **report)
print(f"Total LLM cost: ${report['total_cost_usd']:.4f}")
```

**Query costs**:
```bash
# Cost by model last 30 days
cat ~/.bugtrace/costs.jsonl | jq -s 'group_by(.model) | map({model: .[0].model, total: map(.cost_usd) | add}) | sort_by(.total) | reverse'
```

---

### FEATURE-006: Add Agent Performance Metrics
**Complexity**: 🔵 MEDIUM (3 days)
**Priority**: P1

**Description**: Track success rates, latency, false positive rates per agent

**Implementation**:
```python
# bugtrace/core/agent_metrics.py
from dataclasses import dataclass
from typing import Dict
import statistics

@dataclass
class AgentMetrics:
    agent_name: str
    attempts: int = 0
    successes: int = 0
    failures: int = 0
    false_positives: int = 0
    true_positives: int = 0
    latencies: list = None

    def __post_init__(self):
        if self.latencies is None:
            self.latencies = []

    @property
    def success_rate(self):
        if self.attempts == 0:
            return 0.0
        return self.successes / self.attempts

    @property
    def precision(self):
        total_positives = self.true_positives + self.false_positives
        if total_positives == 0:
            return 0.0
        return self.true_positives / total_positives

    @property
    def avg_latency_ms(self):
        if not self.latencies:
            return 0.0
        return statistics.mean(self.latencies) * 1000

    def record_attempt(self, success, latency, is_true_positive=None):
        self.attempts += 1
        if success:
            self.successes += 1
        else:
            self.failures += 1

        self.latencies.append(latency)

        if is_true_positive is not None:
            if is_true_positive:
                self.true_positives += 1
            else:
                self.false_positives += 1

# Usage
metrics_tracker = {}

async def run_agent(agent_name, url):
    if agent_name not in metrics_tracker:
        metrics_tracker[agent_name] = AgentMetrics(agent_name)

    start = time.time()
    try:
        result = await agent.scan(url)
        latency = time.time() - start

        metrics_tracker[agent_name].record_attempt(
            success=True,
            latency=latency,
            is_true_positive=result.validated
        )

        return result

    except Exception as e:
        latency = time.time() - start
        metrics_tracker[agent_name].record_attempt(
            success=False,
            latency=latency
        )
        raise

# Report (saved locally)
def get_metrics_report():
    return {
        agent_name: {
            "success_rate": metrics.success_rate,
            "precision": metrics.precision,
            "avg_latency_ms": metrics.avg_latency_ms,
            "attempts": metrics.attempts
        }
        for agent_name, metrics in metrics_tracker.items()
    }
```

---

### FEATURE-007: Add Health Check Endpoint (LOCAL)
**Complexity**: 🔵 MEDIUM (2 days)
**Priority**: P1

**Description**: HTTP endpoint for health monitoring (localhost only)

**Implementation**:
```python
# bugtrace/api/health.py
from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn

app = FastAPI()

class HealthStatus(BaseModel):
    status: str  # healthy, degraded, unhealthy
    version: str
    uptime_seconds: float
    active_scans: int
    queue_size: int
    llm_status: str
    database_status: str

@app.get("/health")
async def health_check():
    try:
        # Check database
        async with db.session() as session:
            await session.execute(text("SELECT 1"))
        db_status = "healthy"
    except Exception:
        db_status = "unhealthy"

    # Check LLM
    try:
        await llm_client.health_check()
        llm_status = "healthy"
    except Exception:
        llm_status = "unhealthy"

    overall = "healthy"
    if db_status == "unhealthy" or llm_status == "unhealthy":
        overall = "unhealthy"

    return HealthStatus(
        status=overall,
        version=settings.VERSION,
        uptime_seconds=time.time() - start_time,
        active_scans=reactor.active_task_count(),
        queue_size=job_manager.queue_size(),
        llm_status=llm_status,
        database_status=db_status
    )

@app.get("/metrics")
async def metrics():
    return {
        "scans": {
            "total": scan_counter.total,
            "completed": scan_counter.completed,
            "failed": scan_counter.failed
        },
        "findings": findings_counter.get_summary(),
        "agents": get_metrics_report(),
        "llm": cost_tracker.get_report()
    }

# Start server on LOCALHOST ONLY
if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8001)  # ⚠️ localhost only
```

**Usage**:
```bash
# Check health
curl http://127.0.0.1:8001/health

# Get metrics
curl http://127.0.0.1:8001/metrics
```

---

## 🟠 COMPLEX Tasks (1-2 weeks each)

### FEATURE-008: Add Grafana Dashboard (LOCAL)
**Complexity**: 🟠 COMPLEX (1 week)
**Priority**: P2

**Description**: Pre-built Grafana dashboard for visualization (localhost only)

**Implementation**:
```json
// ~/.bugtrace/grafana/dashboards/bugtrace.json
{
  "dashboard": {
    "title": "BugTraceAI-CLI Monitoring",
    "panels": [
      {
        "title": "Scan Success Rate",
        "targets": [{
          "expr": "rate(bugtrace_scans_total{status='completed'}[5m])"
        }]
      },
      {
        "title": "Findings by Type",
        "targets": [{
          "expr": "sum by(type) (bugtrace_findings_total)"
        }]
      },
      {
        "title": "LLM Cost (Last 24h)",
        "targets": [{
          "expr": "bugtrace_llm_cost_usd - (bugtrace_llm_cost_usd offset 24h)"
        }]
      },
      {
        "title": "Agent Performance",
        "targets": [{
          "expr": "bugtrace_agent_success_rate"
        }]
      },
      {
        "title": "WAF Bypass Rate",
        "targets": [{
          "expr": "bugtrace_waf_bypass_rate"
        }]
      }
    ]
  }
}
```

**Docker Compose Setup** (localhost only):
```yaml
# ~/.bugtrace/docker-compose.yml
version: '3.8'
services:
  prometheus:
    image: prom/prometheus:latest
    ports:
      - "127.0.0.1:9090:9090"  # ⚠️ localhost only
    volumes:
      - ~/.bugtrace/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml
      - ~/.bugtrace/prometheus/data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.listen-address=127.0.0.1:9090'
    restart: unless-stopped

  grafana:
    image: grafana/grafana:latest
    ports:
      - "127.0.0.1:3000:3000"  # ⚠️ localhost only
    environment:
      GF_SECURITY_ADMIN_PASSWORD: bugtrace123
      GF_USERS_ALLOW_SIGN_UP: false
    volumes:
      - ~/.bugtrace/grafana:/var/lib/grafana
      - ~/.bugtrace/grafana/dashboards:/etc/grafana/provisioning/dashboards
    restart: unless-stopped
```

**Setup**:
```bash
# Start local observability stack
cd ~/.bugtrace
docker-compose up -d

# Access Grafana (localhost only)
open http://127.0.0.1:3000
# Login: admin / bugtrace123

# Access Prometheus (localhost only)
open http://127.0.0.1:9090
```

---

### FEATURE-009: Add Alert System (LOCAL)
**Complexity**: 🟠 COMPLEX (1 week)
**Priority**: P2

**Description**: Alerting for critical events (webhooks to Discord/Slack - user controlled)

**Implementation**:
```python
# bugtrace/core/alerts.py
from enum import Enum
import httpx

class AlertLevel(Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"

class AlertManager:
    def __init__(self):
        self.webhooks = []  # User provides webhooks manually

    def add_webhook(self, url, level=AlertLevel.WARNING):
        """User manually adds their Discord/Slack webhook"""
        self.webhooks.append({"url": url, "level": level})

    async def send_alert(self, level, title, message, metadata=None):
        for webhook in self.webhooks:
            if self._should_send(level, webhook["level"]):
                await self._send_webhook(webhook["url"], {
                    "level": level.value,
                    "title": title,
                    "message": message,
                    "metadata": metadata or {},
                    "timestamp": datetime.utcnow().isoformat()
                })

    def _should_send(self, alert_level, webhook_level):
        levels = [AlertLevel.INFO, AlertLevel.WARNING, AlertLevel.CRITICAL]
        return levels.index(alert_level) >= levels.index(webhook_level)

    async def _send_webhook(self, url, data):
        """Send to user's own Discord/Slack webhook"""
        async with httpx.AsyncClient() as client:
            # Format for Discord
            if "discord.com" in url:
                payload = {
                    "content": f"**{data['title']}**\n{data['message']}",
                    "embeds": [{
                        "color": self._get_color(data['level']),
                        "fields": [
                            {"name": k, "value": str(v), "inline": True}
                            for k, v in data['metadata'].items()
                        ]
                    }]
                }
            # Format for Slack
            elif "slack.com" in url:
                payload = {
                    "text": f"{data['title']}\n{data['message']}",
                    "attachments": [{
                        "fields": [
                            {"title": k, "value": str(v), "short": True}
                            for k, v in data['metadata'].items()
                        ]
                    }]
                }
            else:
                payload = data

            await client.post(url, json=payload)

    def _get_color(self, level):
        return {
            "info": 0x3498db,      # Blue
            "warning": 0xf39c12,   # Orange
            "critical": 0xe74c3c   # Red
        }.get(level, 0x95a5a6)

# Usage
alert_manager = AlertManager()

# User provides their own webhook URLs
alert_manager.add_webhook(
    "https://discord.com/api/webhooks/XXX/YYY",  # User's Discord
    AlertLevel.CRITICAL
)

# Send alerts
await alert_manager.send_alert(
    AlertLevel.CRITICAL,
    "Critical Vulnerability Found",
    f"RCE vulnerability detected on {url}",
    metadata={"type": "RCE", "severity": "CRITICAL", "url": url}
)

await alert_manager.send_alert(
    AlertLevel.WARNING,
    "Scan Timeout",
    f"Scan exceeded 1 hour: {scan_id}",
    metadata={"scan_id": scan_id, "duration": 3600}
)
```

**Configuration**:
```ini
# ~/.bugtrace/config.conf
[ALERTS]
ENABLED=true
DISCORD_WEBHOOK=https://discord.com/api/webhooks/YOUR_WEBHOOK  # User provides
SLACK_WEBHOOK=https://hooks.slack.com/services/YOUR_WEBHOOK    # Optional
MIN_LEVEL=WARNING  # Only send WARNING and CRITICAL
```

---

### FEATURE-010: Add CLI Stats Command
**Complexity**: 🔵 MEDIUM (2 days)
**Priority**: P2

**Description**: CLI command to view local statistics

**Implementation**:
```python
# bugtrace/cli/commands/stats.py
import click
from rich.console import Console
from rich.table import Table

@click.command()
@click.option('--days', default=7, help='Number of days to analyze')
def stats(days):
    """Show statistics from local metrics"""
    console = Console()

    # Load local metrics
    metrics = LocalMetrics().get_summary(days=days)

    # Scans summary
    console.print(f"\n[bold]📊 Stats (Last {days} days)[/bold]\n")

    table = Table(title="Scan Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Total Scans", str(metrics['total_scans']))
    table.add_row("Success Rate", f"{metrics['success_rate']:.1%}")
    table.add_row("Avg Duration", f"{metrics['avg_duration']:.1f}s")
    table.add_row("Total Findings", str(metrics['total_findings']))
    table.add_row("Total LLM Cost", f"${metrics['total_cost']:.2f}")

    console.print(table)

    # Findings by type
    table = Table(title="Findings by Type")
    table.add_column("Type", style="cyan")
    table.add_column("Count", style="green")

    for vuln_type, count in metrics['findings_by_type'].items():
        table.add_row(vuln_type.upper(), str(count))

    console.print("\n")
    console.print(table)

# Usage
./bugtraceai-cli stats --days 30
```

---

## Summary

**Total Tasks**: 10
- 🟣 Quick: 3 (4 days)
- 🔵 Medium: 4 (10 days)
- 🟠 Complex: 3 (3 weeks)

**Estimated Effort**: 2 weeks for P1 tasks
**Investment**: ~$15k

**Infrastructure Cost**: $0/month (all local)
- Prometheus: Localhost
- Grafana: Localhost (Docker)
- Logs: `~/.bugtrace/logs/` (local files)
- Metrics: `~/.bugtrace/metrics/` (local files)

**Resource Usage (8GB VPC)**:
- Prometheus: ~500 MB RAM
- Grafana: ~300 MB RAM
- Total: <1GB additional overhead ✅

**Competitive Gap Closed**:
- ✅ PentAGI (Prometheus, Grafana - local)
- ✅ CAI (Metrics, observability - local)
- ✅ Cyber Napoleon (Health checks, alerting - local)

**Privacy Compliance**: ✅ 100% Local
- No cloud services (Langfuse removed)
- No telemetry
- No external dependencies except user-provided webhooks
- All data stays on bug hunter's machine/VPC

**Deliverables**:
- ✅ Structured JSON logging (local files)
- ✅ Prometheus metrics (localhost:9090)
- ✅ Grafana dashboard (localhost:3000)
- ✅ Health check endpoint (localhost:8001)
- ✅ Alert system (user's Discord/Slack webhooks)
- ✅ CLI stats command
- ✅ Docker Compose setup (all localhost)
