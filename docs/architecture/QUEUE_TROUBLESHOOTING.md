# Queue Troubleshooting Guide

> **Module:** `bugtrace.core.queue`
> **Version:** 1.0.0
> **Updated:** 2026-01-29

## Table of Contents

1. [Overview](#overview)
2. [Issue: Queue Backpressure](#issue-queue-backpressure)
3. [Issue: Slow Consumption](#issue-slow-consumption)
4. [Issue: Deduplication Not Working](#issue-deduplication-not-working)
5. [Issue: Events Not Flowing](#issue-events-not-flowing)
6. [Diagnostic Commands](#diagnostic-commands)
7. [Configuration Reference](#configuration-reference)

---

## Overview

### When to Check Queue Health

Queue issues typically manifest during the **Evaluation** and **Exploitation** phases of the 5-phase pipeline. Check queue health when you observe:

- **Scans running slower than expected** - Pipeline may be bottlenecked
- **"Queue full" warnings in logs** - Backpressure is triggered
- **Same vulnerability tested multiple times** - Deduplication failure
- **Pipeline stuck after Discovery** - Event flow issues
- **High memory usage** - Unbounded queue growth

### Pipeline Queue Architecture

```
Discovery Phase          Evaluation Phase              Exploitation Phase
+---------------+       +------------------------+     +------------------+
| SASTDASTAgent | --->  | ThinkingConsolidation  | --> | SpecialistQueues |
|               |       | Agent                  |     |   xss (8 workers)|
+---------------+       | - Deduplication        |     |   sqli (5 workers)|
       |                | - Classification       |     |   csti (5 workers)|
  url_analyzed          | - Prioritization       |     |   ... 8 more     |
    events              +------------------------+     +------------------+
```

### How to Access Diagnostic Information

**Via REST API:**
```bash
# All queue metrics
curl http://localhost:8000/api/metrics/queues

# All metrics including deduplication
curl http://localhost:8000/api/metrics
```

**In Python code:**
```python
from bugtrace.core.queue import queue_manager

# Get all queue stats
stats = queue_manager.get_all_stats()

# Get aggregate stats
aggregate = queue_manager.get_aggregate_stats()
```

---

## Issue: Queue Backpressure

### Symptoms

- Log warnings: `"Queue 'xss' is full (100/100), backpressure triggered"`
- `total_rejected > 0` in queue stats
- Findings being dropped after retry exhaustion
- `backpressure_drops` counter incrementing in ThinkingAgent stats

### Diagnosis

```bash
# Check queue depths via API
curl http://localhost:8000/api/metrics/queues

# Look for in the response:
# - "is_full": true
# - "total_rejected" > 0
# - "current_depth" == "max_depth"
```

**Example response indicating backpressure:**
```json
{
  "aggregate": {
    "total_rejected": 42,
    "queues_with_backpressure": 2
  },
  "by_queue": {
    "xss": {
      "current_depth": 100,
      "max_depth": 100,
      "is_full": true,
      "total_rejected": 30
    }
  }
}
```

### Causes

| Cause | Indicators |
|-------|------------|
| **Specialist too slow** | Low `dequeue_throughput`, workers processing slowly |
| **Burst of findings from Discovery** | High `enqueue_throughput` spike |
| **Worker pool too small** | Sustained high depth with available CPU |
| **Network latency to target** | High latency in specialist testing |
| **Heavy payload testing** | Many tiers/payloads per finding |

### Solutions

**1. Increase queue depth (buffer more items):**
```python
# In .env or environment
QUEUE_DEFAULT_MAX_DEPTH=500
```

**2. Add more workers (process faster):**
```python
# For XSS specifically (high volume)
WORKER_POOL_XSS_SIZE=12

# For all specialists
WORKER_POOL_DEFAULT_SIZE=10
```

**3. Check specialist efficiency:**
- Review network connectivity to target
- Reduce payload count per finding
- Enable early exit on first confirmed finding

**4. Adjust ThinkingAgent retry behavior:**
```python
# Allow more time for queue to drain
THINKING_BACKPRESSURE_RETRIES=5
THINKING_BACKPRESSURE_DELAY=1.0
```

### Backpressure Retry Timing

ThinkingConsolidationAgent implements exponential backoff when queues are full:

| Attempt | Delay |
|---------|-------|
| 1 | 0.5s |
| 2 | 1.0s |
| 3 | 2.0s |
| **Total** | **3.5s max wait** |

If all retries fail, the finding is dropped and counted in `backpressure_drops`.

---

## Issue: Slow Consumption

### Symptoms

- Queue depths steadily growing over time
- Scans taking much longer than expected
- Low `dequeue_throughput` compared to `enqueue_throughput`
- Workers appear idle while queue has items

### Diagnosis

```bash
# Check throughput metrics
curl http://localhost:8000/api/metrics/queues

# Look for:
# - dequeue_throughput << enqueue_throughput
# - avg_latency_ms increasing over time
# - current_depth steadily growing
```

**Example response indicating slow consumption:**
```json
{
  "by_queue": {
    "sqli": {
      "current_depth": 85,
      "enqueue_throughput": 15.2,
      "dequeue_throughput": 3.1,
      "avg_latency_ms": 12500,
      "p95_latency_ms": 25000
    }
  }
}
```

**Key indicator:** `dequeue_throughput` significantly lower than `enqueue_throughput` means consumers cannot keep up with producers.

### Causes

| Cause | How to Identify |
|-------|-----------------|
| **Insufficient workers** | CPU usage low, workers not saturated |
| **Network timeouts in specialists** | High latency, timeout errors in logs |
| **Heavy payload testing** | Many payloads per finding, slow testing |
| **Target rate limiting** | HTTP 429 responses, connection resets |
| **Slow database writes** | High I/O wait, database errors |

### Solutions

**1. Scale up workers:**
```python
# For high-volume specialists
WORKER_POOL_XSS_SIZE=12
WORKER_POOL_SQLI_SIZE=8

# General increase
WORKER_POOL_DEFAULT_SIZE=8
```

**2. Reduce payload count per item:**
- Configure specialists to test fewer payload tiers
- Enable HTTP-first validation to reduce CDP calls

**3. Check network connectivity:**
```bash
# Test target responsiveness
curl -w "Connect: %{time_connect}s\nTotal: %{time_total}s\n" -o /dev/null -s https://target.com
```

**4. Monitor worker utilization:**
```bash
# Check parallelization metrics
curl http://localhost:8000/api/metrics/parallelization

# Look for:
# - current_concurrent vs pool capacity
# - parallelization_factor (should be > 0.5)
```

---

## Issue: Deduplication Not Working

### Symptoms

- Same vulnerability tested multiple times by specialists
- `duplicates_filtered` counter is 0 (should be > 0 normally)
- Higher than expected scan time due to redundant testing
- Multiple reports for identical findings

### Diagnosis

```bash
# Check ThinkingAgent deduplication stats
curl http://localhost:8000/api/metrics/deduplication

# Look for:
# - "total_deduplicated" = 0 (problem!)
# - "dedup_effectiveness_percent" very low
```

**Example response indicating dedup failure:**
```json
{
  "total_received": 500,
  "total_deduplicated": 0,
  "total_distributed": 500,
  "dedup_effectiveness_percent": 0.0
}
```

**Expected healthy deduplication:**
- `dedup_effectiveness_percent` should be 30-60% typically
- More received than distributed indicates dedup is working

### Causes

| Cause | How to Identify |
|-------|-----------------|
| **Different parameter names for same vuln** | Check finding parameter field consistency |
| **Different URL query params making keys unique** | Keys include query params they shouldn't |
| **Cache eviction (too many unique findings)** | Cache size at max, old keys evicted |
| **Inconsistent vuln_type naming** | "xss" vs "XSS" vs "Cross-Site Scripting" |

### Deduplication Key Format

The dedup key is: `{vuln_type}:{parameter}:{url_path}`

```python
# Example finding
finding = {
    "type": "XSS",
    "parameter": "id",
    "url": "https://example.com/api/users?id=1&name=test"
}

# Generated key
key = "xss:id:/api/users"
```

**Note:** Query parameters are stripped from URL path for deduplication.

### Solutions

**1. Increase dedup window (more cache capacity):**
```python
# Allow more unique keys before LRU eviction
THINKING_DEDUP_WINDOW=2000
```

**2. Verify event format consistency:**
```python
# Check url_analyzed events have consistent format:
# - "type" field is lowercase
# - "parameter" field is consistent
# - "url" field includes path
```

**3. Check ThinkingAgent subscription:**
```python
# Verify ThinkingAgent is receiving events
# Look for "[ThinkingAgent] Received url_analyzed" in logs
```

**4. Reset dedup cache between scans:**
```bash
# Reset all metrics including dedup cache
curl -X POST http://localhost:8000/api/metrics/reset
```

---

## Issue: Events Not Flowing

### Symptoms

- Pipeline stuck after Discovery phase completes
- No progress in Exploitation phase
- Specialist queues remain empty
- No `work_queued_*` events emitted

### Diagnosis

**1. Check if ThinkingAgent is running:**
```bash
# Look for subscription setup in logs
grep "ThinkingAgent" logs/bugtrace.log | grep -i "subscribe"

# Look for event receipt
grep "ThinkingAgent" logs/bugtrace.log | grep "url_analyzed"
```

**2. Verify event bus has subscribers:**
```python
# In debug code or test
from bugtrace.core.event_bus import event_bus

subs = event_bus.list_subscriptions()
print(f"Subscriptions: {subs}")
# Should include URL_ANALYZED -> ThinkingConsolidationAgent
```

**3. Check scan_context matching:**
Events are filtered by `scan_context`. Ensure producer and consumer use the same context:
```python
# Producer (SASTDASTAgent)
await event_bus.emit("url_analyzed", {
    "scan_context": "scan_abc123",  # Must match
    "findings": [...]
})

# Consumer (ThinkingAgent)
# Will only receive events with matching scan_context
```

### Causes

| Cause | How to Identify |
|-------|-----------------|
| **ThinkingAgent not started** | No subscription in event bus |
| **Event bus subscription missing** | `_setup_event_subscriptions()` not called |
| **scan_context mismatch** | Events filtered by wrong context |
| **Event emission disabled** | `THINKING_EMIT_EVENTS=false` |

### Solutions

**1. Verify ThinkingAgent setup:**
```python
# Ensure ThinkingAgent._setup_event_subscriptions() is called on start
# This subscribes to EventType.URL_ANALYZED
```

**2. Check scan_context consistency:**
```python
# All pipeline components must use same scan_context
# TeamOrchestrator passes this to all agents
```

**3. Enable event emission:**
```python
# Ensure event emission is enabled
THINKING_EMIT_EVENTS=True
```

**4. Enable debug logging:**
```bash
# Set environment variable for verbose logs
export BUGTRACE_LOG_LEVEL=DEBUG

# Or in code
from bugtrace.utils.logger import set_log_level
set_log_level("DEBUG")
```

**5. Check event bus health:**
```python
# Verify event bus singleton is shared
from bugtrace.core.event_bus import event_bus

# All components should use the same instance
print(f"Event bus ID: {id(event_bus)}")
```

---

## Diagnostic Commands

### Quick Reference

```bash
# === Queue Metrics ===

# All queue stats (depth, throughput, latency per queue)
curl http://localhost:8000/api/metrics/queues

# Specific queue (if endpoint exists)
curl http://localhost:8000/api/metrics/queues/xss

# === Deduplication Metrics ===

# Deduplication effectiveness
curl http://localhost:8000/api/metrics/deduplication

# === Pipeline State ===

# Current pipeline phase and status
curl http://localhost:8000/api/metrics/pipeline

# === All Metrics Combined ===

# CDP, parallelization, dedup, queues
curl http://localhost:8000/api/metrics

# === Reset Metrics ===

# Clear all counters (use between scans)
curl -X POST http://localhost:8000/api/metrics/reset

# === Debug Logging ===

# Enable verbose logging
export BUGTRACE_LOG_LEVEL=DEBUG

# Filter queue-related logs
grep -E "(queue|Queue|backpressure)" logs/bugtrace.log

# Filter ThinkingAgent logs
grep "ThinkingAgent" logs/bugtrace.log

# Filter deduplication logs
grep -i "dedup" logs/bugtrace.log
```

### Interpreting Queue Stats

```json
{
  "xss": {
    "name": "xss",
    "current_depth": 42,        // Items waiting
    "max_depth": 100,           // Capacity limit
    "rate_limit": 100,          // Max enqueue/sec
    "is_full": false,           // Backpressure active?
    "total_enqueued": 1500,     // Total items added
    "total_dequeued": 1458,     // Total items processed
    "total_rejected": 0,        // Dropped due to backpressure
    "enqueue_throughput": 25.5, // Items/sec in
    "dequeue_throughput": 24.3, // Items/sec out
    "avg_latency_ms": 150.2,    // Avg time in queue
    "p95_latency_ms": 320.5,    // 95th percentile latency
    "max_latency_ms": 850.0     // Maximum observed latency
  }
}
```

**Health indicators:**
- `is_full: false` and `total_rejected: 0` = healthy
- `dequeue_throughput` close to `enqueue_throughput` = balanced
- Low `avg_latency_ms` = responsive processing

---

## Configuration Reference

### Queue Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `QUEUE_DEFAULT_MAX_DEPTH` | 1000 | Maximum items per queue before backpressure |
| `QUEUE_DEFAULT_RATE_LIMIT` | 100 | Max enqueue rate (items/second), 0 = unlimited |
| `QUEUE_PERSISTENCE_MODE` | "memory" | Storage mode: "memory" or "redis" |
| `QUEUE_REDIS_URL` | "redis://localhost:6379/0" | Redis connection (if mode=redis) |

### Worker Pool Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `WORKER_POOL_DEFAULT_SIZE` | 5 | Workers per specialist (default) |
| `WORKER_POOL_XSS_SIZE` | 8 | Workers for XSS specialist |
| `WORKER_POOL_SQLI_SIZE` | 5 | Workers for SQLi specialist |
| `WORKER_POOL_SHUTDOWN_TIMEOUT` | 30.0 | Seconds to drain on shutdown |
| `WORKER_POOL_DEQUEUE_TIMEOUT` | 5.0 | Seconds to wait for queue item |

### ThinkingAgent Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `THINKING_MODE` | "streaming" | Processing mode: "streaming" or "batch" |
| `THINKING_DEDUP_WINDOW` | 1000 | Max dedup cache entries (LRU eviction) |
| `THINKING_BACKPRESSURE_RETRIES` | 3 | Retries when queue is full |
| `THINKING_BACKPRESSURE_DELAY` | 0.5 | Initial delay between retries (exponential) |
| `THINKING_EMIT_EVENTS` | true | Emit work_queued_* events |
| `THINKING_FP_THRESHOLD` | 0.5 | Min fp_confidence to forward findings |
| `THINKING_BATCH_SIZE` | 50 | Batch size (if mode=batch) |
| `THINKING_BATCH_TIMEOUT` | 5.0 | Batch timeout in seconds |

### Statistics Settings (Internal)

| Setting | Default | Description |
|---------|---------|-------------|
| `_window_seconds` | 60.0 | Rolling window for throughput calculation |
| `_max_samples` | 1000 | Maximum samples per metric |

### Environment Variables

```bash
# Enable debug logging
export BUGTRACE_LOG_LEVEL=DEBUG

# Override queue settings
export QUEUE_DEFAULT_MAX_DEPTH=500
export WORKER_POOL_XSS_SIZE=12

# Override ThinkingAgent settings
export THINKING_DEDUP_WINDOW=2000
export THINKING_BACKPRESSURE_RETRIES=5
```

---

## Related Documentation

- [Queue Patterns](./QUEUE_PATTERNS.md) - Backpressure, rate limiting, specialist integration
- [ThinkingAgent](./THINKING_AGENT.md) - Deduplication, classification, prioritization algorithms
- [Pipeline Architecture](./PIPELINE_ARCHITECTURE.md) - 5-phase execution model
- [Agent Architecture](./AGENT_ARCHITECTURE.md) - Specialist agent documentation

### Source Code References

- Queue implementation: `bugtrace/core/queue.py`
  - `SpecialistQueue.get_stats()` - Queue statistics
  - `QueueManager.get_all_stats()` - All queue stats
  - `QueueManager.get_aggregate_stats()` - Aggregate summary
- ThinkingAgent: `bugtrace/agents/thinking_consolidation_agent.py`
  - `DeduplicationCache` - LRU dedup implementation
  - `_distribute_to_queue()` - Backpressure retry logic
- Metrics API: `bugtrace/api/routes/metrics.py`
  - `/api/metrics/queues` - Queue statistics endpoint
  - `/api/metrics/deduplication` - Dedup effectiveness

---

*Last updated: 2026-01-29*
