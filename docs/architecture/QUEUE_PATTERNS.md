# Queue Patterns: Backpressure, Rate Limiting, and Specialist Integration

> **Module:** `bugtrace.core.queue`
> **Version:** 1.0.0
> **Updated:** 2026-01-29

## Table of Contents

1. [Overview](#overview)
2. [Queue Architecture](#queue-architecture)
3. [Backpressure Handling](#backpressure-handling)
4. [Rate Limiting](#rate-limiting)
5. [Statistics Tracking](#statistics-tracking)
6. [Specialist Integration](#specialist-integration)
7. [Configuration](#configuration)
8. [Examples](#examples)

---

## Overview

### Purpose of Per-Specialist Queues

The BugTraceAI pipeline uses **per-specialist async queues** to coordinate work distribution between the Evaluation and Exploitation phases. Each specialist agent (XSS, SQLi, CSTI, etc.) has a dedicated queue that buffers work items for parallel processing.

```
ThinkingConsolidationAgent --> SpecialistQueue[xss] --> XSSAgent WorkerPool
                           --> SpecialistQueue[sqli] --> SQLiAgent WorkerPool
                           --> SpecialistQueue[csti] --> CSTIAgent WorkerPool
                           ...
```

### Role in 5-Phase Pipeline

Queues serve as the **bridge between Evaluation and Exploitation phases**:

| Phase | Queue Role |
|-------|-----------|
| Discovery | N/A - direct event emission |
| **Evaluation** | Producer: ThinkingConsolidationAgent enqueues classified findings |
| **Exploitation** | Consumer: Specialist WorkerPools dequeue and test payloads |
| Validation | N/A - event-driven from specialists |
| Reporting | N/A - event-driven collection |

### Key Benefits

1. **Backpressure Handling**: Prevents memory exhaustion when producers outpace consumers
2. **Rate Limiting**: Prevents target server overload with token bucket algorithm
3. **Statistics Tracking**: Real-time visibility into queue health and throughput
4. **Decoupling**: Producers and consumers operate independently
5. **Prioritization**: Higher priority items processed first via priority scoring

---

## Queue Architecture

### Core Classes

The queue system consists of four core classes:

#### QueueItem

Wrapper for items in specialist queue with timing metadata.

```python
@dataclass
class QueueItem:
    """Wrapper for items in specialist queue."""
    payload: Dict[str, Any]      # Finding data to process
    scan_context: str            # Scan context identifier for ordering
    enqueued_at: float = field(  # Monotonic timestamp for latency tracking
        default_factory=time.monotonic
    )
```

**Fields:**
- `payload`: The finding data (url, parameter, vuln_type, priority, etc.)
- `scan_context`: Groups items by scan for ordering guarantees
- `enqueued_at`: Monotonic timestamp for accurate latency measurement

#### SpecialistQueue

Async queue for specialist agents with backpressure and rate limiting.

```python
class SpecialistQueue:
    def __init__(
        self,
        name: str,
        max_depth: int = None,    # Default: QUEUE_DEFAULT_MAX_DEPTH
        rate_limit: float = None  # Default: QUEUE_DEFAULT_RATE_LIMIT
    ):
        ...
```

**Key Methods:**
| Method | Description |
|--------|-------------|
| `enqueue(item, scan_context)` | Add item with backpressure check, returns bool |
| `dequeue(timeout)` | Get next item, returns None on timeout |
| `depth()` | Current queue size |
| `is_full()` | Check if at max capacity |
| `get_stats()` | Get queue statistics dict |
| `reset_stats()` | Reset statistics counters |

#### QueueManager

Singleton managing all specialist queues.

```python
class QueueManager:
    def get_queue(specialist: str) -> SpecialistQueue
    def list_queues() -> List[str]
    def get_all_stats() -> Dict[str, Dict[str, Any]]
    def get_aggregate_stats() -> Dict[str, Any]
    def reset_all_stats() -> None
    def reset() -> None  # Clear all queues (testing)
```

**Usage:**
```python
from bugtrace.core.queue import queue_manager

# Get or create a specialist queue
xss_queue = queue_manager.get_queue("xss")

# List all active queues
queues = queue_manager.list_queues()  # ["xss", "sqli", ...]

# Get aggregate statistics
stats = queue_manager.get_aggregate_stats()
```

#### SPECIALIST_QUEUES

Pre-defined list of 14 specialist queue names:

```python
SPECIALIST_QUEUES = [
    "xss", "sqli", "csti", "lfi", "idor", "rce",
    "ssrf", "xxe", "jwt", "openredirect", "prototype_pollution",
    "file_upload", "chain_discovery", "api_security"
]
```

### Class Diagram

```
+----------------+
|  QueueManager  |  (singleton: queue_manager)
+----------------+
        |
        | get_queue(specialist)
        v
+------------------+       +------------+
| SpecialistQueue  | ----> | QueueStats |
+------------------+       +------------+
        |                       |
        | enqueue/dequeue       | record_enqueue/dequeue
        v                       v
+------------+             Throughput, Latency,
| QueueItem  |             P95, Counters
+------------+
```

### Queue Manager Flow

```
queue_manager.get_queue("xss")
       |
       v
   +-------------------+
   | xss in _queues?   |
   +-------------------+
       |           |
      YES          NO
       |           |
       v           v
   Return      Create new
   existing    SpecialistQueue("xss")
   queue       Add to _queues
               Return new queue
```

---

## Backpressure Handling

### What is Backpressure?

Backpressure occurs when producers (ThinkingConsolidationAgent) generate work faster than consumers (specialist WorkerPools) can process it. Without handling, this leads to:

- Unbounded memory growth
- Out-of-memory crashes
- Lost work on failure

### SpecialistQueue Backpressure

Each queue has a `max_depth` that limits the number of buffered items:

```python
# Configuration
max_depth = settings.QUEUE_DEFAULT_MAX_DEPTH  # Default: 1000

# Check before enqueue
if queue.is_full():
    # Queue at capacity, reject item
    queue._stats.record_rejected()
    return False
```

### Backpressure Flow

```
enqueue(item, scan_context)
       |
       v
   +-----------+
   | is_full() |  --> depth >= max_depth?
   +-----------+
       |     \
      NO      YES
       |       \
       v        v
   rate_limit   record_rejected()
   _wait()      log warning
       |        return False
       v
   put(item)
   record_enqueue()
   return True
```

### Rejection Tracking

The `QueueStats` class tracks rejections:

```python
def record_rejected(self) -> None:
    """Record a rejected enqueue (backpressure)."""
    self.total_rejected += 1
```

**Monitoring:**
```python
stats = queue.get_stats()
if stats["total_rejected"] > 0:
    logger.warning(
        f"Queue {stats['name']} has {stats['total_rejected']} rejected items"
    )
```

### ThinkingAgent Retry Behavior

When a queue rejects an item, ThinkingConsolidationAgent implements retry with exponential backoff:

```python
# Retry configuration
MAX_RETRIES = 3
INITIAL_DELAY = 0.5  # seconds

async def distribute_to_queue(item, specialist):
    for attempt in range(MAX_RETRIES):
        success = await queue.enqueue(item, scan_context)
        if success:
            return True

        # Exponential backoff
        delay = INITIAL_DELAY * (2 ** attempt)
        await asyncio.sleep(delay)

    # All retries failed, record drop
    record_backpressure_drop(specialist)
    return False
```

**Backoff Timing:**
| Attempt | Delay |
|---------|-------|
| 1 | 0.5s |
| 2 | 1.0s |
| 3 | 2.0s |
| Total | 3.5s max |

---

## Rate Limiting

### Token Bucket Algorithm

Each SpecialistQueue uses a **token bucket** algorithm to limit enqueue rate:

```
Token Bucket Concept:
+--------------------+
|   Tokens: 10/10    |  <- Bucket capacity = rate_limit
|   ############     |
|   ############     |
+--------------------+

- Bucket starts full
- Each enqueue consumes 1 token
- Tokens replenish at rate_limit/second
- If no tokens, wait until replenished
```

### Implementation

```python
class SpecialistQueue:
    def __init__(self, name, max_depth=None, rate_limit=None):
        # Token bucket state
        self._tokens = self.rate_limit  # Starts full
        self._last_replenish = time.monotonic()

    async def _wait_for_token(self) -> None:
        """Wait for rate limit token (token bucket algorithm)."""
        async with self._lock:
            # Replenish tokens based on elapsed time
            now = time.monotonic()
            elapsed = now - self._last_replenish
            self._tokens = min(
                self.rate_limit,
                self._tokens + (elapsed * self.rate_limit)
            )
            self._last_replenish = now

            # Wait until we have at least 1 token
            while self._tokens < 1.0:
                await asyncio.sleep(0.01)  # Avoid busy wait
                now = time.monotonic()
                elapsed = now - self._last_replenish
                self._tokens = min(
                    self.rate_limit,
                    self._tokens + (elapsed * self.rate_limit)
                )
                self._last_replenish = now

            # Consume 1 token
            self._tokens -= 1.0
```

### Token Replenishment Formula

```python
tokens = min(rate_limit, tokens + elapsed * rate_limit)
```

**Example (rate_limit = 10/s):**
- `elapsed = 0.5s` -> replenish 5 tokens
- `elapsed = 0.1s` -> replenish 1 token
- Never exceed `rate_limit` (bucket capacity)

### Timing Example

```
rate_limit = 10/s
Token bucket starts full (10 tokens)

Time   Action              Tokens
0.00   Enqueue item 1      10 -> 9
0.00   Enqueue item 2       9 -> 8
0.00   Enqueue item 3       8 -> 7
...
0.00   Enqueue item 10      1 -> 0  (immediate burst)
0.10   Enqueue item 11      1 -> 0  (waited 100ms for replenish)
0.20   Enqueue item 12      1 -> 0  (waited 100ms)
...
Sustained rate: 1 item per 100ms = 10/s
```

**Key Insight:** Token bucket allows **bursts** up to bucket capacity, then enforces sustained rate.

### Rate Limit Configuration

```python
# Default: 100 items/second per queue
QUEUE_DEFAULT_RATE_LIMIT = 100

# Per-specialist override (if needed)
xss_queue = SpecialistQueue(
    "xss",
    rate_limit=50  # Lower rate for XSS testing
)
```

---

## Statistics Tracking

### QueueStats Class

Each queue maintains a `QueueStats` instance for monitoring:

```python
@dataclass
class QueueStats:
    # Counters
    total_enqueued: int = 0
    total_dequeued: int = 0
    total_rejected: int = 0  # Backpressure rejections

    # Timing windows for throughput
    _enqueue_times: List[float] = field(default_factory=list)
    _dequeue_times: List[float] = field(default_factory=list)
    _latencies: List[float] = field(default_factory=list)

    # Configuration
    _window_seconds: float = 60.0   # 60-second rolling window
    _max_samples: int = 1000        # Prevent unbounded memory growth
```

### Throughput Metrics

Throughput is calculated over a **60-second rolling window**:

```python
@property
def enqueue_throughput(self) -> float:
    """Items enqueued per second (rolling window)."""
    if not self._enqueue_times:
        return 0.0
    window = time.monotonic() - self._enqueue_times[0]
    if window <= 0:
        return 0.0
    return len(self._enqueue_times) / window

@property
def dequeue_throughput(self) -> float:
    """Items dequeued per second (rolling window)."""
    # Same calculation for dequeue
```

### Latency Metrics

Latency measures time from enqueue to dequeue:

```python
# On dequeue
def record_dequeue(self, enqueued_at: float) -> None:
    now = time.monotonic()
    latency = now - enqueued_at
    self._latencies.append(latency)
```

**Latency Properties:**

| Property | Description |
|----------|-------------|
| `avg_latency` | Mean latency across samples |
| `p95_latency` | 95th percentile (key performance indicator) |
| `max_latency` | Maximum observed latency |

```python
@property
def p95_latency(self) -> float:
    """95th percentile latency in seconds."""
    if not self._latencies:
        return 0.0
    sorted_latencies = sorted(self._latencies)
    idx = int(len(sorted_latencies) * 0.95)
    return sorted_latencies[min(idx, len(sorted_latencies) - 1)]
```

### Sample Pruning

Old samples are pruned to prevent unbounded memory growth:

```python
def _prune_old_samples(self) -> None:
    """Remove samples older than window."""
    now = time.monotonic()
    cutoff = now - self._window_seconds

    # Prune old timestamps (keep only last 60s)
    self._enqueue_times = [
        t for t in self._enqueue_times if t > cutoff
    ][-self._max_samples:]

    self._dequeue_times = [
        t for t in self._dequeue_times if t > cutoff
    ][-self._max_samples:]

    # Latencies use sample limit only (no time window)
    self._latencies = self._latencies[-self._max_samples:]
```

### Exported Statistics

The `to_dict()` method exports all metrics:

```python
def to_dict(self) -> Dict[str, Any]:
    return {
        "total_enqueued": self.total_enqueued,
        "total_dequeued": self.total_dequeued,
        "total_rejected": self.total_rejected,
        "enqueue_throughput": round(self.enqueue_throughput, 2),
        "dequeue_throughput": round(self.dequeue_throughput, 2),
        "avg_latency_ms": round(self.avg_latency * 1000, 2),
        "p95_latency_ms": round(self.p95_latency * 1000, 2),
        "max_latency_ms": round(self.max_latency * 1000, 2),
    }
```

### API Exposure

Statistics are exposed via REST API at `/api/metrics/queues`:

```json
{
  "xss": {
    "name": "xss",
    "current_depth": 42,
    "max_depth": 1000,
    "rate_limit": 100,
    "is_full": false,
    "total_enqueued": 1500,
    "total_dequeued": 1458,
    "total_rejected": 0,
    "enqueue_throughput": 25.5,
    "dequeue_throughput": 24.3,
    "avg_latency_ms": 150.2,
    "p95_latency_ms": 320.5,
    "max_latency_ms": 850.0
  }
}
```

---

## Specialist Integration

### WorkerPool Pattern

Specialist agents consume from queues via the `WorkerPool` class:

```python
from bugtrace.agents.worker_pool import WorkerPool, WorkerConfig

# Configure pool for XSS specialist
config = WorkerConfig(
    specialist="xss",
    pool_size=8,                           # 8 concurrent workers
    process_func=xss_agent.process_queue_item,
    shutdown_timeout=30,                   # 30s graceful shutdown
    dequeue_timeout=5                      # 5s dequeue timeout
)

# Create and start pool
pool = WorkerPool(config)
await pool.start()
```

### Worker Loop

Each worker runs a continuous loop:

```
while running:
    |
    v
+-----------------+
| dequeue(5s)     |  --> Wait up to 5s for item
+-----------------+
    |         |
   item      None
    |         |
    v         v
process(item)  continue (check running flag)
    |
    v
emit vulnerability_detected event
    |
    v
loop back
```

### Dequeue Timeout Purpose

The 5-second dequeue timeout serves critical functions:

1. **Running Check**: Allows worker to check `_running` flag for shutdown
2. **Pause Point**: Natural point to check pause state between work units
3. **Responsiveness**: Workers respond to shutdown within 5s

```python
async def _worker_loop(self) -> None:
    while self._running:
        # Try to get item (blocks up to 5s)
        item = await self._queue.dequeue(timeout=self._dequeue_timeout)

        if item is None:
            # Timeout - check _running and retry
            continue

        # Process item and emit events
        ...
```

### Event Emission on Findings

When a specialist confirms a vulnerability, it emits a `vulnerability_detected` event:

```python
# Event payload structure
{
    "scan_context": "scan_abc123",
    "specialist": "xss",
    "finding": {
        "url": "https://example.com/search",
        "parameter": "q",
        "payload": "<script>alert(1)</script>",
        "evidence": "Script reflected in response"
    },
    "status": "validated_confirmed",  # ValidationStatus
    "validation_requires_cdp": False
}
```

### Worker Pool Sizing

Default worker counts per specialist:

| Specialist | Workers | Rationale |
|------------|---------|-----------|
| XSS | 8 | High volume, fast HTTP checks |
| SQLi | 5 | Medium volume, varied techniques |
| CSTI | 5 | Default |
| LFI | 5 | Default |
| IDOR | 5 | Default |
| RCE | 5 | Default |
| SSRF | 5 | Default |
| XXE | 5 | Default |
| JWT | 5 | Default |
| OpenRedirect | 5 | Default |
| PrototypePollution | 5 | Default |

Configuration:
```python
WORKER_POOL_DEFAULT_SIZE = 5
WORKER_POOL_XSS_SIZE = 8
WORKER_POOL_SQLI_SIZE = 5
```

### Dynamic Scaling

WorkerPool supports runtime scaling:

```python
# Scale up
await pool.scale(12)  # Add workers

# Scale down
await pool.scale(4)   # Remove workers gracefully
```

### Example: XSSAgent Integration

```python
class XSSAgent:
    async def start_queue_consumer(self):
        config = WorkerConfig(
            specialist="xss",
            pool_size=settings.WORKER_POOL_XSS_SIZE,
            process_func=self._process_queue_item,
            on_result=self._handle_result
        )
        self._pool = WorkerPool(config)
        await self._pool.start()

    async def _process_queue_item(self, item: dict) -> dict:
        url = item["url"]
        parameter = item["parameter"]

        # Test payloads
        result = await self._test_xss(url, parameter)

        if result.confirmed:
            # Emit event
            await event_bus.emit(
                EventType.VULNERABILITY_DETECTED,
                {
                    "specialist": "xss",
                    "finding": result.to_dict(),
                    "status": ValidationStatus.VALIDATED_CONFIRMED,
                    ...
                }
            )

        return result
```

---

## Configuration

### Queue Settings

All queue configuration via `bugtrace.core.config.settings`:

```python
# Maximum queue depth before backpressure (default: 1000)
QUEUE_DEFAULT_MAX_DEPTH = 1000

# Rate limit: items per second (default: 100)
QUEUE_DEFAULT_RATE_LIMIT = 100
```

### Worker Pool Settings

```python
# Default workers per specialist
WORKER_POOL_DEFAULT_SIZE = 5

# XSS specialist (higher volume)
WORKER_POOL_XSS_SIZE = 8

# SQLi specialist
WORKER_POOL_SQLI_SIZE = 5

# Shutdown timeout for worker pools (default: 30s)
WORKER_POOL_SHUTDOWN_TIMEOUT = 30

# Dequeue timeout - allows periodic running checks (default: 5s)
WORKER_POOL_DEQUEUE_TIMEOUT = 5
```

### Statistics Settings

```python
# Rolling window for throughput (default: 60s)
QUEUE_STATS_WINDOW_SECONDS = 60.0

# Maximum samples per metric (default: 1000)
QUEUE_STATS_MAX_SAMPLES = 1000
```

---

## Examples

### Basic Queue Operations

```python
from bugtrace.core.queue import queue_manager

# Get queue for XSS specialist
xss_queue = queue_manager.get_queue("xss")

# Enqueue a work item
success = await xss_queue.enqueue(
    item={
        "url": "https://example.com/search",
        "parameter": "q",
        "vuln_type": "xss",
        "priority": 0.85
    },
    scan_context="scan_123"
)

if not success:
    print("Queue full, item rejected (backpressure)")

# Dequeue with timeout
item = await xss_queue.dequeue(timeout=5.0)
if item is None:
    print("Timeout, no items available")
else:
    print(f"Processing: {item['url']}")
```

### Monitoring Queue Health

```python
from bugtrace.core.queue import queue_manager

# Get all queue statistics
all_stats = queue_manager.get_all_stats()

for name, stats in all_stats.items():
    print(f"\n{name} Queue:")
    print(f"  Depth: {stats['current_depth']}/{stats['max_depth']}")
    print(f"  Enqueue rate: {stats['enqueue_throughput']:.1f}/s")
    print(f"  Dequeue rate: {stats['dequeue_throughput']:.1f}/s")
    print(f"  P95 latency: {stats['p95_latency_ms']:.0f}ms")
    print(f"  Rejections: {stats['total_rejected']}")

# Get aggregate statistics
aggregate = queue_manager.get_aggregate_stats()
print(f"\nTotal queued: {aggregate['total_depth']}")
print(f"Total rejected: {aggregate['total_rejected']}")
print(f"Queues with backpressure: {aggregate['queues_with_backpressure']}")
```

### Starting a Worker Pool

```python
from bugtrace.agents.worker_pool import WorkerPool, WorkerConfig
from bugtrace.core.queue import queue_manager

async def process_finding(item: dict) -> dict:
    """Process a single finding from the queue."""
    # Test the vulnerability
    result = await test_vulnerability(item)
    return result

async def on_result(item: dict, result: dict):
    """Handle processing result."""
    if result.get("confirmed"):
        await emit_vulnerability_event(item, result)

# Configure pool
config = WorkerConfig(
    specialist="sqli",
    pool_size=5,
    process_func=process_finding,
    on_result=on_result,
    shutdown_timeout=30,
    dequeue_timeout=5
)

# Create and start
pool = WorkerPool(config)
await pool.start()

# ... processing happens ...

# Graceful shutdown
await pool.drain()  # Wait for queue to empty
await pool.stop()   # Stop workers
```

### Handling Backpressure

```python
from bugtrace.core.queue import queue_manager
import asyncio

MAX_RETRIES = 3
INITIAL_DELAY = 0.5

async def enqueue_with_retry(queue, item, scan_context):
    """Enqueue with exponential backoff retry."""
    for attempt in range(MAX_RETRIES):
        success = await queue.enqueue(item, scan_context)
        if success:
            return True

        # Log backpressure
        stats = queue.get_stats()
        logger.warning(
            f"Backpressure on {queue.name}: "
            f"depth={stats['current_depth']}, "
            f"attempt={attempt + 1}/{MAX_RETRIES}"
        )

        # Exponential backoff
        delay = INITIAL_DELAY * (2 ** attempt)
        await asyncio.sleep(delay)

    # All retries failed
    logger.error(f"Dropped item after {MAX_RETRIES} retries")
    return False
```

---

## Related Documentation

- [Pipeline Architecture](./PIPELINE_ARCHITECTURE.md) - 5-phase execution model
- [Agent Architecture](./AGENT_ARCHITECTURE.md) - Specialist agent documentation
- [Event Bus](../../bugtrace/core/event_bus.py) - Event system implementation
- [Queue Implementation](../../bugtrace/core/queue.py) - Source code
- [Worker Pool](../../bugtrace/agents/worker_pool.py) - WorkerPool source code

---

*Last updated: 2026-01-29*
