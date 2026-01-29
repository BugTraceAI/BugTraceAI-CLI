# ThinkingConsolidationAgent: Evaluation Phase Algorithms

> **Module:** `bugtrace.agents.thinking_consolidation_agent`
> **Version:** 1.0.0
> **Updated:** 2026-01-29

## Table of Contents

1. [Overview](#overview)
2. [Deduplication Algorithm](#deduplication-algorithm)
3. [Classification Algorithm](#classification-algorithm)
4. [Prioritization Algorithm](#prioritization-algorithm)
5. [Processing Modes](#processing-modes)
6. [Configuration](#configuration)
7. [Statistics & Monitoring](#statistics--monitoring)

---

## Overview

### What is ThinkingConsolidationAgent?

The `ThinkingConsolidationAgent` is the **Evaluation phase coordinator** in the BugTraceAI 5-phase pipeline. It sits between Discovery (SASTDASTAgent) and Exploitation (specialist agents), serving as the central intelligence layer that filters, classifies, and prioritizes findings before they reach specialist queues.

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
                          work_queued_*                       |
                            events                            |
```

### Position in Pipeline

| Phase | Agent | Input | Output |
|-------|-------|-------|--------|
| 1. Discovery | SASTDASTAgent | URLs | `url_analyzed` events |
| **2. Evaluation** | **ThinkingConsolidationAgent** | **`url_analyzed` events** | **`work_queued_*` events** |
| 3. Exploitation | 11 Specialist Agents | `work_queued_*` events | `vulnerability_detected` events |

### Events

**Subscribed Events:**
```python
EventType.URL_ANALYZED = "url_analyzed"
```

**Emitted Events (11 specialist types):**
```python
EventType.WORK_QUEUED_XSS = "work_queued_xss"
EventType.WORK_QUEUED_SQLI = "work_queued_sqli"
EventType.WORK_QUEUED_CSTI = "work_queued_csti"
EventType.WORK_QUEUED_LFI = "work_queued_lfi"
EventType.WORK_QUEUED_IDOR = "work_queued_idor"
EventType.WORK_QUEUED_RCE = "work_queued_rce"
EventType.WORK_QUEUED_SSRF = "work_queued_ssrf"
EventType.WORK_QUEUED_XXE = "work_queued_xxe"
EventType.WORK_QUEUED_JWT = "work_queued_jwt"
EventType.WORK_QUEUED_OPENREDIRECT = "work_queued_openredirect"
EventType.WORK_QUEUED_PROTOTYPE_POLLUTION = "work_queued_prototype_pollution"
```

### Key Benefits

1. **Noise Reduction (40-60%):** Deduplication eliminates redundant findings
2. **Efficient Routing:** Classification ensures findings go to the right specialist
3. **Smart Ordering:** Prioritization ensures high-value findings are tested first
4. **Backpressure Handling:** Graceful degradation when specialist queues are full

---

## Deduplication Algorithm

### Overview

The `DeduplicationCache` class implements an **LRU (Least Recently Used) cache** for filtering duplicate findings. The same vulnerability discovered through different payloads or detection methods should only be tested once by specialists.

### Key Format

Findings are deduplicated using a composite key with three components:

```
{vuln_type}:{parameter}:{url_path}
```

**Key Components:**

| Component | Source | Normalization |
|-----------|--------|---------------|
| `vuln_type` | `finding["type"]` | Lowercase |
| `parameter` | `finding["parameter"]` | Lowercase |
| `url_path` | `finding["url"]` | Path only, no query params |

### Key Generation Example

```python
# Input finding
finding = {
    "type": "XSS",
    "parameter": "id",
    "url": "https://example.com/api/users?id=1&name=test"
}

# Key generation process:
# 1. vuln_type = "xss" (lowercase)
# 2. parameter = "id" (lowercase)
# 3. url_path = "/api/users" (path only, query removed)

# Output key
key = "xss:id:/api/users"
```

### URL Path Normalization

The `_make_key()` method extracts and normalizes the URL path:

```python
def _make_key(self, finding: Dict[str, Any]) -> str:
    url = finding.get("url", "")

    # Extract path from full URL
    url_path = url
    if "://" in url:
        parts = url.split("/", 3)
        url_path = "/" + parts[3] if len(parts) > 3 else "/"

    # Remove query parameters for dedup
    if "?" in url_path:
        url_path = url_path.split("?")[0]

    return f"{vuln_type}:{parameter}:{url_path}"
```

**Why normalize this way?**
- Same endpoint with different query values = same vulnerability
- Same parameter name on same path = test once, not repeatedly
- Lowercase ensures "XSS" and "xss" are deduplicated together

### LRU Eviction

The cache implements LRU eviction when `max_size` is reached:

```python
class DeduplicationCache:
    def __init__(self, max_size: int = 1000):
        self.max_size = max_size
        self._cache: OrderedDict[str, FindingRecord] = OrderedDict()
        self._lock = asyncio.Lock()
```

**Eviction Behavior:**

1. **On duplicate hit:** Entry is moved to end (most recently used)
2. **On new entry:** If cache exceeds `max_size`, oldest entries are evicted
3. **Thread safety:** `asyncio.Lock()` ensures concurrent access is safe

```python
async def check_and_add(self, finding, scan_context) -> tuple[bool, str]:
    key = self._make_key(finding)

    async with self._lock:
        if key in self._cache:
            # Move to end (most recently seen)
            self._cache.move_to_end(key)
            return (True, key)  # Is duplicate

        # Add new entry
        self._cache[key] = FindingRecord(...)

        # Evict oldest if over limit
        while len(self._cache) > self.max_size:
            oldest_key = next(iter(self._cache))
            del self._cache[oldest_key]

        return (False, key)  # Not duplicate
```

### Memory Efficiency

With `max_size=1000` (default), the cache holds at most 1000 unique keys. Each `FindingRecord` contains:

| Field | Approximate Size |
|-------|------------------|
| key (string) | ~50 bytes |
| finding (dict copy) | ~500 bytes |
| received_at (float) | 8 bytes |
| scan_context (string) | ~20 bytes |
| processed (bool) | 1 byte |

**Estimated max memory:** ~600KB for 1000 entries

### Cache Statistics

```python
cache.get_stats()
# Returns:
{
    "size": 234,           # Current entries
    "max_size": 1000,      # Maximum capacity
    "fill_ratio": 0.234    # Utilization percentage
}
```

---

## Classification Algorithm

### Overview

The classification algorithm maps vulnerability types from Discovery findings to the appropriate specialist queue. It uses the `VULN_TYPE_TO_SPECIALIST` dictionary for exact matches with partial matching fallback.

### VULN_TYPE_TO_SPECIALIST Mapping

The complete mapping of 55 vulnerability type variants to 11 specialist queues:

#### XSS Specialist (8 variants)
| Vulnerability Type | Specialist |
|-------------------|------------|
| `xss` | xss |
| `cross-site scripting` | xss |
| `reflected xss` | xss |
| `stored xss` | xss |
| `dom xss` | xss |
| `dom-based xss` | xss |
| `header injection` | xss |
| `crlf injection` | xss |
| `http response splitting` | xss |

#### SQLi Specialist (7 variants)
| Vulnerability Type | Specialist |
|-------------------|------------|
| `sql injection` | sqli |
| `sqli` | sqli |
| `sql` | sqli |
| `blind sql injection` | sqli |
| `boolean-based sqli` | sqli |
| `time-based sqli` | sqli |
| `error-based sqli` | sqli |

#### CSTI Specialist (5 variants)
| Vulnerability Type | Specialist |
|-------------------|------------|
| `ssti` | csti |
| `csti` | csti |
| `server-side template injection` | csti |
| `client-side template injection` | csti |
| `template injection` | csti |

#### LFI Specialist (5 variants)
| Vulnerability Type | Specialist |
|-------------------|------------|
| `lfi` | lfi |
| `local file inclusion` | lfi |
| `path traversal` | lfi |
| `directory traversal` | lfi |
| `file read` | lfi |

#### IDOR Specialist (5 variants)
| Vulnerability Type | Specialist |
|-------------------|------------|
| `idor` | idor |
| `insecure direct object reference` | idor |
| `broken access control` | idor |
| `authorization bypass` | idor |
| `privilege escalation` | idor |

#### RCE Specialist (6 variants)
| Vulnerability Type | Specialist |
|-------------------|------------|
| `rce` | rce |
| `remote code execution` | rce |
| `command injection` | rce |
| `os command injection` | rce |
| `code injection` | rce |
| `deserialization` | rce |

#### SSRF Specialist (3 variants)
| Vulnerability Type | Specialist |
|-------------------|------------|
| `ssrf` | ssrf |
| `server-side request forgery` | ssrf |
| `url injection` | ssrf |

#### XXE Specialist (3 variants)
| Vulnerability Type | Specialist |
|-------------------|------------|
| `xxe` | xxe |
| `xml external entity` | xxe |
| `xml injection` | xxe |

#### JWT Specialist (5 variants)
| Vulnerability Type | Specialist |
|-------------------|------------|
| `jwt` | jwt |
| `jwt vulnerability` | jwt |
| `jwt bypass` | jwt |
| `jwt manipulation` | jwt |
| `authentication bypass` | jwt |

#### OpenRedirect Specialist (4 variants)
| Vulnerability Type | Specialist |
|-------------------|------------|
| `open redirect` | openredirect |
| `openredirect` | openredirect |
| `url redirect` | openredirect |
| `redirect` | openredirect |

#### PrototypePollution Specialist (3 variants)
| Vulnerability Type | Specialist |
|-------------------|------------|
| `prototype pollution` | prototype_pollution |
| `prototype_pollution` | prototype_pollution |
| `__proto__ pollution` | prototype_pollution |

### Classification Logic

The `_classify_finding()` method implements two-phase matching:

```python
def _classify_finding(self, finding: Dict[str, Any]) -> Optional[str]:
    vuln_type = finding.get("type", "").lower().strip()

    # Phase 1: Direct match (O(1) lookup)
    if vuln_type in VULN_TYPE_TO_SPECIALIST:
        return VULN_TYPE_TO_SPECIALIST[vuln_type]

    # Phase 2: Partial match (for compound types)
    for pattern, specialist in VULN_TYPE_TO_SPECIALIST.items():
        if pattern in vuln_type:
            return specialist

    # Unknown type
    logger.warning(f"Unknown vulnerability type: {vuln_type}")
    return None
```

**Partial Match Examples:**

| Finding Type | Pattern Match | Specialist |
|--------------|---------------|------------|
| `reflected xss in search` | `reflected xss` | xss |
| `possible blind sql injection` | `blind sql injection` | sqli |
| `stored xss via file upload` | `stored xss` | xss |

### Unknown Type Handling

When a vulnerability type cannot be classified:
1. A warning is logged
2. `None` is returned
3. The finding is counted in `stats["unclassified"]`
4. The finding is **not** distributed to any specialist queue

---

## Prioritization Algorithm

### Overview

The `_calculate_priority()` method computes a **priority score (0-100)** that determines the order in which findings should be tested by specialists. Higher scores indicate findings more likely to be exploitable.

### Priority Formula

```python
priority = (
    severity_base * 0.40 +         # 40% weight
    fp_confidence * 100 * 0.35 +   # 35% weight
    skeptical_score * 10 * 0.25    # 25% weight
)
```

### Component Weights

| Component | Weight | Input Range | Normalized Range | Source |
|-----------|--------|-------------|------------------|--------|
| Severity | 40% | Critical/High/Medium/Low | 0-100 | `finding["severity"]` |
| FP Confidence | 35% | 0.0-1.0 | 0-100 | `finding["fp_confidence"]` |
| Skeptical Score | 25% | 0-10 | 0-100 | `finding["skeptical_score"]` |

### Severity Base Scores

```python
SEVERITY_PRIORITY: Dict[str, int] = {
    "critical": 100,
    "high": 75,
    "medium": 50,
    "low": 25,
    "info": 10,
    "information": 10,
}
```

### Priority Boosts

After the base calculation, two multiplicative boosts are applied:

| Condition | Boost | Rationale |
|-----------|-------|-----------|
| `finding["validated"] == True` | +20% | Already confirmed by HTTP-first |
| `finding["votes"] >= 4` | +10% | Multiple detection approaches agreed |

```python
# Boost for validated findings
if finding.get("validated", False):
    priority = min(100, priority * 1.2)

# Boost for high vote count
votes = finding.get("votes", 1)
if votes >= 4:
    priority = min(100, priority * 1.1)
```

### Calculation Examples

**Example 1: Critical SQLi with high confidence**
```python
finding = {
    "severity": "critical",
    "fp_confidence": 0.9,
    "skeptical_score": 8,
    "validated": False,
    "votes": 3
}

# Base calculation:
# severity_base = 100 (critical)
# priority = (100 * 0.40) + (0.9 * 100 * 0.35) + (8 * 10 * 0.25)
# priority = 40 + 31.5 + 20 = 91.5

# No boosts applied (not validated, votes < 4)
# Final priority: 91.5
```

**Example 2: Medium XSS with validation**
```python
finding = {
    "severity": "medium",
    "fp_confidence": 0.7,
    "skeptical_score": 6,
    "validated": True,
    "votes": 5
}

# Base calculation:
# severity_base = 50 (medium)
# priority = (50 * 0.40) + (0.7 * 100 * 0.35) + (6 * 10 * 0.25)
# priority = 20 + 24.5 + 15 = 59.5

# Validated boost: 59.5 * 1.2 = 71.4
# Votes boost: 71.4 * 1.1 = 78.54
# Final priority: min(100, 78.54) = 78.54
```

**Example 3: Low severity, low confidence**
```python
finding = {
    "severity": "low",
    "fp_confidence": 0.3,
    "skeptical_score": 3,
    "validated": False,
    "votes": 1
}

# Base calculation:
# severity_base = 25 (low)
# priority = (25 * 0.40) + (0.3 * 100 * 0.35) + (3 * 10 * 0.25)
# priority = 10 + 10.5 + 7.5 = 28.0

# No boosts applied
# Final priority: 28.0
```

### Priority Distribution

In batch mode, findings are sorted by priority (highest first) before distribution to specialist queues. This ensures high-value findings are tested first while low-priority findings wait.

---

## Processing Modes

### Overview

ThinkingConsolidationAgent supports two processing modes that can be switched at runtime:

| Mode | Behavior | Use Case |
|------|----------|----------|
| **Streaming** (default) | Process each finding immediately on event receipt | Real-time scanning, low latency |
| **Batch** | Buffer findings, process when buffer full or timeout | High-volume scanning, better throughput |

### Streaming Mode

In streaming mode, each `url_analyzed` event triggers immediate processing:

```python
async def _handle_url_analyzed(self, data: Dict[str, Any]):
    findings = data.get("findings", [])

    if self._mode == "streaming":
        # Process each finding immediately
        for finding in findings:
            await self._process_finding(finding, scan_context)
```

**Characteristics:**
- Lowest latency from discovery to specialist
- Higher CPU overhead (context switches per finding)
- Better for interactive/real-time scanning

### Batch Mode

In batch mode, findings are buffered until the batch is full or timeout expires:

```python
async def _handle_url_analyzed(self, data: Dict[str, Any]):
    findings = data.get("findings", [])

    if self._mode == "batch":
        async with self._batch_lock:
            for finding in findings:
                finding_with_context = finding.copy()
                finding_with_context["_scan_context"] = scan_context
                self._batch_buffer.append(finding_with_context)

            # Process if buffer full
            if len(self._batch_buffer) >= settings.THINKING_BATCH_SIZE:
                await self._process_batch()
```

**Batch Processing Order:**
```python
# Sort by priority (highest first) before distribution
prioritized_batch.sort(key=lambda p: p.priority, reverse=True)
```

**Characteristics:**
- Higher throughput (amortized overhead)
- Batch size: `THINKING_BATCH_SIZE` (default 50)
- Timeout: `THINKING_BATCH_TIMEOUT` (default 5.0 seconds)
- Priority ordering within batch

### Batch Processor Background Task

A background task ensures partial batches are processed on timeout:

```python
async def _batch_processor(self):
    while self.running:
        await asyncio.sleep(settings.THINKING_BATCH_TIMEOUT)

        async with self._batch_lock:
            if self._batch_buffer:
                await self._process_batch()
```

### Runtime Mode Switching

```python
# Switch to batch mode
agent.set_mode("batch")

# Switch back to streaming
agent.set_mode("streaming")  # Auto-flushes any buffered findings
```

**Important:** Switching from batch to streaming automatically flushes the buffer:

```python
def set_mode(self, mode: str) -> None:
    old_mode = self._mode
    self._mode = mode

    # If switching from batch to streaming, flush buffer
    if old_mode == "batch" and mode == "streaming" and self._batch_buffer:
        asyncio.create_task(self.flush_batch())
```

### Manual Flush

```python
# Flush buffer (useful before shutdown)
count = await agent.flush_batch()
print(f"Flushed {count} findings")
```

---

## Configuration

### Settings Overview

All configuration is via `bugtrace.core.config.settings`:

```python
# Processing mode
THINKING_MODE: str = "streaming"  # "streaming" | "batch"

# Batch mode settings
THINKING_BATCH_SIZE: int = 50     # Max findings per batch
THINKING_BATCH_TIMEOUT: float = 5.0  # Seconds before processing incomplete batch

# Deduplication settings
THINKING_DEDUP_WINDOW: int = 1000  # Max dedup keys (LRU eviction)

# False positive filtering
THINKING_FP_THRESHOLD: float = 0.5  # Min fp_confidence to forward

# Backpressure handling
THINKING_BACKPRESSURE_RETRIES: int = 3  # Max retries on queue full
THINKING_BACKPRESSURE_DELAY: float = 0.5  # Seconds between retries

# Event emission
THINKING_EMIT_EVENTS: bool = True  # Emit work_queued_* events
```

### Configuration Details

| Setting | Default | Description |
|---------|---------|-------------|
| `THINKING_MODE` | `"streaming"` | Processing mode: `"streaming"` or `"batch"` |
| `THINKING_BATCH_SIZE` | `50` | Maximum findings to buffer before processing |
| `THINKING_BATCH_TIMEOUT` | `5.0` | Seconds to wait before processing partial batch |
| `THINKING_DEDUP_WINDOW` | `1000` | Maximum unique keys in dedup cache |
| `THINKING_FP_THRESHOLD` | `0.5` | Minimum `fp_confidence` to pass to specialists |
| `THINKING_BACKPRESSURE_RETRIES` | `3` | Retries when specialist queue is full |
| `THINKING_BACKPRESSURE_DELAY` | `0.5` | Initial delay between retries (exponential backoff) |
| `THINKING_EMIT_EVENTS` | `True` | Whether to emit `work_queued_*` events |

### Backpressure Handling

When a specialist queue is full, the agent implements exponential backoff:

```python
for attempt in range(THINKING_BACKPRESSURE_RETRIES):
    success = await queue.enqueue(payload, scan_context)
    if success:
        return True

    # Exponential backoff: 0.5s, 1.0s, 2.0s
    delay = THINKING_BACKPRESSURE_DELAY * (2 ** attempt)
    await asyncio.sleep(delay)

# All retries failed - finding is dropped
stats["backpressure_drops"] += 1
```

**Retry Schedule (default):**

| Attempt | Delay |
|---------|-------|
| 1 | 0.5s |
| 2 | 1.0s |
| 3 | 2.0s |
| Total | 3.5s max wait |

---

## Statistics & Monitoring

### Get Statistics

```python
stats = agent.get_stats()
```

**Statistics Structure:**

```python
{
    # Processing counts
    "total_received": 1500,      # Total findings received
    "duplicates_filtered": 450,  # Filtered by dedup
    "fp_filtered": 200,          # Filtered by FP threshold
    "distributed": 850,          # Successfully queued
    "unclassified": 0,           # Unknown vuln types
    "backpressure_drops": 0,     # Dropped due to full queues

    # Per-specialist breakdown
    "by_specialist": {
        "xss": 250,
        "sqli": 150,
        "idor": 100,
        ...
    },

    # Cache status
    "dedup_cache": {
        "size": 234,
        "max_size": 1000,
        "fill_ratio": 0.234
    },

    # Current mode
    "mode": "streaming",
    "batch_buffer_size": 0,

    # Dedup metrics (from dedup_metrics singleton)
    "dedup_metrics": {
        "received": 1500,
        "deduplicated": 450,
        "distributed": 850,
        "effectiveness": 30.0  # percentage
    }
}
```

### Key Performance Indicators

| Metric | Formula | Target |
|--------|---------|--------|
| Dedup Effectiveness | `(duplicates_filtered / total_received) * 100` | 40-60% |
| Distribution Rate | `distributed / (total_received - duplicates_filtered - fp_filtered)` | >95% |
| Backpressure Drops | `backpressure_drops` | 0 (ideal) |

### Reset Statistics

```python
# Reset for new scan
agent.reset_stats()
```

---

## Related Documentation

- [Pipeline Architecture](./PIPELINE_ARCHITECTURE.md) - 5-phase execution model
- [Agent Architecture](./AGENT_ARCHITECTURE.md) - All agent documentation
- [Testing Guide](./TESTING_GUIDE.md) - How to test ThinkingAgent
- [Source Implementation](../../bugtrace/agents/thinking_consolidation_agent.py) - Source code

---

*Last updated: 2026-01-29*
