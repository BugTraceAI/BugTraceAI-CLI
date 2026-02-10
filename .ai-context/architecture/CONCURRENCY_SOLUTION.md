# ManipulatorOrchestrator - Concurrency Solution

## Problem: XSS + CSTI Running in Parallel

When `XSSSkill` and `CSTISkill` run simultaneously (both using `ManipulatorOrchestrator`), potential issues:

### 1. BreakoutManager Race Condition ✅ SOLVED
**Problem:** Both skills write to `learned_breakouts.json` simultaneously → file corruption

**Solution:** Already implemented in [breakout_manager.py:56](../../bugtrace/tools/manipulator/breakout_manager.py#L56)
```python
self._lock = asyncio.Lock()  # Protects writes to JSON files

async def record_success(self, payload: str, vuln_type: str):
    async with self._lock:  # Atomic write
        await self._save_learned_breakout(...)
```

### 2. Rate Limiting Coordination ✅ SOLVED
**Problem:** Independent rate limiters → 4 req/s total (2 XSS + 2 CSTI) → saturates target

**Solution:** Global rate limiter singleton

#### Architecture

```
┌─────────────────────────────────────────┐
│ XSSSkill                                │
│  └─ ManipulatorOrchestrator             │
│      └─ RequestController ─────┐        │
└────────────────────────────────┼────────┘
                                 │
                                 ├─→ GlobalRateLimiter (Singleton)
                                 │   - 2.0 req/s TOTAL
┌────────────────────────────────┼────────┐  - Coordinates all requests
│ CSTISkill                      │        │
│  └─ ManipulatorOrchestrator    │        │
│      └─ RequestController ─────┘        │
└─────────────────────────────────────────┘
```

#### Implementation

**File:** [global_rate_limiter.py](../../bugtrace/tools/manipulator/global_rate_limiter.py)
```python
class GlobalRateLimiter:
    _instance = None  # Singleton
    _lock = asyncio.Lock()

    async def acquire(self):
        async with self._lock:
            # Wait until enough time passed since last request
            now = time.monotonic()
            elapsed = now - self.last_request_time

            if elapsed < self.min_interval:
                wait_time = self.min_interval - elapsed
                await asyncio.sleep(wait_time)

            self.last_request_time = time.monotonic()
```

**Modified:** [controller.py](../../bugtrace/tools/manipulator/controller.py)
```python
from .global_rate_limiter import global_rate_limiter

async def execute(self, request: MutableRequest):
    if self.use_global_limiter:
        await global_rate_limiter.acquire()  # Coordinate across all instances
    else:
        await asyncio.sleep(self.rate_limit)  # Old behavior
```

### 3. ContextAnalyzer Singleton ✅ NO PROBLEM
**Status:** Read-only, no state mutations → thread-safe by design

---

## Configuration

### bugtraceaicli.conf
```ini
[MANIPULATOR]
# Global rate limit across XSS + CSTI (total req/s)
GLOBAL_RATE_LIMIT = 2.0

# Enable global coordination
USE_GLOBAL_RATE_LIMITER = True

# LLM expansion (Phase 1b)
ENABLE_LLM_EXPANSION = True
```

### Tuning by Environment

```ini
# Fast local testing
GLOBAL_RATE_LIMIT = 5.0  # 5 req/s total

# Production with WAF
GLOBAL_RATE_LIMIT = 1.0  # 1 req/s total (stealth)

# Balanced
GLOBAL_RATE_LIMIT = 2.0  # 2 req/s total (default)
```

---

## Testing Concurrency

### Scenario: XSS + CSTI Parallel
```python
import asyncio
from bugtrace.skills.injection import XSSSkill, CSTISkill
from bugtrace.tools.manipulator.models import MutableRequest

async def test_parallel():
    xss_skill = XSSSkill()
    csti_skill = CSTISkill()

    request = MutableRequest(
        method="GET",
        url="https://target.com/search",
        params={"q": "test"}
    )

    # Run in parallel
    results = await asyncio.gather(
        xss_skill.execute(request),
        csti_skill.execute(request)
    )

    print(f"XSS result: {results[0]}")
    print(f"CSTI result: {results[1]}")

asyncio.run(test_parallel())
```

**Expected behavior:**
- ✅ Total rate: 2 req/s (not 4 req/s)
- ✅ No file corruption in learned_breakouts.json
- ✅ Auto-learning works correctly for both

---

## Benefits

1. **No Target Saturation**: Global rate limiter prevents overwhelming targets
2. **No Data Loss**: Async locks prevent file corruption
3. **Shared Learning**: Both skills benefit from unified breakout database
4. **Configurable**: Easy tuning per environment (fast/balanced/stealth)
5. **Backward Compatible**: Can disable global limiter if needed (`USE_GLOBAL_RATE_LIMITER = False`)

---

## Future Enhancements

### 1. Per-Target Rate Limiting
Track requests per domain:
```python
class GlobalRateLimiter:
    def __init__(self):
        self.per_domain_limiters = {}  # domain -> RateLimiter

    async def acquire(self, url: str):
        domain = urlparse(url).netloc
        limiter = self.per_domain_limiters.get(domain)
        await limiter.acquire()
```

### 2. Dynamic Rate Adjustment
Adapt to 429 responses:
```python
if response.status_code == 429:
    global_rate_limiter.update_rate(
        requests_per_second=0.5  # Slow down
    )
```

### 3. Distributed Coordination (Redis)
For multi-machine deployments:
```python
class RedisRateLimiter:
    async def acquire(self):
        await redis.incr("global_request_count", ex=1)
        count = await redis.get("global_request_count")
        if count > self.max_per_second:
            await asyncio.sleep(0.5)
```

---

**Last Updated:** 2026-02-02
**Related:** [INTELLIGENT_BREAKOUTS.md](INTELLIGENT_BREAKOUTS.md), [BREAKOUTS_USAGE.md](../guides/BREAKOUTS_USAGE.md)
