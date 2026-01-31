# HTTP Orchestrator Migration Handoff

**Date:** 2026-01-31
**Author:** Claude
**Status:** COMPLETE

## Summary

Migrated all `aiohttp.ClientSession` usages to use the new `HTTPClientOrchestrator` system which provides:
- Destination-based routing (LLM, TARGET, SERVICE, PROBE)
- Adaptive retry policies based on real metrics
- Connection lifecycle tracking (ghost detection)
- Circuit breakers per host
- Backpressure when system is overwhelmed

## New Architecture

### Core Files

| File | Purpose |
|------|---------|
| `bugtrace/core/http_orchestrator.py` | Main orchestrator with all features |
| `bugtrace/core/http_manager.py` | Backward-compatible wrapper |
| `bugtrace/utils/aiohttp_patch.py` | Safety net for unmigrated code |

### Destination Types

```python
class DestinationType(Enum):
    LLM = "llm"        # OpenRouter API calls (120s timeout, 3 retries)
    TARGET = "target"  # Scan target websites (30s timeout, 1 retry)
    SERVICE = "service" # Internal services (30s timeout, 2 retries)
    PROBE = "probe"    # Quick probes (10s timeout, 0 retries)
```

## Files Migrated

### Core
- `bugtrace/core/llm_client.py` (7 usages) - Uses `DestinationType.LLM`
- `bugtrace/core/boot.py` (1 usage) - Uses `DestinationType.LLM`
- `bugtrace/core/diagnostics.py` (2 usages) - Uses `DestinationType.LLM`

### Agents (all use `DestinationType.TARGET`)
- `bugtrace/agents/rce_agent.py` (2 usages)
- `bugtrace/agents/idor_agent.py` (1 usage)
- `bugtrace/agents/openredirect_agent.py` (3 usages)
- `bugtrace/agents/header_injection_agent.py` (2 usages)
- `bugtrace/agents/ssrf_agent.py` (1 usage)
- `bugtrace/agents/lfi_agent.py` (2 usages)
- `bugtrace/agents/fileupload_agent.py` (3 usages)
- `bugtrace/agents/jwt_agent.py` (2 usages)
- `bugtrace/agents/prototype_pollution_agent.py` (5 usages)
- `bugtrace/agents/sqlmap_agent.py` (2 usages)
- `bugtrace/agents/xxe_agent.py` (2 usages - previous session)
- `bugtrace/agents/exploit_specialists.py` (3 usages - previous session)
- `bugtrace/agents/analysis_agent.py` (2 usages - previous session)

### Tools
- `bugtrace/tools/external.py` (1 usage) - Uses `DestinationType.TARGET`
- `bugtrace/tools/exploitation/xxe.py` (1 usage) - Uses `DestinationType.TARGET`

## Usage Pattern

### Before (Old)
```python
import aiohttp

async with aiohttp.ClientSession() as session:
    async with session.get(url) as resp:
        data = await resp.text()
```

### After (New)
```python
from bugtrace.core.http_orchestrator import orchestrator, DestinationType

async with orchestrator.session(DestinationType.TARGET) as session:
    async with session.get(url) as resp:
        data = await resp.text()
```

## Key Features

### 1. Adaptive Retry Calculator
- Adjusts retries based on host success rate, latency P95, circuit state
- Excellent (>95%): minimal retries
- Poor (<50%): no retries (stop wasting resources)

### 2. Connection Lifecycle Tracker
- Tracks every connection open/close
- Detects "ghost" connections (>120s without close)
- Implements backpressure: blocks new requests if 5+ ghosts exist

### 3. Circuit Breaker (per host)
- CLOSED -> OPEN after threshold failures
- OPEN blocks requests for timeout period
- HALF_OPEN tests with limited requests

### 4. Health Monitor
- Background watchdog every 30s
- Detects zombie sessions (no activity >5 min)
- Auto-restarts unhealthy clients

## Auto-Start Feature (Added 2026-01-31)

The orchestrator now auto-starts when any method is called:

```python
# No need to call orchestrator.start() first
async with orchestrator.session(DestinationType.LLM) as session:
    # Orchestrator starts automatically if not already started
    async with session.get(url) as resp:
        data = await resp.text()
```

Methods with auto-start: `get()`, `post()`, `head()`, `request()`, `session()`

This fixes boot check failures when code uses orchestrator before explicit `start()` call.

## Remaining Work

- `bugtrace/core/cdp_client.py` - Uses aiohttp for browser DevTools Protocol
  - Special case: WebSocket connections for Chrome debugging
  - May need separate handling, not standard HTTP

## Verification

Run a scan to verify the migration works:
```bash
cd /home/albert/Tools/BugTraceAI/BugTraceAI-CLI
python -m bugtrace full https://ginandjuice.shop/ 2>&1 | tee /tmp/test_migration.log
```

Check for:
- No `[aiohttp-patch]` warnings (means all code uses orchestrator)
- Normal scan completion
- HTTP lifecycle metrics in dashboard

## Backward Compatibility

- `HTTPClientManager` still works (wraps orchestrator)
- `ConnectionProfile` enum still available
- Old imports work but route to orchestrator internally
