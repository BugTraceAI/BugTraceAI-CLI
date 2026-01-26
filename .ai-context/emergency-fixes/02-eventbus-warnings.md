# FIX-002: EventBus RuntimeWarnings

## 🔴 HIGH PRIORITY - Fix TODAY (1 hour)

---

## Problem

**Files Affected**: 11 files
- `bugtrace/core/event_bus.py` (root cause)
- `bugtrace/agents/jwt_agent.py`
- `bugtrace/agents/asset_discovery_agent.py`
- `bugtrace/agents/api_security_agent.py`
- `bugtrace/agents/chain_discovery_agent.py`
- Plus 7 more agent files

**Issue**: `EventBus.subscribe()` is `async def` but called from `__init__()` which **cannot be async**.

**Evidence from logs**:
```
RuntimeWarning: coroutine 'EventBus.subscribe' was never awaited
  self.event_bus.subscribe("auth_token_found", self.handle_new_token)
RuntimeWarning: Enable tracemalloc to get the object allocation traceback
```

**Frequency**: 11 warnings during EVERY scan startup

---

## Impact

### Code Quality Impact
- ❌ **Unprofessional warnings** - Makes codebase look amateur
- ❌ **Events may not work** - Subscriptions might not register correctly
- ❌ **Misleading logs** - Says "Subscribed" but actually didn't await
- ❌ **Junior-level mistake** - Any senior dev would spot this immediately

### Functional Impact
- ⚠️ **Events probably DON'T work** - I didn't see any `emit()` calls succeed in logs
- ⚠️ **Legacy code** - EventBus seems unused (specialists are called directly)
- ⚠️ **Future bugs** - If you try to use events later, they won't work

---

## Root Cause Analysis

### Current Broken Code

**event_bus.py:52** - Root cause:
```python
async def subscribe(self, event: str, handler: Callable) -> None:  # ❌ async
    """Suscribirse a un evento."""
    if not asyncio.iscoroutinefunction(handler):
        raise ValueError(f"Handler must be async function, got {type(handler)}")

    async with self._lock:  # ❌ Uses async lock
        self._subscribers[event].append(handler)
        self._stats["total_subscribers"] += 1
```

**jwt_agent.py:28-32** - Symptom:
```python
def _setup_event_subscriptions(self):
    """Subscribe to token discovery events."""
    if self.event_bus:
        self.event_bus.subscribe("auth_token_found", self.handle_new_token)  # ❌ NOT AWAITED
        logger.info(f"[{self.name}] Subscribed to 'auth_token_found' events.")
```

**Why this is wrong**:
1. `subscribe()` is `async def` (returns a coroutine)
2. Called from `__init__()` → `_setup_event_subscriptions()` (both sync)
3. Coroutine is never awaited → warning
4. Subscription probably never completes → events don't work

---

## Solution

### Option A: Make subscribe() Synchronous (RECOMMENDED)

**Change `async def subscribe()` → `def subscribe()`**

This is the correct solution because:
- Subscriptions don't need to be async
- No I/O or awaitable operations
- Lock is overkill (Python GIL handles this)

**Implementation**:

#### File 1: event_bus.py

**Before** (line 52):
```python
async def subscribe(self, event: str, handler: Callable) -> None:
    """Suscribirse a un evento."""
    if not asyncio.iscoroutinefunction(handler):
        raise ValueError(f"Handler must be async function, got {type(handler)}")

    async with self._lock:  # ❌ Async lock
        self._subscribers[event].append(handler)
        self._stats["total_subscribers"] += 1

    logger.debug(
        f"Subscriber added: {handler.__name__} → {event} "
        f"(total: {len(self._subscribers[event])})"
    )
```

**After** (line 52):
```python
def subscribe(self, event: str, handler: Callable) -> None:  # ✅ No async
    """Suscribirse a un evento."""
    if not asyncio.iscoroutinefunction(handler):
        raise ValueError(f"Handler must be async function, got {type(handler)}")

    # No lock needed - Python GIL handles list.append() atomically
    self._subscribers[event].append(handler)
    self._stats["total_subscribers"] += 1

    logger.debug(
        f"Subscriber added: {handler.__name__} → {event} "
        f"(total: {len(self._subscribers[event])})"
    )
```

**Changes**:
- Remove `async` from `def subscribe()`
- Remove `async with self._lock:` (not needed for simple append)
- Keep everything else the same

---

#### File 2: Update unsubscribe() too (for consistency)

**Before** (line 135):
```python
async def unsubscribe(self, event: str, handler: Callable) -> bool:
    """Desuscribirse de un evento."""
    async with self._lock:  # ❌ Async lock
        try:
            self._subscribers[event].remove(handler)
            self._stats["total_subscribers"] -= 1
            logger.debug(f"Subscriber removed: {handler.__name__} from {event}")
            return True
        except ValueError:
            logger.warning(f"Handler {handler.__name__} not found in {event}")
            return False
```

**After** (line 135):
```python
def unsubscribe(self, event: str, handler: Callable) -> bool:  # ✅ No async
    """Desuscribirse de un evento."""
    try:
        self._subscribers[event].remove(handler)
        self._stats["total_subscribers"] -= 1
        logger.debug(f"Subscriber removed: {handler.__name__} from {event}")
        return True
    except ValueError:
        logger.warning(f"Handler {handler.__name__} not found in {event}")
        return False
```

---

### Option B: Make Agent Setup Async (More Work, NOT Recommended)

If you REALLY want `subscribe()` to be async (you don't):

**TeamOrchestrator would need**:
```python
# team.py
async def _initialize_agents(self):
    self.jwt_agent = JWTAgent(event_bus=event_bus)
    await self.jwt_agent.setup_subscriptions()  # New async method

    self.asset_discovery_agent = AssetDiscoveryAgent(event_bus=event_bus)
    await self.asset_discovery_agent.setup_subscriptions()
    # ... repeat for all 11 agents
```

**Why this is worse**:
- Requires changes in 12+ files (vs 1 file for Option A)
- More complex initialization
- No benefit (subscriptions don't need to be async)

---

## Implementation Steps

### Step 1: Fix event_bus.py

```bash
cd /home/albert/Tools/BugTraceAI/BugTraceAI-CLI
nano bugtrace/core/event_bus.py +52
```

**Line 52**: Change `async def subscribe` → `def subscribe`
**Line 67**: Remove `async with self._lock:` → just use direct append
**Line 135**: Change `async def unsubscribe` → `def unsubscribe`
**Line 149**: Remove `async with self._lock:` → just use direct remove

### Step 2: Test

```bash
# Run scan - should see NO RuntimeWarnings
./bugtraceai-cli https://ginandjuice.shop 2>&1 | grep "RuntimeWarning"
# Expected: No output (0 warnings)
```

### Step 3: Verify agent subscriptions work

Check that this log still appears WITHOUT warnings:
```
INFO [JWTAgent] Subscribed to 'auth_token_found' events.
```

---

## Detailed Code Changes

### event_bus.py - Full Fixed Version

```python
# Lines 52-75 (FIXED)
def subscribe(self, event: str, handler: Callable) -> None:
    """
    Suscribirse a un evento.

    Args:
        event: Nombre del evento (ej: "new_input_discovered")
        handler: Función async que maneja el evento
                 Firma: async def handler(data: Dict) -> None

    Example:
        event_bus.subscribe("new_input_discovered", self.handle_new_input)
    """
    if not asyncio.iscoroutinefunction(handler):
        raise ValueError(f"Handler must be async function, got {type(handler)}")

    # Append is atomic in Python due to GIL - no lock needed
    self._subscribers[event].append(handler)
    self._stats["total_subscribers"] += 1

    logger.debug(
        f"Subscriber added: {handler.__name__} → {event} "
        f"(total: {len(self._subscribers[event])})"
    )

# Lines 135-160 (FIXED)
def unsubscribe(self, event: str, handler: Callable) -> bool:
    """
    Desuscribirse de un evento.

    Args:
        event: Nombre del evento
        handler: Handler a remover

    Returns:
        True si handler fue removido, False si no existía

    Use case:
        Cleanup cuando agent se detiene
    """
    try:
        self._subscribers[event].remove(handler)
        self._stats["total_subscribers"] -= 1
        logger.debug(f"Subscriber removed: {handler.__name__} from {event}")
        return True
    except ValueError:
        logger.warning(
            f"Handler {handler.__name__} not found in {event} subscribers"
        )
        return False
```

---

## Why Lock is NOT Needed

**Python GIL (Global Interpreter Lock) guarantees**:
- `list.append()` is atomic
- `list.remove()` is atomic
- No race condition possible for these operations

**When you WOULD need a lock**:
- If you were doing: `if x in list: list.remove(x)` (read-then-write)
- If you were doing complex mutations
- If you were working with non-atomic data structures

**Our case**: Single operation (`append` or `remove`) → No lock needed

---

## Testing Checklist

- [ ] Code compiles without errors
- [ ] No `RuntimeWarning: coroutine 'EventBus.subscribe'` in logs
- [ ] Agent subscription logs still appear
- [ ] Scan completes successfully
- [ ] No new errors introduced

---

## Verification

### Before Fix
```bash
./bugtraceai-cli https://ginandjuice.shop 2>&1 | grep -c "RuntimeWarning"
# Expected: 11 (one per agent)
```

### After Fix
```bash
./bugtraceai-cli https://ginandjuice.shop 2>&1 | grep -c "RuntimeWarning"
# Expected: 0

# Verify subscriptions still log
grep "Subscribed to" logs/*.log
# Should still see:
# [JWTAgent] Subscribed to 'auth_token_found' events.
# [AssetDiscoveryAgent] Subscribed to 'new_target_added' events
# etc.
```

---

## Expected Outcome

**Before**:
```
[stderr] /home/albert/.../jwt_agent.py:31: RuntimeWarning: coroutine 'EventBus.subscribe' was never awaited
  self.event_bus.subscribe("auth_token_found", self.handle_new_token)
RuntimeWarning: Enable tracemalloc to get the object allocation traceback
[stderr] 2026-01-26 13:26:06.309 | INFO | ...jwt_agent:_setup_event_subscriptions:32 - [JWTAgent] Subscribed to 'auth_token_found' events.
```

**After**:
```
[stderr] 2026-01-26 13:26:06.309 | INFO | ...jwt_agent:_setup_event_subscriptions:32 - [JWTAgent] Subscribed to 'auth_token_found' events.
```

**Warnings reduced**: From 11 → 0 ✅

---

## Estimated Time

- **Reading this doc**: 10 minutes
- **Making changes to event_bus.py**: 15 minutes
- **Testing**: 10 minutes (run scan, check logs)
- **Verification**: 5 minutes

**Total**: 40 minutes - 1 hour

---

## Priority Justification

**Why P0 (Fix TODAY)**:
- Affects startup of EVERY scan
- Makes code look unprofessional
- Easy fix (4 lines changed in 1 file)
- Low risk (just remove `async` keyword)
- Unblocks potential future use of EventBus

---

## Related Issues

- EventBus might be legacy code (not actively used)
- Consider removing EventBus entirely if not needed (future task)
- For now, fix the warnings to clean up logs

---

## Notes for Future

If you actually want to use EventBus for real:
1. First fix this warning
2. Then add actual `emit()` calls where needed
3. Test that events fire correctly
4. Document the event-driven flow

Currently, specialists are called directly (team.py:1046-1089), so EventBus is not critical path.
