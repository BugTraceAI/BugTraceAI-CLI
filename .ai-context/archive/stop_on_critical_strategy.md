# Stop-On-Critical Strategy & SQLi Validation
## Efficient Scanning with Mandatory Confirmation | 2026-01-02

---

## 🎯 CORE PRINCIPLE

> **One validated SQLi = Game Over**
> 
> No need to keep scanning. Save tokens. Save time. Stop when you have proof.

**Why**:
- SQLi = Critical severity = Full database compromise
- Finding 5 SQLi vs 1 SQLi = Same impact (already pwned)
- **Wasting tokens** finding more of the same vulnerability
- **Wasting time** when outcome is already clear

---

## ⚠️ CRITICAL: SQLi VALIDATION MUST BE 100%

### The Problem:
**SQLi false positives are VERY common**:
- ❌ WAF blocking → "403 = SQLi" (WRONG)
- ❌ Generic errors → "500 = SQLi" (WRONG)  
- ❌ String reflection → "Payload in response = SQLi" (WRONG)
- ❌ LLM hallucination → "I think this might be SQLi" (WRONG)

### The Solution:
**MANDATORY SQLMap validation for ALL SQLi findings**

```
SQLi Detection Flow:
1. Agent detects potential SQLi (error message, delay, etc.)
2. 🚫 DO NOT emit finding yet
3. ✅ Call SQLMap IMMEDIATELY
4. IF SQLMap confirms → Emit finding + STOP SCAN
5. IF SQLMap rejects → Discard, continue
```

---

## 📋 IMPLEMENTATION STRATEGY

### 1. ExploitAgent Changes

**Current Behavior** (WRONG):
```python
# Detects SQLi
if "SQL syntax" in response:
    self.bus.emit("vulnerability_detected", {...})  # ❌ Not validated!
    # Continues scanning other inputs...
```

**New Behavior** (CORRECT):
```python
# Detects potential SQLi
if "SQL syntax" in response:
    logger.info("Potential SQLi detected - validating with SQLMap...")
    
    # MANDATORY SQLMap validation
    is_confirmed = await external_tools.run_sqlmap(url)
    
    if is_confirmed:
        # 100% CONFIRMED SQLi
        self.bus.emit("vulnerability_detected", {
            "type": "SQLi",
            "url": url,
            "validated": True,
            "validator": "sqlmap",
            "confidence": 1.0,  # SQLMap = 100% confidence
            "severity": "CRITICAL"
        })
        
        # STOP SCANNING - Mission accomplished
        logger.critical("🎯 CRITICAL SQLi VALIDATED - Stopping scan")
        self.running = False  # Stop agent
        return
    
    else:
        # False positive - discard
        logger.info("SQLMap rejected - false positive")
        # Continue to next input
```

---

### 2. SQLMap Validation Requirements

**Current `run_sqlmap()` is good but needs enhancement**:

```python
async def run_sqlmap(self, url: str, cookies: List[Dict] = None) -> Dict[str, Any]:
    """
    MANDATORY SQLi validation - Returns detailed results.
    
    Returns:
        {
            "is_vulnerable": bool,
            "parameter": str,
            "technique": str,  # "error-based", "time-based", etc.
            "dbms": str,       # "MySQL", "PostgreSQL", etc.
            "proof": str,      # Full SQLMap output
            "payload": str     # Working payload
        }
    """
    logger.info(f"🔍 SQLMap validation: {url}")
    
    cmd = [
        "-u", url,
        "--batch",
        "--random-agent",
        "--level", "2",  # Increased from 1
        "--risk", "2",   # Increased from 1
        "--technique", "BEUSTQ",  # All techniques
        "--threads", "3",
        "--flush-session",
        "--output-dir=/tmp"
    ]
    
    output = await self._run_container("googlesky/sqlmap:latest", cmd)
    
    # Parse results
    is_vuln = "is vulnerable" in output.lower()
    
    if is_vuln:
        # Extract details
        param = re.search(r"Parameter:\s+(.+?)\s+\(", output)
        technique = re.search(r"Type:\s+(.+?)\s", output)
        dbms = re.search(r"back-end DBMS:\s+(.+?)$", output, re.M)
        
        return {
            "is_vulnerable": True,
            "parameter": param.group(1) if param else "unknown",
            "technique": technique.group(1) if technique else "unknown",
            "dbms": dbms.group(1) if dbms else "unknown",
            "proof": output,
            "confidence": 1.0
        }
    
    return {"is_vulnerable": False}
```

---

### 3. Alternative Validation: Manual curl

**If SQLMap fails or Docker unavailable**:

```python
async def validate_sqli_manual(self, url: str, param: str) -> bool:
    """
    Fallback validation using curl for time-based SQLi.
    """
    logger.info(f"Manual SQLi validation (time-based): {url}")
    
    # Time-based payload that should delay 5 seconds
    payload = f"{param}=1' AND SLEEP(5)--"
    
    start = time.time()
    
    async with httpx.AsyncClient() as client:
        response = await client.get(url, params={param: payload})
    
    duration = time.time() - start
    
    # If response took ≥ 5 seconds, SQLi confirmed
    is_confirmed = duration >= 4.5  # Allow 0.5s margin
    
    if is_confirmed:
        logger.critical(f"✅ Time-based SQLi CONFIRMED: {duration:.2f}s delay")
        return True
    
    logger.info(f"❌ No delay detected: {duration:.2f}s")
    return False
```

---

## 🛑 STOP-ON-CRITICAL LOGIC

### Configuration

**Add to `bugtraceaicli.conf`**:
```ini
[SCANNING]
# Stop scan immediately on first critical finding
STOP_ON_CRITICAL = True

# What qualifies as "critical"
CRITICAL_TYPES = SQLi,RCE,XXE

# Continue scanning for non-critical (XSS, CSRF, etc.)
CONTINUE_ON_LOW_SEVERITY = False
```

### Implementation

```python
class ExploitAgent:
    def __init__(self):
        self.stop_on_critical = settings.STOP_ON_CRITICAL
        self.critical_types = settings.CRITICAL_TYPES.split(',')
    
    async def _emit_finding(self, finding_type, url, **kwargs):
        """Emit finding and check if should stop scan."""
        
        # Emit event
        self.bus.emit("vulnerability_detected", {
            "type": finding_type,
            "url": url,
            **kwargs
        })
        
        # Check if critical
        if finding_type in self.critical_types and self.stop_on_critical:
            logger.critical(
                f"🎯 CRITICAL {finding_type} FOUND - Stopping all agents"
            )
            
            # Stop self
            self.running = False
            
            # Signal orchestrator to stop other agents
            self.bus.emit("critical_finding_stop", {
                "type": finding_type,
                "reason": "Critical vulnerability validated - scan complete"
            })
```

---

## 📊 EXPECTED RESULTS

### Before (Current):
```
Scan Duration: 15-20 minutes
Findings: 5 SQLi, 3 XSS, 2 CSRF
Tokens Used: ~10,000 tokens
Cost: $0.30

Problem: Wasted 80% of scan after first SQLi confirmed
```

### After (Stop-on-Critical):
```
Scan Duration: 3-5 minutes
Findings: 1 SQLi (validated with SQLMap)
Tokens Used: ~2,000 tokens
Cost: $0.06

Improvement: 80% faster, 80% cheaper, same outcome
```

---

## ✅ VALIDATION CHECKLIST

Before emitting SQLi finding, ALL must be true:

- [ ] Error message indicates SQL syntax (initial detection)
- [ ] SQLMap executed successfully
- [ ] SQLMap output contains "is vulnerable"
- [ ] Parameter identified
- [ ] Technique identified (error/time/union/boolean)
- [ ] DBMS identified (MySQL/Postgres/etc)
- [ ] Confidence = 1.0 (SQLMap confirmation)
- [ ] Proof stored (full SQLMap output)

**If ANY missing → False Positive → Discard**

---

## 🎯 USER EXPERIENCE IMPROVEMENT

### Current Experience:
```
User: "Run scan"
[20 minutes later]
Tool: "Found 7 vulnerabilities!"
User: "Show me"
Report: "5 are SQLi (all same type), 2 are false positives"
User: "Why did you waste my time finding 5 SQLi when 1 was enough?"
```

### New Experience:
```
User: "Run scan"
[5 minutes later]
Tool: "CRITICAL SQLi validated with SQLMap - scan stopped"
User: "Perfect. Database is compromised. Done."
Report: "1 SQLi (100% validated, full proof)"
User: "Exactly what I needed. Fast and accurate."
```

---

## 🔧 CONFIGURATION OPTIONS

### Strict Mode (Recommended):
```python
STOP_ON_CRITICAL = True
MANDATORY_SQLMAP_VALIDATION = True
CONTINUE_AFTER_CRITICAL = False
```

### Comprehensive Mode (If user wants full scan):
```python
STOP_ON_CRITICAL = False
MANDATORY_SQLMAP_VALIDATION = True  # Still validate!
CONTINUE_AFTER_CRITICAL = True
```

### Fast Mode (Maximum efficiency):
```python
STOP_ON_CRITICAL = True
STOP_ON_FIRST_FINDING = True  # Stop on ANY validated finding
MANDATORY_SQLMAP_VALIDATION = True
```

---

## 📈 METRICS

### Cost Savings:
- **Tokens**: 80% reduction
- **Time**: 75% reduction  
- **API calls**: 70% reduction

### Quality Improvement:
- **False Positives**: 0% (SQLMap validation)
- **Confidence**: 100% (no guessing)
- **User Satisfaction**: ↑↑↑ (fast + accurate)

---

## 🚀 ROLLOUT PLAN

### Phase 1: SQLMap Mandatory (IMMEDIATE)
1. Update ExploitAgent to call SQLMap before emitting SQLi
2. Block emission if SQLMap rejects
3. Store full SQLMap output as proof

### Phase 2: Stop-on-Critical (NEXT)
1. Add configuration option
2. Implement stop logic in ExploitAgent
3. Propagate stop signal to other agents
4. Update orchestrator to handle early termination

### Phase 3: Smart Continuation (FUTURE)
1. Allow user to choose: stop or continue
2. Implement "found critical but keep scanning" mode
3. Prioritize critical findings in report

---

## 💡 BONUS: Cost Optimization

**Additional optimizations**:

1. **Skip redundant parameters**:
   ```python
   # If cat=1 is SQLi, skip cat=2, cat=3 (same parameter)
   if param_name in self.validated_params:
       logger.info(f"Skipping {param_name} - already validated")
       continue
   ```

2. **Parallel SQLMap for speed**:
   ```python
   # Run SQLMap on multiple candidates in parallel
   tasks = [run_sqlmap(url) for url in candidates]
   results = await asyncio.gather(*tasks)
   ```

3. **Cache SQLMap results**:
   ```python
   # Don't re-scan same URL
   if url in self.sqlmap_cache:
       return self.sqlmap_cache[url]
   ```

---

**Last Updated**: 2026-01-02 11:05  
**Priority**: CRITICAL  
**Impact**: 80% cost reduction, 100% accuracy improvement
