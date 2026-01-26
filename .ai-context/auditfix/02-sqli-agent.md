# SQLi Agent - Audit Fix Tasks

## Feature Overview
The SQLi Agent handles SQL injection detection using both native pattern-based testing and SQLMap integration. It includes:
- **Native SQLi Detection**: Pattern-based error detection, timing attacks
- **SQLMap Integration**: Automated exploitation with command-line interface
- **Validation**: Binary Proof validation via actual database extraction

---

## 🔴 CRITICAL Tasks (2)

### TASK-30: Fix Command Injection in SQLMap Agent
**Severity**: 🔴 CRITICAL
**File**: `bugtrace/agents/sqlmap_agent.py:390,436`
**Issue**: Unquoted `post_data` and parameters passed to shell subprocess
**Impact**: Remote Code Execution (RCE) via shell metacharacters

**Current Code**:
```python
# Line 390 - VULNERABLE
cmd.extend(["--data", post_data])  # Unquoted!

# Line 436 - VULNERABLE
cmd.extend(["--cookie", cookie_string])  # Shell injection risk
```

**Example Attack**:
```python
post_data = "id=1; cat /etc/passwd #"
# Results in RCE: sqlmap --data "id=1; cat /etc/passwd #"
```

**Proposed Fix**:
```python
import shlex

# Option 1: Use shlex.quote()
cmd.extend(["--data", shlex.quote(post_data)])

# Option 2: Write to temp file (safer)
import tempfile
with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
    f.write(post_data)
    temp_file = f.name
cmd.extend(["--data", f"@{temp_file}"])

# Option 3: Use subprocess with list (best)
subprocess.run([
    "sqlmap",
    "--url", url,
    "--data", post_data,  # Passed as argument, not shell-interpreted
    "--batch"
], shell=False)  # CRITICAL: shell=False
```

**Verification**:
1. Test with payload: `id=1; echo "HACKED" > /tmp/test.txt`
2. Verify /tmp/test.txt is NOT created
3. Run security scanner (Bandit, Semgrep)

**Priority**: P0 - Fix immediately (RCE vulnerability)

---

### TASK-31: Fix Time-Based SQLi False Positives
**Severity**: 🔴 CRITICAL
**File**: `bugtrace/agents/sqli_agent.py:844-850`
**Issue**: Network jitter causes false positives in timing thresholds
**Impact**: Incorrect vulnerability reports, wasted validation effort

**Current Code**:
```python
# Lines 844-850
if response_time > baseline * 1.5:
    # Assumes timing difference = SQLi (WRONG!)
    return True
```

**Proposed Fix**:
```python
# Triple-check with isolated baseline
async def verify_time_based_sqli(self, url, param, payload):
    # 1. Establish clean baseline (3 requests)
    baselines = []
    for _ in range(3):
        start = time.time()
        await self.client.get(url, params={param: "1"})
        baselines.append(time.time() - start)

    baseline = statistics.median(baselines)

    # 2. Test with timing payload (3 requests)
    timings = []
    for _ in range(3):
        start = time.time()
        await self.client.get(url, params={param: payload})
        timings.append(time.time() - start)

    median_timing = statistics.median(timings)

    # 3. Require consistent delay
    if median_timing > baseline + 5.0:  # At least 5 second delay
        # 4. Verify with control payload
        control_start = time.time()
        await self.client.get(url, params={param: "1"})
        control_timing = time.time() - control_start

        # Only confirm if control is fast
        return control_timing < baseline * 1.2

    return False
```

**Verification**: Test against known non-vulnerable endpoints with variable latency
**Priority**: P0 - Fix immediately (high false positive rate)

---

## 🟠 HIGH Priority Tasks (4)

### TASK-32: Fix Cookie String Injection
**Severity**: 🟠 HIGH
**File**: `bugtrace/agents/sqlmap_agent.py:394-395`
**Issue**: Cookie values concatenated without escaping
**Impact**: Command injection via malicious cookies

**Current Code**:
```python
cookie_string = "; ".join([f"{k}={v}" for k, v in cookies.items()])
cmd.extend(["--cookie", cookie_string])
```

**Example Attack**:
```python
cookies = {"session": 'test"; --os-shell #'}
# Results in: --cookie "session=test"; --os-shell #"
```

**Proposed Fix**:
```python
# Validate cookie format
import re
def validate_cookie_value(value):
    # Only allow alphanumeric, dash, underscore
    if not re.match(r'^[a-zA-Z0-9_\-=]+$', value):
        raise ValueError(f"Invalid cookie value: {value}")
    return value

cookie_string = "; ".join([
    f"{k}={validate_cookie_value(v)}"
    for k, v in cookies.items()
])
cmd.extend(["--cookie", shlex.quote(cookie_string)])
```

**Priority**: P1 - Fix within 1 week

---

### TASK-33: Fix Header Injection Vulnerability
**Severity**: 🟠 HIGH
**File**: `bugtrace/agents/sqlmap_agent.py:398-400`
**Issue**: Headers can contain newlines that break command arguments
**Impact**: Arbitrary argument injection

**Current Code**:
```python
for k, v in headers.items():
    cmd.extend(["-H", f"{k}: {v}"])  # Newline in v breaks this
```

**Proposed Fix**:
```python
def validate_header(key, value):
    # Reject newlines, null bytes
    if '\n' in key or '\r' in key or '\n' in value or '\r' in value:
        raise ValueError(f"Invalid header: {key}: {value}")
    return key, value

for k, v in headers.items():
    k, v = validate_header(k, v)
    cmd.extend(["-H", shlex.quote(f"{k}: {v}")])
```

**Priority**: P1 - Fix within 1 week

---

### TASK-34: Add SQLMap Output Sanitization
**Severity**: 🟠 HIGH
**File**: `bugtrace/agents/sqlmap_agent.py`
**Issue**: SQLMap output may contain ANSI codes, causing parsing errors

**Proposed Fix**:
```python
import re

def strip_ansi_codes(text):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

# After subprocess.run()
output = strip_ansi_codes(result.stdout.decode())
```

**Priority**: P1 - Fix within 1 week

---

### TASK-35: Add SQLMap Version Check
**Severity**: 🟠 HIGH
**File**: `bugtrace/agents/sqlmap_agent.py`
**Issue**: No validation that SQLMap is installed and correct version

**Proposed Fix**:
```python
async def verify_sqlmap():
    try:
        result = subprocess.run(
            ["sqlmap", "--version"],
            capture_output=True,
            timeout=5
        )
        version = result.stdout.decode().strip()
        logger.info(f"SQLMap version: {version}")
        return True
    except FileNotFoundError:
        logger.error("SQLMap not found in PATH")
        return False
    except Exception as e:
        logger.error(f"SQLMap check failed: {e}")
        return False
```

**Priority**: P1 - Fix within 1 week

---

## 🟡 MEDIUM Priority Tasks (8)

### TASK-36: Implement SQLMap Timeout
**Severity**: 🟡 MEDIUM
**File**: `bugtrace/agents/sqlmap_agent.py`
**Issue**: SQLMap can run forever

**Proposed Fix**:
```python
result = subprocess.run(
    cmd,
    capture_output=True,
    timeout=settings.SQLMAP_TIMEOUT_SECONDS or 600  # 10 minutes default
)
```

**Priority**: P2 - Fix before release

---

### TASK-37: Add SQLMap Output Size Limit
**Severity**: 🟡 MEDIUM
**Issue**: Large outputs can exhaust memory

**Proposed Fix**:
```python
# Redirect output to file
with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
    output_file = f.name

cmd.extend(["--output-dir", output_file])

# Read with size limit
with open(output_file, 'r') as f:
    output = f.read(10_000_000)  # 10MB max
```

**Priority**: P2 - Fix before release

---

### TASK-38: Add SQLMap Error Detection
**Severity**: 🟡 MEDIUM
**Issue**: SQLMap errors not properly detected

**Proposed Fix**:
```python
if result.returncode != 0:
    logger.error(f"SQLMap failed: {result.stderr.decode()}")
    raise SQLMapError(result.stderr.decode())

# Check for specific error patterns
if "no injection found" in output.lower():
    return None  # Not vulnerable
elif "target url is not responding" in output.lower():
    raise TargetUnreachableError()
```

**Priority**: P2 - Fix before release

---

### TASK-39: Add SQLMap Rate Limiting
**Severity**: 🟡 MEDIUM
**Issue**: Multiple SQLMap processes can overload target

**Proposed Fix**:
```python
# Use semaphore to limit concurrent SQLMap processes
sqlmap_semaphore = asyncio.Semaphore(settings.MAX_CONCURRENT_SQLMAP or 2)

async def run_sqlmap(self, cmd):
    async with self.sqlmap_semaphore:
        return await self._execute_sqlmap(cmd)
```

**Priority**: P2 - Fix before release

---

### TASK-40: Implement SQLMap Result Caching
**Severity**: 🟡 MEDIUM
**Issue**: Same URL tested multiple times

**Proposed Fix**:
```python
# Cache SQLMap results by (url, method, data) hash
import hashlib

def cache_key(url, method, data):
    return hashlib.sha256(f"{url}{method}{data}".encode()).hexdigest()

async def test_sqli(self, url, method, data):
    key = cache_key(url, method, data)
    if key in self.cache:
        logger.info(f"Using cached SQLMap result for {url}")
        return self.cache[key]

    result = await self._run_sqlmap(url, method, data)
    self.cache[key] = result
    return result
```

**Priority**: P2 - Fix before release

---

### TASK-41: Add Blind SQLi Detection
**Severity**: 🟡 MEDIUM
**Issue**: Only error-based and time-based covered

**Priority**: P3 - Next release

---

### TASK-42: Add Boolean-Based SQLi Detection
**Severity**: 🟡 MEDIUM
**Issue**: Missing boolean-based blind SQLi

**Priority**: P3 - Next release

---

### TASK-43: Add Union-Based SQLi Detection
**Severity**: 🟡 MEDIUM
**Issue**: Native detection doesn't test union-based

**Priority**: P3 - Next release

---

## 🟢 LOW Priority Tasks (5)

### TASK-44: Add SQLMap Custom Tamper Scripts
**Severity**: 🟢 LOW
**Issue**: Can't use custom tamper scripts

**Priority**: P4 - Technical debt

---

### TASK-45: Add SQLMap Progress Monitoring
**Severity**: 🟢 LOW
**Issue**: No visibility into SQLMap progress

**Priority**: P4 - Technical debt

---

### TASK-46: Add SQLMap Detailed Logging
**Severity**: 🟢 LOW
**Issue**: SQLMap output not saved to logs

**Priority**: P4 - Technical debt

---

### TASK-47: Add Unit Tests for SQLi Agent
**Severity**: 🟢 LOW
**Issue**: ~25% test coverage

**Priority**: P4 - Technical debt

---

### TASK-48: Refactor SQLMap Command Builder
**Severity**: 🟢 LOW
**Issue**: Command building logic is repetitive

**Priority**: P4 - Technical debt

---

## Summary

**Total Tasks**: 19
- 🔴 Critical: 2 (RCE vulnerability!)
- 🟠 High: 4 (Command injection variants)
- 🟡 Medium: 8 (Robustness improvements)
- 🟢 Low: 5 (Technical debt)

**Estimated Effort**: 1-2 weeks for P0-P1 tasks

**Security Note**: TASK-30 (Command Injection) is an RCE vulnerability and MUST be fixed before any production use.
