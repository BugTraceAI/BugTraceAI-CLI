# WAF System - Audit Fix Tasks

## Feature Overview
The WAF (Web Application Firewall) system handles detection and bypass of security filters using:
- **Q-Learning Strategy Router**: Reinforcement learning for adaptive bypass
- **WAF Fingerprinter**: Detection of CloudFlare, ModSecurity, AWS WAF, etc.
- **Payload Encodings**: Base64, URL, Unicode, hex encoding techniques
- **Strategy Evolution**: Persistent learning across scans

---

## 🔴 CRITICAL Tasks (3)

### TASK-66: Fix SSL/TLS Verification Disabled in Fingerprinter
**Severity**: 🔴 CRITICAL
**File**: `bugtrace/tools/waf/fingerprinter.py:241,287`
**Issue**: `verify=False` disables certificate validation globally
**Impact**: MITM attacks, payload interception, credential theft

**Current Code**:
```python
# Lines 241, 287
async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
    response = await client.get(url)
```

**Proposed Fix**:
```python
# Option 1: Enable verification (recommended)
async with httpx.AsyncClient(timeout=timeout, verify=True) as client:
    response = await client.get(url)

# Option 2: Make it configurable
async with httpx.AsyncClient(
    timeout=timeout,
    verify=settings.VERIFY_SSL_CERTIFICATES  # Default True
) as client:
    response = await client.get(url)
```

**Additional Changes**:
```python
# In config.py
VERIFY_SSL_CERTIFICATES: bool = True
ALLOW_SELF_SIGNED_CERTS: bool = False  # For testing environments

# For self-signed certs in testing:
if settings.ALLOW_SELF_SIGNED_CERTS:
    import ssl
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    client = httpx.AsyncClient(verify=ssl_context)
```

**Verification**:
1. Test against HTTPS endpoint with invalid certificate
2. Verify connection fails (as expected)
3. Add override for testing environments only

**Priority**: P0 - Fix immediately (Security vulnerability)

---

### TASK-67: Fix Q-Learning Data Poisoning
**Severity**: 🔴 CRITICAL
**File**: `bugtrace/tools/waf/strategy_router.py:231-266`
**Issue**: No validation on WAF/strategy names, persistent poisoning possible
**Impact**: Adversarial training, model corruption, injection attacks

**Current Code**:
```python
# Lines 231-266
def record_result(self, waf_type, strategy, success):
    # No validation on waf_type or strategy!
    self.q_table[waf_type][strategy] = ...
```

**Example Attack**:
```python
# Attacker can poison Q-table
router.record_result(
    "', }], [{",  # JSON injection
    "../../etc/passwd",  # Path traversal
    success=True
)
```

**Proposed Fix**:
```python
import re

# Whitelist valid names
VALID_WAF_TYPES = {
    "cloudflare", "modsecurity", "aws_waf", "akamai",
    "imperva", "f5", "barracuda", "unknown"
}

VALID_STRATEGIES = {
    "base64", "unicode", "double_encode", "case_variation",
    "comment_injection", "null_byte", "mixed_case"
}

def validate_name(name, allowed_set, max_length=50):
    """Validate that name is in allowed set and matches pattern."""
    if not isinstance(name, str):
        raise ValueError("Name must be string")

    if len(name) > max_length:
        raise ValueError(f"Name too long: {len(name)} > {max_length}")

    # Only alphanumeric and underscore
    if not re.match(r'^[a-z0-9_]+$', name):
        raise ValueError(f"Invalid name format: {name}")

    if name not in allowed_set:
        logger.warning(f"Unknown name: {name}, using 'unknown'")
        return "unknown"

    return name

def record_result(self, waf_type, strategy, success):
    # Validate inputs
    waf_type = validate_name(waf_type, VALID_WAF_TYPES)
    strategy = validate_name(strategy, VALID_STRATEGIES)

    # Ensure keys exist
    if waf_type not in self.q_table:
        self.q_table[waf_type] = {}
    if strategy not in self.q_table[waf_type]:
        self.q_table[waf_type][strategy] = 0.0

    # Update Q-value
    self._update_q_value(waf_type, strategy, success)
```

**Additional Security**:
```python
# Sanitize Q-table file storage
import json

def save_q_table(self):
    """Save Q-table with validation."""
    # Validate structure before saving
    for waf in self.q_table:
        if waf not in VALID_WAF_TYPES:
            logger.error(f"Invalid WAF type in Q-table: {waf}")
            del self.q_table[waf]

    with open(self.q_table_path, 'w') as f:
        json.dump(self.q_table, f, indent=2)
        f.flush()
        os.fsync(f.fileno())  # Ensure written to disk

def load_q_table(self):
    """Load Q-table with validation."""
    try:
        with open(self.q_table_path, 'r') as f:
            data = json.load(f)

        # Validate structure
        validated = {}
        for waf, strategies in data.items():
            if waf in VALID_WAF_TYPES:
                validated[waf] = {
                    s: v for s, v in strategies.items()
                    if s in VALID_STRATEGIES and isinstance(v, (int, float))
                }

        self.q_table = validated
    except (json.JSONDecodeError, FileNotFoundError) as e:
        logger.warning(f"Q-table load failed: {e}, starting fresh")
        self.q_table = {}
```

**Verification**:
1. Attempt to inject malicious WAF type: `"'; DROP TABLE findings; --"`
2. Verify it's rejected or sanitized to "unknown"
3. Attempt path traversal in strategy name
4. Verify Q-table file contains only valid keys

**Priority**: P0 - Fix immediately

---

### TASK-68: Fix Q-Learning Exploration/Exploitation Balance
**Severity**: 🔴 CRITICAL
**File**: `bugtrace/tools/waf/strategy_router.py`
**Issue**: Epsilon-greedy may be too greedy, missing effective strategies
**Impact**: Suboptimal bypass strategies, failed exploitation

**Current Code**:
```python
# Likely using fixed epsilon
if random.random() < epsilon:
    return random.choice(strategies)
else:
    return max(strategies, key=lambda s: q_table[waf][s])
```

**Proposed Fix**:
```python
class AdaptiveEpsilonGreedy:
    def __init__(self, initial_epsilon=0.3, min_epsilon=0.05, decay_rate=0.995):
        self.epsilon = initial_epsilon
        self.min_epsilon = min_epsilon
        self.decay_rate = decay_rate
        self.successes = 0
        self.attempts = 0

    def select_strategy(self, waf_type, strategies, q_table):
        self.attempts += 1

        # Adaptive epsilon based on success rate
        success_rate = self.successes / self.attempts if self.attempts > 0 else 0

        # Increase exploration if success rate is low
        if success_rate < 0.2 and self.attempts > 10:
            effective_epsilon = min(0.5, self.epsilon * 1.5)
        else:
            effective_epsilon = self.epsilon

        # Epsilon-greedy selection
        if random.random() < effective_epsilon:
            # Explore: Use Upper Confidence Bound (UCB) instead of pure random
            return self._ucb_selection(waf_type, strategies, q_table)
        else:
            # Exploit: Best known strategy
            return max(strategies, key=lambda s: q_table.get(waf_type, {}).get(s, 0.0))

    def _ucb_selection(self, waf_type, strategies, q_table):
        """Upper Confidence Bound for exploration."""
        import math

        total_attempts = sum(
            self.attempt_counts.get(waf_type, {}).get(s, 0)
            for s in strategies
        )

        if total_attempts == 0:
            return random.choice(strategies)

        # UCB formula: Q(s) + c * sqrt(ln(N) / n(s))
        c = 2.0  # Exploration constant
        ucb_values = {}

        for strategy in strategies:
            q_value = q_table.get(waf_type, {}).get(strategy, 0.0)
            n_strategy = self.attempt_counts.get(waf_type, {}).get(strategy, 1)
            ucb = q_value + c * math.sqrt(math.log(total_attempts + 1) / n_strategy)
            ucb_values[strategy] = ucb

        return max(ucb_values, key=ucb_values.get)

    def record_result(self, waf_type, strategy, success):
        if success:
            self.successes += 1

        # Decay epsilon
        self.epsilon = max(self.min_epsilon, self.epsilon * self.decay_rate)

        # Track attempts per strategy
        if waf_type not in self.attempt_counts:
            self.attempt_counts[waf_type] = {}
        self.attempt_counts[waf_type][strategy] = \
            self.attempt_counts[waf_type].get(strategy, 0) + 1
```

**Priority**: P0 - Fix immediately (affects core functionality)

---

## 🟠 HIGH Priority Tasks (4)

### TASK-69: Add WAF Fingerprint Caching
**Severity**: 🟠 HIGH
**File**: `bugtrace/tools/waf/fingerprinter.py`
**Issue**: Same domain fingerprinted multiple times

**Proposed Fix**:
```python
from functools import lru_cache
import hashlib

class WAFFingerprinter:
    def __init__(self):
        self.cache = {}

    async def fingerprint(self, url):
        domain = self._extract_domain(url)
        cache_key = hashlib.md5(domain.encode()).hexdigest()

        if cache_key in self.cache:
            logger.info(f"Using cached WAF fingerprint for {domain}")
            return self.cache[cache_key]

        result = await self._perform_fingerprint(url)
        self.cache[cache_key] = result
        return result
```

**Priority**: P1 - Fix within 1 week

---

### TASK-70: Add WAF Detection Confidence Score
**Severity**: 🟠 HIGH
**File**: `bugtrace/tools/waf/fingerprinter.py`
**Issue**: Binary yes/no detection, no confidence metric

**Proposed Fix**:
```python
def calculate_confidence(self, indicators):
    """Calculate confidence score 0.0-1.0."""
    weights = {
        "header_match": 0.4,
        "cookie_match": 0.3,
        "response_pattern": 0.2,
        "timing_pattern": 0.1
    }

    score = sum(
        weights[indicator] for indicator in indicators
        if indicators[indicator]
    )

    return min(1.0, score)

# Usage
detection = {
    "waf_type": "cloudflare",
    "confidence": 0.8,
    "indicators": ["header_match", "cookie_match"]
}
```

**Priority**: P1 - Fix within 1 week

---

### TASK-71: Add Q-Table Backup and Restore
**Severity**: 🟠 HIGH
**File**: `bugtrace/tools/waf/strategy_router.py`
**Issue**: Q-table corruption loses all learned data

**Proposed Fix**:
```python
import shutil
from datetime import datetime

def save_q_table(self):
    """Save Q-table with backup."""
    # Create backup
    if os.path.exists(self.q_table_path):
        backup_path = f"{self.q_table_path}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        shutil.copy2(self.q_table_path, backup_path)

        # Keep only last 5 backups
        self._cleanup_old_backups()

    # Save current
    with open(self.q_table_path, 'w') as f:
        json.dump(self.q_table, f, indent=2)

def _cleanup_old_backups(self, keep=5):
    """Remove old backup files."""
    backups = sorted(glob.glob(f"{self.q_table_path}.backup.*"))
    for old_backup in backups[:-keep]:
        os.remove(old_backup)
```

**Priority**: P1 - Fix within 1 week

---

### TASK-72: Add WAF Bypass Success Metrics
**Severity**: 🟠 HIGH
**File**: `bugtrace/tools/waf/strategy_router.py`
**Issue**: No metrics on bypass effectiveness

**Proposed Fix**:
```python
class WAFMetrics:
    def __init__(self):
        self.attempts = 0
        self.successes = 0
        self.by_waf = {}
        self.by_strategy = {}

    def record_attempt(self, waf_type, strategy, success):
        self.attempts += 1
        if success:
            self.successes += 1

        # Track by WAF
        if waf_type not in self.by_waf:
            self.by_waf[waf_type] = {"attempts": 0, "successes": 0}
        self.by_waf[waf_type]["attempts"] += 1
        if success:
            self.by_waf[waf_type]["successes"] += 1

        # Track by strategy
        if strategy not in self.by_strategy:
            self.by_strategy[strategy] = {"attempts": 0, "successes": 0}
        self.by_strategy[strategy]["attempts"] += 1
        if success:
            self.by_strategy[strategy]["successes"] += 1

    def get_summary(self):
        return {
            "overall_success_rate": self.successes / self.attempts if self.attempts > 0 else 0,
            "by_waf": {
                waf: stats["successes"] / stats["attempts"] if stats["attempts"] > 0 else 0
                for waf, stats in self.by_waf.items()
            },
            "by_strategy": {
                strategy: stats["successes"] / stats["attempts"] if stats["attempts"] > 0 else 0
                for strategy, stats in self.by_strategy.items()
            }
        }
```

**Priority**: P1 - Fix within 2 weeks

---

## 🟡 MEDIUM Priority Tasks (5)

### TASK-73: Add Multi-WAF Detection
**Severity**: 🟡 MEDIUM
**Issue**: Only single WAF detected, can't handle stacked WAFs

**Priority**: P2 - Fix before release

---

### TASK-74: Add WAF Bypass Strategy Combinations
**Severity**: 🟡 MEDIUM
**Issue**: Only single strategy tested, not combinations

**Proposed Fix**: Test combinations like base64+unicode+double_encode
**Priority**: P2 - Fix before release

---

### TASK-75: Add Q-Learning Hyperparameter Tuning
**Severity**: 🟡 MEDIUM
**Issue**: Learning rate, discount factor hardcoded

**Priority**: P2 - Fix before release

---

### TASK-76: Add WAF Evasion Payload Library
**Severity**: 🟡 MEDIUM
**Issue**: Limited bypass techniques

**Priority**: P2 - Fix before release

---

### TASK-77: Add WAF Detection False Positive Handling
**Severity**: 🟡 MEDIUM
**Issue**: False WAF detections lead to unnecessary evasion

**Priority**: P3 - Next release

---

## 🟢 LOW Priority Tasks (3)

### TASK-78: Add Q-Learning Visualization
**Severity**: 🟢 LOW
**Issue**: No visibility into Q-table state

**Priority**: P4 - Technical debt

---

### TASK-79: Add WAF Bypass Documentation
**Severity**: 🟢 LOW
**Issue**: Strategy selection logic under-documented

**Priority**: P4 - Technical debt

---

### TASK-80: Add Unit Tests for WAF System
**Severity**: 🟢 LOW
**Issue**: ~15% test coverage

**Priority**: P4 - Technical debt

---

## Summary

**Total Tasks**: 15
- 🔴 Critical: 3 (SSL disabled, data poisoning)
- 🟠 High: 4 (Caching, metrics, confidence)
- 🟡 Medium: 5 (Multi-WAF, combinations)
- 🟢 Low: 3 (Technical debt)

**Estimated Effort**: 2-3 weeks for P0-P1 tasks

**Security Note**: TASK-66 (SSL disabled) and TASK-67 (Q-learning poisoning) are critical security vulnerabilities.
