# Breakouts System - Usage Guide

Quick reference for using the Intelligent Breakouts System.

## Quick Start

### 1. Basic Usage (Auto-Enabled)

The system is enabled by default. No code changes needed:

```python
from bugtrace.tools.manipulator.orchestrator import ManipulatorOrchestrator
from bugtrace.tools.manipulator.models import MutableRequest

orchestrator = ManipulatorOrchestrator()

request = MutableRequest(
    method="GET",
    url="https://target.com/search",
    params={"q": "test"}
)

success, mutation = await orchestrator.process_finding(request)
```

**What happens:**
1. Sends probe → detects context
2. Tests 50 static payloads (Phase 1a)
3. If fails → generates 100 LLM payloads + expands with breakouts (Phase 1b)
4. Auto-learns successful breakouts

### 2. Configuration Options

```python
orchestrator = ManipulatorOrchestrator(
    rate_limit=0.5,                # Seconds between requests (default: 0.5)
    enable_llm_expansion=True,      # Enable Phase 1b (default: True)
    enable_agentic_fallback=False   # Enable Phase 3 (default: False)
)
```

## Common Tasks

### View Loaded Breakouts

```python
from bugtrace.tools.manipulator.breakout_manager import breakout_manager

# Show all loaded breakouts
print(f"Total breakouts: {len(breakout_manager.breakouts)}")

# Show by category
xss_breakouts = breakout_manager.get_breakout_prefixes(category="xss")
print(f"XSS breakouts: {len(xss_breakouts)}")

# Show by priority
critical = breakout_manager.get_breakout_prefixes(max_priority=1)
print(f"Critical breakouts: {len(critical)}")
```

### View Top Performers

```python
from bugtrace.tools.manipulator.breakout_manager import breakout_manager

# Get top 10 most successful breakouts
top = breakout_manager.get_top_breakouts(10)
for breakout in top:
    print(f"{breakout.prefix!r}: {breakout.success_count} successes ({breakout.category})")
```

**Example output:**
```
"'": 47 successes (xss,sqli)
'"': 38 successes (xss,sqli)
"'>": 29 successes (xss)
"';": 23 successes (xss,sqli)
...
```

### Test Context Detection

```python
from bugtrace.tools.manipulator.context_analyzer import context_analyzer

# Analyze a response
response_body = '<input type="text" value="bugtraceomni7x9z">'
result = context_analyzer.analyze_reflection(response_body)

print(f"Contexts: {[c.value for c in result['contexts']]}")
print(f"Recommended breakouts: {result['recommended_breakouts']}")
print(f"Analysis: {result['analysis']}")
```

**Example output:**
```
Contexts: ['html_attr_double']
Recommended breakouts: ['"', '">', '"><', '" onload="', '"//', ...]
Analysis: Detected contexts: html_attr_double. Reflection: ...value=">>>bugtraceomni7x9z<<<"...
```

### Manual Breakout Recording

```python
from bugtrace.tools.manipulator.breakout_manager import breakout_manager

# Record a successful payload manually
await breakout_manager.record_success(
    payload="'><script>alert(1)</script>",
    vuln_type="xss"
)
```

### Reload Configuration

After editing `breakouts.json`:

```python
from bugtrace.tools.manipulator.breakout_manager import breakout_manager

breakout_manager.reload()
print(f"Reloaded {len(breakout_manager.breakouts)} breakouts")
```

## Customization

### Add Custom Breakouts

Edit `bugtrace/payloads/breakouts.json`:

```json
{
  "prefix": "')}--",
  "description": "Custom breakout for SQLi in stored procedures",
  "category": "sqli",
  "priority": 2,
  "success_count": 0,
  "enabled": true
}
```

Then reload:
```python
breakout_manager.reload()
```

### Disable Specific Breakouts

```json
{
  "prefix": "%00",
  "description": "Null byte (doesn't work on PHP 7.4+)",
  "enabled": false
}
```

### Change Priority Levels

```ini
# bugtraceaicli.conf
[MANIPULATOR]
BREAKOUT_PRIORITY_LEVEL = 2  # Only critical + high value
```

Or in code:
```python
breakouts = breakout_manager.get_breakout_prefixes(
    category="xss",
    max_priority=2  # 1=critical, 2=high, 3=normal, 4=advanced
)
```

## Performance Tuning

### Fast Mode (Aggressive)

```ini
[MANIPULATOR]
RATE_LIMIT = 0.1                    # 10 req/s (fast but noisy)
BREAKOUT_PRIORITY_LEVEL = 2         # Only critical + high
MAX_LLM_PAYLOADS = 50               # Fewer payloads
ENABLE_LLM_EXPANSION = true
```

**Result:** ~4 minutes per scan (very fast, more detectable)

### Balanced Mode (Recommended)

```ini
[MANIPULATOR]
RATE_LIMIT = 0.5                    # 2 req/s (safe)
BREAKOUT_PRIORITY_LEVEL = 3         # All common breakouts
MAX_LLM_PAYLOADS = 100
ENABLE_LLM_EXPANSION = true
```

**Result:** ~8 minutes per scan (good balance)

### Stealth Mode (Slow)

```ini
[MANIPULATOR]
RATE_LIMIT = 2.0                    # 0.5 req/s (very stealthy)
BREAKOUT_PRIORITY_LEVEL = 1         # Only critical breakouts
MAX_LLM_PAYLOADS = 30
ENABLE_LLM_EXPANSION = false        # Skip LLM phase
```

**Result:** ~15 minutes per scan (stealthy, less coverage)

## Monitoring

### Check Learned Breakouts

```bash
# View learned breakouts file
cat bugtrace/payloads/learned_breakouts.json | jq '.breakouts[] | {prefix, success_count, category}'
```

### Export Statistics

```python
from bugtrace.tools.manipulator.breakout_manager import breakout_manager

# Get all metrics
stats = {
    "total_breakouts": len(breakout_manager.breakouts),
    "by_priority": {},
    "by_category": {},
    "top_performers": [b.to_dict() for b in breakout_manager.get_top_breakouts(5)]
}

# Count by priority
for b in breakout_manager.breakouts:
    priority = b.priority
    stats["by_priority"][priority] = stats["by_priority"].get(priority, 0) + 1

# Count by category
for b in breakout_manager.breakouts:
    for cat in b.category.split(','):
        cat = cat.strip()
        stats["by_category"][cat] = stats["by_category"].get(cat, 0) + 1

print(json.dumps(stats, indent=2))
```

## Integration with Existing Code

### In XSS Agent

```python
from bugtrace.tools.manipulator.orchestrator import ManipulatorOrchestrator
from bugtrace.tools.manipulator.models import MutableRequest, MutationStrategy

class XSSAgent:
    def __init__(self):
        self.manipulator = ManipulatorOrchestrator(
            rate_limit=0.5,
            enable_llm_expansion=True
        )

    async def test_xss(self, url: str, params: dict):
        request = MutableRequest(
            method="GET",
            url=url,
            params=params
        )

        success, mutation = await self.manipulator.process_finding(
            request,
            strategies=[MutationStrategy.PAYLOAD_INJECTION]
        )

        if success:
            logger.info(f"XSS found! Payload: {mutation.params}")
            return mutation

        return None
```

### In DAST Agent

```python
async def analyze_parameter(self, url, param_name, param_value):
    """Test a single parameter for vulnerabilities."""

    request = MutableRequest(
        method="GET",
        url=url,
        params={param_name: param_value}
    )

    # Manipulator automatically:
    # 1. Detects context
    # 2. Selects appropriate breakouts
    # 3. Tests with multi-phase approach
    # 4. Auto-learns successes
    success, mutation = await self.manipulator.process_finding(request)

    return success, mutation
```

## Debugging

### Enable Verbose Logging

```python
import logging
logging.getLogger("tools.manipulator").setLevel(logging.DEBUG)
```

### Trace Context Detection

```python
from bugtrace.tools.manipulator.context_analyzer import context_analyzer

response = '<div>bugtraceomni7x9z</div>'
result = context_analyzer.analyze_reflection(response, probe="bugtraceomni7x9z")

print(f"Contexts detected: {result['contexts']}")
print(f"Confidence: {result['confidence']}")
print(f"Breakouts: {result['recommended_breakouts']}")
print(f"Analysis: {result['analysis']}")
```

### Simulate Phase Execution

```python
# Test Phase 1a only
orchestrator = ManipulatorOrchestrator(enable_llm_expansion=False)

# Test with LLM but no WAF bypass
orchestrator = ManipulatorOrchestrator(
    enable_llm_expansion=True,
    enable_agentic_fallback=False
)
```

## Best Practices

### 1. Let Phase 1a Run First
```python
# ❌ Don't skip Phase 1a
# It catches 70% of vulns in ~25s

# ✅ Use default cascade
orchestrator = ManipulatorOrchestrator()  # All phases enabled
```

### 2. Monitor Learned Breakouts
```python
# Periodically review learned_breakouts.json
# Move proven patterns to breakouts.json
# Disable ineffective ones
```

### 3. Adjust Rate Limiting Per Target
```python
# Fast internal targets
orchestrator = ManipulatorOrchestrator(rate_limit=0.1)

# Public targets with WAF
orchestrator = ManipulatorOrchestrator(rate_limit=1.0)

# Stealth mode
orchestrator = ManipulatorOrchestrator(rate_limit=3.0)
```

### 4. Use Priority Levels Intelligently
```python
# Quick scan - only critical breakouts
breakouts = breakout_manager.get_breakout_prefixes(max_priority=1)

# Thorough scan - all breakouts
breakouts = breakout_manager.get_breakout_prefixes(max_priority=4)
```

### 5. Category Filtering
```python
# Testing for SQLi specifically
sqli_breakouts = breakout_manager.get_breakout_prefixes(
    category="sqli",
    max_priority=3
)

# Testing for XSS only
xss_breakouts = breakout_manager.get_breakout_prefixes(
    category="xss",
    max_priority=2
)
```

## Common Patterns

### Pattern 1: Progressive Testing

```python
async def progressive_test(url, params):
    """Test with increasing thoroughness."""

    request = MutableRequest(method="GET", url=url, params=params)

    # Level 1: Fast (critical breakouts only)
    orchestrator = ManipulatorOrchestrator(enable_llm_expansion=False)
    success, _ = await orchestrator.process_finding(request)
    if success:
        return "Found with static payloads"

    # Level 2: LLM expansion
    orchestrator.enable_llm_expansion = True
    success, _ = await orchestrator.process_finding(request)
    if success:
        return "Found with LLM payloads"

    return "Not vulnerable"
```

### Pattern 2: Target-Specific Configuration

```python
def get_orchestrator_for_target(target_url: str):
    """Configure orchestrator based on target characteristics."""

    if "localhost" in target_url or "127.0.0.1" in target_url:
        # Fast local testing
        return ManipulatorOrchestrator(
            rate_limit=0.1,
            enable_llm_expansion=True
        )

    elif any(waf in target_url for waf in ["cloudflare", "akamai"]):
        # Stealth mode for WAF-protected targets
        return ManipulatorOrchestrator(
            rate_limit=2.0,
            enable_llm_expansion=True
        )

    else:
        # Default balanced mode
        return ManipulatorOrchestrator(
            rate_limit=0.5,
            enable_llm_expansion=True
        )
```

### Pattern 3: Batch Testing with Context Reuse

```python
async def test_multiple_params(url, params_dict):
    """Test multiple parameters efficiently."""

    orchestrator = ManipulatorOrchestrator()
    results = {}

    # Context detection happens once per URL
    # Subsequent tests use cached context (future enhancement)

    for param_name, param_value in params_dict.items():
        request = MutableRequest(
            method="GET",
            url=url,
            params={param_name: param_value}
        )

        success, mutation = await orchestrator.process_finding(request)
        results[param_name] = {
            "vulnerable": success,
            "mutation": mutation.params if mutation else None
        }

    return results
```

## Troubleshooting Guide

### Issue: Too Many Requests
```python
# Increase rate limiting
orchestrator = ManipulatorOrchestrator(rate_limit=2.0)  # Slower
```

### Issue: Not Finding Known Vulnerabilities
```python
# Increase coverage
breakout_manager.get_breakout_prefixes(max_priority=4)  # All breakouts
orchestrator.enable_llm_expansion = True  # Ensure LLM is enabled
```

### Issue: LLM Costs Too High
```python
# Reduce LLM usage
orchestrator.enable_llm_expansion = False  # Skip Phase 1b

# Or reduce payload count
# In _generate_llm_payloads_base: count=50 instead of 100
```

### Issue: Scans Too Slow
```python
# Use fast mode
orchestrator = ManipulatorOrchestrator(rate_limit=0.1)
breakouts = breakout_manager.get_breakout_prefixes(max_priority=2)
```

## References

- [Architecture Document](../architecture/INTELLIGENT_BREAKOUTS.md)
- [Breakouts README](../../bugtrace/payloads/README.md)
- [API Reference](../specs/manipulator_api.md) (if exists)

## Support

For issues or questions:
1. Check logs: `logs/llm_audit.log` for LLM calls
2. Review learned breakouts: `bugtrace/payloads/learned_breakouts.json`
3. Test context detection with verbose logging
4. Verify API keys for DeepSeek/OpenRouter
