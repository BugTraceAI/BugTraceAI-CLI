# Payload Breakouts System

This directory contains the intelligent breakout management system for HTTP manipulation campaigns.

## Overview

The breakout system uses context analysis to intelligently select payload prefixes that match the reflection context, dramatically reducing the number of requests needed while increasing success rates.

## Architecture

```
┌─────────────────────────────────────────┐
│ Phase 0: CONTEXT DETECTION              │
│ • Send probe "bugtraceomni7x9z"         │
│ • Detect reflection context             │
│ • Select 5-15 targeted breakouts        │
└─────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────┐
│ Phase 1a: STATIC PAYLOADS (~50)         │
└─────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────┐
│ Phase 1b: LLM EXPANSION                 │
│ • LLM generates 100 creative payloads   │
│ • Expand with context-specific breakouts│
│ • Result: ~1,000 targeted payloads      │
└─────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────┐
│ Phase 2: WAF BYPASS (Q-learning)        │
└─────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────┐
│ Phase 3: AGENTIC FALLBACK               │
└─────────────────────────────────────────┘
```

## Files

### `breakouts.json`
Base breakout prefixes (manually curated). This file is tracked in git.

**Structure:**
```json
{
  "version": "2.0",
  "description": "...",
  "last_updated": "2026-02-02T00:00:00",
  "breakouts": [
    {
      "prefix": "'",
      "description": "Single quote (universal)",
      "category": "xss,sqli",
      "priority": 1,
      "success_count": 0,
      "enabled": true
    }
  ]
}
```

**Priority Levels:**
- `1` = Critical (always used, ~8 breakouts)
- `2` = High value (common contexts, ~19 breakouts)
- `3` = Normal (situational, ~40 breakouts) [DEFAULT]
- `4` = Advanced (specialized, ~45 breakouts)

### `learned_breakouts.json`
Auto-learned breakouts from successful attacks (generated at runtime, gitignored).

When a payload succeeds with an unknown breakout prefix, it's automatically extracted and saved here for future use.

## Manual Editing

### Adding Custom Breakouts

Edit `breakouts.json` to add target-specific breakouts:

```json
{
  "prefix": "'}//",
  "description": "Custom breakout for target X",
  "category": "xss",
  "priority": 2,
  "success_count": 0,
  "enabled": true
}
```

### Disabling Breakouts

Set `enabled: false` to temporarily disable a breakout without deleting it:

```json
{
  "prefix": "%00",
  "description": "Null byte (doesn't work on target)",
  "enabled": false
}
```

### Categories

Breakouts can belong to multiple categories (comma-separated):
- `xss` - Cross-Site Scripting
- `sqli` - SQL Injection
- `ssti` - Server-Side Template Injection
- `cmd` - Command Injection
- `lfi` - Local File Inclusion
- `crlf` - CRLF Injection
- `general` - Universal breakouts

## Auto-Learning

The system automatically learns new breakouts when:

1. A payload succeeds with validation
2. The breakout prefix is extracted from the payload
3. If the prefix is new, it's saved to `learned_breakouts.json`
4. Statistics are updated in `breakouts.json`

**Example:**

```
[INFO] Phase 1b: SUCCESS with intelligent payload #347
[INFO] 🎯 NEW BREAKOUT DISCOVERED: "'%20OR%20" (type: sqli)
[INFO] 💾 Saved learned breakout to learned_breakouts.json
```

## Context Detection

The system detects 15+ reflection contexts:

### HTML Contexts
- `html_attr_single` - Single-quoted attribute: `value='PROBE'`
- `html_attr_double` - Double-quoted attribute: `value="PROBE"`
- `html_tag_body` - Tag body: `<div>PROBE</div>`
- `html_comment` - HTML comment: `<!-- PROBE -->`

### JavaScript Contexts
- `js_string_single` - JS string: `var x = 'PROBE'`
- `js_string_double` - JS string: `var x = "PROBE"`
- `js_template` - Template literal: `` var x = `PROBE` ``
- `script_tag` - Script tag: `<script>PROBE</script>`

### Other Contexts
- `template_engine` - SSTI: `{{PROBE}}`, `${PROBE}`
- `sql_error` - SQL error messages
- `json_string` - JSON: `{"key": "PROBE"}`
- `url_param` - URL parameter: `?x=PROBE`
- `style_tag` - CSS: `<style>PROBE</style>`

Each context maps to 5-15 appropriate breakout prefixes.

## Statistics

View top-performing breakouts:

```python
from bugtrace.tools.manipulator.breakout_manager import breakout_manager

# Show top 10 most successful breakouts
top = breakout_manager.get_top_breakouts(10)
for b in top:
    print(f"{b.prefix!r}: {b.success_count} successes ({b.category})")
```

**Output:**
```
"'": 47 successes (xss,sqli)
'"': 38 successes (xss,sqli)
"'>": 29 successes (xss)
"';": 23 successes (xss,sqli)
...
```

## Reloading Configuration

After manually editing `breakouts.json`, reload without restarting:

```python
from bugtrace.tools.manipulator.breakout_manager import breakout_manager
breakout_manager.reload()
```

## Performance

### Without Context Detection (old)
```
100 LLM payloads × 40 breakouts = 4,000 requests
Success rate: Lower (many irrelevant attempts)
```

### With Context Detection (new)
```
1 probe + 100 LLM payloads × 10 targeted breakouts = ~1,000 requests
Success rate: Higher (focused on relevant breakouts)
Speed: 4x faster
```

## Configuration

Adjust behavior in `bugtraceaicli.conf`:

```ini
[MANIPULATOR]
# Enable/disable LLM expansion
ENABLE_LLM_EXPANSION = true

# Breakout priority level (1-4)
BREAKOUT_PRIORITY_LEVEL = 3

# Enable auto-learning
ENABLE_BREAKOUT_LEARNING = true
```

## Best Practices

1. **Start with default breakouts** - The base list covers 90% of cases
2. **Monitor learned breakouts** - Review `learned_breakouts.json` periodically
3. **Merge successful patterns** - Move proven breakouts from `learned_breakouts.json` to `breakouts.json`
4. **Disable ineffective breakouts** - Set `enabled: false` instead of deleting
5. **Use categories** - Filter breakouts by vulnerability type for speed
6. **Check statistics** - High `success_count` = keep, low count = consider removing

## Troubleshooting

### No breakouts loaded
```
[ERROR] Breakouts file not found: .../breakouts.json
```
**Solution:** Ensure `breakouts.json` exists in `bugtrace/payloads/`

### LLM expansion skipped
```
[WARNING] Phase 1.5: Skipped (no payloads generated)
```
**Solution:** Check DeepSeek API key and model configuration

### Context detection fails
```
[INFO] Phase 0: No reflection detected
```
**Solution:** Parameter may not be injectable, or probe is filtered

## Examples

### Example 1: XSS in HTML Attribute

**Probe result:**
```html
<input type="text" value="bugtraceomni7x9z">
```

**Context detected:** `html_attr_double`

**Selected breakouts:**
```
", ">, "><, " onload=", " autofocus onfocus=", "//
```

**Expansion:**
```
100 base payloads × 6 breakouts = 600 targeted payloads
```

### Example 2: SQLi in Error Message

**Probe result:**
```
SQL Error: You have an error in your SQL syntax near 'bugtraceomni7x9z'
```

**Context detected:** `sql_error`

**Selected breakouts:**
```
', ", '--, '#, '/*, '), ')--,'))--,' OR '1'='1, ' UNION
```

**Expansion:**
```
100 base payloads × 10 breakouts = 1,000 targeted payloads
```

## Contributing

When adding new breakouts to the base list:

1. Test the breakout on real targets
2. Assign appropriate priority (1-4)
3. Add clear description
4. Specify relevant categories
5. Set `success_count: 0` initially
6. Keep `enabled: true`

## License

Part of BugTraceAI project.
