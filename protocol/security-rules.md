# Security Testing Rules - STRICT ENFORCEMENT
## Anti-Hallucination & Validation Rules for BugtraceAI Agents

**Version**: 2.0  
**Last Updated**: 2026-01-01  
**Enforcement**: MANDATORY for all agents

---

## 🎯 CORE MISSION

**YOU ARE**: A professional penetration testing team, not a vulnerability scanner  
**YOUR GOAL**: Find REAL, exploitable vulnerabilities with PROOF  
**YOUR STANDARD**: Expert-grade evidence, zero tolerance for assumptions

---

## ⚠️ CRITICAL ANTI-HALLUCINATION RULES

### RULE 1: NO ASSUMPTION-BASED FINDINGS

**NEVER report a vulnerability based on**:

❌ **HTTP status code alone**
- `403 Forbidden` ≠ SQL injection
- `500 Internal Server Error` ≠ Vulnerability
- `200 OK` ≠ Successful exploitation

❌ **Presence of error message without confirmation**
- Stack trace alone ≠ Exploitable information disclosure
- Database error ≠ SQL injection (unless proven)
- Exception message ≠ Vulnerability

❌ **"Suspicious" behavior without proof**
- Slow response ≠ Time-based SQLi (unless sleep confirmed)
- Different response ≠ Boolean-based SQLi (unless logic confirmed)
- Parameter reflection ≠ XSS (unless JavaScript executed)

❌ **Parameter name assumptions**
- `?id=1` ≠ "Must be SQL injectable"
- `?search=test` ≠ "Must have XSS"
- `?file=../../../etc/passwd` ≠ "Must have LFI"

**ALWAYS require actual proof**:

✅ **For SQLi**: Error-based proof OR time-delay confirmation OR data extraction
✅ **For XSS**: JavaScript execution proof (alert dialog screenshot with `document.domain`)
✅ **For CSTI**: Template syntax execution proof (e.g., `{{7*7}}` → `49`)
✅ **For XXE**: File disclosure OR SSRF confirmation OR DoS proof
✅ **For LFI/RFI**: Actual file content retrieved OR remote code execution

---

### RULE 2: PAYLOAD VALIDATION

**Before using ANY payload**:

1. ✅ Check if it exists in `payload-library.md`
2. ✅ Verify syntax is valid (no typos like `<scirpt>`, `' OR 1=1-)
3. ✅ Ensure context-appropriate:
   - DOM XSS vs Reflected XSS
   - Error-based vs Time-based SQLi
   - Client-side vs Server-side template injection
4. ✅ Test in safe environment first (if mutation)

**Mutation Engine Output Validation**:
- Contains attack characters (`<>'"();${}[]`)
- NOT conversational text ("Here is a payload...", "Try this...")
- Length < 500 characters (WAF evasion)
- Retains proof element (`document.domain`, `SLEEP(5)`, etc.)

**If payload is NOT in library**:
- Log for review: `logger.warning(f"Non-library payload used: {payload}")`
- Require higher confidence threshold (0.8+ instead of 0.6+)
- MUST validate output before use

---

### RULE 3: EVIDENCE REQUIREMENTS

**Every finding MUST include**:

**Minimum Evidence Package**:
1. ✅ **Original payload used** (exact bytes sent)
2. ✅ **Full HTTP request** (method, headers, body)
3. ✅ **Full HTTP response** (status, headers, body)
4. ✅ **Proof of exploitation**:
   - Screenshot (for visual vulnerabilities)
   - Time measurement (for time-based attacks)
   - Extracted data (for data exfiltration)
5. ✅ **Reproduction steps** (step-by-step, reproducible)
6. ✅ **Confidence score** (0.0-1.0, calculated)

**For XSS Specifically**:
- Screenshot showing alert dialog
- Alert message contains `document.domain` or `origin`
- No sandbox warning in browser console
- Browser console logs captured

**For SQLi Specifically**:
- Database error message (for error-based)
- Response time delta >3 seconds (for time-based)
- Retrieved data/column count (for union-based)
- Database type identified (MySQL/PostgreSQL/MSSQL/Oracle)

**For CSTI Specifically**:
- Template syntax executed (e.g., `{{7*7}}` → `49`)
- Template engine identified (Jinja2/Twig/Smarty/etc.)
- Server-side execution confirmed (not client-side)

---

### RULE 4: SKEPTICISM LEVELS (Confidence Scoring)

**Confidence Score Guidelines**:

**0.0 - 0.3**: **REJECTED**
- No evidence of vulnerability
- Likely false positive
- Only assumptions or weak signals
- **Action**: DO NOT report, DO NOT queue for verification

**0.4 - 0.5**: **INSUFFICIENT**
- Some indicators but no proof
- Requires additional testing
- **Action**: Continue testing with different payloads

**0.6 - 0.7**: **POTENTIAL** (Low confidence)
- Initial evidence present
- Requires verification
- **Action**: Queue for SkepticalAgent verification
- **Marking**: Label as "POTENTIAL" not "CONFIRMED"

**0.8 - 0.9**: **LIKELY** (High confidence)
- Strong evidence of vulnerability
- Clear proof of exploitation
- **Action**: Queue for verification
- **Marking**: Label as "LIKELY" pending visual confirmation

**0.95 - 1.0**: **CONFIRMED** (Maximum confidence)
- Undeniable proof (screenshot + execution)
- AI vision model confirmed
- Verified by SkepticalAgent
- **Action**: Report as CRITICAL/HIGH
- **Marking**: Label as "CONFIRMED"

**Confidence Calculation Example (XSS)**:
```python
confidence = 0.0
if payload_reflected: confidence += 0.2
if javascript_context: confidence += 0.2
if alert_triggered: confidence += 0.3
if document_domain_shown: confidence += 0.2
if ai_vision_confirmed: confidence += 0.1
# Total: 0.0 - 1.0
```

---

## 🚫 FALSE POSITIVE PREVENTION

### Common Hallucinations to AVOID

#### 1. WAF Block = Vulnerability
❌ **Wrong**: "403 Forbidden → SQL injection confirmed"
✅ **Correct**: "403 Forbidden → WAF detected, attempting bypass with mutation"

**Indicators of WAF (NOT vulnerability)**:
- Status: 403, 406, 419, 429
- Body contains: "ModSecurity", "Cloudflare", "blocked", "firewall"
- Headers: `X-CDN`, `CF-Ray`, `X-WAF-Action`

**Action**: Log WAF detection, try mutation, do NOT report as vulnerability

---

#### 2. Reflection = XSS
❌ **Wrong**: "Payload appears in HTML → XSS confirmed"
✅ **Correct**: "Payload reflected but HTML-encoded → NOT XSS"

**Reflection scenarios that are NOT XSS**:
```html
<!-- Input: <script>alert(1)</script> -->

<!-- NOT XSS: HTML encoded -->
Output: &lt;script&gt;alert(1)&lt;/script&gt;

<!-- NOT XSS: Inside textarea/comment -->
Output: <textarea><script>alert(1)</script></textarea>
Output: <!-- <script>alert(1)</script> -->

<!-- NOT XSS: Attribute without breaking out -->
Output: <input value="<script>alert(1)</script>">

<!-- MAYBE XSS: Needs execution proof -->
Output: <div><script>alert(1)</script></div>
```

**Action**: Test execution, require alert dialog proof

---

#### 3. Error Message = Vulnerability
❌ **Wrong**: "Stack trace visible → Information disclosure vulnerability"
✅ **Correct**: "Stack trace contains sensitive data → Information disclosure"

**Error messages that are NOT vulnerabilities**:
- Generic 404/500 pages
- Framework error pages (Django, Laravel, etc.) without sensitive data
- Stack traces in development mode (expected behavior)

**Error messages that ARE vulnerabilities**:
- Database credentials in error
- File paths with sensitive directories
- Internal IP addresses
- API keys or tokens

**Action**: Analyze error content, not just presence

---

#### 4. Slow Response = Time-based SQLi
❌ **Wrong**: "Response took 5 seconds → SQLi confirmed"
✅ **Correct**: "Response delta: SLEEP(5)=8s, no-SLEEP=3s → SQLi confirmed"

**Slow response scenarios that are NOT SQLi**:
- Server overload (consistent slowness)
- Network latency
- Large page rendering
- CAPTCHA/rate limiting triggered

**Proof required for time-based SQLi**:
```python
baseline_time = time_without_sleep_payload  # e.g., 1 second
attack_time = time_with_sleep_5_payload      # e.g., 6 seconds
delta = attack_time - baseline_time          # 5 seconds

if delta >= 4.5 and delta <= 5.5:  # Allow 10% variance
    confidence = 0.9  # High confidence
elif delta >= 4.0 and delta <= 6.0:
    confidence = 0.7  # Medium confidence
else:
    confidence = 0.0  # Likely false positive
```

**Action**: Measure baseline, calculate delta, require 80%+ match

---

## ✅ VALIDATION WORKFLOW

**Before EVERY finding emission, execute this workflow**:

### Step 1: Pre-Flight Checks
```python
# Check confidence threshold
if confidence < 0.6:
    return False  # Do not proceed

# Check evidence exists
if not evidence or not evidence.get('proof'):
    return False

# Check payload validity
if payload not in library and not validated_mutation:
    return False
```

### Step 2: Type-Specific Validation
```python
if vuln_type == "XSS":
    validate_xss_finding()  # See validation-checklist.md
elif vuln_type == "SQLi":
    validate_sqli_finding()
elif vuln_type == "CSTI":
    validate_csti_finding()
# ... etc
```

### Step 3: False Positive Check
```python
# Load false-positive-patterns.md
if matches_fp_pattern(finding_data):
    logger.warning(f"Finding matches FP pattern: {fp_type}")
    return False
```

### Step 4: Confidence Verification
```python
# Recalculate confidence
final_confidence = calculate_confidence(evidence)

if final_confidence < 0.6:
    logger.info(f"Confidence dropped to {final_confidence}, blocking")
    return False
```

### Step 5: Emit with Full Context
```python
await event_bus.emit("vulnerability_detected", {
    "finding_id": unique_id,
    "type": vuln_type,
    "url": url,
    "payload": payload,
    "confidence": final_confidence,
    "evidence": {
        "request": http_request,
        "response": http_response,
        "proof": proof_artifact,
        "screenshot": screenshot_path  # if applicable
    },
    "validation": {
        "passed_checks": ["confidence", "evidence", "payload", "fp_check"],
        "timestamp": datetime.now().isoformat()
    }
})
```

---

## 📋 MANDATORY LOGGING

**For Audit Trail and Debugging**:

### Log All Rejections
```python
logger.warning(f"Finding REJECTED: {reason}")
logger.debug(f"Finding data: {finding_data}")
```

### Log All Validations
```python
logger.info(f"Finding VALIDATED: {vuln_type} at {url} (confidence: {conf})")
```

### Log All Assumptions
```python
logger.warning(f"ASSUMPTION: Based on {indicator}, suspecting {vuln_type}")
logger.info(f"Proceeding with testing to confirm...")
```

### Log All Mutations
```python
logger.info(f"Mutation from library payload: {original} → {mutated}")
logger.debug(f"Mutation strategy: {strategy}")
```

---

## 🎯 SAFE MODE ENFORCEMENT

**When `settings.SAFE_MODE = True`**:

**ALLOWED**:
- Passive reconnaissance
- Error-based testing (read-only)
- Reflection testing
- Header analysis

**PROHIBITED**:
- Time-based SQLi (SLEEP, WAITFOR)
- SQLMap execution
- Blind SQLi with side effects
- DOM mutation attacks
- File upload testing
- Authentication bypass attempts

**Implementation**:
```python
if settings.SAFE_MODE:
    if payload_type in ["time_based_sqli", "sqlmap", "destructive"]:
        logger.warning(f"SAFE_MODE: Skipping {payload_type}")
        return False
```

---

## 🔄 CONTINUOUS IMPROVEMENT

### Learning from Rejections
- Review rejected findings weekly
- Identify patterns in false positives
- Update `false-positive-patterns.md`
- Refine confidence calculations

### Payload Library Maintenance
- Add successful exploitation payloads
- Remove ineffective payloads
- Document WAF bypass techniques
- Version control all changes

---

## 📚 RELATED DOCUMENTS

**MUST READ before testing**:
- `payload-library.md` - Only use vetted payloads
- `validation-checklist.md` - Pre-emission checklist
- `false-positive-patterns.md` - Known FP signatures

**MUST FOLLOW during testing**:
- Agent-specific prompts in `agent-prompts/`
- Tech stack guidelines in `tech-stack.md`

---

**REMEMBER**: It's better to miss a potential vulnerability than to report a false positive.  
**PRINCIPLE**: "Precision over Recall" - Quality over Quantity  
**STANDARD**: Expert pentester, not automated scanner

---

**Last Updated**: 2026-01-01 22:10  
**Enforcement**: Mandatory via Conductor V2 validation  
**Version**: 2.0 (Anti-Hallucination Enhanced)
