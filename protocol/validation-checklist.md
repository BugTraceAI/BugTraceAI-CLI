# Pre-Emission Validation Checklist
## Mandatory Checks Before Emitting ANY Finding Event

**Version**: 2.0  
**Last Updated**: 2026-01-01  
**Purpose**: Prevent false positives and hallucinations

---

## 🎯 CRITICAL INSTRUCTION

**RUN THIS CHECKLIST** before calling `event_bus.emit("vulnerability_detected", ...)` or `event_bus.emit("finding_verified", ...)`

**If ANY required item fails** → DO NOT EMIT  
**Log rejection reason** → `logger.warning(f"Finding BLOCKED: {reason}")`

---

## ✅ FOR XSS FINDINGS

### Evidence Checklist:

- [ ] **JavaScript executed** (not just reflected in HTML)
  - Alert dialog triggered
  - OR console.log output captured
  - OR DOM element modified
  - OR network request initiated by JS

- [ ] **Screenshot captured** showing visual proof
  - File exists and readable
  - Shows alert dialog OR console output
  - No error in screenshot capture

- [ ] **Alert message contains proof**
  - Contains `document.domain` OR `origin`
  - Shows actual target domain (not `null`, not `about:blank`)
  - Message is readable in screenshot

- [ ] **No sandbox warning** in browser console
  - Check console logs for "sandboxed"
  - Check for "null origin" errors
  - Confirm execution in target context

- [ ] **Confidence score calculated** and >= 0.6
  ```python
  confidence = calculate_xss_confidence(
      reflected=bool,
      executed=bool,
      domain_shown=bool,
      ai_confirmed=bool
  )
  ```

- [ ] **Payload from library** OR validated mutation
  - Check `payload-library.md` for exact match
  - OR verify mutation passed validation
  - Document payload source

- [ ] **HTTP request/response logged**
  - Full request (method, URL, headers, body)
  - Full response (status, headers, body)
  - Timestamps recorded

- [ ] **Reproduction steps documented**
  - Step-by-step instructions
  - Reproducible by another agent/human
  - Includes browser/environment details

### Context Validation:

- [ ] **Payload context-appropriate**
  - Reflected XSS: Breaks out of context
  - DOM XSS: Exploits DOM sink
  - Stored XSS: Persists across requests

- [ ] **Not a false positive**
  - Not just HTML encoding bypass
  - Not in safe context (textarea, comments)
  - Actual execution path confirmed

### Example Implementation:
```python
def validate_xss_finding(finding: dict) -> tuple[bool, str]:
    evidence = finding.get('evidence', {})
    
    if not evidence.get('alert_triggered'):
        return False, "Alert not triggered"
    
    if not evidence.get('screenshot'):
        return False, "No screenshot proof"
    
    screenshot = evidence.get('screenshot')
    if 'document.domain' not in screenshot and 'origin' not in screenshot:
        return False, "No domain proof in alert"
    
    if finding.get('confidence', 0) < 0.6:
        return False, f"Confidence too low: {finding.get('confidence')}"
    
    payload = finding.get('payload', '')
    if not is_valid_payload(payload, 'XSS'):
        return False, f"Invalid payload: {payload[:50]}"
    
    return True, "XSS validation passed"
```

---

## 💉 FOR SQLi FINDINGS

### Evidence Checklist:

- [ ] **Database error confirmed** (for error-based)
  - Error message contains SQL keywords
  - Database type identified (MySQL/PostgreSQL/MSSQL/Oracle)
  - NOT generic 500 error

- [ ] **OR time delay confirmed** (for time-based)
  - Baseline response time measured
  - Attack response time measured
  - Delta matches SLEEP duration (±10%)
  - Multiple tests confirm consistency

- [ ] **OR data extraction successful** (for union-based)
  - Column count determined
  - Data retrieved from database
  - OR database version retrieved

- [ ] **NOT just 403/500 status code**
  - Actual proof beyond HTTP status
  - Error message OR time delta OR data

- [ ] **Database type identified**
  - MySQL, PostgreSQL, MSSQL, Oracle, SQLite, etc.
  - Evidence: Error message OR syntax OR version()

- [ ] **Payload from library**
  - Exact match OR syntax variation
  - Appropriate for detected database type

- [ ] **Safe mode respected**
  - If `SAFE_MODE=true`, no time-based attacks
  - If `SAFE_MODE=true`, no SQLMap
  - If `SAFE_MODE=true`, no destructive queries

- [ ] **Confidence >= 0.6**
  - Error-based: Usually 0.8-0.9
  - Time-based: 0.7-0.9 (depends on consistency)
  - Union-based: 0.9+ (data extraction is definitive)

### Time-Based Validation:
```python
def validate_time_based_sqli(baseline: float, attack: float, sleep_duration: int) -> tuple[bool, float]:
    delta = attack - baseline
    expected = sleep_duration
    variance = abs(delta - expected) / expected
    
    if variance <= 0.1:  # 10% tolerance
        confidence = 0.9
    elif variance <= 0.2:  # 20% tolerance
        confidence = 0.7
    else:
        confidence = 0.0  # Too much variance
    
    return (confidence >= 0.6), confidence
```

### Example Implementation:
```python
def validate_sqli_finding(finding: dict) -> tuple[bool, str]:
    evidence = finding.get('evidence', {})
    
    has_error = evidence.get('error_message')
    has_time_delay = evidence.get('time_delay')
    has_data = evidence.get('extracted_data')
    
    if not (has_error or has_time_delay or has_data):
        return False, "No SQLi proof (error, time, or data)"
    
    if evidence.get('status_code') in [403, 500] and not has_error:
        return False, "Only status code, no error proof"
    
    if has_time_delay:
        baseline = evidence.get('baseline_time', 0)
        attack_time = evidence.get('attack_time', 0)
        delta = attack_time - baseline
        
        if delta < 3.0:  # Minimum 3 seconds for confidence
            return False, f"Time delta too small: {delta}s"
    
    conf = finding.get('confidence', 0)
    if conf < 0.6:
        return False, f"Confidence too low: {conf}"
    
    return True, "SQLi validation passed"
```

---

## 🔥 FOR CSTI FINDINGS

### Evidence Checklist:

- [ ] **Template syntax executed**
  - Input: `{{7*7}}` → Output: `49` (not `{{7*7}}`)
  - Computation performed server-side
  - NOT client-side JavaScript evaluation

- [ ] **Output shows computed result**
  - Mathematical expression evaluated
  - OR variable/function executed
  - OR template tag processed

- [ ] **Template engine identified**
  - Jinja2, Twig, Smarty, AngularJS, Vue.js, etc.
  - Evidence from error message OR syntax OR known patterns

- [ ] **NOT just reflection**
  - `{{7*7}}` reflected as `{{7*7}}` is NOT CSTI
  - Must show actual execution: `49`

- [ ] **Server-side confirmation**
  - Not AngularJS client-side evaluation
  - Verify execution happens on server

### Example Implementation:
```python
def validate_csti_finding(finding: dict) -> tuple[bool, str]:
    evidence = finding.get('evidence', {})
    payload = finding.get('payload', '')
    response = evidence.get('response_body', '')
    
    # Common test: {{7*7}}
    if '{{7*7}}' in payload:
        if '49' not in response:
            return False, "Template syntax not executed ({{7*7}} didn't become 49)"
        if '{{7*7}}' in response:
            return False, "Payload only reflected, not executed"
    
    if not evidence.get('template_engine'):
        return False, "Template engine not identified"
    
    if finding.get('confidence', 0) < 0.7:
        return False, f"CSTI confidence too low: {finding.get('confidence')}"
    
    return True, "CSTI validation passed"
```

---

## 📋 FOR ALL FINDINGS (Universal Checks)

### Minimum Requirements:

- [ ] **Confidence score >= 0.6**
  - Calculated, not assumed
  - Based on evidence quality
  - Documented calculation

- [ ] **Evidence artifacts saved**
  - HTTP request/response
  - Screenshots (if visual)
  - Logs (if relevant)
  - File paths recorded

- [ ] **No match in false-positive-patterns.md**
  - WAF blocks
  - Error pages
  - Rate limiting
  - CAPTCHA triggers

- [ ] **Reasoning logged**
  - Why this is a vulnerability
  - What proof was collected
  - Confidence calculation steps

- [ ] **Event payload complete**
  - All required fields present
  - `finding_id` unique
  - `type` correct
  - `url` valid
  - `payload` documented
  - `confidence` calculated
  - `evidence` attached

### Event Payload Schema:
```python
required_fields = {
    "finding_id": str,       # Unique identifier
    "type": str,             # XSS, SQLi, CSTI, etc.
    "url": str,              # Target URL
    "payload": str,          # Exact payload used
    "confidence": float,     # 0.0-1.0
    "evidence": dict,        # Proof artifacts
    "timestamp": str         # ISO format
}

optional_fields = {
    "severity": str,         # CRITICAL, HIGH, MEDIUM, LOW
    "detected_by": str,      # Agent name
    "validation": dict       # Validation metadata
}
```

---

## 🚫 AUTOMATIC REJECTION CRITERIA

**Instantly reject if ANY of these are true**:

### Universal Rejections:
- Confidence < 0.6
- No evidence provided
- Payload not in library and not validated mutation
- Matches known FP pattern
- WAF block (403/406) without bypass confirmation
- Generic error page without specifics

### XSS Rejections:
- Alert NOT triggered
- Screenshot missing
- Alert shows `null` or `about:blank` origin
- Payload only reflected, not executed

### SQLi Rejections:
- Only status code, no error/time/data
- Time delay < 3 seconds
- Time variance > 20%
- Generic 500 error without SQL keywords

### CSTI Rejections:
- Template syntax not executed (just reflected)
- Client-side evaluation only (AngularJS in browser)
- No template engine identified

---

## 📊 CONFIDENCE CALCULATION GUIDE

### XSS Confidence:
```python
confidence = 0.0
if payload_reflected: confidence += 0.2
if javascript_context: confidence += 0.1
if alert_triggered: confidence += 0.3
if document_domain_shown: confidence += 0.2
if no_sandbox_warning: confidence += 0.1
if ai_vision_confirmed: confidence += 0.1
# Total: 0.0 - 1.0
```

### SQLi Confidence:
```python
# Error-based
if sql_error_message: confidence = 0.85
if database_type_identified: confidence += 0.05

# Time-based
time_variance = abs(delta - expected) / expected
if time_variance <= 0.1: confidence = 0.9
elif time_variance <= 0.2: confidence = 0.7
else: confidence = 0.3

# Union-based
if data_extracted: confidence = 0.95
if column_count_determined: confidence = 0.8
```

### CSTI Confidence:
```python
confidence = 0.0
if syntax_executed: confidence += 0.4
if template_identified: confidence += 0.2
if server_side_confirmed: confidence += 0.2
if rce_possible: confidence += 0.2
# Total: 0.0 - 1.0
```

---

## 🔍 PRE-EMISSION CODE TEMPLATE

**Use this template before every emit**:

```python
async def emit_finding_with_validation(self, finding_data: dict):
    """
    Validates and emits finding event with full checks.
    """
    # Step 1: Type-specific validation
    vuln_type = finding_data.get('type')
    
    if vuln_type == 'XSS':
        is_valid, reason = validate_xss_finding(finding_data)
    elif vuln_type == 'SQLi':
        is_valid, reason = validate_sqli_finding(finding_data)
    elif vuln_type == 'CSTI':
        is_valid, reason = validate_csti_finding(finding_data)
    else:
        is_valid, reason = validate_generic_finding(finding_data)
    
    # Step 2: Check result
    if not is_valid:
        logger.warning(f"Finding BLOCKED: {reason}")
        logger.debug(f"Finding data: {finding_data}")
        return False
    
    # Step 3: Universal checks
    if finding_data.get('confidence', 0) < 0.6:
        logger.warning(f"Confidence too low: {finding_data.get('confidence')}")
        return False
    
    # Step 4: FP check
    if matches_false_positive_pattern(finding_data):
        logger.warning(f"Matches FP pattern")
        return False
    
    # Step 5: Emit with validation metadata
    finding_data['validation'] = {
        'passed': True,
        'checks_run': ['type_specific', 'confidence', 'fp_check'],
        'timestamp': datetime.now().isoformat()
    }
    
    await self.event_bus.emit("vulnerability_detected", finding_data)
    logger.info(f"Finding EMITTED: {vuln_type} at {finding_data['url']}")
    
    return True
```

---

## ✅ SUCCESS CRITERIA

**A finding is ready to emit when**:

1. ✅ All type-specific checks passed
2. ✅ Confidence >= 0.6
3. ✅ Evidence complete and saved
4. ✅ No FP pattern match
5. ✅ Payload validated
6. ✅ Logged with full context

**Emit rate target**: <5% of tested inputs result in findings (precision over recall)

---

**Last Updated**: 2026-01-01 22:10  
**Enforcement**: Mandatory via Conductor V2  
**Version**: 2.0 (Anti-Hallucination Enhanced)
