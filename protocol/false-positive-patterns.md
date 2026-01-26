# False Positive Patterns - BLOCKLIST
## Known Signatures That Should NOT Be Reported as Vulnerabilities

**Version**: 2.0  
**Last Updated**: 2026-01-01  
**Purpose**: Prevent hallucinations and false positives

---

## 🚫 USAGE

**Before emitting ANY finding, check against these patterns.**

**If finding matches ANY pattern** → BLOCK emission  
**Log rejection** → `logger.warning(f"FP Pattern Match: {pattern_name}")`

---

## Pattern 1: WAF/CDN Blocks

### Signatures:

**HTTP Status Codes**:
```
403 Forbidden
406 Not Acceptable
419 Authentication Timeout
429 Too Many Requests
444 No Response (Nginx)
460-499 (Custom CDN codes)
```

**Response Body Contains**:
```
ModSecurity
Cloudflare
Incapsula
Akamai
Blocked
Forbidden
Firewall
Security policy
Request rejected
Access denied
```

**Response Headers**:
```
X-CDN: Cloudflare
CF-RAY: *
X-Akamai-Session-Info: *
X-WAF-Action: block
Server: cloudflare
Server: AkamaiGHost
```

### Detection Function:
```python
def is_waf_block(response: dict) -> bool:
    status = response.get('status_code')
    body = response.get('body', '').lower()
    headers = response.get('headers', {})
    
    # Status code check
    if status in [403, 406, 419, 429, 444]:
        return True
    
    # Body keywords
    waf_keywords = [
        'modsecurity', 'cloudflare', 'incapsula', 'akamai',
        'blocked', 'firewall', 'security policy', 'request rejected'
    ]
    if any(keyword in body for keyword in waf_keywords):
        return True
    
    # Header check
    waf_headers = ['CF-RAY', 'X-WAF-Action', 'X-Akamai-Session-Info']
    if any(header in headers for header in waf_headers):
        return True
    
    return False
```

### NOT a Vulnerability:
- ❌ "403 Forbidden → SQL injection confirmed"
- ❌ "Blocked by firewall → XSS detected"
- ❌ "ModSecurity triggered → Vulnerability found"

### Correct Action:
- ✅ Log as WAF detection
- ✅ Attempt mutation/bypass
- ✅ If bypass successful, THEN report
- ✅ Never report WAF block alone as vuln

---

## Pattern 2: Generic Error Pages

### Signatures:

**404 Not Found**:
```html
<title>404 Not Found</title>
404 - File or directory not found
The resource you are looking for might have been removed
This page does not exist
```

**500 Internal Server Error** (without SQL/stack trace):
```html
<title>500 Internal Server Error</title>
Internal Server Error
Something went wrong
We're sorry, but something went wrong
The server encountered an error
```

**400 Bad Request**:
```html
<title>400 Bad Request</title>
Bad Request
Your browser sent a request that this server could not understand
Invalid request
```

### Detection Function:
```python
def is_generic_error_page(response: dict) -> bool:
    status = response.get('status_code')
    body = response.get('body', '')
    
    # Only generic errors (no stack trace, no SQL error)
    if status == 404:
        return True
    
    if status == 500:
        # Check for specific error content
        has_stack_trace = any(keyword in body for keyword in [
            'Traceback', 'Exception', 'at line', 'stack trace'
        ])
        has_sql_error = any(keyword in body.lower() for keyword in [
            'sql', 'mysql', 'postgres', 'oracle', 'syntax error'
        ])
        
        # Generic 500 without details
        if not has_stack_trace and not has_sql_error:
            return True
    
    if status == 400:
        # Generic bad request without specifics
        generic_400_msgs = [
            'bad request',
            'invalid request',
            'your browser sent a request'
        ]
        if any(msg in body.lower() for msg in generic_400_msgs):
            return True
    
    return False
```

### NOT a Vulnerability:
- ❌ "404 page → Path traversal"
- ❌ "500 error → SQL injection"
- ❌ "400 bad request → Input validation bypass"

### Correct Action:
- ✅ Verify error has specific details (SQL keywords, stack trace, etc.)
- ✅ Only report if error discloses sensitive information
- ✅ Never report generic error pages

---

## Pattern 3: Reflection Without Execution

### Signatures:

**HTML Encoded Reflection**:
```html
<!-- Input: <script>alert(1)</script> -->
Output: &lt;script&gt;alert(1)&lt;/script&gt;
```

**Inside Textarea** (safe context):
```html
<textarea><script>alert(1)</script></textarea>
```

**Inside HTML Comments**:
```html
<!-- <script>alert(1)</script> -->
<!-- User input: <img src=x onerror=alert(1)> -->
```

**Inside Quoted Attribute** (without breaking out):
```html
<input value="<script>alert(1)</script>">
<div data-user="<img src=x onerror=alert(1)>">
```

**Inside JavaScript String** (properly escaped):
```javascript
var input = "<script>alert(1)<\/script>";
var data = "\<img src=x onerror=alert(1)\>";
```

### Detection Function:
```python
def is_safe_reflection(payload: str, response_body: str) -> bool:
    # Check HTML encoding
    encoded_payload = html.escape(payload)
    if encoded_payload in response_body:
        return True  # Payload is HTML encoded
    
    # Check if inside textarea
    if f'<textarea>{payload}</textarea>' in response_body:
        return True
    
    # Check if inside comment
    if f'<!-- {payload} -->' in response_body:
        return True
    
    # Check if inside quoted attribute without breaking out
    patterns = [
        f'value="{payload}"',
        f"value='{payload}'",
        f'data-user="{payload}"'
    ]
    if any(pattern in response_body for pattern in patterns):
        # Payload is quoted, check if it breaks out
        if not ('"' in payload or "'" in payload):
            return True  # Can't break out
    
    return False
```

### NOT XSS:
- ❌ "Payload reflected → XSS confirmed"
- ❌ "Input appears in HTML → Vulnerability"
- ❌ "Found in page source → Exploitable"

### Correct Action:
- ✅ Verify JavaScript execution (alert dialog)
- ✅ Check if payload breaks out of safe context
- ✅ Only report if actual execution confirmed

---

## Pattern 4: CAPTCHA/Rate Limiting

### Signatures:

**CAPTCHA Triggers**:
```html
<title>Please verify you are human</title>
Complete the CAPTCHA below
reCAPTCHA
hCaptcha
Solve the puzzle
Click all images with
```

**Rate Limiting Messages**:
```
Too many requests
Rate limit exceeded
Please slow down
Try again later
You have been temporarily blocked
429 Too Many Requests
```

**Bot Detection**:
```
We've detected unusual activity
Your IP has been flagged
Automated access detected
Please verify you are not a robot
```

### Detection Function:
```python
def is_bot_protection(response: dict) -> bool:
    status = response.get('status_code')
    body = response.get('body', '').lower()
    
    # Rate limiting
    if status == 429:
        return True
    
    # CAPTCHA keywords
    captcha_keywords = [
        'recaptcha', 'hcaptcha', 'captcha',
        'verify you are human', 'solve the puzzle',
        'you are not a robot'
    ]
    if any(keyword in body for keyword in captcha_keywords):
        return True
    
    # Rate limit keywords
    rate_limit_keywords = [
        'too many requests', 'rate limit', 'slow down',
        'temporarily blocked', 'unusual activity'
    ]
    if any(keyword in body for keyword in rate_limit_keywords):
        return True
    
    return False
```

### NOT a Vulnerability:
- ❌ "CAPTCHA appeared → SQL injection"
- ❌ "Rate limited → Vulnerability confirmed"
- ❌ "Bot detection → Security bypass"

### Correct Action:
- ✅ Log as protection mechanism
- ✅ Reduce request rate
- ✅ Do NOT report as vulnerability

---

## Pattern 5: Authentication/Authorization Required

### Signatures:

**Login Required**:
```html
<title>Login</title>
Please log in
Sign in required
You must be logged in
Unauthorized access
Session expired
```

**403 Forbidden** (with auth message):
```html
403 Forbidden - You don't have permission
Access denied - insufficient privileges
This action requires authentication
Please contact administrator
```

**Redirect to Login**:
```
HTTP 302 → Location: /login
HTTP 301 → Location: /signin
HTTP 307 → Location: /auth/login
```

### Detection Function:
```python
def is_auth_required(response: dict) -> bool:
    status = response.get('status_code')
    body = response.get('body', '').lower()
    headers = response.get('headers', {})
    
    # Auth status codes
    if status in [401, 403]:
        auth_keywords = [
            'login', 'sign in', 'unauthorized',
            'authentication required', 'session expired'
        ]
        if any(keyword in body for keyword in auth_keywords):
            return True
    
    # Redirect to login
    if status in [301, 302, 307]:
        location = headers.get('Location', '').lower()
        if any(path in location for path in ['/login', '/signin', '/auth']):
            return True
    
    return False
```

### NOT a Vulnerability:
- ❌ "401 Unauthorized → Bypassed authentication"
- ❌ "Redirected to login → Security flaw"
- ❌ "Session expired → Vulnerability"

### Correct Action:
- ✅ Attempt authentication if credentials available
- ✅ Test authenticated vs unauthenticated access
- ✅ Only report actual bypass, not auth requirement

---

## Pattern 6: LLM Hallucination Language

### Signatures:

**Hedging Language** (LLM uncertainty):
```
It seems like there might be...
This could potentially lead to...
There appears to be a possibility of...
It looks like this may be vulnerable...
I suspect this could be...
```

**Conversational Responses**:
```
Here is a payload you could try...
You should test this with...
Consider attempting...
Try the following...
Based on the response, it's likely...
```

**Conditional Statements**:
```
If this is vulnerable, then...
Assuming the server is...
In case there is a...
Should there be a...
```

### Detection Function:
```python
def is_llm_hallucination(text: str) -> bool:
    hallucination_phrases = [
        'seems like', 'might be', 'could potentially',
        'appears to be', 'looks like', 'i suspect',
        'here is a', 'you should', 'consider',
        'try the following', 'if this is', 'assuming'
    ]
    
    text_lower = text.lower()
    
    # Check for hedging language
    hedge_count = sum(1 for phrase in hallucination_phrases if phrase in text_lower)
    
    if hedge_count >= 2:
        return True  # Too much uncertainty
    
    # Check for conversational tone
    conversational = [
        'you could', 'you should', 'you might',
        'we can', 'let\'s try', 'i recommend'
    ]
    if any(phrase in text_lower for phrase in conversational):
        return True
    
    return False
```

### NOT Evidence:
- ❌ "AI says 'might be vulnerable' → Report as finding"
- ❌ "Looks like SQLi → Confirmed SQLi"
- ❌ "Could potentially → High confidence"

### Correct Action:
- ✅ Treat as hypothesis, not evidence
- ✅ Test specifically for suggested vulnerability
- ✅ Only report with concrete proof
- ✅ Never base findings on LLM speculation

---

## 🔍 COMPREHENSIVE FP CHECK FUNCTION

**Use this master function**:

```python
def matches_false_positive_pattern(finding: dict) -> tuple[bool, str]:
    """
    Checks finding against all FP patterns.
    Returns: (is_fp, pattern_name)
    """
    response = finding.get('evidence', {}).get('response', {})
    
    # Pattern 1: WAF Block
    if is_waf_block(response):
        return True, "WAF_BLOCK"
    
    # Pattern 2: Generic Error
    if is_generic_error_page(response):
        return True, "GENERIC_ERROR"
    
    # Pattern 3: Safe Reflection
    payload = finding.get('payload', '')
    response_body = response.get('body', '')
    if is_safe_reflection(payload, response_body):
        return True, "SAFE_REFLECTION"
    
    # Pattern 4: Bot Protection
    if is_bot_protection(response):
        return True, "BOT_PROTECTION"
    
    # Pattern 5: Auth Required
    if is_auth_required(response):
        return True, "AUTH_REQUIRED"
    
    # Pattern 6: LLM Hallucination
    reasoning = finding.get('reasoning', '')
    if is_llm_hallucination(reasoning):
        return True, "LLM_HALLUCINATION"
    
    return False, None
```

---

## 📊 FP PATTERN STATISTICS

**Track blocked findings by pattern**:

```python
fp_stats = {
    "WAF_BLOCK": 0,
    "GENERIC_ERROR": 0,
    "SAFE_REFLECTION": 0,
    "BOT_PROTECTION": 0,
    "AUTH_REQUIRED": 0,
    "LLM_HALLUCINATION": 0
}

# Log on each block
def log_fp_block(pattern_name: str):
    fp_stats[pattern_name] += 1
    logger.info(f"FP Pattern Stats: {fp_stats}")
```

---

## ✅ VALIDATION LOGIC

**Integrate with validation workflow**:

```python
# In validate_finding() function
is_fp, pattern = matches_false_positive_pattern(finding_data)

if is_fp:
    logger.warning(f"Finding BLOCKED by FP pattern: {pattern}")
    log_fp_block(pattern)
    return False, f"Matches FP pattern: {pattern}"

return True, "No FP pattern match"
```

---

## 🔄 PATTERN MAINTENANCE

**Update this file when**:
- New FP patterns discovered during testing
- WAF signatures change
- New protection mechanisms deployed
- LLM behavior shifts

**Review Cycle**: Monthly or after 100+ scans

---

**Last Updated**: 2026-01-01 22:10  
**Patterns**: 6 categories, 50+ signatures  
**Enforcement**: Mandatory via Conductor V2  
**Version**: 2.0 (Anti-Hallucination Enhanced)
