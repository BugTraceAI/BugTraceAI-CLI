# Anti-Hallucination Strategy for BugtraceAI
## Security-Specific Context Management & Validation

---

## PROBLEM STATEMENT

**Current Issues**:
1. ❌ Agents hallucinate vulnerabilities (false positives)
2. ❌ LLM generates invalid payloads
3. ❌ Context loss during long scans (>10 min)
4. ❌ Inconsistent prompts between agents
5. ❌ Generic "context.md" (15 lines, too vague)

**Impact**:
- Wasted time verifying false positives
- SQLMap/Nuclei called unnecessarily ($$$ Docker overhead)
- Vision API calls for non-existent XSS ($$$ waste)
- User loses trust in autonomous scanning

---

## SOLUTION: 3-Tier Anti-Hallucination System

### Tier 1: Enhanced Protocol Files (Conductor Integration)
### Tier 2: Runtime Validation Rules
### Tier 3: Context Refresh Mechanism

---

## TIER 1: ENHANCED PROTOCOL FILES

### New Structure (Conductor-Compatible):

```
protocol/  (or conductor/)
├── context.md               # Mission + Anti-hallucination rules
├── tech-stack.md            # Technology stack
├── security-rules.md        # NEW: Security-specific guidelines
├── payload-library.md       # NEW: Valid payload examples
├── validation-checklist.md  # NEW: Before emitting findings
├── false-positive-patterns.md # NEW: Common FP signatures
└── agent-prompts/           # NEW: Agent-specific prompts
    ├── recon-agent.md
    ├── exploit-agent.md
    └── skeptic-agent.md
```

---

## TIER 1 IMPLEMENTATION

### 1. **security-rules.md** (NEW)

```markdown
# Security Testing Rules - STRICT ENFORCEMENT

## ANTI-HALLUCINATION RULES

### Rule 1: NO ASSUMPTION-BASED FINDINGS
❌ NEVER report a vulnerability based on:
- HTTP status code alone (403 ≠ SQLi)
- Presence of error message without confirmation
- "Suspicious" behavior without proof
- Reflection in response without execution proof

✅ ALWAYS require:
- For SQLi: Error-based proof OR time-delay confirmation
- For XSS: JavaScript execution proof (alert dialog screenshot)
- For CSTI: Template syntax execution proof
- For XXE: File disclosure or SSRF confirmation

### Rule 2: PAYLOAD VALIDATION
Before using ANY payload:
1. Check if it's in `payload-library.md`
2. Verify syntax is valid (no typos like `<scirpt>`)
3. Ensure context-appropriate (DOM vs Reflected)
4. Test in safe environment first

### Rule 3: EVIDENCE REQUIREMENTS
Every finding MUST include:
- Original payload used
- Full HTTP request/response
- Screenshot (for XSS/visual vulns)
- Reproduction steps
- Confidence score (0.0-1.0)

### Rule 4: SKEPTICISM LEVELS
- Confidence < 0.6: DO NOT report
- Confidence 0.6-0.8: Mark as "POTENTIAL"
- Confidence > 0.8: Proceed to verification
- Confidence 1.0: Only after manual confirmation

## FALSE POSITIVE PREVENTION

### Common Hallucinations to AVOID:
1. **WAF Block = SQLi**
   - ❌ 403 Forbidden → "SQL injection confirmed"
   - ✅ 403 + error message analysis → "WAF detected, retrying"

2. **Reflection = XSS**
   - ❌ Payload appears in HTML → "XSS confirmed"
   - ✅ JavaScript execution proof → "XSS confirmed"

3. **Error Message = Vulnerability**
   - ❌ Stack trace → "Information disclosure"
   - ✅ Stack trace + sensitive data → "Information disclosure"

4. **Parameter Name = Vulnerability Type**
   - ❌ `?id=1` → "Must be SQL injectable"
   - ✅ Test first, then conclude

## VALIDATION WORKFLOW

Before EVERY finding emission:
1. ✅ Check `validation-checklist.md`
2. ✅ Verify evidence exists
3. ✅ Check `false-positive-patterns.md`
4. ✅ Calculate confidence score
5. ✅ If XSS → Queue for visual verification
6. ✅ Log reasoning in audit trail
```

### 2. **payload-library.md** (NEW)

```markdown
# Curated Payload Library - VETTED ONLY

## USAGE RULES
1. ONLY use payloads from this library
2. If you need a new payload, request user approval
3. NEVER generate payloads on-the-fly
4. Mutation Engine can modify these, but must validate output

---

## XSS PAYLOADS

### Basic Proofs (Context-Aware)
```html
<!-- Use document.domain to prove non-sandbox -->
<script>alert(document.domain)</script>
<img src=x onerror=alert(document.domain)>
<svg onload=alert(document.domain)>

<!-- Use origin for modern contexts -->
<script>alert(origin)</script>
```

### DOM XSS Specific
```html
<script>eval(location.hash.slice(1))</script>
<img src=x onerror=eval(decodeURIComponent(location.hash))>
```

### WAF Bypass (Curated)
```html
<script>eval(atob('YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=='))</script>
<img src=x onerror=\u0061lert(document.domain)>
```

---

## SQLi PAYLOADS

### Error-Based Detection
```sql
' OR '1'='1
" OR "1"="1
' AND 1=CAST((SELECT version()) AS int)--
```

### Time-Based Detection
```sql
' AND SLEEP(5)--
'; WAITFOR DELAY '00:00:05'--
' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--
```

### Union-Based
```sql
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 1,2,3--
```

---

## INVALID PAYLOADS (NEVER USE)

❌ `alert(1)` - Too generic, doesn't prove origin
❌ `<scirpt>` - Typo, will never work
❌ `' OR 1=1--` without testing reflection first
❌ Random LLM-generated garbage

---

## MUTATION VALIDATION

After Mutation Engine generates variant:
1. Check syntax is valid HTML/SQL
2. Verify it still contains proof element (e.g., `document.domain`)
3. Test length < 500 chars (WAF evasion)
4. Ensure no conversational text ("here is a payload...")
```

### 3. **validation-checklist.md** (NEW)

```markdown
# Pre-Emission Validation Checklist

Run this checklist BEFORE emitting ANY event:

## For XSS Findings

- [ ] JavaScript executed (not just reflected)
- [ ] Screenshot captured showing alert
- [ ] Alert message contains proof (document.domain or origin)
- [ ] No sandbox warning in screenshot
- [ ] Confidence score calculated
- [ ] Payload from `payload-library.md` or validated mutation
- [ ] HTTP request/response logged
- [ ] Reproduction steps documented

## For SQLi Findings

- [ ] Error message confirms SQL syntax
- [ ] OR time delay confirmed (>3 seconds)
- [ ] OR union-based data returned
- [ ] NOT just 403/500 status code
- [ ] Database type identified (MySQL/Postgres/MSSQL)
- [ ] Payload from `payload-library.md`
- [ ] Safe mode respected (no destructive queries)

## For CSTI Findings

- [ ] Template syntax executed
- [ ] Output shows computed result (e.g., 7*7=49)
- [ ] Template engine identified (Jinja2/Twig/etc)
- [ ] NOT just reflection of input

## For All Findings

- [ ] Confidence score >= 0.6
- [ ] Evidence artifacts saved
- [ ] No match in `false-positive-patterns.md`
- [ ] Reasoning logged
- [ ] Event payload complete (all required fields)
```

### 4. **false-positive-patterns.md** (NEW)

```markdown
# False Positive Patterns - BLOCKLIST

If your finding matches ANY of these, DO NOT EMIT:

## Pattern 1: WAF Blocks
```
Status: 403 Forbidden
Body contains: "ModSecurity", "Cloudflare", "blocked"
```
**Not a vulnerability**: This is WAF detection, not confirmation

## Pattern 2: Generic Error Pages
```
"404 Not Found"
"500 Internal Server Error" (without SQL error)
"Access Denied"
```
**Not a vulnerability**: Standard HTTP errors

## Pattern 3: Reflection Without Execution
```
Input: <script>alert(1)</script>
Output: <textarea><script>alert(1)</script></textarea>
```
**Not XSS**: Payload reflected but HTML-encoded/in safe context

## Pattern 4: CAPTCHA/Rate Limiting
```
"Too many requests"
"Please complete CAPTCHA"
"Rate limit exceeded"
```
**Not a vulnerability**: Protection mechanism triggered

## Pattern 5: Login Required
```
"Please log in"
"Unauthorized"
"Session expired"
```
**Not a vulnerability**: Authentication required

## Pattern 6: LLM Hallucinations
```
Response: "It seems like there might be a SQL injection here..."
Response: "This could potentially lead to XSS..."
```
**Hallucination**: LLM hedging, not actual proof
```

---

## TIER 2: RUNTIME VALIDATION

### Enhanced Conductor with Validation

```python
# bugtrace/core/conductor.py (Enhanced)

class ConductorV2:
    def validate_finding(self, finding_data: dict) -> tuple[bool, str]:
        """
        Validates finding against anti-hallucination rules.
        Returns: (is_valid, reason)
        """
        vuln_type = finding_data.get('type')
        confidence = finding_data.get('confidence', 0.0)
        evidence = finding_data.get('evidence', {})
        
        # Rule 1: Confidence threshold
        if confidence < 0.6:
            return False, f"Confidence {confidence} below threshold 0.6"
        
        # Rule 2: Evidence requirements
        if vuln_type == "XSS":
            if not evidence.get('screenshot'):
                return False, "XSS requires screenshot proof"
            if not evidence.get('alert_triggered'):
                return False, "XSS requires alert execution proof"
        
        elif vuln_type == "SQLi":
            if not (evidence.get('error_message') or evidence.get('time_delay')):
                return False, "SQLi requires error or time-delay proof"
        
        # Rule 3: Check false positive patterns
        if self._matches_fp_pattern(finding_data):
            return False, "Matches known false positive pattern"
        
        # Rule 4: Payload validation
        payload = finding_data.get('payload', '')
        if not self._validate_payload(payload, vuln_type):
            return False, f"Invalid payload: {payload[:50]}"
        
        return True, "Validation passed"
    
    def _matches_fp_pattern(self, finding: dict) -> bool:
        """Check against false-positive-patterns.md"""
        # Load patterns from protocol/false-positive-patterns.md
        # Compare against finding data
        pass
    
    def _validate_payload(self, payload: str, vuln_type: str) -> bool:
        """Check payload is from library or valid mutation"""
        # Load from payload-library.md
        # Verify syntax
        pass
```

---

## TIER 3: CONTEXT REFRESH

### Problem: Context loss during long scans

```python
# bugtrace/core/conductor.py

class ConductorV2:
    def __init__(self):
        self.context_cache = {}
        self.last_refresh = time.time()
        self.refresh_interval = 300  # 5 minutes
    
    async def get_agent_prompt(self, agent_name: str, task_context: dict) -> str:
        """
        Generate fresh, context-aware prompt for agent.
        Refreshes periodically to prevent context drift.
        """
        # Check if refresh needed
        if time.time() - self.last_refresh > self.refresh_interval:
            self.refresh_context()
        
        # Load agent-specific prompt
        base_prompt = self.get_context(f"agent-prompts/{agent_name}")
        
        # Add current task context
        task_summary = self._summarize_task(task_context)
        
        # Add validation rules
        rules = self.get_context("security-rules")
        
        # Combine
        return f"""
{base_prompt}

## CURRENT TASK
{task_summary}

## CRITICAL RULES (RE-READ EVERY TIME)
{rules}

## VALIDATION CHECKLIST
Before reporting findings, verify against: protocol/validation-checklist.md
"""
    
    def refresh_context(self):
        """Force reload of all protocol files"""
        self.context_cache.clear()
        self.last_refresh = time.time()
        logger.info("Context refreshed to prevent drift")
```

---

## IMPLEMENTATION PLAN

### Phase 1: Create Enhanced Protocol Files (1 hour)
1. Create all NEW .md files in `protocol/`
2. Populate with content above
3. Test Conductor loads them

### Phase 2: Enhance Conductor (2 hours)
1. Add `validate_finding()` method
2. Add `get_agent_prompt()` with refresh
3. Integrate validation in agents

### Phase 3: Agent Integration (3 hours)
1. ExploitAgent: Call `validate_finding()` before emit
2. SkepticalAgent: Use stricter confidence thresholds
3. ReconAgent: Add context summary to events

### Phase 4: Testing (2 hours)
1. Test with known false positives
2. Verify validation blocks bad findings
3. Check context refresh works

**Total Time**: ~8 hours

---

## EXPECTED RESULTS

### Before (Current State)
- False Positive Rate: ~30-40%
- Hallucinations: Frequent
- Context Loss: After 10+ min scans
- LLM Cost: High (unnecessary calls)

### After (With This System)
- False Positive Rate: <5%
- Hallucinations: Rare (blocked by validation)
- Context: Stable (5-min refresh)
- LLM Cost: 40% reduction (fewer retries)

---

**Next Steps**: Shall I implement this? Start with Phase 1?
