# GEMINI HANDOFF: Confidence Scoring System + Missing Agent Integrations

**Date:** 2026-01-20  
**Priority:** HIGH  
**Estimated Time:** 45-60 minutes  
**Scope:** STRICTLY LIMITED - Do NOT modify anything outside this document

---

## 🎯 OBJECTIVES

1. **Implement 0-10 confidence scoring** for DASTySAST → Skeptical pipeline
2. **Add per-vulnerability-type thresholds** in config
3. **Integrate missing agents** (SSRF, LFI, RCE) into the dispatcher

---

## 📋 PART 1: Configuration Changes

### FILE 1: `bugtraceaicli.conf`

**Location:** `/home/ubuntu/Dev/Projects/BugTraceAI/BugTraceAI-CLI/bugtraceaicli.conf`

**Action:** Add this NEW section after the `[MODELS]` section (around line 50):

```ini
# =============================================================================
# SKEPTICAL REVIEW THRESHOLDS
# =============================================================================
# Minimum confidence score (0-10) for findings to pass to specialist agents
# Lower = more permissive (more tested), Higher = stricter (fewer tested)
# CRITICAL vulns have LOWER thresholds to avoid missing them

[SKEPTICAL_THRESHOLDS]
# CRITICAL - Very low threshold, don't miss these
RCE = 4
SQLI = 4

# HIGH - Low threshold
XXE = 5
SSRF = 5
LFI = 5

# MEDIUM - Standard threshold  
XSS = 5
JWT = 6
FILE_UPLOAD = 6

# LOW RISK - Higher threshold
IDOR = 6

# Fallback for unknown types
DEFAULT = 5
```

---

### FILE 2: `bugtrace/core/config.py`

**Location:** `/home/ubuntu/Dev/Projects/BugTraceAI/BugTraceAI-CLI/bugtrace/core/config.py`

**Action:** Add these attributes to the Settings class (find where other settings are defined):

```python
    # Skeptical Review Thresholds (0-10 scale)
    # CRITICAL vulns have LOWER thresholds to avoid missing them
    SKEPTICAL_THRESHOLDS: dict = {
        "RCE": 4,      # Critical - don't miss
        "SQLI": 4,     # Critical - don't miss
        "XXE": 5,      # High risk
        "SSRF": 5,     # High risk
        "LFI": 5,      # High risk
        "XSS": 5,      # Medium, easy to verify
        "JWT": 6,      # Medium
        "FILE_UPLOAD": 6,  # Medium
        "IDOR": 6,     # Lower risk
        "DEFAULT": 5   # Fallback
    }
```

**ALSO add a helper method** to the Settings class:

```python
    def get_threshold_for_type(self, vuln_type: str) -> int:
        """Get the skeptical threshold for a vulnerability type."""
        vuln_upper = vuln_type.upper()
        for key in self.SKEPTICAL_THRESHOLDS:
            if key in vuln_upper:
                return self.SKEPTICAL_THRESHOLDS[key]
        return self.SKEPTICAL_THRESHOLDS.get("DEFAULT", 6)
```

---

## 📋 PART 2: DASTySAST Prompt Changes

### FILE 3: `bugtrace/agents/analysis_agent.py`

**Location:** `/home/ubuntu/Dev/Projects/BugTraceAI/BugTraceAI-CLI/bugtrace/agents/analysis_agent.py`

#### Change 1: Update `_analyze_with_approach` prompt (around line 230-260)

**FIND this text in the prompt:**

```
3. Assign confidence (0.1 - 1.0). Only assign 0.5+ if you have CLEAR indicators
```

**REPLACE with:**

```
3. Assign a CONFIDENCE SCORE from 0 to 10:
   - 0-3: Weak - parameter name only, no evidence
   - 4-5: Low - some patterns but unconfirmed
   - 6-7: Medium - clear patterns, worth testing
   - 8-9: High - error messages, unescaped reflection
   - 10: Confirmed - obvious vulnerability
```

**FIND the XML example:**

```xml
<confidence>0.9</confidence>
```

**REPLACE with:**

```xml
<confidence_score>7</confidence_score>
```

#### Change 2: Update parsing logic (around line 279-292)

**FIND:**

```python
conf_str = parser.extract_tag(vc, "confidence") or "0.5"
try:
    conf = float(conf_str)
except:
    conf = 0.5
```

**REPLACE WITH:**

```python
conf_str = parser.extract_tag(vc, "confidence_score") or parser.extract_tag(vc, "confidence") or "5"
try:
    conf = int(float(conf_str))
    conf = max(0, min(10, conf))  # Clamp to 0-10
except:
    conf = 5
```

**FIND in the vulnerabilities.append block:**

```python
"confidence": conf,
```

**REPLACE with:**

```python
"confidence_score": conf,
```

---

## 📋 PART 3: Skeptical Review Changes

### Same FILE: `bugtrace/agents/analysis_agent.py`

#### Change 3: Update `_skeptical_review` method (around line 340-456)

**FIND the vulns_summary generation (around line 362-367):**

```python
vulns_summary = "\n\n".join([
    f"""{i+1}. {v.get('type')} on '{v.get('parameter')}'
   Confidence: {v.get('confidence'):.2f} | Votes: {v.get('votes', 1)}/5
```

**REPLACE WITH:**

```python
vulns_summary = "\n\n".join([
    f"""{i+1}. {v.get('type')} on '{v.get('parameter')}'
   DASTySAST Score: {v.get('confidence_score', 5)}/10 | Votes: {v.get('votes', 1)}/5
```

#### Change 4: Replace the ENTIRE prompt (lines ~369-418) with

```python
        prompt = f"""You are a security expert reviewing vulnerability findings.

=== TARGET ===
URL: {self.url}

=== FINDINGS ({len(vulnerabilities)} total) ===
{vulns_summary}

=== YOUR TASK ===
For EACH finding, evaluate and assign a FINAL CONFIDENCE SCORE (0-10).

SCORING GUIDE:
- 0-3: REJECT - No evidence, parameter name only, "EXPECTED: SAFE" present
- 4-5: LOW - Weak indicators, probably false positive
- 6-7: MEDIUM - Some patterns, worth testing by specialist
- 8-9: HIGH - Clear evidence (SQL errors, unescaped reflection)
- 10: CONFIRMED - Obvious vulnerability

RULES:
1. "EXPECTED: SAFE" in context → score 0-2
2. "EXPECTED: VULNERABLE" in context → score 8-10
3. Parameter NAME alone (webhook, id, xml) is NOT enough for score > 5
4. SQL errors visible → score 8+
5. Unescaped HTML reflection → score 7+
6. Adjust DASTySAST score up/down based on your analysis

Return XML:
<reviewed>
  <finding>
    <index>1</index>
    <type>XSS</type>
    <final_score>7</final_score>
    <reasoning>Brief explanation</reasoning>
  </finding>
</reviewed>
"""
```

#### Change 5: Replace parsing and filtering logic (after LLM call, around line 434-456)

**FIND the block starting with:**

```python
parser = XmlParser()
approved_blocks = parser.extract_list(response, "vulnerability")
```

**REPLACE EVERYTHING from that line until the `return approved` line with:**

```python
            parser = XmlParser()
            finding_blocks = parser.extract_list(response, "finding")
            
            approved = []
            
            for block in finding_blocks:
                try:
                    idx = int(parser.extract_tag(block, "index")) - 1
                    vuln_type = parser.extract_tag(block, "type") or "UNKNOWN"
                    final_score = int(parser.extract_tag(block, "final_score") or "0")
                    reasoning = parser.extract_tag(block, "reasoning") or ""
                    
                    # Get type-specific threshold
                    threshold = settings.get_threshold_for_type(vuln_type)
                    
                    if 0 <= idx < len(vulnerabilities):
                        vuln = vulnerabilities[idx]
                        vuln["skeptical_score"] = final_score
                        vuln["skeptical_reasoning"] = reasoning
                        
                        if final_score >= threshold:
                            logger.info(f"[{self.name}] ✅ APPROVED #{idx+1} {vuln_type} (score: {final_score}/10 >= {threshold}): {reasoning[:60]}")
                            approved.append(vuln)
                        else:
                            logger.info(f"[{self.name}] ❌ REJECTED #{idx+1} {vuln_type} (score: {final_score}/10 < {threshold}): {reasoning[:60]}")
                except Exception as e:
                    logger.warning(f"[{self.name}] Failed to parse finding: {e}")
            
            logger.info(f"[{self.name}] Skeptical Review: {len(approved)} passed, {len(vulnerabilities)-len(approved)} rejected")
            return approved
```

---

## 📋 PART 4: Integrate Missing Agents into Dispatcher

### FILE 4: `bugtrace/core/team.py`

**Location:** `/home/ubuntu/Dev/Projects/BugTraceAI/BugTraceAI-CLI/bugtrace/core/team.py`

#### Change 6: Add SSRF_AGENT to valid agents list (around line 1164)

**FIND:**

```python
valid_agents = ["XSS_AGENT", "SQL_AGENT", "XXE_AGENT", "PROTO_AGENT", "HEADER_INJECTION", "IDOR_MANUAL", "IGNORE"]
```

**REPLACE with:**

```python
valid_agents = ["XSS_AGENT", "SQL_AGENT", "XXE_AGENT", "SSRF_AGENT", "LFI_AGENT", "RCE_AGENT", "PROTO_AGENT", "HEADER_INJECTION", "IDOR_MANUAL", "JWT_AGENT", "FILE_UPLOAD_AGENT", "IGNORE"]
```

#### Change 7: Add fast-path for SSRF/LFI (around line 1128-1131)

**FIND:**

```python
v_type = str(vuln.get("type", "")).upper()
if "XSS" in v_type: return "XSS_AGENT"
if "SQL" in v_type: return "SQL_AGENT"
if "UPLOAD" in v_type or "FILES" in v_type: return "FILE_UPLOAD_AGENT"
```

**REPLACE with:**

```python
v_type = str(vuln.get("type", "")).upper()
if "XSS" in v_type: return "XSS_AGENT"
if "SQL" in v_type: return "SQL_AGENT"
if "SSRF" in v_type or "SERVER-SIDE REQUEST" in v_type: return "SSRF_AGENT"
if "XXE" in v_type or "XML" in v_type: return "XXE_AGENT"
if "LFI" in v_type or "PATH TRAVERSAL" in v_type or "LOCAL FILE" in v_type: return "LFI_AGENT"
if "RCE" in v_type or "COMMAND" in v_type or "REMOTE CODE" in v_type: return "RCE_AGENT"
if "UPLOAD" in v_type or "FILES" in v_type: return "FILE_UPLOAD_AGENT"
if "JWT" in v_type or "TOKEN" in v_type: return "JWT_AGENT"
```

#### Change 8: Add SSRF_AGENT execution block (after line 1030, after XXE_AGENT block)

**FIND the XXE_AGENT block:**

```python
if "XXE_AGENT" in specialist_dispatches:
    from bugtrace.agents.exploit_specialists import XXEAgent
    p_list = list(params_map.get("XXE_AGENT", [])) or None
    xxe_agent = XXEAgent(url, p_list, url_dir)
    agent_tasks.append(run_agent_with_semaphore(self.url_semaphore, xxe_agent, process_result))
```

**ADD AFTER IT:**

```python
                if "SSRF_AGENT" in specialist_dispatches:
                    from bugtrace.agents.ssrf_agent import SSRFAgent
                    p_list = list(params_map.get("SSRF_AGENT", [])) or None
                    ssrf_agent = SSRFAgent(url, p_list, url_dir)
                    agent_tasks.append(run_agent_with_semaphore(self.url_semaphore, ssrf_agent, process_result))

                if "LFI_AGENT" in specialist_dispatches:
                    from bugtrace.agents.lfi_agent import LFIAgent
                    p_list = list(params_map.get("LFI_AGENT", [])) or None
                    lfi_agent = LFIAgent(url, p_list, url_dir)
                    agent_tasks.append(run_agent_with_semaphore(self.url_semaphore, lfi_agent, process_result))

                if "RCE_AGENT" in specialist_dispatches:
                    from bugtrace.agents.rce_agent import RCEAgent
                    p_list = list(params_map.get("RCE_AGENT", [])) or None
                    rce_agent = RCEAgent(url, p_list, url_dir)
                    agent_tasks.append(run_agent_with_semaphore(self.url_semaphore, rce_agent, process_result))
```

---

## ✅ VERIFICATION STEPS

```bash
# 1. Start Validation Dojo
python3 testing/dojos/dojo_validation.py

# 2. Run scan
./bugtraceai-cli --clean http://127.0.0.1:5050

# 3. Check logs for new scoring format
grep -E "(APPROVED|REJECTED|Skeptical)" logs/execution.log | tail -30
```

**Expected log output:**

```
[DASTySASTAgent] ✅ APPROVED #1 XSS (score: 8/10 >= 5): Unescaped reflection...
[DASTySASTAgent] ❌ REJECTED #2 SSRF (score: 4/10 < 7): Just parameter name...
[DASTySASTAgent] Skeptical Review: 3 passed, 2 rejected
```

---

## ⛔ DO NOT DO

1. ❌ Do NOT create new agent files (SSRF, LFI, RCE already exist)
2. ❌ Do NOT modify the agent implementations themselves
3. ❌ Do NOT change test files
4. ❌ Do NOT refactor unrelated code
5. ❌ Do NOT add new dependencies
6. ❌ Do NOT change the AgenticValidator

---

## 📁 FILES SUMMARY

| File | Changes |
|------|---------|
| `bugtraceaicli.conf` | Add `[SKEPTICAL_THRESHOLDS]` section |
| `bugtrace/core/config.py` | Add `SKEPTICAL_THRESHOLDS` dict + helper method |
| `bugtrace/agents/analysis_agent.py` | Update prompts + parsing for 0-10 scoring |
| `bugtrace/core/team.py` | Add SSRF/LFI/RCE to dispatcher + execution |

**Total: 4 files, ~100 lines changed**

---

## 🎯 SUCCESS CRITERIA

1. ✅ DASTySAST outputs `confidence_score` (0-10)
2. ✅ Skeptical outputs `final_score` (0-10) with type-specific thresholds
3. ✅ Logs show `✅ APPROVED` and `❌ REJECTED` with scores
4. ✅ SSRF findings now route to SSRFAgent
5. ✅ LFI findings now route to LFIAgent
6. ✅ RCE findings now route to RCEAgent
7. ✅ No other functionality is broken
