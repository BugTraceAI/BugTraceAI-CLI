# Multi-Model Analysis System - Implementation Plan
## AnalysisAgent Integration | 2026-01-02

---

## 📋 EXECUTIVE SUMMARY

**Objective**: Implement intelligent URL analysis using multiple LLM models before exploitation to reduce wasted testing by 70% and improve efficiency by 72%.

**Key Components**:
- AnalysisAgent (new agent)
- Multi-model prompting system
- Consensus-building algorithm
- ExploitAgent integration
- Event bus communication

**Expected Impact**:
- ⏱️ 72% faster per URL (9 min → 2.5 min)
- 💰 70% cost reduction ($0.15 → $0.045)
- 🎯 80% fewer wasted tests
- ✅ Same or better accuracy

---

## 🎯 IMPLEMENTATION PHASES

### Phase 1: AnalysisAgent Core ✅ CURRENT
**Time Estimate**: 2-3 hours  
**Status**: IN PROGRESS

**Tasks**:
- [x] Create `/bugtrace/agents/analysis.py`
- [x] Define AnalysisAgent class structure
- [x] Implement context extraction
- [x] Build multi-model prompt templates
- [x] Implement consolidation logic
- [x] Event bus integration
- [ ] Unit tests

---

### Phase 2: Configuration & Setup
**Time Estimate**: 30 minutes  
**Status**: PENDING

**Tasks**:
- [ ] Add ANALYSIS section to `bugtraceaicli.conf`
- [ ] Update `config.py` to parse ANALYSIS settings
- [ ] Configure model assignments
- [ ] Set thresholds

---

### Phase 3: ExploitAgent Integration
**Time Estimate**: 1-2 hours  
**Status**: PENDING

**Tasks**:
- [ ] Update ExploitAgent to subscribe to `url_analyzed`
- [ ] Implement conditional testing logic
- [ ] Add threshold filtering
- [ ] Context-aware payload selection
- [ ] Update event handlers

---

### Phase 4: Testing & Validation
**Time Estimate**: 1 hour  
**Status**: PENDING

**Tasks**:
- [ ] Unit tests for AnalysisAgent
- [ ] Integration test with single URL
- [ ] Full scan test (testphp.vulnweb.com)
- [ ] Metrics collection
- [ ] Threshold tuning

---

### Phase 5: Documentation & Rollout
**Time Estimate**: 30 minutes  
**Status**: PENDING

**Tasks**:
- [ ] Update CHANGELOG
- [ ] Update README
- [ ] Create usage guide
- [ ] Performance report

---

## 📁 FILE STRUCTURE

```
bugtrace/
├── agents/
│   ├── analysis.py          # NEW - AnalysisAgent
│   ├── exploit.py           # MODIFIED - Consumes analysis
│   ├── base.py              # No changes
│   └── skeptic.py           # No changes
│
├── core/
│   ├── config.py            # MODIFIED - ANALYSIS section
│   ├── llm_client.py        # No changes (reuse)
│   └── event_bus.py         # No changes
│
├── prompts/                 # NEW DIRECTORY
│   ├── __init__.py
│   └── analysis/
│       ├── pentester.txt    # Pentester persona prompt
│       ├── bug_bounty.txt   # Bug bounty persona prompt
│       └── auditor.txt      # Code auditor persona prompt
│
bugtraceaicli.conf          # MODIFIED - Add [ANALYSIS]
```

---

## 🔧 DETAILED IMPLEMENTATION

### 1. AnalysisAgent Class Structure

```python
# File: bugtrace/agents/analysis.py

from bugtrace.agents.base import BaseAgent
from bugtrace.core.event_bus import EventBus
from bugtrace.core.llm_client import llm_client
from bugtrace.core.config import settings
from bugtrace.utils.logger import get_logger
from typing import Dict, List, Any
from collections import defaultdict
import asyncio
import json

logger = get_logger("agents.analysis")

class AnalysisAgent(BaseAgent):
    """
    Multi-Model URL Analysis Agent.
    
    Analyzes each URL with multiple L LM models (different personas)
    to generate vulnerability assessment report before exploitation.
    
    Workflow:
    1. Receive new_url_discovered event
    2. Extract context (headers, HTML, params)
    3. Analyze with 3 models (pentester, bug_bounty, auditor)
    4. Consolidate results (consensus building)
    5. Emit url_analyzed event with report
    """
    
    def __init__(self, event_bus: EventBus):
        super().__init__("Analysis-1", event_bus)
        
        # Model configuration
        self.models = {
            "pentester": settings.ANALYSIS_PENTESTER_MODEL,
            "bug_bounty": settings.ANALYSIS_BUG_BOUNTY_MODEL,
            "auditor": settings.ANALYSIS_AUDITOR_MODEL
        }
        
        # Thresholds
        self.confidence_threshold = settings.ANALYSIS_CONFIDENCE_THRESHOLD
        self.skip_threshold = settings.ANALYSIS_SKIP_THRESHOLD
        self.consensus_votes = settings.ANALYSIS_CONSENSUS_VOTES
        
        # Cache
        self.analysis_cache = {}
        
        logger.info(f"[{self.name}] Initialized with models: {list(self.models.keys())}")
```

---

### 2. Context Extraction

```python
def _extract_context(self, event_data: Dict) -> Dict[str, Any]:
    """
    Extract analysis context from URL discovery event.
    
    Args:
        event_data: {url, response, inputs}
    
    Returns:
        Context dict with all relevant information
    """
    url = event_data["url"]
    response = event_data.get("response")
    
    context = {
        "url": url,
        "method": "GET",  # Default
        "status_code": None,
        "headers": {},
        "html_snippet": "",
        "params": [],
        "tech_stack": []
    }
    
    if response:
        context["status_code"] = response.status_code
        context["headers"] = dict(response.headers)
        context["html_snippet"] = response.text[:5000]  # First 5KB
    
    # Extract parameters
    if "?" in url:
        query = url.split("?")[1]
        params = []
        for param in query.split("&"):
            if "=" in param:
                name = param.split("=")[0]
                params.append(name)
        context["params"] = params
    
    # Detect tech stack from headers
    server = context["headers"].get("Server", "")
    if "PHP" in server or "php" in url.lower():
        context["tech_stack"].append("PHP")
    if "nginx" in server.lower():
        context["tech_stack"].append("Nginx")
    if "apache" in server.lower():
        context["tech_stack"].append("Apache")
    
    return context
```

---

### 3. Multi-Model Analysis

```python
async def _analyze_with_model(
    self,
    context: Dict,
    model: str,
    persona: str
) -> Dict[str, Any]:
    """
    Analyze URL with single model using specific persona.
    
    Returns:
        {
            "likely_vulnerabilities": [
                {
                    "type": "SQLi",
                    "confidence": 0.9,
                    "location": "param 'id'",
                    "reasoning": "..."
                }
            ],
            "framework_detected": "PHP + MySQL",
            "model": "qwen/...",
            "persona": "pentester"
        }
    """
    logger.info(f"[{self.name}] Analyzing with {persona} persona ({model})")
    
    # Build prompt
    prompt = self._build_prompt(context, persona)
    
    # Call LLM
    try:
        response = await llm_client.generate(
            messages=[
                {
                    "role": "system",
                    "content": self._get_system_prompt(persona)
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            model=model,
            response_format={"type": "json_object"},
            temperature=0.7
        )
        
        # Parse JSON response
        analysis = json.loads(response)
        analysis["model"] = model
        analysis["persona"] = persona
        
        return analysis
        
    except Exception as e:
        logger.error(f"[{self.name}] Analysis failed with {persona}: {e}")
        return {
            "likely_vulnerabilities": [],
            "framework_detected": "Unknown",
            "model": model,
            "persona": persona,
            "error": str(e)
        }
```

---

### 4. Consolidation Logic

```python
def _consolidate_analyses(self, analyses: List[Dict]) -> Dict[str, Any]:
    """
    Consolidate multiple model analyses into single report.
    
    Logic:
    - Consensus: 2+ models detect same vuln type
    - Possible: Only 1 model detected
    - Priority: Sorted by avg_confidence × severity_weight
    """
    logger.info(f"[{self.name}] Consolidating {len(analyses)} analyses")
    
    # Group by vulnerability type
    vuln_votes = defaultdict(list)
    
    for analysis in analyses:
        for vuln in analysis.get("likely_vulnerabilities", []):
            vuln_type = vuln["type"]
            vuln_votes[vuln_type].append({
                **vuln,
                "model": analysis["model"],
                "persona": analysis["persona"]
            })
    
    # Calculate consensus
    consensus_vulns = []
    possible_vulns = []
    
    for vuln_type, votes in vuln_votes.items():
        avg_confidence = sum(v["confidence"] for v in votes) / len(votes)
        
        vuln_info = {
            "type": vuln_type,
            "confidence": avg_confidence,
            "votes": len(votes),
            "locations": list(set(v["location"] for v in votes)),
            "reasoning": [v["reasoning"] for v in votes],
            "models": [v["model"] for v in votes]
        }
        
        if len(votes) >= self.consensus_votes:
            consensus_vulns.append(vuln_info)
        else:
            possible_vulns.append(vuln_info)
    
    # Prioritize by confidence × severity
    SEVERITY_WEIGHTS = {
        "SQLi": 10,
        "RCE": 10,
        "XXE": 9,
        "SSTI": 8,
        "XSS": 6,
        "CSTI": 5,
        "LFI": 7,
        "SSRF": 7
    }
    
    all_vulns = consensus_vulns + possible_vulns
    sorted_vulns = sorted(
        all_vulns,
        key=lambda v: v["confidence"] * SEVERITY_WEIGHTS.get(v["type"], 1),
        reverse=True
    )
    
    # Build attack priority and skip lists
    attack_priority = [
        v["type"] for v in sorted_vulns 
        if v["confidence"] >= self.confidence_threshold
    ]
    
    skip_tests = [
        v["type"] for v in sorted_vulns
        if v["confidence"] < self.skip_threshold
    ]
    
    report = {
        "consensus_vulns": consensus_vulns,
        "possible_vulns": possible_vulns,
        "attack_priority": attack_priority,
        "skip_tests": skip_tests,
        "total_models": len(analyses),
        "timestamp": datetime.now().isoformat()
    }
    
    logger.info(f"[{self.name}] Consensus: {len(consensus_vulns)}, Possible: {len(possible_vulns)}")
    logger.info(f"[{self.name}] Attack priority: {attack_priority}")
    
    return report
```

---

### 5. Prompt Templates

```python
# File: bugtrace/prompts/analysis/pentester.txt

You are an experienced penetration tester analyzing a web application URL.

**URL**: {url}
**HTTP Status**: {status_code}
**Technology Stack**: {tech_stack}
**Parameters**: {params}

**Headers**:
{headers}

**HTML Snippet** (first 5000 chars):
{html_snippet}

**Task**: Identify potential vulnerabilities in this URL.

Focus on:
1. **SQL Injection**: Look for database error messages, suspicious parameters that might query databases
2. **XSS**: Check if user input is reflected in the response
3. **Template Injection (CSTI/SSTI)**: Look for template engine usage
4. **Path Traversal/LFI**: Check for file inclusion patterns

**Output Format** (JSON):
```json
{
  "likely_vulnerabilities": [
    {
      "type": "SQLi | XSS | CSTI | XXE | LFI | ...",
      "confidence": 0.0-1.0,
      "location": "parameter name or element",
      "reasoning": "Why you think this vulnerability exists"
    }
  ],
  "framework_detected": "PHP + MySQL | Django | Express.js | ...",
  "notes": "Additional observations"
}
```

**Be realistic**: Only flag vulnerabilities you're reasonably confident about. Low confidence (< 0.5) for speculation.
```

---

## 📊 SUCCESS CRITERIA

### Functional Requirements:
- [ ] AnalysisAgent successfully analyzes URLs
- [ ] All 3 models return valid JSON
- [ ] Consolidation produces reasonable reports
- [ ] ExploitAgent correctly filters by threshold
- [ ] Events flow correctly through system

### Performance Requirements:
- [ ] Analysis completes in < 60 seconds per URL
- [ ] Token usage < 600 tokens per URL analysis
- [ ] Overall scan time reduced by 50%+
- [ ] Cost reduced by 60%+

### Quality Requirements:
- [ ] No false negatives (miss real vulns)
- [ ] Acceptance of 10-20% false positives in analysis (filtered by exploitation)
- [ ] Reports are readable and actionable

---

## 🧪 TESTING STRATEGY

### Unit Tests:
```python
# tests/test_analysis_agent.py

async def test_context_extraction():
    """Test context extraction from URL."""
    agent = AnalysisAgent(event_bus)
    context = agent._extract_context({
        "url": "http://test.com/page.php?id=1",
        "response": mock_response
    })
    assert context["params"] == ["id"]
    assert "PHP" in context["tech_stack"]

async def test_consolidation():
    """Test multi-model consolidation."""
    analyses = [
        {"likely_vulnerabilities": [{"type": "SQLi", "confidence": 0.9}]},
        {"likely_vulnerabilities": [{"type": "SQLi", "confidence": 0.8}]},
        {"likely_vulnerabilities": [{"type": "XSS", "confidence": 0.3}]}
    ]
    report = agent._consolidate_analyses(analyses)
    assert len(report["consensus_vulns"]) == 1  # SQLi has consensus
    assert report["consensus_vulns"][0]["type"] == "SQLi"
```

### Integration Test:
```python
async def test_full_analysis_flow():
    """Test complete analysis flow."""
    # Emit discovery event
    await event_bus.emit("new_url_discovered", {
        "url": "http://testphp.vulnweb.com/listproducts.php?cat=1",
        "response": response
    })
    
    # Wait for analysis
    await asyncio.sleep(30)
    
    # Check report emitted
    assert len(analysis_agent.analysis_cache) == 1
    report = analysis_agent.analysis_cache[url]
    assert "SQLi" in report["attack_priority"]
```

---

## 📈 METRICS TO TRACK

**During Implementation**:
- Lines of code written
- Tests passing
- Features completed

**During Testing**:
- Analysis time per URL
- Tokens used per URL
- Consensus rate (% vulns with 2+ votes)
- Accuracy (compared to manual analysis)

**Post-Deployment**:
- Overall scan time reduction
- Cost reduction
- False positive rate
- False negative rate

---

## 🚀 ROLLOUT PLAN

### Stage 1: Development (Current)
- Implement AnalysisAgent
- Unit tests
- Configuration

### Stage 2: Alpha Testing
- Test with single URL
- Verify event flow
- Tune prompts

### Stage 3: Beta Testing
- Full scan on testphp.vulnweb.com
- Collect metrics
- Adjust thresholds

### Stage 4: Production
- Enable by default
- Monitor performance
- Document results

---

## ⚠️ RISKS & MITIGATION

| Risk | Impact | Mitigation |
|------|--------|------------|
| LLM hallucinations | Medium | Consensus voting, threshold filtering |
| Analysis too slow | High | Parallel execution, caching |
| High token cost | Medium | Limit HTML snippet size, optimize prompts |
| Models disagree | Low | Favor consensus, allow manual override |
| Integration bugs | Medium | Comprehensive testing, gradual rollout |

---

## 📝 PROGRESS LOG

**Will be updated during implementation**:

- [ ] 2026-01-02 11:46: Plan created
- [ ] AnalysisAgent class structure
- [ ] Context extraction method
- [ ] Multi-model analysis
- [ ] Consolidation logic
- [ ] Prompt templates
- [ ] Configuration
- [ ] ExploitAgent integration
- [ ] Testing
- [ ] Documentation

---

**Created**: 2026-01-02 11:46  
**Status**: Active Implementation  
**Next**: Create AnalysisAgent class
