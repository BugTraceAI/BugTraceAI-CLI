# Multi-Model URL Analysis System Design
## Inspired by BugTrace-AI | 2026-01-02

---

## 🎯 CORE CONCEPT

> **Analyze First, Attack Second**
> 
> Para cada URL, generar un **informe de vulnerabilidades probables** usando múltiples modelos LLM con diferentes perspectivas. Ese informe guía qué pruebas ejecutar.

**Inspiración**: BugTrace-AI de @yz9yt
- Múltiples análisis con prompts variados
- Diferentes "personas" (bug bounty hunter, code auditor, etc.)
- Análisis desde múltiples ángulos reduce falsos negativos

---

## 📊 ARQUITECTURA PROPUESTA

```
┌──────────────────────────────────────────────────┐
│          NUEVO FLUJO DE SCANNING                 │
└──────────────────────────────────────────────────┘

Para CADA URL descubierta:

1️⃣ ANÁLISIS MULTI-MODELO (AnalysisAgent)
   ├─ Fetch Response (HTML, headers, JS)
   ├─ Modelo 1 (Qwen Coder): "Analiza como pentester"
   ├─ Modelo 2 (DeepSeek): "Analiza como bug bounty hunter"
   ├─ Modelo 3 (GLM-4): "Analiza como code auditor"
   └─ Consolidar resultados → INFORME

2️⃣ INFORME DE ANÁLISIS (JSON)
   {
     "url": "http://example.com/products.php?id=1",
     "framework_detected": "PHP + MySQL",
     "likely_vulnerabilities": [
       {
         "type": "SQLi",
         "confidence": 0.95,
         "location": "parameter 'id'",
         "reasoning": "Error message reveals MySQL database",
         "recommended_payloads": ["' OR '1'='1", "' UNION SELECT..."]
       },
       {
         "type": "XSS",
         "confidence": 0.30,
         "location": "parameter 'search'",
         "reasoning": "No immediate evidence, low priority"
       }
     ],
     "attack_priority": ["SQLi"],  // Solo atacar lo de alta confianza
     "skip_tests": ["CSTI", "XXE", "SSRF"]  // No perder tiempo aquí
   }

3️⃣ EXPLOTACIÓN FOCALIZADA (ExploitAgent)
   ├─ Lee informe de análisis
   ├─ SI SQLi confidence > 0.7 → _ladder_sqli()
   ├─ SI XSS confidence > 0.7 → _ladder_xss()
   └─ SKIP tests con baja confianza

4️⃣ VALIDACIÓN (Conductor V2 + SQLMap)
   ├─ Findings pasan por validación normal
   └─ Reporte final generado
```

---

## 🧠 MULTI-MODEL ANALYSIS

### Estrategia: Múltiples Perspectivas

**Modelo 1: Qwen Coder (Pentester)**
```python
prompt = f"""
You are an experienced penetration tester analyzing this URL.

URL: {url}
Response Headers: {headers}
HTML Body: {html[:2000]}
JavaScript: {js_code[:1000]}

Identify potential vulnerabilities:
- SQL Injection (look for database errors, suspicious parameters)
- XSS (check if input is reflected)
- CSTI/SSTI (template engine usage)
- Path Traversal (file inclusion patterns)

Return JSON with vulnerability likelihood and reasoning.
"""
```

**Modelo 2: DeepSeek (Bug Bounty Hunter)**
```python
prompt = f"""
You are a bug bounty hunter looking for high-impact vulnerabilities.

URL: {url}
Technology Stack: {tech_stack}
Parameters: {params}

Focus on:
1. Critical vulnerabilities (SQLi, RCE, XXE)
2. What would pay the most in bug bounty?
3. What's the fastest route to compromise?

Prioritize by severity and exploitability.
"""
```

**Modelo 3: GLM-4 (Code Auditor)**
```python
prompt = f"""
You are a meticulous code auditor reviewing this application.

URL: {url}
Framework: {framework}
Source Code Hints: {source_hints}

Analyze for:
- Coding patterns that suggest vulnerabilities
- Insecure defaults
- Missing input validation
- Logic flaws

Be conservative - only flag high-confidence issues.
"""
```

### Consolidación de Resultados

```python
async def consolidate_analyses(analyses: List[Dict]) -> Dict:
    """
    Combina análisis de múltiples modelos.
    
    Lógica:
    - Si 2+ modelos detectan misma vulnerabilidad → Alta confianza
    - Si solo 1 modelo detecta → Baja confianza (pero no descartar)
    - Promedio de confidence scores
    - Priorizar por severidad y confianza
    """
    consolidated = {
        "consensus_vulns": [],  # 2+ modelos de acuerdo
        "possible_vulns": [],   # Solo 1 modelo detectó
        "attack_priority": []   # Ordenado por confianza * severidad
    }
    
    # Agrupar por tipo de vulnerabilidad
    vuln_votes = defaultdict(list)
    
    for analysis in analyses:
        for vuln in analysis["likely_vulnerabilities"]:
            vuln_votes[vuln["type"]].append(vuln)
    
    # Calcular consenso
    for vuln_type, votes in vuln_votes.items():
        avg_confidence = sum(v["confidence"] for v in votes) / len(votes)
        
        if len(votes) >= 2:  # Consenso
            consolidated["consensus_vulns"].append({
                "type": vuln_type,
                "confidence": avg_confidence,
                "votes": len(votes),
                "reasoning": [v["reasoning"] for v in votes]
            })
        else:  # Posible
            consolidated["possible_vulns"].append({
                "type": vuln_type,
                "confidence": avg_confidence,
                "votes": 1,
                "reasoning": votes[0]["reasoning"]
            })
    
    # Ordenar por prioridad
    all_vulns = consolidated["consensus_vulns"] + consolidated["possible_vulns"]
    consolidated["attack_priority"] = sorted(
        all_vulns, 
        key=lambda v: v["confidence"] * SEVERITY_WEIGHTS[v["type"]],
        reverse=True
    )
    
    return consolidated
```

---

## 🔧 IMPLEMENTATION

### 1. AnalysisAgent (Nuevo)

```python
class AnalysisAgent(BaseAgent):
    """
    Multi-model URL analysis agent.
    Generates vulnerability assessment report before exploitation.
    """
    
    def __init__(self, event_bus: EventBus):
        super().__init__("Analysis-1", event_bus)
        
        # Modelos especializados
        self.models = {
            "pentester": "qwen/qwen-2.5-coder-32b-instruct",
            "bug_bounty": "deepseek/deepseek-chat",
            "auditor": "zhipu/glm-4-plus"
        }
    
    async def analyze_url(
        self, 
        url: str, 
        response: httpx.Response
    ) -> Dict[str, Any]:
        """
        Multi-model analysis of URL.
        
        Returns:
            Consolidated vulnerability assessment report
        """
        # Extract context
        context = {
            "url": url,
            "status": response.status_code,
            "headers": dict(response.headers),
            "html": response.text[:5000],
            "params": self._extract_params(url)
        }
        
        # Analyze with each model
        analyses = []
        
        for persona, model in self.models.items():
            analysis = await self._analyze_with_model(context, model, persona)
            analyses.append(analysis)
        
        # Consolidate results
        report = await self.consolidate_analyses(analyses)
        
        # Store report
        self.analysis_cache[url] = report
        
        # Emit event
        await self.event_bus.emit("url_analyzed", {
            "url": url,
            "report": report
        })
        
        return report
    
    async def _analyze_with_model(
        self, 
        context: Dict, 
        model: str, 
        persona: str
    ) -> Dict:
        """
        Single model analysis with specific persona.
        """
        prompt = self._build_prompt(context, persona)
        
        response = await llm_client.generate(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPTS[persona]},
                {"role": "user", "content": prompt}
            ],
            model=model,
            response_format={"type": "json_object"}
        )
        
        return json.loads(response)
```

### 2. ExploitAgent Integration

```python
class ExploitAgent(BaseAgent):
    """Modified to use analysis reports."""
    
    async def handle_url_analyzed(self, event_data: Dict):
        """
        Handle URL analysis completion.
        Only exploit high-confidence vulnerabilities.
        """
        url = event_data["url"]
        report = event_data["report"]
        
        # Filter by confidence threshold
        threshold = 0.7
        
        for vuln in report["attack_priority"]:
            if vuln["confidence"] < threshold:
                logger.info(f"Skipping {vuln['type']} - low confidence ({vuln['confidence']})")
                continue
            
            # Exploit based on type
            if vuln["type"] == "SQLi":
                await self._ladder_sqli(url, context=vuln)
            elif vuln["type"] == "XSS":
                await self._ladder_xss(url, context=vuln)
            # ... etc
```

### 3. Event Flow

```python
# ReconAgent discovers URL
await event_bus.emit("new_url_discovered", {"url": url, "response": response})

# AnalysisAgent analyzes
analysis_agent.subscribe("new_url_discovered", analysis_agent.analyze_url)
# ... generates report ...
await event_bus.emit("url_analyzed", {"url": url, "report": report})

# ExploitAgent exploits (only high-confidence)
exploit_agent.subscribe("url_analyzed", exploit_agent.handle_url_analyzed)
# ... focused exploitation ...
await event_bus.emit("vulnerability_detected", finding_data)

# SkepticalAgent validates
# ... normal flow ...
```

---

## 📊 EXPECTED IMPROVEMENTS

### Before (Current):
```
URL: /products.php?id=1
├─ Test SQLi (3 min)
├─ Test XSS (2 min)
├─ Test CSTI (2 min)
├─ Test XXE (2 min)
└─ Total: 9 minutes, 5000 tokens

Result: 1 SQLi found (rest wasted)
```

### After (Multi-Model Analysis):
```
URL: /products.php?id=1
├─ Analyze (30 sec, 500 tokens)
│   └─ Report: SQLi 95% confident, XSS 20%, CSTI 5%
├─ Test ONLY SQLi (2 min, 1000 tokens)
└─ Total: 2.5 minutes, 1500 tokens

Result: 1 SQLi found (70% time saved)
```

### Metrics:

| Métrica | Before | After | Improvement |
|---------|--------|-------|-------------|
| Time per URL | 9 min | 2.5 min | **72% faster** |
| Tokens per URL | 5000 | 1500 | **70% cheaper** |
| False attempts | 4-5 | 0-1 | **80% reduction** |
| Accuracy | Same | Same+ | **Better focus** |

---

## 🎯 PHASED ROLLOUT

### Phase 1: Analysis Core (IMMEDIATE)
- [ ] Create AnalysisAgent class
- [ ] Implement multi-model prompts
- [ ] Build consolidation logic
- [ ] Event bus integration

### Phase 2: ExploitAgent Integration (NEXT)
- [ ] Update to consume analysis reports
- [ ] Conditional test execution
- [ ] Threshold configuration

### Phase 3: Optimization (FUTURE)
- [ ] Cache analysis results
- [ ] Parallel model execution
- [ ] Dynamic threshold tuning
- [ ] Cost tracking per analysis

---

## 🔐 CONFIGURATION

**Add to bugtraceaicli.conf**:
```ini
[ANALYSIS]
# Enable multi-model URL analysis before exploitation
ENABLE_ANALYSIS = True

# Models to use for analysis (persona: model)
PENTESTER_MODEL = qwen/qwen-2.5-coder-32b-instruct
BUG_BOUNTY_MODEL = deepseek/deepseek-chat
AUDITOR_MODEL = zhipu/glm-4-plus

# Minimum confidence to attempt exploitation
CONFIDENCE_THRESHOLD = 0.7

# Skip tests below this confidence
SKIP_THRESHOLD = 0.3

# Number of models required for consensus
CONSENSUS_VOTES = 2
```

---

## 💡 ADVANTAGES

1. **Context-Aware**: Each URL analyzed before blind testing
2. **Cost-Effective**: 70% reduction in wasted attempts
3. **Time-Efficient**: 72% faster per URL
4. **Higher Quality**: Focus on real vulnerabilities
5. **Consensus**: Multiple models reduce false negatives
6. **Prioritized**: Attack high-value targets first

---

## 🚀 NEXT STEPS

1. **Review this design** with user
2. **Approve approach** before implementation
3. **Create AnalysisAgent** class
4. **Test with single URL** to validate
5. **Full integration** with ExploitAgent
6. **Comprehensive testing** on testphp.vulnweb.com

---

**Last Updated**: 2026-01-02 11:40  
**Status**: Design Complete - Awaiting Approval  
**Inspiration**: BugTrace-AI by @yz9yt  
**Impact**: 70% cost reduction, 72% time savings
