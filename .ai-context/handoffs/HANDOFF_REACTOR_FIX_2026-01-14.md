# HANDOFF: Reactor.py DAST Integration Fix

**Tech Lead**: Claude Opus
**Fecha**: 2026-01-14
**Para**: Programador (Gemini)
**Prioridad**: CRITICAL

---

## 1. RESUMEN EJECUTIVO

### El Problema

El `reactor.py` (V4) **IGNORA** completamente el sistema de análisis DAST+SAST de 5 approaches que ya existe y funciona en `team.py` (V2).

En lugar de usar inteligencia artificial para decidir qué vulnerabilidades buscar, el reactor usa heurísticas simples basadas en keywords y lanza agentes XSS/SQLi para **TODOS** los parámetros de **TODAS** las URLs.

### Impacto Observado

En test contra `ginandjuice.shop`:
- **Encontrado**: 19 IDOR findings (falsos positivos por heurística `"id" in param`)
- **No encontrado**: XSS real en `/catalog`, SQLi real en `/catalog?category=Juice`
- **Causa raíz 1**: GoSpider no descubrió `/catalog?category=Juice`
- **Causa raíz 2**: Reactor no usa DAST para analizar qué vulnerabilidades son probables

---

## 2. ANÁLISIS TÉCNICO

### 2.1. Código Problemático: `reactor.py` líneas 76-108

```python
elif j_type == "ANALYSIS":
     # DAST ANALYSIS  <-- MENTIRA: No hay DAST aquí
     from urllib.parse import urlparse, parse_qs
     parsed = urlparse(target)

     # 1. Check for File Upload  <-- Heurística simple
     if "upload" in parsed.path.lower():
         self.job_manager.add_job("ATTACK_UPLOAD", target, priority=90)

     # 2. Check for XXE (Endpoint heuristic)  <-- Heurística simple
     if "xml" in parsed.path.lower() or "xxe" in parsed.path.lower():
         self.job_manager.add_job("ATTACK_XXE", target, priority=90)

     # 3. Check for Params (SQLi/XSS + New Vectors)
     if parsed.query:
         q_params = parse_qs(parsed.query)
         for p in q_params:
             # Standard Attacks (Always XSS/SQLi)  <-- PROBLEMA: SIEMPRE
             self.job_manager.add_job("ATTACK_XSS", target, {"param": p}, priority=80)
             self.job_manager.add_job("ATTACK_SQLI", target, {"param": p}, priority=80)

             # Specialized Attacks based on param name  <-- Heurística simple
             p_lower = p.lower()
             if "id" in p_lower or "user" in p_lower:  # <-- CAUSA 19 IDOR FPs
                 ...
```

### 2.2. Código Correcto: `team.py` líneas 858-884

```python
# A. DAST ANALYSIS  <-- DAST REAL
dast = DASTAgent(url, tech_profile, url_dir, state_manager=self.state_manager)
analysis_result = await dast.run()

vulnerabilities = analysis_result.get("vulnerabilities", [])

# B. ORCHESTRATOR DECISION & SPECIALISTS
if vulnerabilities:
    for vuln in vulnerabilities:
        v_type = vuln.get("type", "").upper()
        param = vuln.get("parameter")
        confidence = float(vuln.get("confidence", 0))

        # INTELLIGENT DISPATCHER
        specialist_type = await self._decide_specialist(vuln)

        if specialist_type == "XSS_AGENT":
            xss_agent = XSSAgent(url, params=[param], report_dir=url_dir)
            specialist_result = await xss_agent.run_loop()
        elif specialist_type == "SQL_AGENT":
            sql_agent = SQLMapAgent(url, [param], url_dir)
            ...
```

### 2.3. Cómo Funciona el DASTAgent Correctamente

El `DASTAgent` (`bugtrace/agents/dast_agent.py`) implementa:

1. **5 Approaches Paralelos** (líneas 65-74):
   - Pentester
   - Bug Bounty Hunter
   - Code Auditor
   - Red Team
   - Security Researcher

2. **Consensus Voting** (líneas 298-325):
   ```python
   def _consolidate(self, analyses: List[Dict]) -> List[Dict]:
       merged = {}
       for analysis in analyses:
           for vuln in analysis.get("vulnerabilities", []):
               key = f"{v_type}:{v_param}"
               if key not in merged:
                   merged[key] = vuln
                   merged[key]["votes"] = 1
               else:
                   merged[key]["votes"] += 1

       min_votes = settings.ANALYSIS_CONSENSUS_VOTES  # Default: 1
       return [v for v in merged.values() if v.get("votes", 1) >= min_votes]
   ```

3. **Output Estructurado**:
   ```python
   {
       "url": "https://target.com/page?id=1",
       "vulnerabilities": [
           {
               "type": "SQL Injection",
               "parameter": "id",
               "confidence": 0.85,
               "votes": 4,  # 4/5 approaches coinciden
               "reasoning": "Numeric ID likely used in query"
           }
       ]
   }
   ```

---

## 3. PLAN DE IMPLEMENTACIÓN

### PASO 1: Importar DASTAgent en Reactor

**Archivo**: `bugtrace/core/reactor.py`
**Línea**: ~13 (después de los otros imports)

```python
# AÑADIR:
from bugtrace.agents.dast_agent import DASTAgent
from bugtrace.core.state import get_state_manager
```

### PASO 2: Reemplazar Lógica de ANALYSIS Job

**Archivo**: `bugtrace/core/reactor.py`
**Líneas**: 76-108 (reemplazar completamente)

```python
elif j_type == "ANALYSIS":
    # DAST + SAST: 5-Approach Analysis (Correcto)
    logger.info(f"🧠 Running DAST Analysis on {target}")

    # Crear directorio para este análisis
    job_report_dir = Path(f"reports/jobs/job_{job['id']}")
    job_report_dir.mkdir(parents=True, exist_ok=True)

    # Obtener state_manager (necesario para DASTAgent)
    state_manager = get_state_manager(self.target)

    # Tech profile básico (se puede mejorar con Nuclei más adelante)
    tech_profile = {"frameworks": [], "server": "unknown"}

    # Ejecutar DASTAgent
    try:
        dast = DASTAgent(target, tech_profile, job_report_dir, state_manager=state_manager)
        analysis_result = await dast.run()

        vulnerabilities = analysis_result.get("vulnerabilities", [])
        result = {"vulnerabilities": vulnerabilities}

        # REACTIVE LOGIC: Crear jobs SOLO para lo que DAST sugiere
        for vuln in vulnerabilities:
            v_type = (vuln.get("type") or "").upper()
            param = vuln.get("parameter")
            confidence = float(vuln.get("confidence", 0))

            # Solo procesar vulnerabilidades con confianza >= 0.3
            if confidence < 0.3:
                logger.debug(f"Skipping low-confidence vuln: {v_type} ({confidence})")
                continue

            # Mapeo de tipo de vulnerabilidad a job type
            if "SQL" in v_type:
                self.job_manager.add_job("ATTACK_SQLI", target, {"param": param}, priority=90)
            elif "XSS" in v_type or "SCRIPT" in v_type:
                self.job_manager.add_job("ATTACK_XSS", target, {"param": param}, priority=85)
            elif "XXE" in v_type or "XML" in v_type:
                self.job_manager.add_job("ATTACK_XXE", target, priority=90)
            elif "SSRF" in v_type or "SERVER-SIDE REQUEST" in v_type:
                self.job_manager.add_job("ATTACK_SSRF", target, {"param": param}, priority=85)
            elif "IDOR" in v_type or "OBJECT REFERENCE" in v_type or "ACCESS CONTROL" in v_type:
                val = None
                from urllib.parse import urlparse, parse_qs
                parsed = urlparse(target)
                if parsed.query:
                    q_params = parse_qs(parsed.query)
                    if param in q_params:
                        val = q_params[param][0]
                self.job_manager.add_job("ATTACK_IDOR", target, {"param": param, "value": val}, priority=80)
            elif "JWT" in v_type or "TOKEN" in v_type:
                from urllib.parse import urlparse, parse_qs
                parsed = urlparse(target)
                if parsed.query:
                    q_params = parse_qs(parsed.query)
                    if param in q_params:
                        self.job_manager.add_job("ATTACK_JWT", target, {"token": q_params[param][0]}, priority=90)
            elif "UPLOAD" in v_type or "FILE" in v_type:
                self.job_manager.add_job("ATTACK_UPLOAD", target, priority=90)
            elif "HEADER" in v_type or "CRLF" in v_type:
                # Header injection ya detectado por DAST, registrar finding directo
                logger.success(f"🔓 Header Injection detected by DAST on {target}")
            else:
                logger.debug(f"Unknown vuln type from DAST: {v_type}")

    except Exception as e:
        logger.error(f"DAST Analysis failed: {e}")
        result = {"error": str(e), "vulnerabilities": []}
        status = JobStatus.FAILED
```

### PASO 3: Mejorar GoSpider Discovery (Opcional pero Recomendado)

El otro problema es que GoSpider no descubrió `/catalog?category=Juice`. Esto se puede mejorar:

**Archivo**: `bugtrace/agents/gospider_agent.py`

Añadir extracción de links de JavaScript renderizado:

```python
# En _fallback_discovery() o run(), después de GoSpider:
# Añadir crawling con Playwright para SPAs
async def _crawl_with_playwright(self, base_url: str) -> List[str]:
    """Fallback para sitios JS-heavy que GoSpider no puede crawlear."""
    from bugtrace.tools.visual.browser import browser_manager

    urls = []
    try:
        page = await browser_manager.get_page()
        await page.goto(base_url, wait_until="networkidle")

        # Extraer todos los hrefs
        links = await page.query_selector_all("a[href]")
        for link in links:
            href = await link.get_attribute("href")
            if href and not href.startswith("#"):
                full_url = urljoin(base_url, href)
                urls.append(full_url)

        # Extraer forms con action
        forms = await page.query_selector_all("form[action]")
        for form in forms:
            action = await form.get_attribute("action")
            if action:
                full_url = urljoin(base_url, action)
                urls.append(full_url)

    except Exception as e:
        logger.warning(f"Playwright crawl failed: {e}")

    return list(set(urls))
```

### PASO 4: Test de Validación

Después de implementar, ejecutar:

```bash
# 1. Limpiar estado previo
rm -rf reports/jobs/ state/jobs.db logs/*.log

# 2. Ejecutar contra Dojo (regresión)
python -m pytest tests/test_dojo.py -v

# 3. Ejecutar contra target real
python bugtraceai-cli scan https://ginandjuice.shop/catalog

# 4. Verificar que DAST se ejecuta
grep "Running DAST Analysis" logs/execution.log

# 5. Verificar que no hay jobs de XSS/SQLi sin análisis previo
grep "ATTACK_XSS" logs/execution.log | head -5
```

**Criterios de Éxito**:
- [ ] DAST Analysis se ejecuta para cada URL
- [ ] Jobs de ataque SOLO se crean para vulnerabilidades sugeridas por DAST
- [ ] XSS en `/catalog` es detectado
- [ ] SQLi en `/catalog?category=Juice` es detectado
- [ ] No hay 19 IDOR falsos positivos

---

## 4. CONSIDERACIONES DE ARQUITECTURA

### 4.1. Por Qué NO Usar Heurísticas

Las heurísticas como `"id" in param` generan:
- **Falsos Positivos**: "productId", "sessionId", "transactionId" no son vulnerables a IDOR
- **Falsos Negativos**: Parámetros como "category", "sort", "filter" pueden tener SQLi/XSS

El sistema de 5 approaches analiza el **contexto completo**:
- Tipo de endpoint (search, login, profile, etc.)
- Tecnología detectada (PHP, ASP, Java)
- Patrones de respuesta (errores SQL, reflection HTML)

### 4.2. Costo vs Beneficio del DAST

| Métrica | Sin DAST (Actual) | Con DAST (Propuesto) |
|---------|-------------------|----------------------|
| Tokens LLM | 0 por análisis | ~2000-4000 por URL |
| Jobs creados | N*M (todos params x todos ataques) | Solo vulnerabilidades sugeridas |
| Falsos Positivos | Alto (heurísticas) | Bajo (consensus) |
| Tiempo total | Más largo (muchos jobs inútiles) | Más corto (jobs targeted) |

### 4.3. Flujo Correcto Según Documentación V4

```
PHASE 1: RECON
  └─ GoSpider → URLs

PHASE 2: ANALYSIS (Este es el FIX)
  └─ DASTAgent (5 approaches) → Vulnerabilities with confidence
  └─ Consensus Voting → Filter high-confidence
  └─ Create targeted jobs ONLY for suggested vulns

PHASE 3: ATTACK
  └─ XSSAgent, SQLMapAgent, etc. (SOLO cuando DAST sugiere)

PHASE 3.5: VALIDATION
  └─ AgenticValidator (Senior Pentester review)

PHASE 4: REPORT
  └─ ReportingAgent
```

---

## 5. ARCHIVOS RELEVANTES

| Archivo | Descripción | Líneas Clave |
|---------|-------------|--------------|
| `bugtrace/core/reactor.py` | **FIX AQUÍ** | 76-108 |
| `bugtrace/agents/dast_agent.py` | DASTAgent correcto | 37-139, 298-325 |
| `bugtrace/core/team.py` | Ejemplo de uso correcto | 858-991 |
| `bugtrace/core/config.py` | ANALYSIS_CONSENSUS_VOTES | ~línea 50 |

---

## 6. NOTAS FINALES

### Lo que NO hacer:
- NO duplicar la lógica del DASTAgent en reactor.py
- NO añadir más heurísticas basadas en keywords
- NO eliminar el job de ANALYSIS, solo cambiar su implementación

### Lo que SÍ hacer:
- Reutilizar DASTAgent existente
- Respetar el consensus voting (ANALYSIS_CONSENSUS_VOTES en config)
- Mantener la arquitectura de jobs (RECON → ANALYSIS → ATTACK)

---

**Firmado**: Claude Opus (Tech Lead)
**Fecha**: 2026-01-14 01:30 UTC
**Versión del Plan**: 1.0
