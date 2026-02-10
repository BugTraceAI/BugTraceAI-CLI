# ThinkingConsolidationAgent - El Cerebro del Pipeline

> **Fase**: 3 (Strategy)  
> **Rol**: Coordinador Central, Deduplicador, Clasificador y Priorizador  
> **Clase**: `bugtrace.agents.thinking_consolidation_agent.ThinkingConsolidationAgent`  
> **Archivo**: `bugtrace/agents/thinking_consolidation_agent.py`

---

## Overview

**ThinkingConsolidationAgent** es el **cerebro central** del pipeline de BugTraceAI, posicionado entre la Fase 2 (Discovery) y la Fase 4 (Exploitation). Es el agente más crítico del sistema porque **decide qué findings pasan a los specialist agents** y cuáles son descartados.

Su misión: **Convertir el caos de Discovery (miles de findings) en un plan de batalla ordenado y optimizado**.

### 🎯 **Responsabilidades Principales**

| Responsabilidad | Descripción | Impacto |
|-----------------|-------------|---------|
| **Deduplicación Masiva** | Agrupa 1000 URLs con `?id=` → 1 tarea única | Reduce 90% de trabajo redundante |
| **Clasificación Semántica** | `?q=` → XSS, `?file=` → LFI, `?id=` → SQLi | Routing inteligente a specialists |
| **FP Filtering** | fp_confidence < 0.5 → FILTERED (excepto SQLi) | Ahorra tiempo de specialists |
| **Priorización** | Formula weighted score: severity + confidence + skeptical | Ataca lo relevante primero |
| **Batch Processing** | Acumula findings y procesa en batches | Reduce overhead de LLM calls |
| **Queue Distribution** | Enruta a colas de specialists (`xss`, `sqli`, etc.) | Orquesta enjambre de agentes |

---

## Arquitectura del Agente

```
┌─────────────────────────────────────────────────────────────────┐
│       THINKING CONSOLIDATION AGENT (El Director de Orquesta)     │
└─────────────────────────────────────────────────────────────────┘

Input: url_analyzed events (de DASTySASTAgent, NucleiAgent, GoSpider)
│
▼
┌────────────────────────────────────────────────────────────────┐
│ STEP 1: EVENT RECEPTION (Real-time)                            │
├────────────────────────────────────────────────────────────────┤
│  📨 Event Bus Subscription                                     │
│  • Escucha: EventType.URL_ANALYZED                             │
│  • Payload: {                                                   │
│      "url": "https://example.com/product?id=123",              │
│      "vulnerabilities": [                                       │
│        {                                                        │
│          "type": "XSS",                                         │
│          "parameter": "q",                                      │
│          "confidence": 0.8,                                     │
│          "severity": "high",                                    │
│          "skeptical_score": 7,                                  │
│          "evidence": {...}                                      │
│        },                                                       │
│        ...                                                      │
│      ]                                                          │
│    }                                                            │
│                                                                 │
│  • Puede recibir ~100 events/minuto en scans grandes           │
└────────────┬───────────────────────────────────────────────────┘
             │
             ▼
┌────────────────────────────────────────────────────────────────┐
│ STEP 2: DEDUPLICATION (LRU Cache)                              │
├────────────────────────────────────────────────────────────────┤
│  🔑 Deduplication Key Generation                               │
│  Formula: vuln_type:parameter:url_path                         │
│                                                                 │
│  Ejemplos:                                                      │
│  • https://shop.com/product?id=1   → "XSS:id:/product"         │
│  • https://shop.com/product?id=999 → "XSS:id:/product" (DUPE!) │
│  • https://shop.com/search?q=test  → "XSS:q:/search"           │
│                                                                 │
│  LRU Cache (max_size: 1000):                                   │
│  • Si key ya existe → DUPLICATE (skip)                         │
│  • Si key nueva → Añadir a cache                               │
│  • Si cache lleno → Evict oldest entry                         │
│                                                                 │
│  Métricas:                                                      │
│  • Total findings: 5000                                        │
│  • Duplicates detected: 4500 (90%)                             │
│  • Unique findings: 500                                        │
└────────────┬───────────────────────────────────────────────────┘
             │ (~90% de findings descartados aquí)
             ▼
┌────────────────────────────────────────────────────────────────┐
│ STEP 3: FALSE POSITIVE FILTERING                               │
├────────────────────────────────────────────────────────────────┤
│  🚫 FP Confidence Threshold (default: 0.5)                     │
│                                                                 │
│  IF fp_confidence < 0.5:                                       │
│    IF vuln_type == "SQLi":                                     │
│      → BYPASS filter (SQLMap is authoritative)                 │
│    ELSE IF probe_validated == True:                            │
│      → BYPASS filter (has concrete evidence)                   │
│    ELSE:                                                        │
│      → FILTERED (too many false positives)                     │
│                                                                 │
│  Código:                                                        │
│  ```python                                                      │
│  if not is_sqli and not probe_validated and fp_confidence < 0.5: │
│      logger.info(f"Finding filtered by FP threshold")          │
│      return  # DESCARTADO                                      │
│  ```                                                            │
│                                                                 │
│  Métricas:                                                      │
│  • Findings after dedup: 500                                   │
│  • Findings filtered by FP: 200 (40%)                          │
│  • Findings remaining: 300                                     │
└────────────┬───────────────────────────────────────────────────┘
             │ (~60% de findings sobreviven el filtro)
             ▼
┌────────────────────────────────────────────────────────────────┐
│ STEP 4: CLASSIFICATION (Semantic Routing)                      │
├────────────────────────────────────────────────────────────────┤
│  🏷️ Vuln Type → Specialist Mapping                            │
│                                                                 │
│  VULN_TYPE_TO_SPECIALIST = {                                   │
│    # XSS variants                                              │
│    "xss": "xss",                                               │
│    "cross-site scripting": "xss",                              │
│    "reflected xss": "xss",                                     │
│    "dom xss": "xss",                                           │
│                                                                 │
│    # SQLi variants                                             │
│    "sql injection": "sqli",                                    │
│    "sqli": "sqli",                                             │
│    "blind sqli": "sqli",                                       │
│                                                                 │
│    # SSRF variants                                             │
│    "ssrf": "ssrf",                                             │
│    "server-side request forgery": "ssrf",                      │
│    "url injection": "ssrf",                                    │
│                                                                 │
│    # ... 60+ mappings total                                    │
│  }                                                              │
│                                                                 │
│  Normalización:                                                 │
│  • "Cross-Site Scripting" → normalize → "xss" → XSSAgent      │
│  • "SQL Injection (Blind)" → normalize → "sqli" → SQLiAgent   │
│  • Unknown types → default to "generic" queue                  │
└────────────┬───────────────────────────────────────────────────┘
             │
             ▼
┌────────────────────────────────────────────────────────────────┐
│ STEP 5: PRIORITIZATION (Weighted Scoring)                      │
├────────────────────────────────────────────────────────────────┤
│  📊 Priority Score Formula                                     │
│                                                                 │
│  Priority = 40% severity + 35% fp_confidence + 25% skeptical   │
│                                                                 │
│  Component Scores:                                              │
│  • Severity (0-40 points):                                     │
│    - CRITICAL → 40                                             │
│    - HIGH → 30                                                 │
│    - MEDIUM → 20                                               │
│    - LOW → 10                                                  │
│    - INFO → 5                                                  │
│                                                                 │
│  • FP Confidence (0-35 points):                                │
│    - confidence * 35                                           │
│    - 1.0 confidence → 35 points                                │
│    - 0.5 confidence → 17.5 points                              │
│                                                                 │
│  • Skeptical Score (0-25 points):                              │
│    - (skeptical_score / 10) * 25                               │
│    - 10 skeptical → 25 points                                  │
│    - 5 skeptical → 12.5 points                                 │
│                                                                 │
│  Ejemplo:                                                       │
│  Finding: {                                                     │
│    severity: "high",        # 30 points                        │
│    fp_confidence: 0.8,      # 28 points (0.8 * 35)             │
│    skeptical_score: 7       # 17.5 points (7/10 * 25)          │
│  }                                                              │
│  → Priority = 30 + 28 + 17.5 = 75.5/100 (ALTA PRIORIDAD)       │
└────────────┬───────────────────────────────────────────────────┘
             │
             ▼
┌────────────────────────────────────────────────────────────────┐
│ STEP 6: BATCH PROCESSING (Optimization)                        │
├────────────────────────────────────────────────────────────────┤
│  📦 Batch Mode (optional, configurable)                        │
│                                                                 │
│  Config:                                                        │
│  • batch_size: 10 (default)                                    │
│  • batch_timeout: 30s                                          │
│                                                                 │
│  Behavior:                                                      │
│  • Acumula findings hasta batch_size O timeout                 │
│  • Procesa batch completo de golpe                             │
│  • Reduce LLM API calls (bulk classification)                  │
│                                                                 │
│  Modo Batch OFF (default):                                     │
│  • Procesa cada finding inmediatamente                         │
│  • Latencia más baja                                           │
│  • Más LLM calls pero más responsive                           │
└────────────┬───────────────────────────────────────────────────┘
             │
             ▼
┌────────────────────────────────────────────────────────────────┐
│ STEP 7: QUEUE DISTRIBUTION (Specialist Routing)                │
├────────────────────────────────────────────────────────────────┤
│  🚀 Event Emission to Specialist Queues                        │
│                                                                 │
│  Specialist Queues:                                             │
│  • work_queued_xss       → XSSAgent                            │
│  • work_queued_sqli      → SQLiAgent                           │
│  • work_queued_ssrf      → SSRFAgent                           │
│  • work_queued_lfi       → LFIAgent                            │
│  • work_queued_rce       → RCEAgent                            │
│  • work_queued_xxe       → XXEAgent                            │
│  • work_queued_idor      → IDORAgent                           │
│  • work_queued_jwt       → JWTAgent                            │
│  • work_queued_openredirect → OpenRedirectAgent                │
│  • work_queued_csti      → CSTIAgent                           │
│  • work_queued_prototype → PrototypePollutionAgent             │
│                                                                 │
│  Event Payload:                                                 │
│  {                                                              │
│    "finding": {...},                                           │
│    "priority": 75.5,                                           │
│    "scan_context": "scan_abc123",                              │
│    "classified_at": 1738435678.123                             │
│  }                                                              │
│                                                                 │
│  Specialists consumen de su cola y atacan en paralelo          │
└────────────────────────────────────────────────────────────────┘
```

---

## Deduplication Logic (El Algoritmo Crítico)

### Deduplication Key Formula

```python
def _make_key(self, finding: Dict[str, Any]) -> str:
    """
    Genera clave de deduplicación única.
    
    Format: vuln_type:parameter:url_path
    
    Ejemplos:
    - XSS en ?id= en /product → "XSS:id:/product"
    - SQLi en ?user= en /api/users → "SQLi:user:/api/users"
    """
    
    vuln_type = finding.get("type", "UNKNOWN").upper()
    parameter = finding.get("parameter", "UNKNOWN")
    
    # Extraer URL path (sin query string, sin dominio)
    url = finding.get("url", "")
    parsed = urlparse(url)
    url_path = parsed.path or "/"
    
    # Normalizar path (remover trailing slash, IDs numericos)
    url_path = re.sub(r'/\d+', '/{id}', url_path)  # /users/123 → /users/{id}
    url_path = url_path.rstrip('/')
    
    key = f"{vuln_type}:{parameter}:{url_path}"
    
    return key
```

### Path Normalization (Clave para Dedup Agresivo)

```python
# ANTES de normalización:
"/users/1"     → "XSS:id:/users/1"
"/users/2"     → "XSS:id:/users/2"
"/users/999"   → "XSS:id:/users/999"
→ 3 findings DUPLICADOS SEMÁNTICAMENTE pero con keys diferentes

# DESPUÉS de normalización:
"/users/1"     → "XSS:id:/users/{id}"
"/users/2"     → "XSS:id:/users/{id}"  ← DUPLICATE (misma key)
"/users/999"   → "XSS:id:/users/{id}"  ← DUPLICATE (misma key)
→ Solo 1 finding único, los otros 2 descartados
```

### LRU Cache Implementation

```python
class DeduplicationCache:
    """
    LRU cache con max_size = 1000.
    
    Cuando el cache se llena:
    1. Ordenar entries por timestamp (más antiguo primero)
    2. Evict oldest 10% (100 entries)
    3. Añadir nueva entry
    """
    
    def __init__(self, max_size: int = 1000):
        self.cache: Dict[str, FindingRecord] = {}
        self.max_size = max_size
        self.hits = 0
        self.misses = 0
        self._lock = threading.Lock()
    
    def check_and_add(self, finding: Dict, scan_context: str):
        """
        Atomic check-and-add operation.
        
        Returns:
            (is_duplicate, key)
        """
        with self._lock:
            key = self._make_key(finding)
            
            # Check for duplicate
            if key in self.cache:
                self.hits += 1
                existing = self.cache[key]
                
                # Log duplicate
                logger.debug(
                    f"DUPLICATE finding: {key} "
                    f"(original from {existing.scan_context}, "
                    f"duplicate from {scan_context})"
                )
                
                # Update dedup metrics
                dedup_metrics.record_duplicate(key, scan_context)
                
                return (True, key)  # IS DUPLICATE
            
            # Not duplicate - add to cache
            self.misses += 1
            
            # Evict if cache full
            if len(self.cache) >= self.max_size:
                self._evict_oldest()
            
            # Add new entry
            self.cache[key] = FindingRecord(
                key=key,
                finding=finding,
                scan_context=scan_context
            )
            
            # Update dedup metrics
            dedup_metrics.record_unique(key, scan_context)
            
            return (False, key)  # NOT DUPLICATE
    
    def _evict_oldest(self):
        """Evict oldest 10% of entries."""
        evict_count = max(1, self.max_size // 10)
        
        # Sort by timestamp
        sorted_entries = sorted(
            self.cache.items(),
            key=lambda x: x[1].received_at
        )
        
        # Evict oldest
        for key, _ in sorted_entries[:evict_count]:
            del self.cache[key]
        
        logger.debug(f"Evicted {evict_count} oldest cache entries")
```

---

## False Positive Filtering

### The SQLi Exception Rule

**Por qué SQLi bypasea el filtro de FP?**

```python
# findings_consolidation_agent.py (línea ~420)

fp_confidence = finding.get("fp_confidence", 0.5)
probe_validated = finding.get("probe_validated", False)
is_sqli = "sql" in finding.get("type", "").lower()

# Standard FP filter
if not is_sqli and not probe_validated and fp_confidence < 0.5:
    logger.info(f"Finding filtered by FP threshold: {finding['id']}")
    return  # FILTERED

# SQLi bypass
if is_sqli and fp_confidence < 0.5:
    logger.info("SQLi bypass: forwarded to SQLMap for authoritative validation")
    # BYPASEA EL FILTRO - SQLMap decide, no el LLM
```

**Razón**: SQLMap es **authoritative** y **determinístico**. Un LLM puede equivocarse al analizar si un parámetro es vulnerable a SQLi, pero SQLMap ejecuta payloads reales y confirma de forma definitiva. Es mejor enviar 10 falsos positivos a SQLMap (que los rechaza en 10s) que perder 1 SQLi real.

### Probe Validated Exception

```python
# Si el probe ACTIVO confirmó comportamiento sospechoso:
if probe_validated == True:
    # BYPASS el filtro de FP
    # La evidencia concreta supera al score del LLM
```

**Ejemplo**:
```json
{
  "type": "XSS",
  "parameter": "q",
  "fp_confidence": 0.3,  // Bajo (normalmente filtrado)
  "probe_validated": true,  // PERO probe confirmó reflexión
  "evidence": {
    "reflection_context": "html_text",
    "survived_chars": ["<",">","\""]  // Caracteres no filtrados
  }
}
// → NO FILTRADO (evidencia concreta > LLM score)
```

---

## Priority Scoring Formula

### Weighted Components

| Component | Weight | Range | Example |
|-----------|--------|-------|---------|
| **Severity** | 40% | 0-40 | HIGH (high=30) |
| **FP Confidence** | 35% | 0-35 | 0.8 × 35 = 28 |
| **Skeptical Score** | 25% | 0-25 | 7/10 × 25 = 17.5 |

**Total**: 0-100 points

### Severity Mapping

```python
SEVERITY_PRIORITY = {
    "critical": 40,  # RCE, SQLi con admin access
    "high": 30,      # XSS, SQLi sin admin
    "medium": 20,    # IDOR, SSRF
    "low": 10,       # Info disclosure
    "info": 5,       # Missing headers
}
```

### Examples

**Ejemplo 1: Critical SQLi con alta confianza**
```python
{
  "severity": "critical",     # 40 points
  "fp_confidence": 0.95,      # 33.25 points (0.95 * 35)
  "skeptical_score": 9        # 22.5 points (9/10 * 25)
}
# → Priority = 40 + 33.25 + 22.5 = 95.75/100 (MÁXIMA PRIORIDAD)
```

**Ejemplo 2: Medium IDOR con baja confianza**
```python
{
  "severity": "medium",       # 20 points
  "fp_confidence": 0.4,       # 14 points (0.4 * 35)
  "skeptical_score": 3        # 7.5 points (3/10 * 25)
}
# → Priority = 20 + 14 + 7.5 = 41.5/100 (BAJA PRIORIDAD)
```

**Ejemplo 3: Low info con alta confianza**
```python
{
  "severity": "low",          # 10 points
  "fp_confidence": 1.0,       # 35 points (1.0 * 35)
  "skeptical_score": 10       # 25 points (10/10 * 25)
}
# → Priority = 10 + 35 + 25 = 70/100 (MEDIA-ALTA PRIORIDAD)
# Nota: Aunque es LOW severity, la alta confidence lo hace relevante
```

---

## Batch Processing vs Real-Time

### Real-Time Mode (Default)

```python
# config.yaml
consolidation:
  batch_mode: false  # Process findings immediately
```

**Pros**:
- ✅ Latencia ultra-baja (~100ms)
- ✅ Findings llegan a specialists ASAP
- ✅ Better para scans interactivos

**Cons**:
- ❌ Más LLM API calls (1 call por finding)
- ❌ Mayor costo en scans grandes

### Batch Mode

```python
# config.yaml
consolidation:
  batch_mode: true
  batch_size: 10
  batch_timeout: 30  # seconds
```

**Pros**:
- ✅ Reduce LLM calls (1 call por 10 findings)
- ✅ Más eficiente en scans grandes
- ✅ Menor costo de API

**Cons**:
- ❌ Latencia más alta (hasta 30s de espera)
- ❌ Findings se acumulan en buffer

### Batch Processing Logic

```python
async def _batch_processor_loop(self):
    """
    Background task que procesa batches cada N segundos.
    """
    while self.running:
        await asyncio.sleep(self.batch_timeout)
        
        # Check if batch accumulated
        if len(self.batch_buffer) > 0:
            logger.info(f"Processing batch of {len(self.batch_buffer)} findings")
            await self.flush_batch()
```

---

## Configuración

```yaml
consolidation:
  # Deduplication
  dedup_enabled: true
  dedup_cache_size: 1000              # LRU cache max entries
  
  # False Positive Filtering
  fp_filtering_enabled: true
  fp_confidence_threshold: 0.5        # Mínimo confidence para pasar
  sqli_bypass_fp_filter: true         # SQLi siempre pasa a SQLMap
  probe_bypass_fp_filter: true        # Probe validated bypasea filtro
  
  # Priority Scoring
  priority_weights:
    severity: 0.40
    fp_confidence: 0.35
    skeptical_score: 0.25
  
  # Batch Processing
  batch_mode: false                   # true = accumulate, false = immediate
  batch_size: 10
  batch_timeout: 30                   # seconds
  
  # Queue Distribution
  specialist_queues_enabled: true
  default_queue: "generic"            # For unknown vuln types
  
  # Logging
  log_duplicates: true
  log_filtered: true
  log_priority_scores: true
```

---

## Métricas y Reporting

### Deduplication Metrics

```python
# Al final del scan:
summary = get_dedup_summary()

{
  "total_findings_received": 5000,
  "unique_findings": 500,
  "duplicates_detected": 4500,
  "dedup_rate": 0.90,  # 90% duplicados
  
  "top_duplicated_keys": [
    {"key": "XSS:id:/product", "count": 450},
    {"key": "SQLi:user_id:/api/users", "count": 380},
    {"key": "IDOR:id:/profile", "count": 290}
  ],
  
  "cache_stats": {
    "size": 500,
    "max_size": 1000,
    "hit_rate": 0.90,
    "evictions": 0
  }
}
```

### FP Filtering Metrics

```json
{
  "findings_after_dedup": 500,
  "findings_filtered_by_fp": 200,
  "findings_passed": 300,
  "filter_rate": 0.40,
  
  "sqli_bypass_count": 15,
  "probe_bypass_count": 35
}
```

### Priority Distribution

```json
{
  "high_priority": 80,      // 70-100 score
  "medium_priority": 150,   // 40-69 score
  "low_priority": 70        // 0-39 score
}
```

---

## Ventajas del Diseño

✅ **Deduplicación agresiva** (90% reduction)  
✅ **Filtro de FP inteligente** con excepciones (SQLi, probes)  
✅ **Priorización weighted** multi-factor  
✅ **Event-driven** (reactive, no polling)  
✅ **LRU cache** con eviction automático  
✅ **Thread-safe** (locks en operaciones críticas)  

---

## Referencias

- **Event-Driven Architecture**: Reactor Pattern
- **LRU Cache**: https://en.wikipedia.org/wiki/Cache_replacement_policies#LRU
- **Weighted Scoring**: Multi-criteria decision analysis

---

*Última actualización: 2026-02-01*  
*Versión: 2.0.0 (Phoenix Edition)*
