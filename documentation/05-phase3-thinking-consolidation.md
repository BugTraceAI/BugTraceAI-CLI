# 05 - Fase 3: Thinking Consolidation

## Resumen

La Thinking Consolidation es el "cerebro de enrutamiento" del pipeline. Recibe findings de la Fase 2 (Analysis), los deduplica, filtra falsos positivos y los distribuye a las colas de los agentes especialistas. No tiene semaforo propio (es event-driven, no bloqueante).

**Archivo:** `bugtrace/agents/thinking_consolidation_agent.py` (~58KB)

---

## ThinkingConsolidationAgent

### Clase

```python
class ThinkingConsolidationAgent(BaseAgent):
    def __init__(self, scan_id: int, event_bus=None):
        super().__init__(
            name="ThinkingConsolidation",
            role="Central Router",
            event_bus=event_bus
        )
        self.scan_id = scan_id
        self._dedup_registry = {}  # key -> finding
        self._metrics = {
            "received": 0,
            "deduplicated": 0,
            "fp_filtered": 0,
            "routed": 0,
        }
```

### Subscripcion a Eventos

```python
def _setup_event_subscriptions(self):
    self.event_bus.subscribe("url_analyzed", self.handle_url_analyzed)
```

---

## Pipeline de Procesamiento

```
[url_analyzed event]
        |
        v
[1. Clasificacion por tipo de vuln]
        |
        v
[2. Deduplicacion]
   key = (vuln_type, parameter, url_path)
        |
        v
[3. Filtrado FP]
   fp_confidence < THINKING_FP_THRESHOLD (0.5)
   EXCEPCIONES:
     - SQLi bypasses FP filter (SQLMap decide)
     - probe_validated bypasses FP filter
        |
        v
[4. Priorizacion]
   score = severity * confidence * (1 - skeptical_score/10)
        |
        v
[5. Distribucion a colas de especialistas]
   work_queued_xss, work_queued_sqli, etc.
```

---

## Paso 1: Clasificacion

Cada finding se clasifica al tipo de especialista correspondiente:

```python
SPECIALIST_MAPPING = {
    "XSS": "xss",
    "SQLI": "sqli",
    "CSTI": "csti",
    "LFI": "lfi",
    "IDOR": "idor",
    "SSRF": "ssrf",
    "XXE": "xxe",
    "RCE": "rce",
    "JWT": "jwt",
    "OPEN_REDIRECT": "openredirect",
    "PROTOTYPE_POLLUTION": "prototype_pollution",
    "HEADER_INJECTION": "header_injection",
    "FILE_UPLOAD": "fileupload",
}
```

---

## Paso 2: Deduplicacion

La deduplicacion usa una clave compuesta para evitar enviar el mismo hallazgo multiples veces a los especialistas:

```python
def _deduplicate(self, finding: Dict) -> bool:
    """Returns True if finding is a duplicate."""
    key = (
        finding.get("type", ""),
        finding.get("parameter", ""),
        self._normalize_url_path(finding.get("url", ""))
    )

    if key in self._dedup_registry:
        existing = self._dedup_registry[key]
        # Keep finding with higher confidence
        if finding.get("confidence_score", 0) > existing.get("confidence_score", 0):
            self._dedup_registry[key] = finding
        self._metrics["deduplicated"] += 1
        return True  # Is duplicate

    self._dedup_registry[key] = finding
    return False  # Not duplicate
```

### Normalizacion de URL Path

```python
def _normalize_url_path(self, url: str) -> str:
    """Normalize URL to path only for dedup comparison."""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    return parsed.path  # Ignora query params y fragment
```

---

## Paso 3: Filtrado de Falsos Positivos

### Regla General

```python
if finding["fp_confidence"] < settings.THINKING_FP_THRESHOLD:
    # FILTERED OUT - Likely false positive
    self._metrics["fp_filtered"] += 1
    return
```

Default threshold: `0.5`

### Excepciones (Bypasses)

**SQLi bypasses FP filter:**
```python
if finding["type"] == "SQLI":
    # SQLMap is authoritative - let it decide
    # Even low-confidence SQLi goes to specialist
    pass  # Do NOT filter
```

Razon: SQLMap es una herramienta determinista. Si SQLMap confirma SQLi, es SQLi. No tiene sentido que un LLM filtre lo que SQLMap puede verificar.

**probe_validated bypasses FP filter:**
```python
if finding.get("probe_validated"):
    # Already confirmed by active testing
    pass  # Do NOT filter
```

Razon: Si un probe activo ya confirmo la vulnerabilidad, el filtro FP seria contraproducente.

---

## Paso 4: Priorizacion

```python
def _calculate_priority(self, finding: Dict) -> float:
    severity_scores = {
        "CRITICAL": 10,
        "HIGH": 8,
        "MEDIUM": 5,
        "LOW": 2,
        "INFO": 1,
    }

    severity = severity_scores.get(finding.get("severity", "MEDIUM"), 5)
    confidence = finding.get("confidence_score", 5) / 10.0
    skeptical = finding.get("skeptical_score", 5) / 10.0

    # Higher priority = more likely to be real AND more severe
    priority = severity * confidence * (1 - skeptical / 10)

    return priority
```

Los findings se ordenan por prioridad antes de enviarse a las colas, asegurando que los mas criticos se procesan primero.

---

## Paso 5: Distribucion a Colas de Especialistas

```python
async def _route_to_specialist(self, finding: Dict):
    vuln_type = finding.get("type", "").upper()
    specialist = SPECIALIST_MAPPING.get(vuln_type)

    if not specialist:
        logger.warning(f"No specialist for type: {vuln_type}")
        return

    event_name = f"work_queued_{specialist}"

    await self.event_bus.emit(event_name, {
        "finding": finding,
        "scan_id": self.scan_id,
        "priority": self._calculate_priority(finding),
    })

    self._metrics["routed"] += 1
```

### Eventos Emitidos por Cola

| Evento | Especialista Receptor |
|--------|-----------------------|
| `work_queued_xss` | XSSAgent |
| `work_queued_sqli` | SQLiAgent |
| `work_queued_csti` | CSTIAgent |
| `work_queued_lfi` | LFIAgent |
| `work_queued_idor` | IDORAgent |
| `work_queued_ssrf` | SSRFAgent |
| `work_queued_xxe` | XXEAgent |
| `work_queued_rce` | RCEAgent |
| `work_queued_jwt` | JWTAgent |
| `work_queued_openredirect` | OpenRedirectAgent |
| `work_queued_prototype_pollution` | PrototypePollutionAgent |
| `work_queued_header_injection` | HeaderInjectionAgent |
| `work_queued_fileupload` | FileUploadAgent |

---

## Metricas

El agente rastrea metricas de efectividad:

```python
self._metrics = {
    "received": 142,      # Total findings recibidos
    "deduplicated": 38,    # Eliminados por dedup
    "fp_filtered": 52,     # Filtrados como FP
    "routed": 52,          # Enviados a especialistas
}
```

Estas metricas se exponen via la API de metricas (`/api/metrics/deduplication`) y se muestran en el dashboard TUI.

---

## Backpressure

Cuando las colas de especialistas estan llenas, ThinkingConsolidation aplica backpressure:

- Monitoriza profundidad de colas via `queue_manager`
- Si una cola supera el umbral, pausa el enrutamiento a esa cola
- Los findings se acumulan en un buffer interno
- Cuando la cola se drena, se reanudan los envios

Esto previene que los especialistas se saturen cuando hay muchos hallazgos.
