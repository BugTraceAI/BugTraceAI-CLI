# 07 - Fase 5: Validation (AgenticValidator)

## Resumen

La fase de Validation es el ultimo filtro antes de reportar. El AgenticValidator usa Chrome DevTools Protocol (CDP) para verificar hallazgos de edge cases que los especialistas no pudieron confirmar definitivamente. Concurrencia: **1** (hardcoded, limitacion de CDP).

**Archivo:** `bugtrace/agents/agentic_validator.py` (~66KB)

---

## Por que Concurrencia = 1 (Hardcoded)

CDP (Chrome DevTools Protocol) tiene limitaciones arquitecturales criticas:

1. **Una sesion por proceso Chrome** (port 9222 unico)
2. **`alert()` bloquea CDP indefinidamente** - sin timeout externo, el validador se cuelga
3. **Multiples conexiones causan corrupcion de estado** o crashes de Chrome
4. **No hay soporte para sesiones concurrentes** en la especificacion CDP

```python
ScanPhase.VALIDATION → Semaphore(1)  # CDP HARDCODED - cannot change
```

**Estrategia de mitigacion:** Filtrar agresivamente ANTES de CDP (Fases 2-4) para minimizar la cola de validacion.

---

## AgenticValidator

### Clase

```python
class AgenticValidator(BaseAgent):
    def __init__(self, scan_id: int, event_bus=None):
        super().__init__(
            name="AgenticValidator",
            role="Final Validation",
            event_bus=event_bus
        )
        self.scan_id = scan_id
        self.timeout_per_finding = 45  # seconds
```

### Flujo de Ejecucion

```
[Findings con status PENDING_VALIDATION]
        |
        v
[1. Pre-filtrado agresivo]
   - Ya confirmados por especialistas? → Skip
   - Score muy bajo? → Skip
   - Tipo no necesita CDP? → Skip
        |
        v
[2. Iniciar sesion CDP]
   - Lanzar Chrome headless
   - Conectar via CDP (port 9222)
        |
        v
[3. Para CADA finding (secuencial):]
   |
   +--[3a. Navegar a URL con payload]
   |     timeout: 45 segundos
   |
   +--[3b. Capturar screenshot]
   |     evidencia visual
   |
   +--[3c. Analizar con Vision AI]
   |     GPT-4 Vision analiza screenshot
   |     Busca: popups, cambios DOM, errores
   |
   +--[3d. Verificar ejecucion]
   |     page.evaluate() para XSS
   |     Response analysis para SQLi
   |
   +--[3e. Actualizar status]
         VALIDATED_CONFIRMED o
         VALIDATED_FALSE_POSITIVE
        |
        v
[4. Cerrar sesion CDP]
        |
        v
[5. Emitir validation_complete]
```

---

## Pre-Filtrado Agresivo

Antes de enviar al CDP (cuello de botella), se aplican filtros estrictos:

```python
def _should_validate_with_cdp(self, finding: Dict) -> bool:
    """
    Determine if finding needs CDP validation.
    Most findings are resolved by specialists - CDP is last resort.
    """
    # Already confirmed by specialist
    if finding.get("probe_validated"):
        return False

    # Already rejected
    if finding.get("status") == "VALIDATED_FALSE_POSITIVE":
        return False

    # Very low confidence - not worth CDP time
    if finding.get("confidence_score", 0) < 3:
        return False

    # Types that benefit from browser validation
    cdp_types = {"XSS", "CSTI", "OPEN_REDIRECT"}
    if finding.get("type") not in cdp_types:
        return False

    return True
```

---

## Sesion CDP

### Inicializacion

```python
async def _init_cdp_session(self):
    """Initialize Chrome DevTools Protocol session."""
    # Launch Chrome headless
    self.browser_process = await asyncio.create_subprocess_exec(
        "google-chrome",
        "--headless",
        "--remote-debugging-port=9222",
        "--no-sandbox",
        "--disable-gpu",
    )

    # Connect via CDP
    self.cdp_session = await CDPSession.connect("localhost", 9222)
```

### Timeout de 45 Segundos

Cada finding tiene un timeout estricto para prevenir que `alert()` cuelgue el validador:

```python
async def _validate_finding(self, finding: Dict) -> Dict:
    try:
        result = await asyncio.wait_for(
            self._execute_validation(finding),
            timeout=self.timeout_per_finding  # 45 seconds
        )
        return result
    except asyncio.TimeoutError:
        logger.warning(
            f"Validation timeout for {finding['type']} "
            f"on {finding.get('url', 'unknown')}"
        )
        return {
            "status": "MANUAL_REVIEW_RECOMMENDED",
            "notes": "Validation timeout (possible alert() hang)"
        }
```

---

## Vision AI Verification

Para hallazgos que requieren validacion visual, se captura un screenshot y se analiza con Vision AI:

```python
async def _verify_with_vision(self, screenshot_path: str, finding: Dict) -> Dict:
    """
    Use Vision AI to analyze screenshot for vulnerability evidence.
    """
    prompt = f"""
    Analyze this screenshot of a web page after injecting a {finding['type']} payload.

    Look for:
    - Alert dialogs or popups (XSS confirmation)
    - Error messages (SQL errors, stack traces)
    - Changed page content (template injection)
    - Unexpected redirects
    - Visual anomalies

    Is the vulnerability CONFIRMED or is this a FALSE POSITIVE?
    Provide your analysis with confidence level.
    """

    response = await vision_client.analyze(
        image_path=screenshot_path,
        prompt=prompt,
    )

    return self._parse_vision_response(response)
```

---

## Actualizacion de Estado

```python
async def _update_finding_status(self, finding_id: int, status: str, notes: str):
    """Update finding status in SQLite database."""
    async with db.session() as session:
        finding = await session.get(FindingTable, finding_id)
        finding.status = FindingStatus(status)
        finding.validator_notes = notes
        if status == "VALIDATED_CONFIRMED":
            finding.visual_validated = True
        await session.commit()
```

### Estados Posibles

| Status | Significado |
|--------|-------------|
| `VALIDATED_CONFIRMED` | Confirmado por CDP + Vision AI |
| `VALIDATED_FALSE_POSITIVE` | Falso positivo descartado |
| `MANUAL_REVIEW_RECOMMENDED` | Timeout o resultado ambiguo |
| `SKIPPED` | No requeria validacion CDP |
| `ERROR` | Error durante validacion |

---

## Eventos

| Evento | Data | Receptor |
|--------|------|----------|
| `finding_validated` | `{finding_id, status, notes}` | ReportingAgent |
| `finding_rejected` | `{finding_id, reason}` | Metricas |
| `validation_complete` | `{scan_id, total_validated, confirmed, rejected}` | TeamOrchestrator |

---

## Metricas CDP

```python
validation_metrics = {
    "total_received": 25,       # Findings recibidos
    "pre_filtered": 18,         # Filtrados antes de CDP
    "cdp_validated": 7,         # Procesados por CDP
    "confirmed": 4,             # Confirmados
    "rejected": 2,              # Rechazados como FP
    "timeout": 1,               # Timeout (alert hang)
    "avg_time_per_finding": 12, # Segundos promedio
}
```

La metrica clave es `pre_filtered / total_received` - cuanto mas alta, mejor funciona el filtrado agresivo pre-CDP.

---

## Optimizacion: Minimizar la Cola de Validacion

La Fase 5 es el cuello de botella del pipeline (single-threaded, 45s max por finding). Estrategias de mitigacion:

1. **Fase 2:** Consensus voting (4/5 votos requeridos) elimina hallazgos debiles
2. **Fase 2:** SkepticalAgent filtra FPs antes de salir de Analysis
3. **Fase 3:** ThinkingConsolidation dedup + FP filter
4. **Fase 4:** Especialistas confirman con `probe_validated` (bypass CDP)
5. **Fase 5:** Pre-filtrado agresivo antes de CDP

**Meta:** Que solo lleguen a CDP los hallazgos que REALMENTE necesitan validacion visual/browser.
