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
        log_text = str(log.get('text', log)) if isinstance(log, dict) else str(log)
        log_lower = log_text.lower()
        
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
                for char in '<>"\\\'()[]{}':
                    if char in original and char not in reflected:
                        stripped_chars.append(char)
        
        # Obtener contexto detectado
        detected_context = vision_result.get('context') or vision_result.get('detected_context')
    
    return ValidationFeedback(
        finding_id=finding.get('id', 0),
        original_payload=finding.get('payload', ''),
        url=finding.get('url', ''),
        parameter=finding.get('parameter', ''),
        vuln_type=str(finding.get('type', 'XSS')) if finding.get('type') else 'XSS',
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
