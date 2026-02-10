# Pipeline de 6 Fases (Reactor V6)

> **Versión**: 2.0.0 (Phoenix Edition)  
> **Lógica de Ejecución**: Secuencial por fases, Paralela dentro de fases  
> **Control**: Semáforos de Fase para gestión de concurrencia  
> **Última Actualización**: Febrero 2026

---

## 📊 Diagrama del Pipeline

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   FASE 1    │───▶│   FASE 2    │───▶│   FASE 3    │───▶│   FASE 4    │───▶│   FASE 5    │───▶│   FASE 6    │
│RECONNAISSANCE│    │  DISCOVERY  │    │  STRATEGY   │    │EXPLOITATION │    │ VALIDATION  │    │  REPORTING  │
│     🔍      │    │     🧪      │    │     🧠      │    │     ⚔️      │    │     ✅      │    │     📝      │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
   El Mapa           El Escáner        El Cerebro         El Enjambre        El Auditor         El Escriba
```

**Ver diagramas visuales detallados:**
- `../diagrams/pipeline_v6_diagram.png` - Vista del flujo completo con gradientes
- `../diagrams/agents_architecture_diagram.png` - Arquitectura de agentes jerárquica
- `../diagrams/data_flow_diagram.png` - Transformación de datos por fase

---

## 🔍 Fase 1: RECONNAISSANCE (El Mapa)

**Objetivo**: Identificar *dónde* atacar sin tocar el objetivo agresivamente.

### 📁 Archivos Responsables
- **Principal**: `bugtrace/agents/gospider_agent.py` → `GoSpiderAgent`
- **Orquestación**: `bugtrace/core/team.py` → `TeamOrchestrator._run_reconnaissance()`
- **Soporte**:
  - `bugtrace/agents/nuclei_agent.py` → `NucleiAgent` (tech detection)
  - `bugtrace/agents/subdomain_enum.py` (si existe)

### 🔄 Modos de Operación

#### Modo 1: Auto-Discovery (Default)
**Comando**: `./bugtraceai-cli https://example.com`

1. **Entrada**: Dominio raíz (ej. `https://example.com`)
2. **Agentes**:
   - **NucleiAgent**: Tech detection en dominio principal
   - **GoSpiderAgent**: Crawling para descubrir URLs y endpoints
3. **Salida**:
   - URLs descubiertas (~50-100 típico)
   - Stack tecnológico detectado
4. **Duración**: ~30s (GoSpider) + ~5s (Nuclei) = **~35s**

#### Modo 2: URL List (NEW v3.2)
**Comando**: `./bugtraceai-cli https://example.com -ul urls.txt`

1. **Entrada**:
   - Dominio raíz para Nuclei
   - Archivo con lista de URLs (una por línea)
2. **Agentes**:
   - **NucleiAgent**: Tech detection SOLO en dominio principal
   - **GoSpiderAgent**: ⏩ **BYPASEADO**
3. **Salida**:
   - URLs del archivo filtradas por dominio
   - Stack tecnológico detectado
4. **Duración**: ~5s (solo Nuclei) = **~6x más rápido**

**Implementación**:
```python
# bugtrace/core/team.py:1206
async def _run_reconnaissance(self, dashboard, recon_dir) -> list:
    # Modo URL List (nuevo)
    if self.url_list_provided:
        # Nuclei solo en target principal
        nuclei_agent = NucleiAgent(self.target, recon_dir)
        self.tech_profile = await nuclei_agent.run()

        # GoSpider bypaseado
        urls_to_scan = self.url_list_provided
        return self._normalize_urls(urls_to_scan)

    # Modo normal (GoSpider)
    # ...
```

**Formato del archivo de URLs**:
```txt
# Comentarios con #
https://example.com/api/products
https://example.com/product?productId=1
https://example.com/search?q=test

# URLs de otros dominios son filtradas automáticamente
```

### 📊 Métricas Comparativas

| Métrica | Modo Auto-Discovery | Modo URL List |
|---------|---------------------|---------------|
| **URLs descubiertas** | 50-500+ | 5-50 (provistas) |
| **Duración** | ~30-60s | ~5s |
| **Precisión** | Variable | Alta (targeted) |
| **GoSpider ejecuta** | ✅ Sí | ❌ No (bypassed) |
| **Nuclei ejecuta** | ✅ En target | ✅ En target |
| **Use case** | Exploración completa | Rescans, integración tools |

### 🎯 Use Cases del Modo URL List

1. **Integración con Burp Suite**: Exportar URLs descubiertas → BugTraceAI
2. **Rescans dirigidos**: Solo URLs con parámetros críticos
3. **API endpoint testing**: Lista específica de endpoints
4. **Integración CI/CD**: URLs fijas para regression testing
5. **Post-crawling con herramientas externas**: katana, waybackurls, etc.

---

## 🧪 Fase 2: DISCOVERY (El Escáner)

**Objetivo**: Identificar *qué* parece vulnerable.

### 📁 Archivos Responsables
- **Análisis de Parámetros**: `bugtrace/analyzers/parameter_analyzer.py`
- **Detector de Formularios**: `bugtrace/analyzers/form_scanner.py`
- **Análisis Estático**: `bugtrace/analyzers/static_analyzer.py`

### 🔄 Flujo de Ejecución
1. **Entrada**: Lista de URLs limpia de la Fase 1
2. **Agentes**:
   - **ParameterAnalyzer**: Identifica parámetros sensibles (`?id=`, `?file=`, `?url=`)
   - **FormScanner**: Analiza formularios (inputs, métodos, validaciones)
   - **StaticAnalyzer**: Análisis de responses (reflexiones, headers, errores)
3. **Acción**: 
   - Probing ligero con payloads básicos
   - Detección de reflexiones de entrada
   - Fuzzing no agresivo de parámetros
4. **Salida**: "Vectores Sospechosos" (Suspected Findings)

### 📊 Métricas Típicas
- Parámetros analizados: 500-2000+
- Vectores sospechosos: 50-200
- Duración: 5-15 minutos

---

## 🧠 Fase 3: STRATEGY (El Cerebro)

**Objetivo**: Planificar *cómo* atacar eficientemente.

### 📁 Archivos Responsables
- **Principal**: `bugtrace/agents/thinking_consolidation_agent.py` → `ThinkingConsolidationAgent`
- **Documentación**: `.ai-context/architecture/agents/thinking_consolidation_agent.md`

### 🔄 Flujo de Ejecución
1. **Entrada**: Vectores sospechosos desordenados de la Fase 2
2. **Agente**: **ThinkingConsolidationAgent** (El Estratega)
3. **Acción**:
   - **Deduplicación Agresiva**: Agrupar 50 URLs con `?id=` en 1 tarea maestra de SQLi
   - **Correlación Semántica**: 
     - `?q=` → Probable XSS
     - `?file=` → Probable LFI
     - `?url=` → Probable SSRF/Open Redirect
   - **Priorización Inteligente**: 
     - Scoring basado en tecnologías detectadas
     - Patrones históricos de éxito
     - Complejidad de explotación
4. **Salida**: Cola de tareas optimizada (`work_queued_*` events)

### 🎯 Optimización
- Reduce tareas de 1000+ a ~50-100 tareas de alta prioridad
- Evita trabajo redundante
- Maximiza la eficiencia del enjambre

---

## ⚔️ Fase 4: EXPLOITATION (El Enjambre)

**Objetivo**: Confirmar o descartar la vulnerabilidad mediante ataque activo.

### 📁 Archivos Responsables (11+ Agentes Especialistas)

#### Inyecciones
- `bugtrace/agents/sqli_agent.py` → **SQLiAgent** - SQL Injection
- `bugtrace/agents/xss_agent.py` → **XSSAgent** - Cross-Site Scripting
- `bugtrace/agents/xxe_agent.py` → **XXEAgent** - XML External Entity
- `bugtrace/agents/csti_agent.py` → **CSTIAgent** - Client-Side Template Injection

#### Ataques de Sistema
- `bugtrace/agents/rce_agent.py` → **RCEAgent** - Remote Code Execution
- `bugtrace/agents/lfi_agent.py` → **LFIAgent** - Local File Inclusion
- `bugtrace/agents/ssrf_agent.py` → **SSRFAgent** - Server-Side Request Forgery

#### Lógica de Negocio
- `bugtrace/agents/idor_agent.py` → **IDORAgent** - Insecure Direct Object References
- `bugtrace/agents/jwt_agent.py` → **JWTAgent** - JWT Vulnerabilities
- `bugtrace/agents/open_redirect_agent.py` → **OpenRedirectAgent** - URL Redirection

#### Avanzados
- `bugtrace/agents/prototype_pollution_agent.py` → **PrototypePollutionAgent** - JavaScript Prototype Pollution

### 🔄 Flujo de Ejecución
1. **Entrada**: Tareas priorizadas con metadatos (ej. "SQLi en `?id=` de `example.com/user`")
2. **Enjambre**: Los 11+ especialistas ejecutan en paralelo (limitado por semáforos)
3. **Acción**:
   - Generación de payloads específicos por tipo
   - Fuzzing inteligente guiado por IA
   - Detección de respuestas anómalas
4. **Restricción**: Validación HTTP-first (sin browser si no es necesario)
5. **Salida**: Hallazgos clasificados
   - `CONFIRMED` - Confirmado con evidencia HTTP
   - `PENDING_VALIDATION` - Requiere validación con browser

### ⚡ Características del Enjambre
- Ejecución paralela controlada
- Timeout inteligente por agente
- Retry logic con backoff exponencial
- WAF evasion automática

---

## ✅ Fase 5: VALIDATION (El Auditor)

**Objetivo**: Certidumbre absoluta y prueba visual.

### 📁 Archivos Responsables
- **Principal**: `bugtrace/agents/agentic_validator.py` → `AgenticValidator`
- **Documentación**: `.ai-context/architecture/agents/agentic_validator.md`

### 🔄 Flujo de Ejecución
1. **Entrada**: Hallazgos `PENDING_VALIDATION` (típicamente XSS DOM, clickjacking, etc.)
2. **Agente**: **AgenticValidator** (El Auditor)
3. **Acción**:
   - 🌐 Levantar navegador Chrome headless (CDP)
   - 🎯 Navegar a URL con payload inyectado
   - 👂 Escuchar eventos:
     - JavaScript alerts (`window.alert`)
     - Console errors/warnings
     - Network requests sospechosas (exfiltración)
   - 📸 Capturar screenshot
   - 🤖 Análisis con **Vision AI** (Gemini/Claude multimodal)
     - "¿Se ve un alert box?"
     - "¿Hay evidencia visual de explotación?"
4. **Salida**: Veredicto final
   - `CONFIRMED` + Evidencia visual
   - `REJECTED` - Falso positivo

### 🛠️ Tecnologías
- **CDP (Chrome DevTools Protocol)**: Control total del navegador
- **Playwright**: Automatización cross-browser
- **Vision AI**: Gemini 2.0 Flash para análisis visual

---

## 📝 Fase 6: REPORTING (El Escriba)

**Objetivo**: Entregar inteligencia accionable.

### 📁 Archivos Responsables
- **Principal**: `bugtrace/agents/reporting.py` → `ReportingAgent`
- **Templates**: `bugtrace/templates/` (Jinja2)
- **Exporters**: `bugtrace/exporters/` (JSON, HTML, Markdown, PDF)

### 🔄 Flujo de Ejecución
1. **Entrada**: Base de datos SQLite con hallazgos confirmados
2. **Agente**: **ReportingAgent** (El Escriba)
3. **Acción**:
   - **Enriquecimiento de Datos**:
     - Agregar descripción técnica (CWE)
     - Calcular CVSS score
     - Incluir pasos de remediación
     - Añadir referencias (OWASP, CVE)
   - **Generación de Artefactos**:
     - JSON (para integración con otros tools)
     - HTML (reporte visual interactivo)
     - Markdown (para documentación)
     - PDF (opcional, para entrega formal)
   - **Limpieza Final**:
     - Eliminar duplicados residuales
     - Ordenar por severidad (Critical → Low)
     - Agregar estadísticas del escaneo
4. **Salida**: Reporte Final multi-formato

### 📊 Contenido del Reporte
- **Executive Summary**: Resumen de alto nivel
- **Findings Table**: Tabla de hallazgos con severidad
- **Detailed Findings**: Descripción técnica por vulnerabilidad
- **Screenshots**: Evidencia visual para cada hallazgo
- **Remediation**: Pasos de corrección específicos
- **Scan Metadata**: Duración, URLs escaneadas, agentes usados

---

## 🔗 Referencias Cruzadas

### Documentos Relacionados
- **Arquitectura Actual**: `../architecture_now.md`
- **Arquitectura Futura**: `../architecture_future.md`
- **Agentes Individuales**: `../agents/*.md`
- **Índice Principal**: `../README.md`

### Diagramas Visuales
- **Pipeline V6 Flow**: `../diagrams/pipeline_v6_diagram.png` - Vista del flujo completo
- **Agents Architecture**: `../diagrams/agents_architecture_diagram.png` - Arquitectura de agentes  
- **Data Flow**: `../diagrams/data_flow_diagram.png` - Transformación de datos por fase

---

## 📈 Métricas de Performance (Ejemplo Real)

```
Target: https://example.com
Total Duration: 42 minutes

Fase 1 - RECONNAISSANCE:  3 min  │ 847 URLs descubiertas
Fase 2 - DISCOVERY:       8 min  │ 143 vectores sospechosos
Fase 3 - STRATEGY:        1 min  │ 38 tareas priorizadas
Fase 4 - EXPLOITATION:    25 min │ 12 hallazgos preliminares
Fase 5 - VALIDATION:      4 min  │ 9 confirmados, 3 rechazados
Fase 6 - REPORTING:       1 min  │ Reporte generado (HTML + JSON)

RESULTADO: 9 vulnerabilidades confirmadas (3 Critical, 4 High, 2 Medium)
```

---

**🚀 Next Steps**: Para implementar una nueva feature, consulta el workflow `/implement_feature_v3`
