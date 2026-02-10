# 📁 Estructura Completa de la Documentación de Arquitectura

> **Última Actualización**: 2026-02-01  
> **Estado**: ✅ Completamente documentado con diagramas

---

## 🌳 Árbol de Archivos

```
.ai-context/architecture/
│
├── 📄 README.md                           ← Índice principal (EMPIEZA AQUÍ)
│   ├── Guía de navegación
│   ├── Enlaces a todos los documentos
│   └── Referencias cruzadas
│
├── 📘 ARCHITECTURE_V7.md                 ← Estado actual (V7.1 TeamOrchestrator)
│   ├── Visión general del sistema
│   ├── Componentes principales
│   └── Tecnologías clave
│
├── 🗺️ architecture_future.md              ← Roadmap Q3-Q4 2026
│   ├── Aprendizaje por refuerzo (WAF Bypass)
│   ├── Knowledge Graph
│   ├── Marketplace comunitario
│   └── Mejoras de Vision AI
│
├── 📂 phases/                             ← Documentación del Pipeline
│   │
│   ├── 📊 pipeline_phases.md              ← DOCUMENTO MASTER (21 KB)
│   │   ├── Diagrama de flujo completo
│   │   ├── Fase 1: RECONNAISSANCE 🔍
│   │   │   ├── Archivos responsables
│   │   │   ├── Agentes activos
│   │   │   └── Entrada/Salida
│   │   ├── Fase 2: DISCOVERY 🧪
│   │   │   ├── Archivos responsables
│   │   │   ├── Agentes activos
│   │   │   └── Entrada/Salida
│   │   ├── Fase 3: STRATEGY 🧠
│   │   │   ├── Archivos responsables
│   │   │   ├── Agentes activos
│   │   │   └── Entrada/Salida
│   │   ├── Fase 4: EXPLOITATION ⚔️
│   │   │   ├── Archivos responsables (11+ agentes)
│   │   │   ├── Tabla de agentes con CWEs
│   │   │   └── Entrada/Salida
│   │   ├── Fase 5: VALIDATION ✅
│   │   │   ├── Archivos responsables
│   │   │   ├── Agentes activos
│   │   │   └── Entrada/Salida
│   │   ├── Fase 6: REPORTING 📝
│   │   │   ├── Archivos responsables
│   │   │   ├── Componentes activos
│   │   │   └── Entrada/Salida
│   │   ├── Flujo de control del TeamOrchestrator
│   │   └── Métricas de rendimiento
│   │
│   └── 🎨 flow_diagrams.md                ← Diagramas Mermaid (10 KB)
│       ├── Diagrama de flujo principal
│       ├── Diagrama de secuencia
│       ├── Arquitectura de componentes
│       ├── Diagrama de estados de Finding
│       ├── Tabla de responsabilidades
│       ├── Flujo de decisión - Validación
│       ├── Diagrama de enjambre (Phase 4)
│       └── Instrucciones de visualización
│
├── 📂 agents/                             ← Especificaciones individuales
│   │
│   ├── 🧠 thinking_consolidation_agent.md ← FASE 3: Strategy
│   │   └── Motor de consolidación inteligente
│   │
│   ├── 🎯 xss_agent.md                    ← FASE 4: XSS (CWE-79)
│   ├── 💉 sqli_agent.md                   ← FASE 4: SQLi (CWE-89)
│   ├── 💥 rce_agent.md                    ← FASE 4: RCE (CWE-78)
│   ├── 🌐 ssrf_agent.md                   ← FASE 4: SSRF (CWE-918)
│   ├── 📁 lfi_agent.md                    ← FASE 4: LFI (CWE-22)
│   ├── 📄 xxe_agent.md                    ← FASE 4: XXE (CWE-611)
│   ├── 🔑 idor_agent.md                   ← FASE 4: IDOR (CWE-639)
│   ├── 🎫 jwt_agent.md                    ← FASE 4: JWT (CWE-287)
│   ├── 🧬 csti_agent.md                   ← FASE 4: CSTI (CWE-94)
│   ├── ↗️ open_redirect_agent.md           ← FASE 4: Open Redirect (CWE-601)
│   ├── ⚛️ prototype_pollution_agent.md    ← FASE 4: Prototype Pollution (CWE-1321)
│   │
│   └── ✅ agentic_validator.md            ← FASE 5: Validation
│       ├── Validación con CDP
│       ├── Visual Proof Engine
│       └── LLM Analyzer
│
└── 📂 diagrams/                           ← Diagramas PNG (si existen)
    ├── pipeline_v6_diagram.png
    ├── agents_architecture_diagram.png
    └── data_flow_diagram.png
```

---

## 📊 Estadísticas de Documentación

| Categoría | Cantidad | Tamaño Total |
|-----------|----------|--------------|
| **Documentos Core** | 3 | ~10 KB |
| **Documentos de Fases** | 2 | ~31 KB |
| **Documentos de Agentes** | 13 | ~37 KB |
| **Total** | **18 archivos** | **~78 KB** |

---

## 🎯 Mapa de Navegación por Caso de Uso

### 🆕 Nuevo en el proyecto
```
1. README.md
   ↓
2. ARCHITECTURE_V7.md (visión general)
   ↓
3. phases/pipeline_phases.md (entender el flujo)
   ↓
4. phases/flow_diagrams.md (visualizar)
```

### 🔍 Buscar un agente específico
```
1. README.md → Sección "Agentes Especializados"
   ↓
2. agents/{nombre}_agent.md
   ↓
3. (Opcional) phases/pipeline_phases.md para ver contexto de fase
```

### 🏗️ Implementar nueva feature
```
1. ARCHITECTURE_V7.md (entender arquitectura actual)
   ↓
2. phases/pipeline_phases.md (identificar fase correcta)
   ↓
3. agents/{agente_similar}.md (referencia)
   ↓
4. architecture_future.md (verificar alineación con roadmap)
```

### 📊 Revisar diagramas
```
1. phases/flow_diagrams.md (diagramas Mermaid interactivos)
   ↓
2. diagrams/ (PNGs estáticos si existen)
```

### 🐛 Debug/Auditoría
```
1. phases/pipeline_phases.md (mapeo de archivos)
   ↓
2. Localizar archivo en bugtrace/agents/
   ↓
3. Consultar agents/{agente}.md para spec
```

---

## ✅ Checklist de Calidad

### Documentación Completa ✅
- [x] README.md con índice completo
- [x] ARCHITECTURE_V7.md actualizado
- [x] architecture_future.md con roadmap
- [x] pipeline_phases.md con todas las fases
- [x] flow_diagrams.md con diagramas Mermaid
- [x] 13 archivos de agentes documentados

### Mapeo de Archivos ✅
- [x] Cada fase tiene archivos responsables especificados
- [x] Cada agente tiene su archivo .py mapeado
- [x] Tablas de agentes con CWEs

### Visualización ✅
- [x] Diagramas de flujo ASCII en pipeline_phases.md
- [x] 7 diagramas Mermaid en flow_diagrams.md
- [x] Tablas de métricas y responsabilidades

### Navegación ✅
- [x] README con guías de navegación
- [x] Enlaces cruzados entre documentos
- [x] Índice en cada documento principal

---

## 🔄 Diagramas Disponibles

### En `pipeline_phases.md`:
1. **Diagrama de Flujo Completo** (ASCII)
   - Vista de las 6 fases verticales
   - Muestra agentes principales
   - Flujo de datos entre fases

### En `flow_diagrams.md`:
1. **Diagrama de Flujo Principal** (Mermaid)
   - Subgrafos para cada fase
   - Agentes en cada fase
   - Flujo de datos completo

2. **Diagrama de Secuencia** (Mermaid)
   - Interacción User → TeamOrchestrator → Fases
   - Comunicación con SQLite
   - Ejecución paralela en Phase 4

3. **Arquitectura de Componentes** (Mermaid)
   - TeamOrchestrator Core (EventBus, Semaphore, StateManager)
   - Agent Swarm
   - Validation Layer
   - Storage

4. **Diagrama de Estados de Finding** (Mermaid)
   - Ciclo de vida completo: SUSPECTED → CONFIRMED
   - Estados intermedios: QUEUED, TESTING, REQUIRES_VALIDATION
   - Estados finales: ENRICHED, FAILED, FALSE_POSITIVE

5. **Tabla de Responsabilidades** (Markdown)
   - Componentes por fase
   - Entrada/Salida
   - Nivel de paralelismo

6. **Flujo de Decisión - Validación** (Mermaid)
   - Lógica HTTP vs Browser
   - Vision AI confirmation
   - Ramificación CONFIRMED/FAILED

7. **Diagrama de Enjambre Phase 4** (Mermaid)
   - Task Dispatcher
   - 11+ agentes en paralelo
   - Findings DB

---

## 📝 Mejoras Realizadas

### ✨ Antes vs Después

#### Antes:
- ❌ Nombres de archivos incompletos o faltantes en fases
- ❌ No había diagramas visuales
- ❌ Documentación dispersa
- ❌ Sin guía de navegación clara

#### Después:
- ✅ **Cada fase** tiene archivos responsables especificados
- ✅ **7 diagramas Mermaid** interactivos completos
- ✅ **Estructura clara** con README índice
- ✅ **Guías de navegación** por caso de uso
- ✅ **Tablas de métricas** de rendimiento
- ✅ **Mapeo CWE** completo para todos los agentes

---

## 🚀 Próximos Pasos Sugeridos

### 1. Generar Diagramas PNG
Si quieres versiones estáticas de los Mermaid:
```bash
npm install -g @mermaid-js/mermaid-cli
cd .ai-context/architecture/phases
mmdc -i flow_diagrams.md -o ../diagrams/
```

### 2. Validar Mapeo con Código
Verificar que los archivos mencionados existan:
```bash
# Ejemplo: verificar que xss_agent.py existe
ls -l ../../bugtrace/agents/exploitation/xss_agent.py
```

### 3. Actualizar Documentación de Agentes
Algunos archivos en `agents/` pueden necesitar actualizarse para seguir la estructura estándar.

### 4. Crear Diagrama de CVSS
Añadir un diagrama que muestre cómo se calcula el CVSS en la Fase 6.

---

## 📞 Referencias

- **Código fuente**: `/home/albert/Tools/BugTraceAI/BugTraceAI-CLI/bugtrace/`
- **Workflows**: `.agent/workflows/implement_feature_v3.md`
- **Skills**: `.agent/skills/architecture_validator/SKILL.md`
- **Master Doc**: `.ai-context/project/master_doc.md`

---

<div align="center">

**✅ La documentación de arquitectura está completa y lista para usar**

</div>
