# BugTraceAI TUI - Design Brief

## Objetivo
Diseñar la interfaz visual del TUI (Terminal User Interface) de BugTraceAI usando la paleta de colores de la web y manteniendo la estructura actual.

---

## Paleta de Colores (Web Brand)

```
PRIMARY:      #2D1B4D  ████  Fondos principales, backgrounds oscuros
SECONDARY:    #3D2B5F  ████  Cards, paneles elevados
ACCENT:       #FF7F50  ████  CTAs, highlights, elementos importantes
TEXT:         #F8F9FA  ████  Texto principal
TEXT-MUTED:   #B0A8C0  ████  Texto secundario, hints
SUCCESS:      #2ECC71  ████  Estados de éxito, confirmaciones
WARNING:      #FFC107  ████  Advertencias, procesos activos
ERROR:        #FF3131  ████  Errores, vulnerabilidades críticas
```

### Mapeo de Colores Actual → Nuevo

| Elemento | Color Actual | Nuevo Color | Uso |
|----------|-------------|-------------|-----|
| Background | `#1e1e2e` | `#2D1B4D` (PRIMARY) | Fondo principal |
| Paneles | `#313244` | `#3D2B5F` (SECONDARY) | Cards, widgets |
| Bordes principales | `#89b4fa` (azul) | `#FF7F50` (ACCENT) | Bordes importantes |
| Texto | `#cdd6f4` | `#F8F9FA` (TEXT) | Texto principal |
| Texto muted | `#6c7086` | `#B0A8C0` (TEXT-MUTED) | Texto secundario |
| Success | `#a6e3a1` | `#2ECC71` (SUCCESS) | Éxitos |
| Warning | `#f9e2af` | `#FFC107` (WARNING) | Advertencias |
| Error | `#f38ba8` | `#FF3131` (ERROR) | Errores |

---

## Layout del Dashboard

### Vista General (Terminal 120x30)

```
╔═══════════════════════════════════════════════════════════════════════════════════════════════════════╗
║ BugTraceAI Reactor                                                                         14:23:45   ║
╠═══════════════════════════════════════════════════════════════════════════════════════════════════════╣
║                                                                                                       ║
║  ┌─────────────────────── PROGRESS ───────────────────────────────────────────────────────────────┐  ║
║  │  ✓RECON → ✓DISCOVER → ▶ANALYZE → ○EXPLOIT → ○REPORT                               [67%]       │  ║
║  │  🔍 Analyzing 89/127 URLs                                                                       │  ║
║  └──────────────────────────────────────────────────────────────────────────────────────────────────┘  ║
║                                                                                                       ║
║  ┌───── Activity ──────┐  ┌─────────────────── Agent Swarm ────────────────────────────────────────┐  ║
║  │                     │  │                                                                         │  ║
║  │  Req/s:  23.4      │  │  🟢 XSS     [Queue: 5 | Processed: 23 | Vulns: 2]                      │  ║
║  │  Peak:   45.2      │  │  ⚪ SQLi    [Idle]                                                      │  ║
║  │                     │  │  🟡 SSRF    [Queue: 2 | Processing...]                                 │  ║
║  │  ▁▃▅█▅▃▁▂▄         │  │  ⚪ CSTI    [Idle]                                                      │  ║
║  │                     │  │  ✓ LFI     [Done: 15 tested]                                           │  ║
║  └─────────────────────┘  │  ⚪ RCE     [Idle]                                                      │  ║
║  ┌──── Metrics ────────┐  │  ⚪ XXE     [Idle]                                                      │  ║
║  │  CPU: 67% ████████░ │  └─────────────────────────────────────────────────────────────────────────┘  ║
║  │  RAM: 42% █████░░░░ │                                                                              ║
║  └─────────────────────┘  ┌─────────────────── Findings ────────────────────────────────────────────┐  ║
║                           │  Severity  │ Type │ Parameter │ Time     │ Status                       │  ║
║  ┌─── Payload Feed ────┐  ├────────────┼──────┼───────────┼──────────┼──────────────────────────────┤  ║
║  │                     │  │  CRITICAL  │ SQLi │ username  │ 14:23:15 │ new                          │  ║
║  │  ✓ <script>alert   │  │  HIGH      │ XSS  │ q         │ 14:23:42 │ new                          │  ║
║  │    (XSS)            │  │  MEDIUM    │ SSRF │ url       │ 14:24:01 │ reviewed                     │  ║
║  │  ✗ ' OR 1=1--       │  │  LOW       │ Redir│ next      │ 14:24:15 │ false_positive               │  ║
║  │    (SQLi)           │  └─────────────────────────────────────────────────────────────────────────┘  ║
║  │  ⚠ http://169...    │                                                                              ║
║  │    (SSRF) [WAF]     │  ┌─────────────────── Log Inspector ──────────────────────────────────────┐  ║
║  │                     │  │  Filter: [xss_______________]                                           │  ║
║  └─────────────────────┘  │                                                                         │  ║
║                           │  [INFO] [XSSAgent] Starting scan...                                     │  ║
║                           │  [INFO] [XSSAgent] Testing 42 payloads on /search                       │  ║
║                           │  [WARN] [XSSAgent] Possible reflection detected                         │  ║
║                           │  [SUCC] [XSSAgent] XSS confirmed in 'q' parameter                       │  ║
║  > /help for commands     │  [ERRO] [SQLiAgent] Connection timeout                                  │  ║
║                           └─────────────────────────────────────────────────────────────────────────┘  ║
╠═══════════════════════════════════════════════════════════════════════════════════════════════════════╣
║ [q]uit  [f]indings  [l]ogs  [:]command                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════════════════════════════╝
```

---

## Componentes Clave

### 1. Pipeline Progress (Top)
```
┌─────────────────────── PROGRESS ───────────────────────────────────────┐
│  ✓RECON → ✓DISCOVER → ▶ANALYZE → ○EXPLOIT → ○REPORT         [67%]    │
│  🔍 Analyzing 89/127 URLs                                               │
└─────────────────────────────────────────────────────────────────────────┘

COLORES:
- Borde:             #FF7F50 (ACCENT)
- Texto fase actual: #FF7F50 (ACCENT)
- Fases completadas: #2ECC71 (SUCCESS)
- Fases pendientes:  #B0A8C0 (TEXT-MUTED)
- Porcentaje:        #F8F9FA (TEXT)
- Background:        #3D2B5F (SECONDARY)
```

### 2. Agent Swarm
```
┌─────────────────── Agent Swarm ──────────────────────────────────────┐
│                                                                       │
│  🟢 XSS     [Queue: 5 | Processed: 23 | Vulns: 2]                   │
│  ⚪ SQLi    [Idle]                                                   │
│  🟡 SSRF    [Queue: 2 | Processing...]                               │
│  ⚪ CSTI    [Idle]                                                   │
│  ✓ LFI     [Done: 15 tested]                                        │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘

COLORES:
- Borde:           #FF7F50 (ACCENT)
- Background:      #3D2B5F (SECONDARY)
- Agente activo:   #2ECC71 (SUCCESS) 🟢
- Agente idle:     #B0A8C0 (TEXT-MUTED) ⚪
- Agente warning:  #FFC107 (WARNING) 🟡
- Agente done:     #2ECC71 (SUCCESS) ✓
- Agente error:    #FF3131 (ERROR) 🔴
- Texto:           #F8F9FA (TEXT)
- Números:         #FF7F50 (ACCENT) para destacar
```

### 3. Findings Table
```
┌─────────────────── Findings ──────────────────────────────────────┐
│  Severity  │ Type │ Parameter │ Time     │ Status                │
├────────────┼──────┼───────────┼──────────┼───────────────────────┤
│  CRITICAL  │ SQLi │ username  │ 14:23:15 │ new                   │
│  HIGH      │ XSS  │ q         │ 14:23:42 │ new                   │
│  MEDIUM    │ SSRF │ url       │ 14:24:01 │ reviewed              │
└───────────────────────────────────────────────────────────────────┘

COLORES SEVERIDAD:
- CRITICAL: #FF3131 (ERROR) - Bold
- HIGH:     #FF7F50 (ACCENT)
- MEDIUM:   #FFC107 (WARNING)
- LOW:      #F8F9FA (TEXT)
- INFO:     #B0A8C0 (TEXT-MUTED)

OTROS:
- Borde:      #FF3131 (ERROR) - Destacar vulnerabilidades
- Background: #3D2B5F (SECONDARY)
- Header:     #FF7F50 (ACCENT)
- Fila seleccionada: #FF7F50 (ACCENT) como highlight
```

### 4. Activity Graph
```
┌───── Activity ──────┐
│                     │
│  Req/s:  23.4      │
│  Peak:   45.2      │
│                     │
│  ▁▃▅█▅▃▁▂▄         │
│                     │
└─────────────────────┘

COLORES:
- Borde:      #FF7F50 (ACCENT)
- Background: #3D2B5F (SECONDARY)
- Texto:      #F8F9FA (TEXT)
- Labels:     #B0A8C0 (TEXT-MUTED)
- Gráfico:    #FF7F50 (ACCENT) - Gradient hacia #2ECC71
```

### 5. System Metrics
```
┌──── Metrics ────────┐
│  CPU: 67% ████████░ │
│  RAM: 42% █████░░░░ │
└─────────────────────┘

COLORES:
- Borde:         #FF7F50 (ACCENT)
- Background:    #3D2B5F (SECONDARY)
- Texto:         #F8F9FA (TEXT)
- Barra < 60%:   #2ECC71 (SUCCESS)
- Barra 60-80%:  #FFC107 (WARNING)
- Barra > 80%:   #FF3131 (ERROR)
```

### 6. Payload Feed
```
┌─── Payload Feed ────┐
│                     │
│  ✓ <script>alert   │
│    (XSS)            │
│  ✗ ' OR 1=1--       │
│    (SQLi)           │
│  ⚠ http://169...    │
│    (SSRF) [WAF]     │
│                     │
└─────────────────────┘

COLORES:
- Borde:       #2ECC71 (SUCCESS)
- Background:  #3D2B5F (SECONDARY)
- ✓ Success:   #2ECC71 (SUCCESS)
- ✗ Failed:    #FF3131 (ERROR)
- ⚠ Blocked:   #FFC107 (WARNING)
- ○ Testing:   #B0A8C0 (TEXT-MUTED)
- Payload:     #F8F9FA (TEXT)
- Agent tag:   #FF7F50 (ACCENT)
```

### 7. Log Inspector
```
┌─────────────────── Log Inspector ──────────────────────────────────┐
│  Filter: [xss_______________]                                      │
│                                                                     │
│  [INFO] [XSSAgent] Starting scan...                                │
│  [WARN] [XSSAgent] Possible reflection detected                    │
│  [SUCC] [XSSAgent] XSS confirmed                                   │
│  [ERRO] [SQLiAgent] Connection timeout                             │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘

COLORES:
- Borde:      #FF7F50 (ACCENT)
- Background: #3D2B5F (SECONDARY)
- Input:      #2D1B4D (PRIMARY) - Más oscuro
- [INFO]:     #F8F9FA (TEXT)
- [WARN]:     #FFC107 (WARNING)
- [SUCC]:     #2ECC71 (SUCCESS)
- [ERRO]:     #FF3131 (ERROR)
- [DEBUG]:    #B0A8C0 (TEXT-MUTED)
- Agent name: #FF7F50 (ACCENT)
```

---

## Estados Visuales

### Pipeline Progress - Fases

#### Fase 1: Recon (Iniciando)
```
▶RECON → ○DISCOVER → ○ANALYZE → ○EXPLOIT → ○REPORT  [15%]
⚙️ Initializing scan engine...

▶ = #FF7F50 (ACCENT)
○ = #B0A8C0 (TEXT-MUTED)
```

#### Fase 2: Discovery (En progreso)
```
✓RECON → ▶DISCOVER → ○ANALYZE → ○EXPLOIT → ○REPORT  [40%]
🕷️ Found 127 URLs, analyzing...

✓ = #2ECC71 (SUCCESS)
▶ = #FF7F50 (ACCENT)
```

#### Fase 5: Complete
```
✓RECON → ✓DISCOVER → ✓ANALYZE → ✓EXPLOIT → ✓REPORT  [100%]
🎯 Scan complete: 5 vulnerabilities found

Todo ✓ = #2ECC71 (SUCCESS)
```

### Agent Swarm - Estados

```
⚪ Idle       → #B0A8C0 (TEXT-MUTED)
🟡 Queued    → #FFC107 (WARNING)
🟢 Active    → #2ECC71 (SUCCESS)
✓ Done       → #2ECC71 (SUCCESS)
🔴 Error     → #FF3131 (ERROR)
```

---

## Iconos y Símbolos

### Estados
```
✓  Success / Complete     #2ECC71
✗  Failed / Error         #FF3131
⚠  Warning / Blocked      #FFC107
○  Idle / Pending         #B0A8C0
●  Active                 #FF7F50
▶  Current                #FF7F50
→  Separator              #B0A8C0
```

### Fases
```
🕷️  Spider / Discovery
🔍 Analysis
⚡ Exploitation
📝 Reporting
🎯 Complete
```

### Agentes
```
🟢 Active                 #2ECC71
🟡 Warning                #FFC107
🔴 Error                  #FF3131
⚪ Idle                   #B0A8C0
```

---

## Jerarquía Visual

### Nivel 1: Crítico (Máxima atención)
- **Color**: `#FF7F50` (ACCENT)
- **Uso**: Bordes principales, fase actual, highlights
- **Elementos**: Pipeline actual, comandos CTA, elementos interactivos

### Nivel 2: Éxito/Confirmación
- **Color**: `#2ECC71` (SUCCESS)
- **Uso**: Fases completadas, payloads confirmados, agentes activos
- **Elementos**: Checkmarks, confirmaciones, progreso positivo

### Nivel 3: Advertencia
- **Color**: `#FFC107` (WARNING)
- **Uso**: Procesos en espera, WAF detection, agentes en queue
- **Elementos**: Warnings, estados intermedios

### Nivel 4: Error/Crítico
- **Color**: `#FF3131` (ERROR)
- **Uso**: Vulnerabilidades, errores, fallos
- **Elementos**: Findings críticos, errores de sistema

### Nivel 5: Información
- **Color**: `#F8F9FA` (TEXT)
- **Uso**: Texto principal, datos
- **Elementos**: Logs INFO, texto general

### Nivel 6: Secundario
- **Color**: `#B0A8C0` (TEXT-MUTED)
- **Uso**: Texto secundario, elementos inactivos
- **Elementos**: Agentes idle, hints, timestamps

---

## Ejemplos de Uso de Color

### Scan XSS Exitoso
```
PIPELINE:
✓RECON → ✓DISCOVER → ✓ANALYZE → ▶EXPLOIT → ○REPORT  [82%]
⚡ XSS Agent testing payloads...

✓ = #2ECC71 (SUCCESS)
▶ = #FF7F50 (ACCENT)
○ = #B0A8C0 (TEXT-MUTED)

AGENT SWARM:
🟢 XSS     [Queue: 3 | Processed: 47 | Vulns: 2]

🟢 = #2ECC71 (SUCCESS)
Números = #FF7F50 (ACCENT)

PAYLOAD FEED:
✓ <script>alert(1)</script>
  (XSS) ← Confirmed

✓ = #2ECC71 (SUCCESS)
Payload = #F8F9FA (TEXT)
Tag = #FF7F50 (ACCENT)

FINDINGS:
HIGH │ XSS │ q │ 14:23:42 │ new

HIGH = #FF7F50 (ACCENT)
Resto = #F8F9FA (TEXT)
```

### WAF Detection
```
AGENT:
🟡 XSS     [Queue: 10 | Blocked by WAF]

🟡 = #FFC107 (WARNING)

PAYLOAD FEED:
⚠ <script>alert(1)</script>
  (XSS) [WAF BLOCKED]

⚠ = #FFC107 (WARNING)

LOGS:
[WARN] [XSSAgent] WAF detected: Cloudflare
[INFO] [XSSAgent] Switching to evasion payloads...

[WARN] = #FFC107 (WARNING)
[INFO] = #F8F9FA (TEXT)
```

### Error State
```
AGENT:
🔴 SQLi    [Error: Connection timeout]

🔴 = #FF3131 (ERROR)

LOGS:
[ERRO] [SQLiAgent] Connection timeout after 30s
[INFO] [SQLiAgent] Retrying (1/3)...

[ERRO] = #FF3131 (ERROR)
```

---

## Mockup: Estado Completo

```
╔═══════════════════════════════════════════════════════════════════════╗
║ BugTraceAI Reactor                                         14:23:45   ║  ← TEXT (#F8F9FA)
╠═══════════════════════════════════════════════════════════════════════╣
║                                                                       ║
║  ┌── PROGRESS ──────────────────────────────────────────────────┐    ║  ← Borde ACCENT (#FF7F50)
║  │  ✓RECON → ✓DISCOVER → ▶ANALYZE → ○EXPLOIT → ○REPORT  [67%] │    ║
║  │     ↑          ↑          ↑           ↑         ↑             │    ║
║  │  SUCCESS   SUCCESS    ACCENT    TEXT-MUTED TEXT-MUTED        │    ║
║  │  #2ECC71   #2ECC71    #FF7F50    #B0A8C0   #B0A8C0           │    ║
║  └───────────────────────────────────────────────────────────────┘    ║
║                                                                       ║
║  ┌─ Agent Swarm ──────────────────────────────────────────────┐      ║  ← Borde ACCENT (#FF7F50)
║  │                                                             │      ║  ← Background SECONDARY (#3D2B5F)
║  │  🟢 XSS    [Queue: 5 | Processed: 23 | Vulns: 2]          │      ║
║  │   ↑        ↑                                    ↑           │      ║
║  │ SUCCESS  ACCENT (destacar)                   ACCENT         │      ║
║  │ #2ECC71  #FF7F50                             #FF7F50        │      ║
║  │                                                             │      ║
║  │  ⚪ SQLi   [Idle]  ← TEXT-MUTED (#B0A8C0)                  │      ║
║  └─────────────────────────────────────────────────────────────┘      ║
║                                                                       ║
║  ┌─ Findings ──────────────────────────────────────────────────┐     ║  ← Borde ERROR (#FF3131)
║  │  Severity │ Type │ Parameter │ Time     │ Status           │     ║     para destacar vulns
║  ├───────────┼──────┼───────────┼──────────┼──────────────────┤     ║
║  │  CRITICAL │ SQLi │ username  │ 14:23:15 │ new              │     ║
║  │     ↑                                                       │     ║
║  │  ERROR (#FF3131) - Bold                                    │     ║
║  │                                                             │     ║
║  │  HIGH     │ XSS  │ q         │ 14:23:42 │ new              │     ║
║  │   ↑                                                         │     ║
║  │ ACCENT (#FF7F50)                                           │     ║
║  └─────────────────────────────────────────────────────────────┘     ║
║                                                                       ║
╠═══════════════════════════════════════════════════════════════════════╣
║ [q]uit  [f]indings  [l]ogs  [:]command                               ║  ← TEXT (#F8F9FA)
║   ↑                                                                   ║
║ Hotkeys destacados en ACCENT (#FF7F50)                               ║
╚═══════════════════════════════════════════════════════════════════════╝
```

---

## Recomendaciones para el Diseñador

### 1. Contraste
- Background principal: `#2D1B4D` (muy oscuro)
- Texto principal: `#F8F9FA` (casi blanco) → Excelente contraste
- Acento: `#FF7F50` (naranja coral) → Destaca muy bien sobre oscuro

### 2. Jerarquía
- **Más importante**: `#FF7F50` (ACCENT) - Fase actual, CTAs, highlights
- **Éxito**: `#2ECC71` (SUCCESS) - Confirmaciones, completados
- **Peligro**: `#FF3131` (ERROR) - Vulnerabilidades, errores
- **Advertencia**: `#FFC107` (WARNING) - Procesos, esperas
- **Normal**: `#F8F9FA` (TEXT) - Contenido general
- **Secundario**: `#B0A8C0` (TEXT-MUTED) - Info no crítica

### 3. Consistencia
- Bordes principales siempre `#FF7F50` (ACCENT)
- Background de widgets siempre `#3D2B5F` (SECONDARY)
- Severidades siempre con los mismos colores
- Estados de agentes siempre con mismos iconos + colores

### 4. Accesibilidad
- Ratio de contraste > 7:1 para texto principal
- No depender solo del color (usar iconos + color)
- Estados claros visualmente (✓✗⚠○●)

---

## Archivos de Referencia

### Código Actual
- Widgets: `bugtrace/core/ui/tui/widgets/*.py`
- Estilos: `bugtrace/core/ui/tui/styles.tcss`
- Pantalla principal: `bugtrace/core/ui/tui/screens/main.py`

### Para Testing
```bash
# Ver el TUI en demo mode
python -m bugtrace.core.ui.tui.app --demo
```

---

**Resumen**: Aplicar la paleta de colores de la web (#2D1B4D, #FF7F50, etc.) manteniendo la estructura y componentes actuales del TUI. Priorizar contraste, jerarquía visual y consistencia.
