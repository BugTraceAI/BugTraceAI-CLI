# 11 - Interfaz de Usuario (TUI)

## Resumen

BugTraceAI-CLI tiene dos sistemas de UI para terminal:
1. **Textual TUI** (nuevo) - Dashboard moderno y reactivo
2. **Rich Legacy** (viejo) - Dashboard basado en Rich Live display

Ambos coexisten pero el Textual TUI desactiva el Legacy al montarse.

---

## 1. Textual TUI (`core/ui/tui/`)

### BugTraceApp (`core/ui/tui/app.py`)

```python
class BugTraceApp(App):
    """BugTraceAI Terminal User Interface Application."""

    CSS_PATH = Path(__file__).parent / "styles.tcss"
    TITLE = "BugTraceAI Reactor"
    SUB_TITLE = "Advanced Security Scanner"

    def __init__(self, target: str = None, demo_mode: bool = False):
        super().__init__()
        self.target = target
        self.demo_mode = demo_mode
        self.scan_worker: Optional[Worker] = None
        self._shutdown_event = asyncio.Event()
```

### Bindings (Atajos de Teclado)

| Tecla | Accion | Descripcion |
|-------|--------|-------------|
| `q` | `quit` | Salir |
| `d` | `toggle_dark` | Alternar modo oscuro |
| `?` | `show_help` | Mostrar ayuda |
| `s` | `start_scan` | Iniciar scan |
| `f` | `focus_findings` | Enfocar tabla de findings |
| `l` | `focus_logs` | Enfocar panel de logs |
| `:` | `focus_command` | Enfocar input de comandos |
| `Escape` | `unfocus` | Desenfocar widget actual |

### Widgets

| Widget | Archivo | Descripcion |
|--------|---------|-------------|
| `PipelineStatus` | `widgets/pipeline.py` | Visualizacion de progreso por fase |
| `AgentSwarm` | `widgets/swarm.py` | Actividad de agentes en tiempo real |
| `FindingsTable` | `widgets/findings_table.py` | Tabla paginada de hallazgos |
| `FindingsSummary` | `widgets/findings.py` | Resumen estadistico |
| `LogPanel` | `widgets/log_panel.py` | Panel de logs en vivo |
| `LogInspector` | `widgets/log_inspector.py` | Inspector detallado de logs |
| `SystemMetrics` | `widgets/metrics.py` | CPU, memoria, metricas del sistema |
| `PayloadFeed` | `widgets/payload_feed.py` | Feed de payloads testeados en vivo |
| `ActivityGraph` | `widgets/activity.py` | Grafico de actividad historica |
| `CommandInput` | `widgets/command_input.py` | Input de comandos `:` |

### Screens

| Screen | Descripcion |
|--------|-------------|
| `LoaderScreen` | Pantalla de carga inicial (spinner) |
| `MainScreen` | Dashboard principal con todos los widgets |
| `FindingDetailsModal` | Modal con detalles de un finding |

### Messages (Eventos Textual)

```python
# core/ui/tui/messages.py
class AgentUpdate(Message)      # Agente cambio de estado
class LogEntry(Message)          # Nueva entrada de log
class MetricsUpdate(Message)     # Metricas actualizadas
class NewFinding(Message)        # Nuevo hallazgo encontrado
class PayloadTested(Message)     # Payload probado
class PipelineProgress(Message)  # Progreso del pipeline
class ScanComplete(Message)      # Scan completado
```

### Lifecycle

```python
def on_mount(self):
    """Called when app is mounted."""
    # 1. Show loader or main screen
    if self.demo_mode:
        self.push_screen(MainScreen())
    else:
        self.push_screen(LoaderScreen())

    # 2. Install logging handler
    self._install_logging_handler()

    # 3. DISABLE legacy dashboard (prevent conflicts)
    from bugtrace.core.ui import dashboard
    dashboard._live = None  # Prevent Rich drawing

    # 4. Auto-start scan if target provided
    if self.target:
        self.set_timer(0.5, self._auto_start_scan)
```

### TUILoggingHandler

```python
class TUILoggingHandler(logging.Handler):
    """Captures Python logging to TUI widgets."""

    def emit(self, record):
        # Convert log record to TUI LogEntry message
        message = LogEntry(
            level=record.levelname,
            message=record.getMessage(),
            module=record.module,
        )
        self.app.post_message(message)
```

### UICallback

```python
class UICallback:
    """Bridge between scan events and TUI messages."""

    def on_agent_update(self, agent_name, status):
        self.app.post_message(AgentUpdate(agent_name, status))

    def on_finding(self, finding):
        self.app.post_message(NewFinding(finding))

    def on_progress(self, phase, percent):
        self.app.post_message(PipelineProgress(phase, percent))
```

### Estilos (`styles.tcss`)

Textual usa TCSS (Textual CSS) para estilos:

```tcss
Screen {
    layout: grid;
    grid-size: 3 4;
    grid-gutter: 1;
}

PipelineStatus {
    column-span: 3;
    height: auto;
}

FindingsTable {
    column-span: 2;
    row-span: 2;
}

LogPanel {
    column-span: 1;
    row-span: 2;
}
```

---

## 2. Rich Legacy Dashboard (`core/ui_legacy.py`)

### Dashboard Class

```python
class Dashboard:
    """Advanced multi-page terminal dashboard using Rich."""

    # Pages
    PAGE_MAIN = 0
    PAGE_FINDINGS = 1
    PAGE_LOGS = 2
    PAGE_STATS = 3
    PAGE_AGENTS = 4
    PAGE_QUEUES = 5
    PAGE_CONFIG = 6
```

### Componentes

- **SparklineBuffer**: Buffer circular para graficos sparkline
- **DashboardHandler**: Handler de logging que captura a dashboard
- **Spinner**: Animacion de progreso con frames ASCII
- **Logo**: ASCII art con gradiente de colores
- **Multi-panel Layout**: Layout con paneles Rich

### Rich Live Display

```python
with Live(layout, refresh_per_second=4, screen=True) as live:
    while self.running:
        live.update(self._render_current_page())
        await asyncio.sleep(0.25)
```

`screen=True` activa modo pantalla alternativa (fullscreen).

### Keyboard Listener

Thread daemon separado para manejar input de teclado:

```python
def start_keyboard_listener(self):
    """Start background thread for keyboard input."""
    self._kb_thread = threading.Thread(
        target=self._keyboard_loop,
        daemon=True
    )
    self._kb_thread.start()

def _keyboard_loop(self):
    """Listen for key presses."""
    while not self._stop_requested.is_set():
        key = self._read_key()
        if key == 'q':
            self._request_shutdown()
        elif key in '1234567':
            self._switch_page(int(key) - 1)
```

### Re-export para Compatibilidad

```python
# core/ui/__init__.py
from bugtrace.core.ui_legacy import Dashboard, DashboardHandler, SparklineBuffer

# Global singleton
dashboard = Dashboard()
```

---

## Convivencia de UIs

Cuando el Textual TUI se activa:

1. Desactiva `dashboard._live = None` para prevenir que Rich dibuje
2. Mockea `dashboard.update_task()` para evitar intentos de rendering
3. Redirige logs al TUILoggingHandler
4. El Textual TUI toma control total del terminal

Cuando se usa sin TUI (modo API/headless):
- El Legacy Dashboard se usa como log sink
- No activa `screen=True`
- Solo registra logs sin rendering

---

## Demo Mode

```bash
python -m bugtrace --demo
```

En demo mode:
- Los widgets muestran datos animados de ejemplo
- No se ejecuta ningun scan real
- Util para development y testing de la UI
- Se salta LoaderScreen y va directo a MainScreen
