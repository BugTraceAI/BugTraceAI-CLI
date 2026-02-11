# 02 - Sistema de Configuracion

## Fuentes de Configuracion (orden de prioridad)

1. **Valores por defecto** en la clase `Settings` (Pydantic BaseSettings)
2. **`.env`** en el directorio raiz del CLI (variables de entorno)
3. **`bugtraceaicli.conf`** (ConfigParser INI) - sobreescribe valores por defecto
4. **API PATCH `/api/config`** - cambios en runtime (no persistentes)

---

## Archivo: `core/config.py`

### Clase `Settings(BaseSettings)`

Singleton global accesible como `settings` en todo el codebase.

```python
from bugtrace.core.config import settings
```

### Carga de Configuracion

```python
class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8"
    )

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.load_from_conf()  # Sobreescribe con bugtraceaicli.conf
```

Flujo:
1. Pydantic carga `.env` automaticamente
2. `load_from_conf()` lee `bugtraceaicli.conf` y sobreescribe campos
3. `validate_config()` valida coherencia (llamado antes de iniciar scan)

---

## Campos de Configuracion

### API Keys

| Campo | Default | Fuente | Descripcion |
|-------|---------|--------|-------------|
| `OPENROUTER_API_KEY` | `""` | `.env` | API key de OpenRouter (requerida) |
| `GLM_API_KEY` | `""` | `.env` | API key alternativa |

### Rutas

| Campo | Default | Descripcion |
|-------|---------|-------------|
| `BASE_DIR` | Directorio de `config.py` | Raiz del proyecto CLI |
| `LOG_DIR` | `BASE_DIR / "logs"` | Directorio de logs |
| `REPORT_DIR` | `BASE_DIR / "reports"` | Directorio de reportes |

### Crawler (GoSpider)

| Campo | Default | Conf Section | Descripcion |
|-------|---------|--------------|-------------|
| `MAX_DEPTH` | `2` | `[CRAWLER]` | Profundidad de crawling |
| `MAX_URLS` | `20` | `[CRAWLER]` | URLs maximas a descubrir |
| `GOSPIDER_CONCURRENT` | `5` | `[CRAWLER]` | Hilos de GoSpider |
| `GOSPIDER_TIMEOUT` | `30` | `[CRAWLER]` | Timeout por request (seg) |

### Paralelizacion (Semaforos por Fase)

| Campo | Default | Conf Section | Descripcion |
|-------|---------|--------------|-------------|
| `MAX_CONCURRENT_DISCOVERY` | `1` | `[PARALLELIZATION]` | GoSpider single-threaded |
| `MAX_CONCURRENT_ANALYSIS` | `5` | `[PARALLELIZATION]` | URLs DAST en paralelo |
| `MAX_CONCURRENT_SPECIALISTS` | `10` | `[PARALLELIZATION]` | Especialistas en paralelo |
| `MAX_CONCURRENT_VALIDATION` | `1` | hardcoded | CDP no soporta concurrencia |
| `MAX_CONCURRENT_LLM` | `2` | `[PARALLELIZATION]` | Rate limiting OpenRouter |
| `MAX_CONCURRENT_REQUESTS` | `10` | `[PARALLELIZATION]` | HTTP requests paralelos |

### Modelos LLM

| Campo | Default | Conf Section | Descripcion |
|-------|---------|--------------|-------------|
| `DEFAULT_MODEL` | `"google/gemini-2.0-flash-001"` | `[LLM_MODELS]` | Modelo general |
| `CODE_MODEL` | `"google/gemini-2.0-flash-001"` | `[LLM_MODELS]` | Modelo para codigo |
| `ANALYSIS_MODEL` | `"google/gemini-2.0-flash-001"` | `[LLM_MODELS]` | Modelo para analisis |
| `SKEPTICAL_MODEL` | `"anthropic/claude-3.5-haiku"` | `[LLM_MODELS]` | Modelo para filtro FP |
| `LONE_WOLF_MODEL` | `"deepseek/deepseek-r1"` | `[LLM_MODELS]` | Modelo para exploracion autonoma |

#### Modelos por Persona de Analisis

| Campo | Default | Descripcion |
|-------|---------|-------------|
| `ANALYSIS_SAST_MODEL` | fallback a `ANALYSIS_MODEL` | Persona SAST |
| `ANALYSIS_DAST_MODEL` | fallback a `ANALYSIS_MODEL` | Persona DAST |
| `ANALYSIS_FUZZER_MODEL` | fallback a `ANALYSIS_MODEL` | Persona Fuzzer |
| `ANALYSIS_RED_TEAM_MODEL` | fallback a `ANALYSIS_MODEL` | Persona Red Team |
| `ANALYSIS_RESEARCHER_MODEL` | fallback a `ANALYSIS_MODEL` | Persona Researcher |

### Thinking Consolidation

| Campo | Default | Conf Section | Descripcion |
|-------|---------|--------------|-------------|
| `THINKING_FP_THRESHOLD` | `0.5` | `[THINKING]` | Umbral de fp_confidence (0.0-1.0) |
| `ANALYSIS_CONSENSUS_VOTES` | `4` | `[THINKING]` | Votos minimos para pasar (de 5 personas) |

### Pesos de FP Confidence

| Campo | Default | Descripcion |
|-------|---------|-------------|
| `FP_SKEPTICAL_WEIGHT` | `0.4` | Peso del score skeptical |
| `FP_VOTES_WEIGHT` | `0.3` | Peso de los votos de consenso |
| `FP_EVIDENCE_WEIGHT` | `0.3` | Peso de la calidad de evidencia |

### Optimizacion

| Campo | Default | Descripcion |
|-------|---------|-------------|
| `SAFE_MODE` | `True` | Modo seguro (limita payloads agresivos) |
| `EARLY_EXIT_ON_FINDING` | `False` | Parar al primer hallazgo confirmado |
| `DEBUG` | `False` | Logging verbose |

### Umbrales Skeptical por Tipo de Vulnerabilidad

```python
SKEPTICAL_THRESHOLDS = {
    "XSS": 6,
    "SQLI": 4,        # Mas permisivo (SQLMap decide)
    "RCE": 7,
    "SSRF": 6,
    "LFI": 5,
    "IDOR": 5,
    "XXE": 6,
    "CSTI": 5,
    # ...
}
```

---

## Archivo: `bugtraceaicli.conf`

Formato INI con secciones:

```ini
[CRAWLER]
MAX_DEPTH = 3
MAX_URLS = 50
GOSPIDER_CONCURRENT = 10

[PARALLELIZATION]
MAX_CONCURRENT_ANALYSIS = 8
MAX_CONCURRENT_SPECIALISTS = 15

[LLM_MODELS]
DEFAULT_MODEL = google/gemini-2.0-flash-001
SKEPTICAL_MODEL = anthropic/claude-3.5-haiku
ANALYSIS_SAST_MODEL = google/gemini-2.5-pro-preview-03-25
ANALYSIS_RED_TEAM_MODEL = deepseek/deepseek-r1

[THINKING]
FP_THRESHOLD = 0.5
CONSENSUS_VOTES = 4

[OPTIMIZATION]
SAFE_MODE = true
EARLY_EXIT_ON_FINDING = false

[SKEPTICAL_THRESHOLDS]
XSS = 6
SQLI = 4
```

### Metodo de Carga: `load_from_conf()`

```python
def load_from_conf(self):
    config = configparser.ConfigParser()
    conf_path = self.BASE_DIR / "bugtraceaicli.conf"
    if not conf_path.exists():
        return
    config.read(conf_path)

    # Carga en orden especifico:
    self._load_paths_config(config)
    self._load_crawler_config(config)
    self._load_scan_config(config)
    self._load_parallelization_config(config)
    self._load_url_prioritization_config(config)
    self._load_thinking_config(config)
    self._load_llm_models_config(config)
    self._load_conductor_and_scanning_config(config)
    self._load_analysis_and_misc_config(config)
    self._load_authority_config(config)
    self._load_lonewolf_config(config)
    self._load_anthropic_config(config)
```

---

## Validacion de Configuracion

`validate_config()` retorna lista de errores. Lanza `ValueError` si hay errores criticos.

**Validaciones:**
- `OPENROUTER_API_KEY` requerida
- `MAX_DEPTH >= 1`, `MAX_URLS >= 1`
- `MAX_CONCURRENT_* >= 1`
- Confidence thresholds entre 0.0 y 1.0
- `BASE_DIR` debe existir

---

## Utilidades de Config

| Metodo | Descripcion |
|--------|-------------|
| `mask_secrets()` | Retorna config con API keys enmascaradas |
| `log_config()` | Log de config en modo DEBUG |
| `generate_config_docs()` | Genera markdown de todos los campos |
| `export_config(path)` | Exporta a JSON (secrets enmascarados) |
| `import_config(path)` | Importa JSON, retorna diff sin aplicar |
| `diff_config(other)` | Compara dos configuraciones |
| `snapshot(label)` | Snapshot para versionado en memoria |

### Field Validator

```python
@field_validator(
    'ANALYSIS_SAST_MODEL', 'ANALYSIS_DAST_MODEL',
    'ANALYSIS_FUZZER_MODEL', 'ANALYSIS_RED_TEAM_MODEL',
    'ANALYSIS_RESEARCHER_MODEL', mode='before'
)
def validate_model_name(cls, v):
    # Valida formato "provider/model"
    if v and '/' not in str(v):
        raise ValueError(f"Model must be in 'provider/model' format: {v}")
    return v
```
