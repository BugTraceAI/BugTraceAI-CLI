# BugtraceAI-CLI - Guía de Inicio Rápido
## Para Nuevos Desarrolladores

**Versión**: Phoenix Edition v1.2.1
**Actualizado**: 2026-01-02

---

## 🎯 ¿QUÉ ES ESTO?

**BugtraceAI-CLI** es un framework de seguridad web autónomo que usa:
- **LLMs** (GPT/Qwen) para toma de decisiones inteligente
- **Playwright** para renderizado de JavaScript
- **Arquitectura Multi-Agente** para escaneo paralelo

---

## 🚀 INSTALACIÓN

```bash
# 1. Clonar repositorio
git clone https://github.com/yz9yt/bugtraceai-cli.git
cd bugtraceai-cli

# 2. Crear entorno virtual
python -m venv .venv
source .venv/bin/activate

# 3. Instalar dependencias
pip install -r requirements.txt

# 4. Instalar navegador Playwright
playwright install chromium

# 5. Configurar API Key
export OPENROUTER_API_KEY="your_key_here"
```

---

## 💻 USO BÁSICO

```bash
# Escaneo estándar (recomendado)
python -m bugtrace "http://target.com"

# Con más URLs
python -m bugtrace "http://target.com" --max-urls 50

# Con más profundidad de crawling
python -m bugtrace "http://target.com" --max-depth 3
```

---

## 🏗️ ARQUITECTURA EN 30 SEGUNDOS

```
1. Usuario ejecuta: python -m bugtrace "http://target.com"
                        │
2. VisualCrawler descubre URLs (JavaScript rendering)
                        │
3. Por cada URL, se crea un URLMasterAgent
                        │
4. Cada URLMaster tiene 15 skills:
   ├── exploit_xss   → ManipulatorOrchestrator
   ├── exploit_sqli  → sqli_detector
   ├── exploit_lfi   → Browser + payloads
   ├── tool_sqlmap   → Docker SQLMap
   └── ... (11 más)
                        │
5. LLM decide qué skill ejecutar
                        │
6. Se generan reportes con vulnerabilidades confirmadas
```

---

## 📁 ARCHIVOS IMPORTANTES

### Los que DEBES conocer:
```
bugtrace/
├── agents/url_master.py     ← ⭐ EL AGENTE PRINCIPAL (1100 líneas)
├── core/team.py             ← Orquestador del sistema
├── tools/manipulator/       ← Motor de explotación HTTP
└── tools/exploitation/      ← Detectores de vulnerabilidades
```

### Los de configuración:
```
bugtraceaicli.conf           ← Configuración general
.env                         ← Variables de entorno (API keys)
```

---

## 🔧 SKILLS DISPONIBLES (15)

### Básicos
| Skill | Qué hace |
|-------|----------|
| `recon` | Descubre URLs e inputs |
| `analyze` | Analiza respuestas con LLM |
| `browser` | Toma screenshots |
| `report` | Genera reporte JSON |

### Explotación
| Skill | Qué detecta |
|-------|-------------|
| `exploit_xss` | Cross-Site Scripting |
| `exploit_sqli` | SQL Injection |
| `exploit_lfi` | Local File Inclusion |
| `exploit_xxe` | XML External Entity |
| `exploit_header` | CRLF/Header Injection |
| `exploit_ssti` | Template Injection |
| `exploit_proto` | Prototype Pollution |

### Herramientas Externas (Docker)
| Skill | Herramienta |
|-------|-------------|
| `tool_sqlmap` | SQLMap |
| `tool_nuclei` | Nuclei |
| `tool_gospider` | GoSpider |

### Avanzados
| Skill | Qué hace |
|-------|----------|
| `mutate` | Muta payloads con LLM para bypass WAF |

---

## 🐛 DEBUGGING

### Ver logs de ejecución
```bash
tail -f logs/bugtrace.log
```

### Ver conversación de un agente
```bash
cat logs/thread_abc123.json | jq
```

### Ver findings
```bash
cat reports/*/consolidated_report.json | jq '.findings'
```

---

## 🧪 TARGET DE PRUEBA

Para probar que todo funciona:

```bash
python -m bugtrace "http://testphp.vulnweb.com" --max-urls 5
```

**Vulnerabilidades esperadas**:
- SQLi en `listproducts.php?cat=`
- SQLi en `artists.php?artist=`
- XSS en múltiples parámetros

---

## 📚 DOCUMENTACIÓN ADICIONAL

En `.ai-context/`:

1. `vertical_agent_architecture.md` - Arquitectura completa
2. `http_manipulator.md` - Motor de explotación
3. `feature_inventory.md` - Catálogo de herramientas
4. `evaluation_methodology.md` - Cómo medir resultados

---

## ⚠️ NOTAS IMPORTANTES

1. **OPENROUTER_API_KEY** es obligatorio
2. **Docker** requerido para SQLMap/Nuclei/GoSpider
3. **SAFE_MODE** desactiva herramientas agresivas
4. **Vertical Mode** es el default (mejor rendimiento)

---

## 🆘 TROUBLESHOOTING

### "Browser not found"
```bash
playwright install chromium
```

### "Docker command failed"
```bash
docker pull projectdiscovery/nuclei:latest
docker pull googlesky/sqlmap:latest
```

### "API key invalid"
```bash
export OPENROUTER_API_KEY="sk-or-v1-..."
```

---

## 🎓 SIGUIENTE PASO

Lee el archivo completo: `.ai-context/vertical_agent_architecture.md`

---

**¿Preguntas?** Revisa la documentación en `.ai-context/` o los logs en `logs/`
