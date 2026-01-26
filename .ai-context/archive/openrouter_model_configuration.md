# OpenRouter Model Configuration Guide
## 2026-01-02 - Reference Documentation

---

## 🎯 MODELO SELECCIONADO

**Modelo**: `google/gemini-2.5-flash`  
**URL**: https://openrouter.ai/google/gemini-2.5-flash  
**Uso**: Análisis multi-approach (5 enfoques)

---

## ✅ CONFIGURACIÓN CORRECTA

```ini
# bugtraceaicli.conf
[ANALYSIS]
PENTESTER_MODEL = google/gemini-2.5-flash
BUG_BOUNTY_MODEL = google/gemini-2.5-flash
AUDITOR_MODEL = google/gemini-2.5-flash
```

```python
# bugtrace/core/config.py
ANALYSIS_PENTESTER_MODEL: str = "google/gemini-2.5-flash"
ANALYSIS_BUG_BOUNTY_MODEL: str = "google/gemini-2.5-flash"
ANALYSIS_AUDITOR_MODEL: str = "google/gemini-2.5-flash"
```

---

## ❌ MODELOS INCORRECTOS (NO USAR)

### 1. Gemini con :free (rate limited)
```
❌ google/gemini-2.0-flash-exp:free
```
**Problema**: Rate limit agresivo (429), solo para pruebas mínimas

### 2. Nombres inexistentes
```
❌ google/gemini-2.5-flash-latest  (404 - no existe)
❌ google/gemini-flash-1.5         (404 - no existe)
❌ google/gemini-flash-1.5-8b      (404 - no existe)
```

---

## 📋 MODELOS GEMINI DISPONIBLES EN OPENROUTER

### Gemini 2.5 (Recomendado)
- ✅ `google/gemini-2.5-flash` - **USAR ESTE**
- `google/gemini-2.5-flash-image`
- `google/gemini-2.5-flash-preview-09-2025`
- `google/gemini-2.5-flash-lite`
- `google/gemini-2.5-flash-lite-preview-09-2025`

### Gemini 2.0
- `google/gemini-2.0-flash-001`
- `google/gemini-2.0-flash-lite-001`
- `google/gemini-2.0-flash-exp:free` (rate limited)

### Gemini 3.0 (Preview)
- `google/gemini-3-flash-preview`

---

## 🔍 CÓMO VERIFICAR MODELOS DISPONIBLES

```bash
# Listar todos los modelos Gemini Flash
curl -s "https://openrouter.ai/api/v1/models" | \
  python3 -m json.tool | \
  grep -B 3 "gemini.*flash" | \
  grep '"id"'
```

---

## 💡 RAZÓN DE LA ELECCIÓN

### Por qué Gemini 2.5 Flash:
1. **Sin rate limits free tier** (usar créditos OpenRouter)
2. **JSON consistente** (alta reliability)
3. **Velocidad alta** (Flash model)
4. **Costo razonable** (más barato que Pro)
5. **Calidad buena** para análisis de seguridad

### Por qué NO models free:
- Rate limits muy agresivos (429)
- Inestables para testing
- No producción

### Por qué mismo modelo × 5:
- **Fase de testing**: Consistencia > Diversidad
- JSON predecible y confiable
- Más fácil debug
- **Fase de producción**: Diversificar después

---

## 🚀 IMPLEMENTACIÓN

### 1. Actualizar Config
```bash
# En bugtraceaicli.conf
PENTESTER_MODEL = google/gemini-2.5-flash
BUG_BOUNTY_MODEL = google/gemini-2.5-flash
AUDITOR_MODEL = google/gemini-2.5-flash
```

### 2. Actualizar Defaults
```bash
# En bugtrace/core/config.py
ANALYSIS_PENTESTER_MODEL: str = "google/gemini-2.5-flash"
```

### 3. Verificar
```bash
python3 -c "from bugtrace.core.config import settings; \
  print(f'Modelo: {settings.ANALYSIS_PENTESTER_MODEL}')"
```

Debe mostrar: `Modelo: google/gemini-2.5-flash`

---

## 📊 COSTO ESTIMADO

**Gemini 2.5 Flash**:
- Prompt: ~$0.075 / 1M tokens
- Completion: ~$0.30 / 1M tokens

**Por análisis** (5 approaches):
- ~500 tokens prompt × 5 = 2,500 tokens
- ~300 tokens output × 5 = 1,500 tokens
- **Costo**: ~$0.0005 por URL

**100 URLs**: ~$0.05  
**1000 URLs**: ~$0.50

---

## ⚠️ TROUBLESHOOTING

### Error 404: "No endpoints found"
**Causa**: Nombre de modelo incorrecto  
**Solución**: Usar exactamente `google/gemini-2.5-flash`

### Error 429: Rate limited
**Causa**: Usando modelo :free  
**Solución**: Quitar `:free` del nombre

### Error 400: Invalid model ID
**Causa**: Modelo no existe en OpenRouter  
**Solución**: Verificar lista de modelos disponibles

---

## 📝 HISTORIAL DE CAMBIOS

1. **Inicial**: `qwen/qwen-2.5-coder-32b-instruct` (JSON inconsistente)
2. **Test 1**: Múltiples modelos (solo 1/3 funcionó)
3. **Intento 2**: `google/gemini-2.0-flash-exp:free` (rate limited)
4. **Intento 3**: `google/gemini-2.5-flash-latest` (404)
5. **Intento 4**: `anthropic/claude-3-haiku` (funcionó, pero no era lo pedido)
6. **Intento 5**: `google/gemini-flash-1.5` (404)
7. **Intento 6**: `google/gemini-flash-1.5-8b` (404)
8. **✅ CORRECTO**: `google/gemini-2.5-flash`

---

## 🎯 LECCIÓN APRENDIDA

**SIEMPRE** verificar el nombre exacto del modelo en:
- https://openrouter.ai/models
- O via API: `GET https://openrouter.ai/api/v1/models`

**NO ASUMIR** nombres de modelos, usar solo nombres confirmados.

---

**Última Actualización**: 2026-01-02 12:50  
**Modelo Actual**: `google/gemini-2.5-flash`  
**Status**: ✅ Configurado correctamente
