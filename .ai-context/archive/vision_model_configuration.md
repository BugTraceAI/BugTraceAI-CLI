# Vision Model Configuration for XSS Validation
## 2026-01-02 - Cost-Conscious Strategy

---

## 🎯 MODELO SELECCIONADO

**Modelo**: `qwen/qwen3-vl-8b-thinking`  
**URL**: https://openrouter.ai/qwen/qwen3-vl-8b-thinking  
**Uso**: SOLO para validación XSS (confirmar alert() en screenshots)

---

## 💰 ESTRATEGIA COST-CONSCIOUS

### ❌ NO USAR Vision Para:
- Análisis general de páginas
- Detección automática de vulns
- Exploración de UI
- Análisis masivo de screenshots

### ✅ USAR Vision SOLO Para:
- **Confirmar XSS**: ¿Hay alert() en screenshot?
- **Respuesta binaria**: Sí/No
- **1 imagen por payload** exitoso
- **Solo cuando payload ejecuta**

---

## 📊 COSTO ESTIMADO

**Qwen3-VL-8b-thinking**:
- Por imagen: ~$0.001 - $0.005
- Por validación: 1 imagen

**Escenario típico**:
- XSS encontrado → 1 payload exitoso → 1 screenshot → 1 validación
- **Costo por XSS validado**: ~$0.001 - $0.005

**100 URLs con XSS**:
- ~10 XSS confirmados → 10 validaciones
- **Total**: ~$0.01 - $0.05

---

## 🔧 IMPLEMENTACIÓN

### Configuración:
```ini
# bugtraceaicli.conf
[VALIDATION]
VISION_MODEL = qwen/qwen3-vl-8b-thinking
VISION_ENABLED = True
VISION_ONLY_FOR_XSS = True  # No usar para análisis general
MAX_VISION_CALLS_PER_URL = 3  # Límite de seguridad
```

### Flujo de Validación:
```
1. ExploitAgent lee report
2. Ve "XSS detectado (0.60 confidence)"
3. Lanza payload XSS
4. Browser ejecuta → Screenshot capturado
5. SOLO SI screenshot existe:
   → Vision model: "¿Hay alert() aquí?"
   → Respuesta: Sí/No
6. Si Sí → XSS CONFIRMADO ✅
```

---

## 🎯 PROMPT PARA VISION

**Prompt ultra-conciso** (minimizar tokens):
```
Image shows browser screenshot. 
Question: Is there a JavaScript alert() dialog visible?
Answer only: YES or NO
```

**Respuesta esperada**: `YES` o `NO`

---

## ⚠️ LÍMITES DE SEGURIDAD

1. **Max 3 vision calls por URL** (evitar costo excesivo)
2. **Solo para XSS** (no SQLi, no otros)
3. **Solo si screenshot existe** (no llamar sin imagen)
4. **Solo si payload ejecutó** (no llamar en fallos)
5. **Timeout 10s** (no esperar indefinidamente)

---

## 📝 LOGGING

```python
logger.info(f"[Vision] XSS validation requested for {url}")
logger.info(f"[Vision] Screenshot: {screenshot_path}")
logger.info(f"[Vision] Model: qwen/qwen3-vl-8b-thinking")
logger.info(f"[Vision] Result: {result}")  # YES/NO
logger.info(f"[Vision] Cost: ~$0.001-0.005")
```

---

## 🚀 INTEGRACIÓN CON EXPLOITAGENT

```python
async def validate_xss_with_vision(self, screenshot_path: str) -> bool:
    """
    Validate XSS using vision model.
    Cost-conscious: ONLY call if screenshot exists.
    """
    if not Path(screenshot_path).exists():
        logger.warning(f"[Vision] Screenshot not found: {screenshot_path}")
        return False
    
    # Check vision call count
    if self.vision_calls >= self.max_vision_calls:
        logger.warning(f"[Vision] Max calls reached ({self.max_vision_calls})")
        return False
    
    # Ultra-concise prompt
    prompt = "Image shows browser. Is there alert() dialog? Answer: YES or NO"
    
    # Call vision model
    result = await self.llm_client.generate_with_image(
        prompt=prompt,
        image_path=screenshot_path,
        model_override="qwen/qwen3-vl-8b-thinking",
        module_name="ExploitAgent-Vision"
    )
    
    self.vision_calls += 1
    
    # Parse response
    is_xss = "YES" in result.upper()
    
    logger.info(f"[Vision] XSS validation: {is_xss} (cost: ~$0.003)")
    
    return is_xss
```

---

## ✅ VENTAJAS

1. **Cost-effective**: Solo 1 imagen por XSS
2. **Preciso**: Vision confirma visual evidence
3. **Limitado**: No análisis masivo
4. **Binario**: Respuesta simple Sí/No
5. **Seguro**: Límites de uso incorporados

---

**Modelo**: `qwen/qwen3-vl-8b-thinking`  
**Uso**: XSS validation ONLY  
**Costo**: ~$0.001-0.005 por validación  
**Status**: Listo para implementar ✅
