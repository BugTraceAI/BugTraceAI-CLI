# XSS Agent: HTTP Method-Aware Exploitation (POST Support)

**Fecha**: 2026-02-10
**Estado**: Implementado y verificado

## Problema

El XSSAgent descubria parametros de formularios HTML pero **nunca extraia el `method` del `<form>`**. Todos los requests en el pipeline de escalacion (L1-L6) iban por GET hardcodeado.

Resultado: parametros POST (como `searchFor` en testphp.vulnweb.com) se descubrian correctamente pero se testeaban con GET → no reflejaban → 6 niveles agotados → **XSS no encontrado**.

### Ejemplo real

```
testphp.vulnweb.com/search.php

<form action="/search.php" method="POST">
    <input name="searchFor" type="text">
</form>
```

- `GET /search.php?searchFor=<payload>` → **NO refleja** (servidor ignora query string)
- `POST /search.php` con `searchFor=<payload>` → **Refleja sin escapar** en `<h2>searched for: <payload></h2>`

XSS trivial por POST, invisible para el pipeline anterior.

## Diagnostico

La informacion del method se perdia porque **nunca se extraia**:

| Etapa | Tenia method? |
|-------|:---:|
| `_discover_xss_params()` | NO — parseaba `<input>` sin mirar el `<form>` padre |
| WET findings | NO — campo `http_method` vacio |
| LLM dedup (WET→DRY) | NO — schema no incluia method |
| DRY findings | NO |
| `_xss_escalation_pipeline()` | NO — no aceptaba method |
| `_send_payload()` | **GET hardcodeado** (`session.get()`) |
| Go bridge | **GET hardcodeado** (solo query string) |

## Solucion

### 1. Discovery: Extraer method del form padre

`_discover_xss_params()` ahora busca el `<form>` padre de cada `<input>`:

```python
parent_form = tag.find_parent("form")
form_method = (parent_form.get("method") or "GET").upper()
self._param_methods[param_name] = form_method
```

Los metodos se almacenan en `self._param_methods: Dict[str, str]`.

### 2. Propagacion WET → DRY

- `analyze_and_dedup_queue()` agrega `http_method` a cada finding expandido
- `_llm_analyze_and_dedup()` incluye `http_method` en el schema del LLM
- Post-LLM merge: si el LLM pierde el campo, se recupera del WET original

### 3. `_send_payload()` — GET y POST

```python
if method == "POST":
    # Payload en body con form-encoded
    async with session.post(base_url, data={param: payload}, ...)
else:
    # Payload en query string (comportamiento original)
    async with session.get(attack_url, ...)
```

Usa `self._current_http_method` como atributo de instancia para evitar cambiar 20+ firmas internas.

### 4. Go bridge: Skip para POST

Go fuzzer solo soporta GET (query string injection). Para params POST:
- L2 salta el Go bridge
- Usa Python fallback directamente
- Log: `"Skipping Go bridge for POST param"`

### 5. L4 Manipulator: Method en MutableRequest

```python
MutableRequest(method="POST", url=..., data=base_params)
```

`MutableRequest` ya soportaba `method` y `data`, solo no se usaba.

### 6. L5 Browser: Skip para POST (prototipo)

Playwright form submission es complejo. Por ahora L5 se salta para params POST.

### 7. XSSFinding: Campo `http_method`

- Nuevo campo `http_method: str = "GET"` en el dataclass
- `_tag_method()` wrapper asegura que cada finding lleva el method correcto
- `_finding_to_dict()` genera `curl -X POST` para reproduccion

## Patron de diseno: `self._current_http_method`

En vez de modificar las firmas de 20+ metodos internos (L1, L2, L3, etc.), usamos un atributo de instancia:

```
_xss_escalation_pipeline(http_method="POST")
  → self._current_http_method = "POST"
    → _send_payload() lee self._current_http_method
```

Simple, no invasivo, backwards-compatible.

## Archivos modificados

Solo 1 fichero: `bugtrace/agents/xss_agent.py`

| Zona | Cambio |
|------|--------|
| `XSSFinding` dataclass | Campo `http_method` |
| `_discover_xss_params()` | `self._param_methods` desde `<form>` padre |
| `analyze_and_dedup_queue()` | Propagar `http_method` en expanded findings |
| `_llm_analyze_and_dedup()` | Schema + post-LLM merge |
| `exploit_dry_list()` | Leer y pasar `http_method` |
| `_xss_escalation_pipeline()` | Param + `self._current_http_method` + `_tag_method()` |
| `_send_payload()` | Branch GET/POST |
| L2 static bombing | Skip Go para POST |
| L4 Manipulator | `MutableRequest` con method |
| L5 Browser | Skip para POST |
| `_finding_to_dict()` | `http_method` + reproduction con curl |

## Verificacion

### Test 1: testphp.vulnweb.com (POST)
```
Discovery: searchFor → POST ✅
POST refleja: True ✅
GET NO refleja: True ✅ (confirma el bug original)
L2 confirma XSS con payload visual ✅
```

### Test 2: ginandjuice.shop (regresion GET)
```
category → GET ✅
searchTerm → GET ✅
Todos params GET ✅ (sin falsos POST)
```

### Payload confirmado
```
"><img src=x onerror=var b=document.createElement('div');b.id='bt-pwn';
b.innerText='HACKED BY BUGTRACEAI';document.body.prepend(b)>
```
Method: POST | Level: L2 | Validation: HTTP confirmed

## Limitaciones actuales (prototipo)

1. **Go bridge** no soporta POST → Python fallback (mas lento, ~882 payloads en ~30s vs ~3s)
2. **L5 Browser** skip para POST → si L1-L4 no confirman, va directo a L6 CDP
3. **Solo XSSAgent** — los otros 12 specialists siguen asumiendo GET
4. **Hardcoded** — la deteccion de method es codigo, no razonamiento LLM

## Trabajo futuro

Reemplazar la logica hardcodeada de discovery por un **LLM reasoning step** en el WET→DRY:

```
"Para cada finding, analiza el HTML y dime:
method, content-type, contexto real, payload recomendado"
```

Esto cubriria POST, JSON body, PUT, multipart, etc. sin mas `if/else`.
El sistema de skills (`XSSSkill`, `SQLiSkill`) ya existe y podria encapsular esta logica.
