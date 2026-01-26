# SKILL: INSECURE DIRECT OBJECT REFERENCE (IDOR)

<!-- critical -->
IDOR ocurre cuando una aplicación usa un identificador para acceder a un objeto sin verificar que el usuario tenga permisos para ese objeto. Permite ver, modificar o borrar datos de otros usuarios (Escalada de privilegios horizontal o vertical).
<!-- /critical -->

## 1. SCOPE - Dónde Buscar

<!-- scope -->
- **IDs en la URL**: `/api/user/123`, `/account/view?id=123`.
- **IDs en el Body**: `{"user_id": 123}`, `order_id=456`.
- **IDs en Cookies**: `current_user=123`.
- **Funcionalidades**:
  - Ver perfiles
  - Descargar facturas/tickets
  - Editar información personal
  - Resetear contraseñas
<!-- /scope -->

## 2. METHODOLOGY

<!-- methodology -->
1. **IDENTIFY**: Detectar parámetros que parezcan identificadores (números, UUIDs, nombres de usuario).
2. **CAPTURE**: Obtener un request válido con tu propio ID.
3. **TAMPER**: Cambiar el ID por el de otro usuario (e.g., de 123 a 124).
4. **COMPARE**: Verificar si la respuesta contiene datos que no te pertenecen o si la acción se realizó con éxito.
5. **ESCALATE**: Intentar acceder a IDs de niveles superiores (admin) o realizar acciones críticas (delete).
<!-- /methodology -->

## 3. KNOWLEDGE BASE

<!-- knowledge -->

### ID Types

- **Numeric**: Probar incrementos/decrementos (`123` -> `122`).
- **UUID**: Buscar UUIDs de otros usuarios en el código fuente, comentarios o listas públicas.
- **Hashed**: Determinar el algoritmo (MD5, Base64) y ver si el input es predecible (`base64(123)`).

### Common Bypasses

- **Parameter Pollution**: `/api/user?id=MINE&id=VICTIM`.
- **Method Swapping**: Cambiar `GET` por `POST` o `PUT` usando el ID de la víctima.
- **Change Content-Type**: Cambiar `application/json` por `application/xml` (a veces los filtros solo aplican a uno).
- **Wrap in Array**: `{"id": 123}` -> `{"id": [124]}`.

### Chaining Opportunities

- **IDOR → Account Takeover**: Si puedes editar el email del usuario vía IDOR en `/api/profile`.
- **IDOR → Information Leak**: Exfiltrar toda la base de datos de usuarios incrementando el ID en un script.

<!-- /knowledge -->

## 4. SCORING GUIDE

<!-- scoring_guide -->

| Score | Criterio | Ejemplo |
| :--- | :--- | :--- |
| **9-10** | **CONFIRMED** - Acceso a datos de otro usuario | Ves el email o datos privados de `user_124` siendo `user_123` |
| **7-8** | **HIGH** - Acción exitosa sobre objeto ajeno | Puedes "editar" o "borrar" un recurso que no es tuyo |
| **5-6** | **MEDIUM** - Error indica existencia pero no acceso | `403 Forbidden` al cambiar ID (indica que el objeto existe) |
| **3-4** | **LOW** - Id acepta diferentes valores pero no hay datos | Cambias ID y recibes `200 OK` pero la respuesta es vacía |
| **0-2** | **REJECT** - Falso positivo claro | Todos los IDs devuelven el mismo error o son tus propios datos |

**AUTO-SCORING KEYWORDS:**

- 9-10: "different user data", "modified successfully", "deleted successfully"
- 7-8: "unauthorized" (en contexto de acción exitosa), "Success"
- 5-6: "Access Denied" (específico por ID)
- 0-2: "EXPECTED: SAFE", "your profile"

<!-- /scoring_guide -->

## 5. FALSE POSITIVES

<!-- false_positives -->

**RECHAZAR INMEDIATAMENTE:**

1. El objeto es público por diseño (E.g., un post de blog).
2. El ID cambiado devuelve tus propios datos de nuevo.
3. El servidor usa un token de sesión fuerte que invalida el cambio de ID.
4. "EXPECTED: SAFE" marcado explícitamente.

**NO SON FALSOS POSITIVOS:**

- Que recibas un 403 Forbidden **SOLO** cuando el ID es válido de otro usuario (Confirma Enumeración).
- Que el ID sea un UUID pero se filtre en alguna parte de la aplicación.
- Que la vulnerabilidad requiera estar logueado (Sigue siendo un IDOR).

<!-- /false_positives -->

## 6. PAYLOADS

<!-- payloads -->

### HIGH VALUE (Manual Tampering)

```text
/api/v1/user/1
/api/v1/user/settings?id=1001
/download/invoice_2023_1001.pdf
```

### MEDIUM VALUE (Parameter Pollution)

```text
/api/edit_user?id=123&id=124
{"id": 124, "current_id": 123}
```

<!-- /payloads -->

## 7. PRO TIPS

<!-- pro_tips -->
1. **Always test with two accounts**: Una cuenta atacante, otra víctima. Confirma que el dato es de la PRECISIÓN.
2. **Numeric ID guessing**: Si el ID es `1000`, prueba `1` o `2` - a veces los admins tienen los primeros IDs.
3. **Check for "Me" or "Self" aliases**: Si la API usa `/api/user/me`, intenta cambiarlo por `/api/user/1`.
<!-- /pro_tips -->
