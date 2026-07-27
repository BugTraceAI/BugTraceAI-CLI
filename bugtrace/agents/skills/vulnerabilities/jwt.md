# SKILL: JWT VULNERABILITIES

<!-- critical -->
Las vulnerabilidades en JSON Web Tokens (JWT) pueden permitir el bypass de autenticación, la suplantación de identidad de otros usuarios (especialmente administradores) y en casos raros, RCE o ataques a la base de datos.
<!-- /critical -->

## 1. SCOPE - Dónde Buscar

<!-- scope -->
- **Authorization Header**: `Bearer eyJ...`
- **Cookies**: `session=eyJ...`, `auth_token=eyJ...`
- **LocalStorage/SessionStorage**: Donde la app guarda el token antes de enviarlo.
- **Funcionalidades**:
  - Login y persistencia de sesión.
  - APIs que requieren autenticación.
  - Integraciones de terceros (OAuth/OIDC).
<!-- /scope -->

## 2. METHODOLOGY

<!-- methodology -->
1. **DECODE**: Decodificar el JWT (base64) para inspeccionar el Header y el Payload.
2. **ALG NONE**: Intentar cambiar el `alg` a `none` y eliminar la firma.
3. **WEAK SECRET**: Intentar crackear la firma usando `hashcat` o `john` con diccionarios comunes.
4. **KEY CONFUSION**: Si el servidor usa RSA, intentar firmar el token con la clave pública usando el algoritmo `HS256`.
5. **KID INJECTION**: Inyectar en el campo `kid` para realizar Path Traversal o SQLi.
6. **CLAIM TAMPERING**: Cambiar claims como `admin=false` a `admin=true` o `user_id` de la víctima.
<!-- /methodology -->

## 3. KNOWLEDGE BASE

<!-- knowledge -->

### Common Attack Vectors

- **Algorithm None**: El servidor no verifica la firma si `alg: none`.
- **Weak Secret**: Uso de secretos como "secret", "123456", "admin".
- **JWKS Spoofing**: Cambiar la URL de `jku` o `jwk` hacia un servidor del atacante.
- **KID (Key ID) Issues**: El `kid` se usa directamente en una consulta o para cargar un archivo de clave.

### JWT Structure

- **Header**: Algoritmo y tipo de token.
- **Payload**: Datos del usuario (claims).
- **Signature**: Verificación de integridad.

### Bypasses

- **Remove Signature**: Algunos parsers aceptan el token sin el tercer segmento si el `alg` es modificado.
- **Case Sensitivity**: Probar `nOnE`, `None`, `NONE` para evadir filtros.

<!-- /knowledge -->

## 4. SCORING GUIDE

<!-- scoring_guide -->

| Score | Criterio | Ejemplo |
| :--- | :--- | :--- |
| **9-10** | **CONFIRMED** - Bypass de autenticación exitoso | Acceso a cuenta de admin tras modificar el token |
| **7-8** | **HIGH** - Firma crackeada o `alg: none` aceptado | El servidor devuelve `200 OK` con un token modificado |
| **5-6** | **MEDIUM** - Error indica validación débil | `Invalid signature` vs `Algorithm not supported` |
| **3-4** | **LOW** - Token presente pero bien configurado | Firma fuerte, claims poco interesantes |
| **0-2** | **REJECT** - Falso positivo claro | El token no se usa para autenticación real o es "EXPECTED: SAFE" |

**AUTO-SCORING KEYWORDS:**

- 9-10: "auth bypass confirmed", "logged as admin", "privileged access"
- 7-8: "signature bypass", "none algorithm accepted"
- 5-6: "weak secret detected", "kid injection reflected"
- 0-2: "token valid", "display only"

<!-- /scoring_guide -->

## 5. FALSE POSITIVES

<!-- false_positives -->

**RECHAZAR INMEDIATAMENTE:**

1. El token modificado siempre devuelve `401 Unauthorized` o `403 Forbidden`.
2. El servidor no usa el JWT para decisiones de autorización (es solo informativo).
3. "EXPECTED: SAFE" marcado explícitamente.
4. El token expira antes de poder probarlo y no hay forma de renovarlo.

**NO SON FALSOS POSITIVOS:**

- Que el servidor acepte un token con `alg: none` aunque no seas admin.
- Que el secreto sea crackeable aunque los claims sean limitados.
- Que el `kid` sea vulnerable a inyección aunque el token esté firmado.

<!-- /false_positives -->

## 6. PAYLOADS

<!-- payloads -->

### HIGH VALUE (None Algorithm)

```bash
# Header: {"alg":"none","typ":"JWT"}
# Payload: {"user":"admin"}
# Signature: (Empty)
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ.
```

### MEDIUM VALUE (Tampered Claims)

```text
# Change "admin": false to true and maintain same signature (only works if signature is not verified)
```

<!-- /payloads -->

## 7. PRO TIPS

<!-- pro_tips -->
1. **Check 'exp' claim**: Algunos servidores no validan la expiración del token.
2. **KID Path Traversal**: Intenta `kid: "../../../../../dev/null"` con un secreto vacío.
3. **Empty Secret**: A veces la clave secreta está vacía o es nula por error de configuración.
<!-- /pro_tips -->
